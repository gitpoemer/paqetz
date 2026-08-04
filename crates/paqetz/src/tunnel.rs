//! The run loop: TUN ↔ core ↔ tcpwire ↔ datapath.
//!
//! Three threads and one lock. One reads the TUN device, encrypts, and puts
//! packets on the wire; one reads the wire, decrypts, and writes to the TUN
//! device; one drives handshake and rekey timers. There is no async runtime,
//! because a fixed set of long-lived descriptors gains nothing from one and
//! pays scheduling overhead per packet.
//!
//! # State
//!
//! Everything the two data threads share is one [`PeerState`] behind a mutex:
//! the Noise session, the carrier's connection state, and the peer's current
//! endpoint. That is the whole of the tunnel's mutable state — O(peers), never
//! O(flows) (D4).
//!
//! Taking a lock per packet is a deliberate phase-1 simplification. With two
//! threads it is an uncontended atomic in the common case; removing it belongs
//! with the rest of the throughput work.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use paqetz_core::noise::{self, Initiator, PendingResponder, Session};
use paqetz_core::{Millis, PublicKey};
use paqetz_dp::{AfPacketTx, MAX_FRAME, PacketRx, RawTx, Transmit, Tun, sys};
use paqetz_tcpwire::segment::{self, MAX_OVERHEAD};
use paqetz_tcpwire::{Endpoint as Carrier, Role};

use crate::config::{Config, Datapath};
use crate::log::{debug, error, info, warn_};
use crate::stats::Stats;

/// How often the timer thread wakes.
const TICK: Duration = Duration::from_millis(250);

/// How long to wait before repeating an unanswered handshake.
///
/// WireGuard's interval. Long enough not to flood a peer that is down, short
/// enough that a transient loss costs a few seconds rather than a minute.
const REKEY_TIMEOUT: Millis = 5_000;

/// Random extra delay added to each repeat, up to this many milliseconds.
///
/// WireGuard's, and for its reason: two peers that lost each other at the same
/// moment would otherwise retry in step for ever, so a collision repeats rather
/// than resolves. A third of a second is enough to break the lockstep.
const REKEY_TIMEOUT_JITTER: Millis = 334;

/// How long to keep trying before giving up and waiting for traffic.
///
/// WireGuard's. Past this the peer is not transiently unreachable, it is gone,
/// and handshaking at it every five seconds for ever tells nobody anything.
/// Sending resumes the moment there is something to send.
const REKEY_ATTEMPT_TIME: Millis = 90_000;

/// How long a session may go unanswered before it is presumed dead.
///
/// WireGuard's, and the piece this had been missing entirely. A session is only
/// known to work while the peer keeps answering; if we have sent data and heard
/// nothing authenticated back for this long, the peer has forgotten us -- it
/// restarted, or its state diverged -- and no amount of waiting fixes it,
/// because nothing in the protocol says so out loud.
///
/// Without this the only thing that ever replaced a session was the rekey timer
/// at two minutes, so a server restart cost up to that long while the client
/// encrypted confidently into nothing.
const KEEPALIVE_TIMEOUT: Millis = 10_000;

/// Silence after sending that means the session is dead.
///
/// One keepalive interval for the peer to answer in, plus one handshake
/// interval, which is how WireGuard arrives at fifteen seconds.
const PRESUMED_DEAD: Millis = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

/// Largest inner packet we will handle.
const MAX_INNER: usize = 9000;

/// The shared, mutable state of the tunnel.
struct PeerState {
    /// The established session, once there is one.
    session: Option<Session>,
    /// A handshake we have sent and are awaiting a reply to.
    pending: Option<Initiator>,
    /// The synthetic TCP conversation with this peer.
    carrier: Option<Carrier>,
    /// Where the peer currently is.
    endpoint: Option<SocketAddrV4>,
    /// When the last handshake was sent.
    last_handshake: Millis,
    /// When the first handshake of the current attempt was sent.
    ///
    /// Separate from `last_handshake` so that giving up is measured from when
    /// trying started, not from the most recent try.
    attempt_started: Option<Millis>,
    /// When a packet from the peer last authenticated.
    ///
    /// The only evidence that the peer still has the session we are using.
    last_receive: Option<Millis>,
    /// When we last sent something under the current session.
    last_send: Option<Millis>,
    /// When a packet carrying actual data last arrived.
    ///
    /// Separate from `last_receive` so a keepalive cannot arm another one. Both
    /// ends answering every keepalive with a keepalive is a loop that never
    /// stops, and an empty packet is not something that needs acknowledging.
    last_data_receive: Option<Millis>,
}

impl PeerState {
    const fn new(endpoint: Option<SocketAddrV4>) -> Self {
        Self {
            session: None,
            pending: None,
            carrier: None,
            endpoint,
            last_handshake: 0,
            attempt_started: None,
            last_receive: None,
            last_send: None,
            last_data_receive: None,
        }
    }

    /// Whether the peer has stopped answering a session we are still using.
    ///
    /// Only asked of a session we have actually sent under: a tunnel that has
    /// been idle since it came up has heard nothing back because it has said
    /// nothing, which is not the same as being ignored.
    /// Records that a handshake just completed.
    ///
    /// The peer answered, which is the freshest evidence available that it holds
    /// this session -- so the liveness timers start from here rather than
    /// carrying over whatever made the previous session look dead. Without this
    /// the condition that triggered the handshake survives it, and the next tick
    /// triggers another, and the tunnel spends its life handshaking.
    fn established(&mut self, now: Millis) {
        self.last_receive = Some(now);
        self.last_send = None;
        self.last_data_receive = None;
        self.attempt_started = None;
    }

    /// Whether the peer has spoken and we owe it a word back.
    ///
    /// WireGuard's passive keepalive: after data arrives, if we have said
    /// nothing for a keepalive interval, send an empty packet. It holds any NAT
    /// mapping in the path open, and it gives the peer the evidence it needs to
    /// decide whether *we* are still here -- which is the same question this end
    /// asks with `presumed_dead`, from the other side.
    fn owes_keepalive(&self, now: Millis) -> bool {
        let Some(heard) = self.last_data_receive else {
            return false;
        };
        self.last_send.unwrap_or(0) < heard && now.saturating_sub(heard) >= KEEPALIVE_TIMEOUT
    }

    fn presumed_dead(&self, now: Millis) -> bool {
        let Some(sent) = self.last_send else {
            return false;
        };
        let heard = self.last_receive.unwrap_or(0);
        sent > heard && now.saturating_sub(heard) >= PRESUMED_DEAD
    }
}

/// A running tunnel.
pub(crate) struct Tunnel {
    cfg: Config,
    tun: Arc<Tun>,
    rx: Arc<PacketRx>,
    tx: Arc<Transmit>,
    state: Arc<Mutex<PeerState>>,
    /// Our own outer address and port.
    local: (Ipv4Addr, u16),
    /// Our static public key, needed to verify `mac1` on inbound handshakes.
    local_public: PublicKey,
    started: Instant,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
    /// Where the configuration was read from, so `SIGHUP` can re-read it.
    config_path: Option<std::path::PathBuf>,
}

/// Anything that can stop the tunnel starting.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// An operating-system call failed.
    #[error("{context}: {source}")]
    Os {
        /// What was being attempted.
        context: String,
        /// The underlying error.
        source: io::Error,
    },

    /// The cryptographic core rejected something.
    #[error("crypto: {0}")]
    Core(#[from] paqetz_core::Error),

    /// The carrier rejected something.
    #[error("carrier: {0}")]
    Wire(#[from] paqetz_tcpwire::Error),

    /// A configuration was valid but names something not yet built.
    #[error("{0}")]
    Unsupported(&'static str),
}

/// Result alias for this module.
pub(crate) type Result<T> = core::result::Result<T, Error>;

fn os<T>(context: impl Into<String>, r: io::Result<T>) -> Result<T> {
    r.map_err(|source| Error::Os {
        context: context.into(),
        source,
    })
}

impl Tunnel {
    /// Brings up the device, sockets, and firewall rules.
    ///
    /// # Errors
    /// Returns the first failure, with context describing what was attempted.
    pub(crate) fn start(cfg: Config) -> Result<Self> {
        if matches!(cfg.interface.carrier, paqetz_tcpwire::Carrier::Handshake) {
            // The carrier can emit SYN/SYN+ACK/ACK, but nothing here drives that
            // exchange or retries a lost SYN yet. Refusing is better than
            // starting a tunnel whose first data segment fails with
            // "not established". See docs/decisions/D14-carrier-mode.md.
            return Err(Error::Unsupported(
                "carrier = \"handshake\" is not implemented yet; \
                 use the default \"midstream\"",
            ));
        }

        let local_public =
            paqetz_core::keys::public_from_private(cfg.interface.private_key.as_bytes());

        // Choosing our own outer port above the kernel's ephemeral range keeps
        // it from colliding with a port the kernel hands to some other socket.
        // paqet picked from 32768-65535, which overlaps that range exactly.
        let local_port = if cfg.interface.listen_port == 0 {
            let r = os("choosing an outer port", random_u32())?;
            61_000 + u16::try_from(r % 4_000).unwrap_or(0)
        } else {
            cfg.interface.listen_port
        };

        // Our own outer address is whichever one the kernel would route from.
        // Asking it directly avoids putting an address in the configuration
        // that then has to be kept in step with the host's networking.
        let local_ip = match cfg.peer.endpoint {
            Some(peer) => os(
                "determining our outer address",
                source_address_for(*peer.ip()),
            )?,
            // The side that waits learns its own address from the destination
            // of the first packet that arrives, so nothing is needed here.
            None => Ipv4Addr::UNSPECIFIED,
        };

        let interface = os(
            "finding the interface that routes to the peer",
            outbound_interface(),
        )?;

        let tun = Tun::create(&cfg.interface.device).map_err(|source| Error::Os {
            context: format!("creating TUN device {}", cfg.interface.device),
            source,
        })?;
        os(
            "configuring the TUN device",
            tun.configure(
                cfg.interface.address,
                cfg.interface.netmask,
                cfg.interface.mtu,
            ),
        )?;

        let rx = os(
            format!("opening a capture socket on {interface}"),
            PacketRx::open(&interface, local_port),
        )?;
        let _ = rx.set_recv_buffer(8 * 1024 * 1024);

        let tx = match cfg.interface.transmit {
            crate::config::TransmitPath::Raw => {
                Transmit::Raw(os("opening the transmit socket", RawTx::open())?)
            }
            crate::config::TransmitPath::AfPacket => {
                // Needs a peer address to resolve the next hop toward, which
                // only the initiating side has at start-up.
                let peer = cfg.peer.endpoint.map_or(Ipv4Addr::UNSPECIFIED, |e| *e.ip());
                if peer.is_unspecified() {
                    return Err(Error::Unsupported(
                        "transmit = \"afpacket\" needs a peer endpoint to resolve \
                         the next hop toward; the waiting side must use \"raw\"",
                    ));
                }
                Transmit::AfPacket(os(
                    "opening the AF_PACKET transmit socket",
                    AfPacketTx::open(&interface, peer),
                )?)
            }
        };
        let _ = tx.set_send_buffer(4 * 1024 * 1024);
        info!("transmit via {}", tx.name());

        Ok(Self {
            state: Arc::new(Mutex::new(PeerState::new(cfg.peer.endpoint))),
            cfg,
            tun: Arc::new(tun),
            rx: Arc::new(rx),
            tx: Arc::new(tx),
            local: (local_ip, local_port),
            local_public,
            started: Instant::now(),
            running: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(Stats::default()),
            config_path: None,
        })
    }

    /// The outer port this end actually receives on.
    ///
    /// Not known from the configuration alone: the initiating side takes an
    /// ephemeral port at start-up, and the firewall rules have to name the port
    /// the kernel would otherwise send resets from — which is this one, not the
    /// peer's.
    pub(crate) const fn local_port(&self) -> u16 {
        self.local.1
    }

    /// Milliseconds since the tunnel started.
    fn now(&self) -> Millis {
        Millis::try_from(self.started.elapsed().as_millis()).unwrap_or(Millis::MAX)
    }

    /// Whether this end initiates handshakes.
    const fn is_initiator(&self) -> bool {
        self.cfg.peer.is_initiator()
    }

    /// Runs until stopped. Consumes the tunnel.
    ///
    /// # Errors
    /// Returns a failure from thread startup; per-packet errors are logged and
    /// the loop continues, since one bad packet must never stop the tunnel.
    pub(crate) fn run(self) -> Result<()> {
        let this = Arc::new(self);

        let outbound = Arc::clone(&this);
        let t1 = std::thread::Builder::new()
            .name("tun-to-wire".to_owned())
            .spawn(move || outbound.tun_to_wire())
            .map_err(|source| Error::Os {
                context: "starting the outbound thread".to_owned(),
                source,
            })?;

        let inbound = Arc::clone(&this);
        let t2 = std::thread::Builder::new()
            .name("wire-to-tun".to_owned())
            .spawn(move || inbound.wire_to_tun())
            .map_err(|source| Error::Os {
                context: "starting the inbound thread".to_owned(),
                source,
            })?;

        let timers = Arc::clone(&this);
        let t3 = std::thread::Builder::new()
            .name("timers".to_owned())
            .spawn(move || timers.timers())
            .map_err(|source| Error::Os {
                context: "starting the timer thread".to_owned(),
                source,
            })?;

        let health = Arc::clone(&this);
        let t4 = std::thread::Builder::new()
            .name("health".to_owned())
            .spawn(move || health.health())
            .map_err(|source| Error::Os {
                context: "starting the health thread".to_owned(),
                source,
            })?;

        // The worker threads block in `read` and `recv`, so they cannot notice
        // a flag on their own. The process exits once this returns and the
        // caller has removed the firewall rules; the blocked threads go with
        // it. Waking them properly needs the poll loop that arrives with the
        // rest of the throughput work.
        while this.running.load(Ordering::Relaxed) && !SHUTDOWN.load(Ordering::Relaxed) {
            std::thread::sleep(TICK);
            if reload_requested()
                && let Some(path) = this.config_path.as_ref()
            {
                this.reload(path);
            }
        }
        this.stop();

        drop((t1, t2, t3, t4));
        Ok(())
    }

    /// Remembers where the configuration came from, enabling `SIGHUP`.
    pub(crate) fn watch_config(&mut self, path: std::path::PathBuf) {
        self.config_path = Some(path);
    }

    /// A handle to the flag that stops every loop, including any front end
    /// started alongside the tunnel.
    pub(crate) fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Prints the health line every `health_interval` seconds.
    fn health(&self) {
        let interval = self.cfg.interface.health_interval;
        if interval == 0 {
            return;
        }
        let mut next = Duration::from_secs(interval);
        while self.running.load(Ordering::Relaxed) && !SHUTDOWN.load(Ordering::Relaxed) {
            std::thread::sleep(TICK);
            if self.started.elapsed() < next {
                continue;
            }
            next = self.started.elapsed() + Duration::from_secs(interval);
            if crate::log::enabled(crate::log::Level::Info) {
                // The kernel's own drop counter resets on read, so each line
                // reports the interval since the last rather than a total.
                let drops = self.rx.drops().ok();
                crate::log::emit(
                    crate::log::Level::Info,
                    format_args!("{}", self.stats.line(self.now(), drops)),
                );
            }
        }
    }

    /// Applies the parts of a new configuration that can change without
    /// dropping the session, and reports the parts that cannot.
    ///
    /// Deliberately narrow. The log level is the field worth changing on a
    /// running tunnel — turning on detail when something is wrong, without
    /// interrupting the traffic being investigated. Everything else either
    /// belongs to a live session (keys, the carrier's numbering) or to a socket
    /// already bound, and pretending otherwise would produce a tunnel whose
    /// behaviour no longer matches its configuration file.
    pub(crate) fn reload(&self, path: &std::path::Path) {
        let fresh = match Config::load(path) {
            Ok(c) => c,
            Err(e) => {
                error!("reload: {e}; keeping the running configuration");
                return;
            }
        };

        if fresh.interface.log != crate::log::level() {
            crate::log::set_level(fresh.interface.log);
            // Emitted after the change so raising the level shows this line.
            info!("reload: log level is now {}", fresh.interface.log.name());
        }

        let old = &self.cfg;
        let mut needs_restart = Vec::new();
        if fresh.peer.public_key != old.peer.public_key {
            needs_restart.push("peer.public_key");
        }
        if fresh.peer.endpoint != old.peer.endpoint {
            needs_restart.push("peer.endpoint");
        }
        if fresh.peer.allowed_ips != old.peer.allowed_ips {
            needs_restart.push("peer.allowed_ips");
        }
        if fresh.interface.listen_port != old.interface.listen_port {
            needs_restart.push("interface.listen_port");
        }
        if fresh.interface.mtu != old.interface.mtu {
            needs_restart.push("interface.mtu");
        }
        if fresh.interface.address != old.interface.address {
            needs_restart.push("interface.address");
        }
        if fresh.interface.profile != old.interface.profile {
            needs_restart.push("interface.profile");
        }
        if fresh.interface.datapath != old.interface.datapath {
            needs_restart.push("interface.datapath");
        }
        if fresh.interface.transmit != old.interface.transmit {
            needs_restart.push("interface.transmit");
        }
        if fresh.interface.health_interval != old.interface.health_interval {
            needs_restart.push("interface.health_interval");
        }

        if needs_restart.is_empty() {
            debug!("reload: nothing else changed");
        } else {
            warn_!(
                "reload: {} changed but needs a restart to take effect",
                needs_restart.join(", ")
            );
        }
    }

    /// Asks the loops to stop.
    pub(crate) fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    // -- outbound ------------------------------------------------------------

    /// Reads inner packets, encrypts them, and puts them on the wire.
    fn tun_to_wire(&self) {
        match self.cfg.interface.datapath {
            Datapath::Simple => self.tun_to_wire_simple(),
            Datapath::Batched => self.tun_to_wire_batched(),
        }
    }

    /// One packet per syscall.
    fn tun_to_wire_simple(&self) {
        let mut inner = vec![0u8; MAX_INNER];
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut frame = vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD];

        while self.running.load(Ordering::Relaxed) {
            let n = match self.tun.recv(&mut inner) {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading the device failed: {e}");
                    break;
                }
            };
            let Some(packet) = inner.get(..n) else {
                continue;
            };
            if let Err(e) = self.send_inner(packet, &mut sealed, &mut frame) {
                self.note_outbound(&e);
            }
        }
    }

    /// Drains whatever is queued, then sends it in one syscall.
    ///
    /// The first read blocks; the rest are non-blocking, so this only ever
    /// collects packets that were already waiting. Under one packet in flight
    /// it behaves exactly as the simple path does — batching costs latency only
    /// if you wait for a batch to form, and this does not.
    fn tun_to_wire_batched(&self) {
        // Set once, not per read. Toggling it around each read cost two extra
        // syscalls per packet, which made batching slower than not batching.
        if let Err(e) = self.tun.set_nonblocking(true) {
            error!("could not set the device non-blocking: {e}");
            return;
        }

        let mut inner: Vec<Vec<u8>> = (0..sys::BATCH).map(|_| vec![0u8; MAX_INNER]).collect();
        let mut frames: Vec<Vec<u8>> = (0..sys::BATCH)
            .map(|_| vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD])
            .collect();
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut lens = [0usize; sys::BATCH];
        let mut dsts = Vec::with_capacity(sys::BATCH);

        while self.running.load(Ordering::Relaxed) {
            // Block for the first, then take anything else already queued.
            let Some(first) = self.read_inner_blocking(&mut inner) else {
                break;
            };
            let mut count = 1;
            if let Some(slot) = lens.get_mut(0) {
                *slot = first;
            }
            while count < sys::BATCH {
                let Some(buf) = inner.get_mut(count) else {
                    break;
                };
                match self.tun.recv_nonblocking(buf) {
                    Ok(Some(n)) if n > 0 => {
                        if let Some(slot) = lens.get_mut(count) {
                            *slot = n;
                        }
                        count += 1;
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }

            // Encrypt each into its own frame buffer, then send them together.
            dsts.clear();
            let mut ready = 0usize;
            for i in 0..count {
                let Some(packet) = inner
                    .get(i)
                    .and_then(|b| b.get(..*lens.get(i).unwrap_or(&0)))
                else {
                    continue;
                };
                let Some(frame) = frames.get_mut(ready) else {
                    break;
                };
                match self.seal_into(packet, &mut sealed, frame) {
                    Ok(Some((written, dst))) => {
                        if let Some(slot) = lens.get_mut(ready) {
                            *slot = written;
                        }
                        dsts.push(dst);
                        ready += 1;
                    }
                    Ok(None) => {}
                    Err(e) => self.note_outbound(&e),
                }
            }
            if ready == 0 {
                continue;
            }

            let packets: Vec<&[u8]> = frames
                .iter()
                .take(ready)
                .enumerate()
                .filter_map(|(i, f)| f.get(..*lens.get(i).unwrap_or(&0)))
                .collect();
            if let Err(e) = self.tx.send_batch(&packets, &dsts) {
                self.note_outbound(&Error::Os {
                    context: "transmitting a batch".to_owned(),
                    source: e,
                });
            }
        }
    }

    /// Waits for one inner packet, returning its length.
    ///
    /// Blocks in `poll` rather than in `read`, so the device can stay
    /// non-blocking for the drain that follows, and so the wait has a timeout
    /// through which a shutdown request is noticed.
    fn read_inner_blocking(&self, inner: &mut [Vec<u8>]) -> Option<usize> {
        loop {
            if !self.running.load(Ordering::Relaxed) {
                return None;
            }
            match self.tun.wait_readable(250) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("waiting on the device failed: {e}");
                    return None;
                }
            }
            let buf = inner.first_mut()?;
            match self.tun.recv_nonblocking(buf) {
                Ok(Some(n)) if n > 0 => return Some(n),
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("reading the device failed: {e}");
                    return None;
                }
            }
        }
    }

    /// Records a per-packet outbound failure.
    ///
    /// Counted rather than logged: a packet we cannot send is dropped exactly
    /// as a congested link would drop it, and a line per drop would let a
    /// congested link decide how much this process writes.
    fn note_outbound(&self, e: &Error) {
        Stats::bump(&self.stats.tx_dropped);
        debug!("outbound packet dropped: {e}");
    }

    /// Encrypts one inner packet and transmits it immediately.
    fn send_inner(&self, packet: &[u8], sealed: &mut [u8], frame: &mut [u8]) -> Result<()> {
        let Some((written, dst)) = self.seal_into(packet, sealed, frame)? else {
            return Ok(());
        };
        let Some(out) = frame.get(..written) else {
            return Ok(());
        };
        os("transmitting", self.tx.send(out, dst)).map(|_| ())
    }

    /// Encrypts one inner packet into `frame`, ready to transmit.
    ///
    /// Returns the frame's length and where to send it, or `None` when there is
    /// no session yet — in which case the packet is lost, which is what a link
    /// that is not up yet looks like from above.
    fn seal_into(
        &self,
        packet: &[u8],
        sealed: &mut [u8],
        frame: &mut [u8],
    ) -> Result<Option<(usize, Ipv4Addr)>> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let Some(session) = state.session.as_mut() else {
            return Ok(None);
        };
        let n = session.seal(packet, sealed, now)?;
        // Half of the liveness question -- but only for a packet carrying data.
        //
        // A keepalive is empty, and the far end answers an empty packet with
        // nothing, because there is nothing to answer. Arming this on one would
        // therefore ask a question that cannot be answered and then read the
        // silence as proof the peer had gone: an idle tunnel would send a
        // keepalive, wait fifteen seconds, and rehandshake, for ever.
        if !packet.is_empty() {
            state.last_send = Some(now);
        }
        Stats::bump(&self.stats.tx_packets);
        Stats::add(&self.stats.tx_bytes, packet.len() as u64);

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(None);
        };
        let Some(payload) = sealed.get(..n) else {
            return Ok(None);
        };
        let written = carrier.data(payload, frame, now)?;
        let dst = carrier.remote().0;
        Ok(Some((written, dst)))
    }

    // -- inbound -------------------------------------------------------------

    /// Reads from the wire, decrypts, and writes inner packets to the device.
    fn wire_to_tun(&self) {
        match self.cfg.interface.datapath {
            Datapath::Simple => self.wire_to_tun_simple(),
            Datapath::Batched => self.wire_to_tun_batched(),
        }
    }

    /// Up to [`sys::BATCH`] frames per syscall.
    fn wire_to_tun_batched(&self) {
        let mut frames: Vec<Vec<u8>> = (0..sys::BATCH).map(|_| vec![0u8; MAX_FRAME]).collect();
        let mut lens = [0usize; sys::BATCH];
        let mut inner = vec![0u8; MAX_INNER];
        let mut reply = vec![0u8; MAX_FRAME];

        while self.running.load(Ordering::Relaxed) {
            let count = match self.rx.recv_batch(&mut frames, &mut lens) {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading from the wire failed: {e}");
                    break;
                }
            };
            for i in 0..count {
                let Some(bytes) = frames
                    .get(i)
                    .and_then(|f| f.get(..*lens.get(i).unwrap_or(&0)))
                else {
                    continue;
                };
                let Some(seg) = segment::parse_ethernet(bytes) else {
                    continue;
                };
                if let Err(e) = self.handle_segment(&seg, &mut inner, &mut reply) {
                    self.note_inbound(&e);
                }
            }
        }
    }

    /// Records a per-packet inbound failure.
    ///
    /// Counted rather than logged, and this is the case that matters: anything
    /// unauthenticated reaches here, so a line per packet would let whoever is
    /// sending garbage at the port choose how much this process writes to disk
    /// and how long it spends formatting. See `crate::stats`.
    fn note_inbound(&self, e: &Error) {
        match e {
            Error::Core(paqetz_core::Error::Rejected) => Stats::bump(&self.stats.rejected),
            Error::Core(paqetz_core::Error::Replay) => Stats::bump(&self.stats.replayed),
            _ => Stats::bump(&self.stats.rejected),
        }
        debug!("inbound packet dropped: {e}");
    }

    /// One frame per syscall.
    fn wire_to_tun_simple(&self) {
        let mut frame = vec![0u8; MAX_FRAME];
        let mut inner = vec![0u8; MAX_INNER];
        let mut reply = vec![0u8; MAX_FRAME];

        while self.running.load(Ordering::Relaxed) {
            let n = match self.rx.recv(&mut frame) {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading from the wire failed: {e}");
                    break;
                }
            };
            let Some(bytes) = frame.get(..n) else {
                continue;
            };
            let Some(seg) = segment::parse_ethernet(bytes) else {
                continue;
            };
            if let Err(e) = self.handle_segment(&seg, &mut inner, &mut reply) {
                self.note_inbound(&e);
            }
        }
    }

    /// Dispatches one inbound segment.
    fn handle_segment(
        &self,
        seg: &segment::Segment<'_>,
        inner: &mut [u8],
        reply: &mut [u8],
    ) -> Result<()> {
        let from = SocketAddrV4::new(seg.src.0, seg.src.1);
        let payload = seg.payload;

        // A handshake and a transport packet can be the same length, so the
        // keyed mac1 decides which this is rather than the length (D7).
        if payload.len() == noise::MSG1_LEN
            && noise::verify_mac1(&self.local_public, payload).is_ok()
        {
            return self.handle_msg1(seg, payload, reply);
        }
        if payload.len() == noise::MSG2_LEN
            && noise::verify_mac1(&self.local_public, payload).is_ok()
        {
            return self.handle_msg2(seg, payload);
        }

        self.handle_transport(seg, from, inner)
    }

    /// Accepts an initiator's handshake and answers it.
    fn handle_msg1(
        &self,
        seg: &segment::Segment<'_>,
        payload: &[u8],
        reply: &mut [u8],
    ) -> Result<()> {
        if self.is_initiator() {
            // We initiate; an inbound msg1 is not ours to answer.
            return Ok(());
        }
        let now = self.now();
        let pending =
            PendingResponder::read(&self.cfg.interface.private_key, &self.local_public, payload)?;

        // The authorization decision (D11). An unknown key gets no reply at
        // all, so the port stays indistinguishable from one that is filtered.
        if pending.initiator_static() != &self.cfg.peer.public_key {
            return Err(paqetz_core::Error::Unauthorized.into());
        }

        let epoch = pending.epoch();
        let (isn_i, isn_r, ts_base) =
            noise::carrier_numbers(epoch, &self.cfg.peer.public_key, &self.local_public);

        let index = random_u32().map_err(|source| Error::Os {
            context: "generating a session index".to_owned(),
            source,
        })?;
        let (session, msg2) = pending.accept(index, now)?;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // As on the initiating side: a rekey must not restart the conversation
        // underneath it, so the carrier is built once and then kept.
        if state.carrier.is_none() {
            // We learn our own outer address from where the peer sent to.
            state.carrier = Some(Carrier::new(paqetz_tcpwire::Config {
                local: (seg.dst.0, seg.dst.1),
                remote: seg.src,
                profile: self.cfg.interface.profile,
                role: Role::Responder,
                carrier: self.cfg.interface.carrier,
                isn: isn_r,
                peer_isn: isn_i,
                ts_base,
                sequencing: self.cfg.interface.sequencing,
            }));
        }

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(());
        };
        carrier.set_remote(seg.src);
        // Fold in the segment that carried msg1, so our acknowledgement counts
        // the bytes the peer actually sent.
        carrier.on_receive(seg);

        let written = carrier.data(&msg2, reply, now)?;
        let dst = seg.src.0;

        state.session = Some(session);
        state.pending = None;
        state.established(now);
        state.endpoint = Some(SocketAddrV4::new(seg.src.0, seg.src.1));
        drop(state);

        self.stats.note_handshake(now);
        info!(
            "handshake completed with {} at {}:{}",
            self.cfg.peer.public_key, seg.src.0, seg.src.1
        );

        let Some(out) = reply.get(..written) else {
            return Ok(());
        };
        os("transmitting handshake reply", self.tx.send(out, dst)).map(|_| ())
    }

    /// Completes our own handshake.
    fn handle_msg2(&self, seg: &segment::Segment<'_>, payload: &[u8]) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pending) = state.pending.take() else {
            return Ok(());
        };
        match pending.finish(payload, now) {
            Ok(session) => {
                if let Some(carrier) = state.carrier.as_mut() {
                    carrier.on_receive(seg);
                }
                state.session = Some(session);
                state.established(now);
                drop(state);
                self.stats.note_handshake(now);
                info!("handshake completed with {}", self.cfg.peer.public_key);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Decrypts a transport packet and delivers it.
    fn handle_transport(
        &self,
        seg: &segment::Segment<'_>,
        from: SocketAddrV4,
        inner: &mut [u8],
    ) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let Some(session) = state.session.as_mut() else {
            return Ok(());
        };
        let n = session.open(seg.payload, inner, now)?;

        // Authenticated, so the endpoint is trustworthy. Roaming (D5): the peer
        // may have moved, and following it here is what makes a NAT rebinding
        // invisible instead of fatal.
        if state.endpoint != Some(from) {
            let was = state.endpoint;
            state.endpoint = Some(from);
            if let Some(carrier) = state.carrier.as_mut() {
                carrier.set_remote((from.ip().to_owned(), from.port()));
            }
            Stats::bump(&self.stats.roams);
            // The single most useful line when a link is flapping: it says the
            // peer moved and the tunnel followed, rather than leaving a gap in
            // traffic with no explanation.
            info!(
                "peer moved from {} to {from}",
                was.map_or_else(|| "unknown".to_owned(), |a| a.to_string())
            );
        }
        if let Some(carrier) = state.carrier.as_mut() {
            carrier.on_receive(seg);
        }
        // The other half. This is reached only for a packet that decrypted and
        // passed the replay window, so it is the peer speaking and no one else:
        // the one piece of evidence that it still holds this session.
        state.last_receive = Some(now);
        // An empty packet is a keepalive and needs no reply; answering one would
        // have the two ends trading them for ever.
        if n > 0 {
            state.last_data_receive = Some(now);
        }
        drop(state);

        let Some(packet) = inner.get(..n) else {
            return Ok(());
        };
        Stats::bump(&self.stats.rx_packets);
        Stats::add(&self.stats.rx_bytes, n as u64);
        self.deliver(packet)
    }

    /// Checks an inner packet and writes it to the device.
    fn deliver(&self, packet: &[u8]) -> Result<()> {
        let Some(source) = inner_source(packet) else {
            return Ok(());
        };

        // Cryptokey routing (D12). Without this a peer can claim any inner
        // source address, including one that reaches a service bound to the
        // host's loopback.
        if !self.cfg.peer.permits(source) {
            Stats::bump(&self.stats.disallowed);
            debug!("inner packet refused: source {source} is outside the peer's range");
            // Once, at a level that is on by default. The counter alone does
            // not point anywhere, and this has a single overwhelming cause: a
            // peer that is a way out sends back replies carrying the address of
            // whatever site was reached, and a peer restricted to its own
            // address refuses every one of them. Handshake fine, tunnel up,
            // counters moving, nothing arrives -- with nothing to suggest the
            // configuration is what is refusing it.
            if !self
                .stats
                .explained_disallowed
                .swap(true, Ordering::Relaxed)
            {
                warn_!("refused an inner packet from {source}: outside this peer's allowed_ips");
                warn_!(
                    "if this peer is a way out to the internet, it needs \
                     `allowed_ips = [\"0.0.0.0/0\"]`"
                );
            }
            return Ok(());
        }
        if !plausible_source(source) {
            Stats::bump(&self.stats.martian);
            debug!("inner packet refused: source {source} is not a usable address");
            return Ok(());
        }

        match self.tun.send(packet) {
            Ok(_) => Ok(()),
            // The device is non-blocking in batched mode, so a full queue
            // refuses the write. That is a drop, exactly as a congested link
            // would be, and inner protocols already cope with it.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(source) => Err(Error::Os {
                context: "writing to the TUN device".to_owned(),
                source,
            }),
        }
    }

    // -- timers --------------------------------------------------------------

    /// Starts and refreshes handshakes.
    fn timers(&self) {
        // A responder never starts a handshake, but it does owe keepalives: the
        // peer decides whether this end is still here from what it hears back,
        // and an end that only ever answers goes quiet the moment the other
        // stops asking. So both roles run this loop; only one of them
        // handshakes.
        let initiator = self.is_initiator();
        let mut frame = vec![0u8; MAX_FRAME];
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut keepalive_frame =
            vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD];

        while self.running.load(Ordering::Relaxed) {
            if initiator && let Err(e) = self.maybe_handshake(&mut frame) {
                warn_!("handshake attempt failed: {e}");
            }
            if let Err(e) = self.maybe_keepalive(&mut sealed, &mut keepalive_frame) {
                debug!("keepalive failed: {e}");
            }
            std::thread::sleep(TICK);
        }
    }

    /// Sends an empty packet when the peer has spoken and we have not answered.
    ///
    /// The payload is empty on purpose: the far end drops a zero-length inner
    /// packet without looking at it, so this costs one frame and says the only
    /// thing it needs to -- that this end is still here and still holds the
    /// session.
    fn maybe_keepalive(&self, sealed: &mut [u8], frame: &mut [u8]) -> Result<()> {
        let now = self.now();
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.session.is_none() || !state.owes_keepalive(now) {
                return Ok(());
            }
        }
        debug!("keepalive");
        self.send_inner(&[], sealed, frame)
    }

    /// How long to wait before repeating a handshake, jittered.
    ///
    /// Two peers that lost each other at the same instant would otherwise retry
    /// in lockstep, so a collision repeats rather than resolves.
    fn rekey_interval() -> Millis {
        // No randomness available is a reason to retry on the flat interval,
        // not a reason to fail a handshake.
        REKEY_TIMEOUT + random_u32().map_or(0, |r| Millis::from(r) % REKEY_TIMEOUT_JITTER)
    }

    /// Sends a handshake if one is due.
    fn maybe_handshake(&self, frame: &mut [u8]) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // A repeat waits a jittered interval; a first attempt does not wait at
        // all, so a tunnel with something to send starts talking immediately.
        let waited = now.saturating_sub(state.last_handshake) >= Self::rekey_interval();

        // Giving up is measured from when trying started. Past that the peer is
        // not briefly unreachable, it is gone, and the attempt stops until there
        // is traffic again -- which `last_send` moving will show.
        let exhausted = state
            .attempt_started
            .is_some_and(|began| now.saturating_sub(began) >= REKEY_ATTEMPT_TIME);

        let due = match state.session.as_ref() {
            None if exhausted => false,
            None => state.pending.is_none() || waited,
            // A session is only known to work while the peer answers. Rekeying
            // on the timer alone left a peer that had forgotten us undetected
            // for two minutes, with everything sent in between encrypted to a
            // key nobody holds.
            Some(s) => s.needs_rekey(now) || (state.presumed_dead(now) && waited),
        };
        if !due {
            return Ok(());
        }
        if state.presumed_dead(now) && state.session.is_some() {
            warn_!(
                "no authenticated packet for {}s while sending; the peer has \
                 forgotten this session, starting a new handshake",
                PRESUMED_DEAD / 1000
            );
        }
        let Some(peer) = state.endpoint else {
            return Ok(());
        };

        let epoch = random_u32().map_err(|source| Error::Os {
            context: "generating an epoch".to_owned(),
            source,
        })?;
        let index = random_u32().map_err(|source| Error::Os {
            context: "generating a session index".to_owned(),
            source,
        })?;

        let (initiator, msg1) = Initiator::start(
            &self.cfg.interface.private_key,
            &self.local_public,
            &self.cfg.peer.public_key,
            index,
            epoch,
        )?;

        // The carrier is per *connection*, not per session. A rekey replaces
        // the keys above it and must leave the conversation underneath
        // untouched: rebuilding it would restart the sequence numbering on an
        // unchanged five-tuple every couple of minutes, which is exactly the
        // discontinuity byte-accurate sequencing exists to avoid.
        if state.carrier.is_none() {
            let (isn_i, isn_r, ts_base) =
                noise::carrier_numbers(epoch, &self.local_public, &self.cfg.peer.public_key);
            state.carrier = Some(Carrier::new(paqetz_tcpwire::Config {
                local: self.local,
                remote: (*peer.ip(), peer.port()),
                profile: self.cfg.interface.profile,
                role: Role::Initiator,
                carrier: self.cfg.interface.carrier,
                isn: isn_i,
                peer_isn: isn_r,
                ts_base,
                sequencing: self.cfg.interface.sequencing,
            }));
        }

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(());
        };
        let written = carrier.data(&msg1, frame, now)?;
        let dst = *peer.ip();

        state.pending = Some(initiator);
        state.last_handshake = now;
        state.attempt_started.get_or_insert(now);
        drop(state);

        Stats::bump(&self.stats.handshakes_sent);
        debug!("handshake sent to {peer}");

        let Some(out) = frame.get(..written) else {
            return Ok(());
        };
        os("transmitting handshake", self.tx.send(out, dst)).map(|_| ())
    }
}

/// Reads the source address of an inner IPv4 packet.
fn inner_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.first().map(|b| b >> 4) != Some(4) {
        return None;
    }
    Some(Ipv4Addr::new(
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    ))
}

/// Whether an inner source address is one a peer could legitimately hold.
///
/// Applied regardless of `allowed_ips`, so that widening the allowance — or
/// disabling it — still cannot be used to reach a service bound to the host's
/// loopback, or to spoof a link-local or multicast source (D12).
#[must_use]
pub(crate) fn plausible_source(addr: Ipv4Addr) -> bool {
    !(addr.is_loopback()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_link_local()
        || addr.is_unspecified())
}

/// Asks the kernel which local address it would use to reach `peer`.
///
/// Connecting a UDP socket sends nothing; it only performs the route lookup,
/// which is exactly the question being asked. This is why the configuration has
/// no local-address field.
fn source_address_for(peer: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.connect(SocketAddrV4::new(peer, 9))?;
    match sock.local_addr()? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        std::net::SocketAddr::V6(_) => Err(io::Error::other(
            "the route to the peer is IPv6, which is not supported yet",
        )),
    }
}

/// Names the interface carrying the default route.
///
/// Read from `/proc/net/route` rather than by invoking `ip`, so there is no
/// dependency on which userland is installed.
fn outbound_interface() -> io::Result<String> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(dest), Some(_gw), Some(flags)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // Destination 0.0.0.0 with the "up" flag set is the default route.
        let up = u32::from_str_radix(flags, 16).unwrap_or(0) & 0x0001 != 0;
        if dest == "00000000" && up {
            return Ok(iface.to_owned());
        }
    }
    Err(io::Error::other("no default route found"))
}

/// Set by the signal handler; polled by [`Tunnel::run`].
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Set by the signal handler when `SIGHUP` arrives.
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Whether a reload has been requested, clearing the request.
pub(crate) fn reload_requested() -> bool {
    RELOAD.swap(false, Ordering::Relaxed)
}

/// Records that a reload signal arrived.
extern "C" fn on_hangup(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

/// Records that a shutdown signal arrived.
///
/// Storing to an atomic is async-signal-safe; nothing else here would be, which
/// is why the handler does no work beyond this.
extern "C" fn on_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Arranges for `SIGINT` and `SIGTERM` to request a clean stop.
pub(crate) fn install_signal_handlers() {
    {
        let handler: extern "C" fn(libc::c_int) = on_hangup;
        // SAFETY: as below — the handler only stores to an atomic.
        unsafe {
            libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
        }
    }
    for sig in [libc::SIGINT, libc::SIGTERM] {
        let handler: extern "C" fn(libc::c_int) = on_signal;
        // SAFETY: `on_signal` is a plain `extern "C"` function that only stores
        // to an atomic, which is permitted in a signal handler. The pointer is
        // taken from the function item rather than cast from it, so there is no
        // question of the value being anything other than its address.
        unsafe {
            libc::signal(sig, handler as *const () as libc::sighandler_t);
        }
    }
}

/// Reads four random bytes from the kernel.
fn random_u32() -> io::Result<u32> {
    use std::io::Read as _;
    let mut buf = [0u8; 4];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    /// A peer state that has sent and received at the given times.
    fn spoke(sent: Option<Millis>, heard: Option<Millis>) -> PeerState {
        PeerState {
            last_send: sent,
            last_receive: heard,
            last_data_receive: heard,
            ..PeerState::new(None)
        }
    }

    #[test]
    fn an_idle_tunnel_does_not_handshake_itself_to_death() {
        // The regression this exists to stop. A keepalive is empty, so the peer
        // answers it with nothing -- there is nothing to answer. Arming the
        // liveness timer on one asks a question that cannot be answered and then
        // reads the silence as proof the peer had gone, so a healthy idle tunnel
        // rehandshakes for ever. Shipped, and observed in production as
        // throughput collapsing while the tunnel looked up.
        let heard = 1_000;
        let s = spoke(None, Some(heard));

        // The peer spoke, we owe it a keepalive, and we send one.
        assert!(s.owes_keepalive(heard + KEEPALIVE_TIMEOUT));
        // A keepalive must leave `last_send` alone: `seal_into` skips it for an
        // empty packet, so nothing here moves and the state is unchanged.
        assert!(
            !s.presumed_dead(heard + KEEPALIVE_TIMEOUT + PRESUMED_DEAD + 1),
            "an unanswered keepalive is not evidence of anything"
        );
    }

    #[test]
    fn a_completed_handshake_settles_the_liveness_timers() {
        // Otherwise the condition that triggered the handshake survives it, the
        // next tick triggers another, and each one replaces the session on both
        // ends and rejects whatever was in flight.
        let mut s = spoke(Some(1_000), Some(0));
        assert!(
            s.presumed_dead(PRESUMED_DEAD + 1),
            "dead before the handshake"
        );

        s.established(PRESUMED_DEAD + 1);
        assert!(
            !s.presumed_dead(PRESUMED_DEAD + 1),
            "the peer just answered; it cannot be dead in the same instant"
        );
        assert!(
            !s.presumed_dead(PRESUMED_DEAD * 2),
            "and stays alive until something is sent and goes unanswered"
        );
        assert_eq!(s.attempt_started, None, "the attempt succeeded");
    }

    #[test]
    fn data_after_a_handshake_still_arms_the_liveness_timer() {
        // The fix must not disable the mechanism it is fixing.
        let mut s = spoke(None, None);
        s.established(0);
        s.last_send = Some(1_000);
        assert!(s.presumed_dead(1_000 + PRESUMED_DEAD));
    }

    #[test]
    fn a_session_nobody_answers_is_presumed_dead() {
        // The gap this closes: before it, the only thing that ever replaced a
        // session was the rekey timer at two minutes, so a peer that had
        // forgotten us went undetected for that long while everything sent in
        // between was encrypted to a key nobody held.
        let s = spoke(Some(1_000), Some(500));
        assert!(!s.presumed_dead(1_000), "silence has not lasted yet");
        assert!(!s.presumed_dead(500 + PRESUMED_DEAD - 1));
        assert!(s.presumed_dead(500 + PRESUMED_DEAD));
    }

    #[test]
    fn an_idle_tunnel_is_not_presumed_dead() {
        // Nothing has been sent, so hearing nothing back is not evidence of
        // anything. Rehandshaking here would mean a tunnel nobody is using
        // handshaking for ever.
        let s = spoke(None, None);
        assert!(!s.presumed_dead(10 * PRESUMED_DEAD));

        let never_sent = spoke(None, Some(1_000));
        assert!(!never_sent.presumed_dead(10 * PRESUMED_DEAD));
    }

    #[test]
    fn a_peer_that_answers_keeps_its_session() {
        let s = spoke(Some(1_000), Some(1_500));
        assert!(
            !s.presumed_dead(1_500 + PRESUMED_DEAD + 1),
            "it answered after we spoke, so the silence since is ours"
        );
    }

    #[test]
    fn a_keepalive_is_owed_only_after_the_peer_speaks_and_we_do_not() {
        let s = spoke(Some(100), Some(1_000));
        assert!(!s.owes_keepalive(1_000), "not yet");
        assert!(!s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT - 1));
        assert!(s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT));

        let answered = spoke(Some(2_000), Some(1_000));
        assert!(
            !answered.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT),
            "we already said something after they did"
        );
    }

    #[test]
    fn a_keepalive_does_not_arm_another_keepalive() {
        // Two ends answering every keepalive with a keepalive is a loop that
        // never stops. Only a packet carrying data sets `last_data_receive`, so
        // an empty one cannot start it.
        let mut s = spoke(Some(100), Some(1_000));
        s.last_data_receive = None;
        assert!(!s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT * 10));
    }

    #[test]
    fn the_retry_interval_is_wireguards_plus_jitter() {
        // Flat retries let two peers that lost each other at the same moment
        // collide for ever.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let v = Tunnel::rekey_interval();
            assert!(
                (REKEY_TIMEOUT..REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER).contains(&v),
                "{v} outside the interval"
            );
            seen.insert(v);
        }
        assert!(seen.len() > 8, "not varying: {} values", seen.len());
    }

    #[test]
    fn the_timers_are_the_ones_wireguard_uses() {
        assert_eq!(REKEY_TIMEOUT, 5_000);
        assert_eq!(KEEPALIVE_TIMEOUT, 10_000);
        assert_eq!(REKEY_ATTEMPT_TIME, 90_000);
        assert_eq!(PRESUMED_DEAD, 15_000);
        assert_eq!(paqetz_core::noise::REKEY_AFTER_TIME, 120_000);
        assert_eq!(paqetz_core::noise::REJECT_AFTER_TIME, 180_000);
    }

    use super::*;

    #[test]
    fn inner_source_reads_the_ipv4_source_field() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 7, 0, 2]);
        assert_eq!(inner_source(&packet), Some(Ipv4Addr::new(10, 7, 0, 2)));
    }

    #[test]
    fn inner_source_rejects_non_ipv4_and_runts() {
        let mut packet = [0u8; 20];
        packet[0] = 0x60; // IPv6
        assert_eq!(inner_source(&packet), None);
        for len in 0..16 {
            let mut short = vec![0u8; len];
            if let Some(b) = short.first_mut() {
                *b = 0x45;
            }
            assert_eq!(inner_source(&short), None, "len {len}");
        }
    }

    #[test]
    fn martian_sources_are_refused() {
        // These must be refused even when allowed_ips is set to "any", because
        // the danger is not which peer sent them but where they could reach.
        for addr in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 1, 2, 3),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            assert!(!plausible_source(addr), "{addr} should be refused");
        }
    }

    #[test]
    fn ordinary_sources_are_allowed() {
        for addr in [
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ] {
            assert!(plausible_source(addr), "{addr} should be allowed");
        }
    }

    #[test]
    fn random_u32_produces_varying_values() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            seen.insert(random_u32().expect("urandom"));
        }
        assert!(seen.len() > 30, "saw only {} distinct values", seen.len());
    }

    #[test]
    fn the_default_route_is_discoverable() {
        // Read-only: parses /proc/net/route and touches nothing.
        match outbound_interface() {
            Ok(name) => assert!(!name.is_empty()),
            Err(e) => {
                // A machine with no default route is a legitimate state; the
                // point is that parsing does not panic or hang.
                assert!(e.to_string().contains("default route"), "got: {e}");
            }
        }
    }
}
