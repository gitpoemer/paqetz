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

/// How often the timer thread wakes.
const TICK: Duration = Duration::from_millis(250);

/// How long to wait before repeating an unanswered handshake.
///
/// WireGuard's interval. Long enough not to flood a peer that is down, short
/// enough that a transient loss costs a few seconds rather than a minute.
const REKEY_TIMEOUT: Millis = 5_000;

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
}

impl PeerState {
    const fn new(endpoint: Option<SocketAddrV4>) -> Self {
        Self {
            session: None,
            pending: None,
            carrier: None,
            endpoint,
            last_handshake: 0,
        }
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
        println!("paqetz: transmit via {}", tx.name());

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

        // The worker threads block in `read` and `recv`, so they cannot notice
        // a flag on their own. The process exits once this returns and the
        // caller has removed the firewall rules; the blocked threads go with
        // it. Waking them properly needs the poll loop that arrives with the
        // rest of the throughput work.
        while this.running.load(Ordering::Relaxed) && !SHUTDOWN.load(Ordering::Relaxed) {
            std::thread::sleep(TICK);
        }
        this.stop();

        drop((t1, t2, t3));
        Ok(())
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
                    eprintln!("tun read failed: {e}");
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
            eprintln!("could not set the device non-blocking: {e}");
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
                    eprintln!("waiting on the device failed: {e}");
                    return None;
                }
            }
            let buf = inner.first_mut()?;
            match self.tun.recv_nonblocking(buf) {
                Ok(Some(n)) if n > 0 => return Some(n),
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("tun read failed: {e}");
                    return None;
                }
            }
        }
    }

    /// Reports a per-packet outbound failure, unless it is an ordinary one.
    fn note_outbound(&self, e: &Error) {
        // A packet we cannot send is dropped, exactly as a congested link would
        // drop it. Inner TCP retries; nothing here should treat it as fatal.
        if !matches!(e, Error::Core(paqetz_core::Error::Expired)) {
            eprintln!("dropping outbound packet: {e}");
        }
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
                    eprintln!("capture read failed: {e}");
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

    /// Reports a per-packet inbound failure, unless it is an ordinary one.
    fn note_inbound(&self, e: &Error) {
        // Anything unauthenticated lands here. It is dropped silently in the
        // sense that matters — nothing goes back on the wire — but it is worth
        // a line at this stage of development.
        if !matches!(
            e,
            Error::Core(paqetz_core::Error::Rejected | paqetz_core::Error::Replay)
        ) {
            eprintln!("dropping inbound packet: {e}");
        }
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
                    eprintln!("capture read failed: {e}");
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
        state.endpoint = Some(SocketAddrV4::new(seg.src.0, seg.src.1));
        drop(state);

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
            state.endpoint = Some(from);
            if let Some(carrier) = state.carrier.as_mut() {
                carrier.set_remote((from.ip().to_owned(), from.port()));
            }
        }
        if let Some(carrier) = state.carrier.as_mut() {
            carrier.on_receive(seg);
        }
        drop(state);

        let Some(packet) = inner.get(..n) else {
            return Ok(());
        };
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
            eprintln!("dropping inner packet with disallowed source {source}");
            return Ok(());
        }
        if !plausible_source(source) {
            eprintln!("dropping inner packet with martian source {source}");
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
        if !self.is_initiator() {
            // A responder answers handshakes but never starts one, so it has
            // nothing to do on a timer.
            while self.running.load(Ordering::Relaxed) {
                std::thread::sleep(TICK);
            }
            return;
        }

        let mut frame = vec![0u8; MAX_FRAME];
        while self.running.load(Ordering::Relaxed) {
            if let Err(e) = self.maybe_handshake(&mut frame) {
                eprintln!("handshake attempt failed: {e}");
            }
            std::thread::sleep(TICK);
        }
    }

    /// Sends a handshake if one is due.
    fn maybe_handshake(&self, frame: &mut [u8]) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let due = match state.session.as_ref() {
            None => {
                state.pending.is_none() || now.saturating_sub(state.last_handshake) >= REKEY_TIMEOUT
            }
            Some(s) => s.needs_rekey(now),
        };
        if !due {
            return Ok(());
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
            }));
        }

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(());
        };
        let written = carrier.data(&msg1, frame, now)?;
        let dst = *peer.ip();

        state.pending = Some(initiator);
        state.last_handshake = now;
        drop(state);

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

/// Records that a shutdown signal arrived.
///
/// Storing to an atomic is async-signal-safe; nothing else here would be, which
/// is why the handler does no work beyond this.
extern "C" fn on_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Arranges for `SIGINT` and `SIGTERM` to request a clean stop.
pub(crate) fn install_signal_handlers() {
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
