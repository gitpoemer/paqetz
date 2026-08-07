//! Configuration file parsing and validation.
//!
//! The shape follows WireGuard's, because that is what an operator setting up a
//! point-to-point tunnel already knows. Everything paqet required and this does
//! not is worth noting, since removing it was the point: no interface name, no
//! gateway MAC address, no cipher selection, no KCP tuning, no window sizes, no
//! buffer sizes, and no `role` field — which side initiates follows from
//! whether a peer has an endpoint.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;

use paqetz_core::{PrivateKey, PublicKey};
use serde::Deserialize;

/// Everything one process runs.
///
/// A client may carry several tunnels at once — one per destination, chosen by
/// firewall mark — so a configuration is a list of tunnels plus the few settings
/// that belong to the process rather than to any one of them.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// How much to say.
    pub(crate) log: crate::log::Level,
    /// Seconds between status lines; zero disables them.
    pub(crate) health_interval: u64,
    /// Whether to install the firewall rules the carrier needs (D9).
    ///
    /// One table covers every tunnel in the process, so this belongs to the
    /// process rather than to a tunnel.
    pub(crate) manage_firewall: bool,
    /// The tunnels, in the order they were written.
    pub(crate) tunnels: Vec<TunnelConfig>,
}

/// One tunnel: an identity, a device, and the peer at the far end.
#[derive(Debug, Clone)]
pub(crate) struct TunnelConfig {
    /// What to call it in logs and on the command line.
    pub(crate) name: String,
    /// This end's settings.
    pub(crate) interface: Interface,
    /// An optional SOCKS5 front end, for debugging (phase 4).
    pub(crate) socks5: Option<Socks5>,
    /// The peer at the far end. Exactly one per tunnel; several destinations
    /// means several tunnels, which is what `[[tunnel]]` is for.
    pub(crate) peer: Peer,
}

/// This end of the tunnel.
#[derive(Debug, Clone)]
pub(crate) struct Interface {
    /// Our static secret.
    pub(crate) private_key: PrivateKey,
    /// Our address inside the tunnel.
    pub(crate) address: Ipv4Addr,
    /// The tunnel subnet's mask.
    pub(crate) netmask: Ipv4Addr,
    /// Inner MTU.
    pub(crate) mtu: u32,
    /// The outer TCP port we receive on.
    ///
    /// Zero means "choose an ephemeral port", which is the sensible default for
    /// the side that initiates: it has no need for a stable port, and a fixed
    /// one is one more thing to collide.
    pub(crate) listen_port: u16,
    /// Name of the TUN device to create.
    pub(crate) device: String,
    /// Which operating system the carrier should look like.
    pub(crate) profile: paqetz_tcpwire::OsProfile,
    /// Whether the carrier performs a synthetic handshake (D14).
    pub(crate) carrier: paqetz_tcpwire::Carrier,
    /// How the carrier numbers its segments.
    ///
    /// `opaque` by default. Numbering by payload bytes is truthful, and
    /// therefore checkable by anything modelling the flow — including after a
    /// loss this carrier cannot repair, which it then never recovers from.
    pub(crate) sequencing: paqetz_tcpwire::Sequencing,
    /// Whether to forward and translate the peer's traffic to the internet.
    ///
    /// The server side of a tunnel that is meant to be a way out. Without it
    /// the two ends can reach each other and nothing beyond, which looks
    /// exactly like a broken tunnel while nothing is broken.
    pub(crate) gateway: bool,
    /// Whether to route this host's traffic through the tunnel.
    ///
    /// The client side of the same arrangement.
    pub(crate) route_all: bool,
    /// Install a policy route so sockets carrying this firewall mark use the
    /// tunnel, and everything else does not.
    ///
    /// This is how a proxy in front of the tunnel — Xray and anything else that
    /// can set `SO_MARK` on its outbound sockets — sends only the traffic it is
    /// forwarding through the tunnel, while its own inbound connections keep
    /// the host's ordinary path. `route_all` cannot express that: it would
    /// capture the replies to the proxy's own users too, and break them.
    pub(crate) route_marked: Option<u32>,
    /// The routing table the mark rule points at.
    pub(crate) route_table: u32,
    /// Send the peer's forwarded traffic out this interface instead of the
    /// default route, so the destination sees that interface's address.
    pub(crate) egress: Option<String>,
    /// The routing table holding that interface's default route.
    pub(crate) egress_table: u32,
    /// Whether to move packets in batches.
    pub(crate) datapath: Datapath,
    /// Which transmit path to use.
    pub(crate) transmit: TransmitPath,
    /// Whether to answer a quiet peer with an empty packet.
    ///
    /// What this end will spend on repeating packets a lossy path swallowed.
    ///
    /// Off by default. Everything the tunnel carries already recovers from
    /// loss on its own, and on an ordinary link a second mechanism doing the
    /// same job is waste -- worse than waste, since it hides loss from the
    /// congestion control that ought to see it. Turn it on for a path whose
    /// loss has been *measured*, by comparing one end's `tx` against the
    /// other's `rx` over the same window.
    ///
    /// `retransmit` turns it on. The rest follow from the path rather than
    /// from taste: `retransmit_buffer` from its packet rate,
    /// `retransmit_deadline` from its round trip, `retransmit_asks` from how
    /// much it loses, and `retransmit_reorder` from whether it reorders. They
    /// keep their values while it is off, so it can be turned off and on again
    /// without losing what was measured.
    pub(crate) repeat: crate::repeat::Limits,
    /// WireGuard's passive keepalive, and on by default because a silent tunnel
    /// goes cold: measured on a live path, the first two seconds of traffic
    /// after any idle period were lost to a mapping that had lapsed, while every
    /// packet under load arrived. It costs a fixed-size packet every ten
    /// seconds, which is a metronome — a real trade, and the wrong side of it is
    /// losing the first click after a pause.
    pub(crate) keepalive: bool,
    /// Whether the carrier moves between outer ports while it runs.
    ///
    /// On by default. A five-tuple that lives for hours and carries gigabytes
    /// gets classified and then shaped: throughput collapses with no loss at
    /// all, and a restart cures it, because a restart is a new five-tuple.
    /// Moving on a timer is the same cure without the outage.
    pub(crate) rotate: bool,
}

/// The SOCKS5 debugging front end.
///
/// Off unless configured. It is a convenience for pointing one program at the
/// tunnel without touching the routing table, and it is the one place in the
/// design that holds per-flow state — so it is opt-in rather than assumed.
#[derive(Debug, Clone)]
pub(crate) struct Socks5 {
    /// Where to listen. Loopback unless there is a deliberate reason otherwise.
    pub(crate) listen: SocketAddr,
    /// The firewall mark stamped on its outbound connections.
    pub(crate) mark: u32,
    /// The routing table the policy rule points at.
    pub(crate) table: u32,
    /// Credentials clients must present, if any.
    pub(crate) credentials: Option<(String, String)>,
    /// Where to resolve names, reached through the tunnel.
    ///
    /// `None` means this host's own resolver, which is the network the tunnel
    /// exists to get out of: it sees every name asked for, and decides what the
    /// answers are. Set `dns = "system"` to accept that deliberately.
    pub(crate) dns: Option<SocketAddrV4>,
}

/// How packets move between the device and the wire.
///
/// `simple` is the default, on measurement rather than on principle. Over a
/// veth pair, batching moved UDP packet rate by +6 to +8% and TCP throughput by
/// −2 to −7% — a contradictory signal, which is what a difference near the
/// noise floor looks like. The cipher dominates the per-packet budget, so
/// amortising the syscall has little left to win, exactly as
/// `docs/08-rewrite-plan.md` §8.11 predicted.
///
/// Given no clear gain, the simpler path wins the tie: one code path, a
/// blocking device, and no writes that can be refused because a queue is full.
/// Worth re-measuring on a real path, where the syscall cost relative to
/// everything else may differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Datapath {
    /// One packet per syscall.
    #[default]
    Simple,
    /// Up to 32 packets per syscall, drained from whatever is already queued.
    ///
    /// Only ever takes packets that were waiting anyway, so it costs no
    /// latency: with one packet in flight it behaves as the simple path does.
    Batched,
}

/// Which mechanism puts frames on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TransmitPath {
    /// Raw socket with `IP_HDRINCL`; the kernel routes and resolves the next
    /// hop.
    ///
    /// The default, because it has no moving parts: no hardware address to go
    /// stale when a gateway fails over or a lease moves, which is the failure
    /// paqet suffered from making the operator write one down.
    #[default]
    Raw,
    /// `AF_PACKET`, naming the next hop ourselves.
    ///
    /// Skips the route lookup and the netfilter `OUTPUT` chain. Measurably
    /// faster — a consistent +3 to +10% over a veth pair, on both TCP
    /// throughput and UDP packet rate — but it needs the next hop's hardware
    /// address, which can go stale when a gateway fails over or a lease moves.
    ///
    /// Not the default, because that margin does not buy back a failure mode
    /// the other path simply does not have. Worth switching to on a host where
    /// the gateway is stable and the throughput matters.
    AfPacket,
}

/// The other end.
#[derive(Debug, Clone)]
pub(crate) struct Peer {
    /// Their static public key, which is their identity.
    pub(crate) public_key: PublicKey,
    /// Where to reach them, if known.
    ///
    /// Present on the side that initiates. Absent on the side that waits, which
    /// learns the endpoint from whichever address sends a packet that
    /// authenticates (D5) — which is what makes roaming work.
    pub(crate) endpoint: Option<SocketAddrV4>,
    /// Inner addresses this peer may use.
    ///
    /// Derived from `tunnel_address` when not given (D12), so there is normally
    /// nothing to configure.
    pub(crate) allowed_ips: Vec<(Ipv4Addr, u8)>,
    /// The peer's address inside the tunnel.
    pub(crate) tunnel_address: Ipv4Addr,
}

impl Config {
    /// The single tunnel this describes, taken by value.
    ///
    /// `None` when there are several, because the places that want this are
    /// asking "is this file the one for this host", and a file describing three
    /// hosts is not an answer to that.
    #[must_use]
    pub(crate) fn into_only(self) -> Option<TunnelConfig> {
        let mut it = self.tunnels.into_iter();
        match (it.next(), it.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        }
    }

    /// A tunnel by name.
    #[must_use]
    pub(crate) fn named(&self, name: &str) -> Option<&TunnelConfig> {
        self.tunnels.iter().find(|t| t.name == name)
    }
}

impl TunnelConfig {
    /// The tunnel's inner subnet, from this end's address and prefix.
    ///
    /// The gateway translates traffic from this range, so it has to be the
    /// network rather than the host address.
    #[must_use]
    pub(crate) fn tunnel_subnet(&self) -> (Ipv4Addr, u8) {
        let mask = u32::from_be_bytes(self.interface.netmask.octets());
        let addr = u32::from_be_bytes(self.interface.address.octets());
        (
            Ipv4Addr::from((addr & mask).to_be_bytes()),
            u8::try_from(mask.count_ones()).unwrap_or(32),
        )
    }
}

impl Peer {
    /// Whether this end initiates the handshake.
    #[must_use]
    pub(crate) const fn is_initiator(&self) -> bool {
        self.endpoint.is_some()
    }

    /// Whether an inner source address is one this peer may use (D12).
    #[must_use]
    pub(crate) fn permits(&self, addr: Ipv4Addr) -> bool {
        self.allowed_ips
            .iter()
            .any(|(net, prefix)| in_network(addr, *net, *prefix))
    }
}

/// Reads a resolver address, defaulting the port to 53.
///
/// Written as a bare address in almost every case, since a resolver on a port
/// other than 53 is unusual enough that spelling it out is the clearer thing to
/// have to do.
fn parse_resolver(text: &str) -> core::result::Result<SocketAddrV4, String> {
    if let Ok(addr) = text.parse::<SocketAddrV4>() {
        return Ok(addr);
    }
    text.parse::<Ipv4Addr>()
        .map(|ip| SocketAddrV4::new(ip, 53))
        .map_err(|e| format!("{text:?}: {e}"))
}

/// Whether `addr` falls inside `net/prefix`.
#[must_use]
pub(crate) fn in_network(addr: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let shift = 32 - u32::from(prefix);
    let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
    (u32::from_bits(addr) & mask) == (u32::from_bits(net) & mask)
}

/// Helper so the mask arithmetic reads clearly.
trait Bits {
    fn from_bits(addr: Ipv4Addr) -> u32;
}

impl Bits for u32 {
    fn from_bits(addr: Ipv4Addr) -> Self {
        Self::from_be_bytes(addr.octets())
    }
}

// ---------------------------------------------------------------------------
// On-disk form
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawConfig {
    // Process settings. Written at the top level in the `[[tunnel]]` form and
    // under `[interface]` in the original one, so both places are read.
    #[serde(default)]
    log: Option<String>,
    #[serde(default)]
    health_interval: Option<u64>,
    #[serde(default)]
    manage_firewall: Option<bool>,

    // The original form: one tunnel, spelled without saying so.
    #[serde(default)]
    interface: Option<RawInterface>,
    #[serde(default)]
    peer: Option<RawPeer>,
    #[serde(default)]
    socks5: Option<RawSocks5>,

    // The form that can name more than one.
    #[serde(default)]
    tunnel: Option<Vec<RawTunnel>>,
}

/// One `[[tunnel]]` section.
///
/// `interface` and `peer` are nested rather than flattened. Serde cannot do
/// both `flatten` and `deny_unknown_fields`, and the flag is what turns a
/// mistyped key into an error instead of a line that is silently ignored — a
/// trade this tunnel has lost too often to make again. Nesting also makes the
/// two forms the same file at different depths: `[interface]` becomes
/// `[tunnel.interface]`, every key unchanged.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    #[serde(default)]
    name: Option<String>,
    interface: RawInterface,
    peer: RawPeer,
    #[serde(default)]
    socks5: Option<RawSocks5>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSocks5 {
    listen: String,
    #[serde(default)]
    mark: Option<u32>,
    #[serde(default)]
    table: Option<u32>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    dns: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    private_key: String,
    address: String,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    sequencing: Option<String>,
    #[serde(default)]
    manage_firewall: Option<bool>,
    #[serde(default)]
    datapath: Option<String>,
    #[serde(default)]
    transmit: Option<String>,
    #[serde(default)]
    keepalive: Option<bool>,
    retransmit: Option<RawRetransmit>,
    retransmit_buffer: Option<usize>,
    retransmit_deadline: Option<u64>,
    retransmit_asks: Option<u8>,
    retransmit_reorder: Option<u64>,
    #[serde(default)]
    rotate: Option<bool>,
    #[serde(default)]
    log: Option<String>,
    #[serde(default)]
    health_interval: Option<u64>,
    #[serde(default)]
    gateway: Option<bool>,
    #[serde(default)]
    route_all: Option<bool>,
    #[serde(default)]
    route_marked: Option<u32>,
    #[serde(default)]
    route_table: Option<u32>,
    #[serde(default)]
    egress: Option<String>,
    #[serde(default)]
    egress_table: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    public_key: String,
    tunnel_address: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    allowed_ips: Option<Vec<String>>,
}

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },

    /// The file was not valid TOML, or had unexpected keys.
    #[error("parsing {path}: {source}")]
    Parse {
        /// The path that could not be parsed.
        path: String,
        /// The underlying error.
        source: toml::de::Error,
    },

    /// A field was present but not usable.
    #[error("{field}: {problem}")]
    Invalid {
        /// Which field.
        field: &'static str,
        /// What is wrong with it.
        problem: String,
    },
}

/// Result alias for this module.
pub(crate) type Result<T> = core::result::Result<T, Error>;

/// How `retransmit` may be written.
///
/// A boolean, which is what it means. An integer is the spelling it had before
/// there was a switch, when the size of the buffer doubled as the way to turn
/// the thing off -- accepted so that a configuration written against that
/// version still loads, and read as "on, with this buffer".
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
enum RawRetransmit {
    /// `retransmit = true`.
    On(bool),
    /// `retransmit = 1200`, as it used to be written.
    Buffer(usize),
}

/// How many packets are held when nothing says otherwise.
///
/// The useful size is the path's packet rate times the deadline, and 1024 at
/// the default 400ms covers about 2500 packets a second -- more than a tunnel
/// like this usually carries, and under two megabytes.
const DEFAULT_BUFFER: usize = 1024;

/// The most packets that may be held for repeating.
///
/// At a 1400-byte MTU this is about twelve megabytes, and it covers a path
/// moving twenty thousand packets a second at the default deadline -- far past
/// anything a tunnel like this carries.
const MAX_RETRANSMIT: usize = 8192;

/// The shortest useful repeat deadline: a repeat has to survive a round trip.
const MIN_DEADLINE: u64 = 50;

/// The longest. Past this the inner protocol has recovered without help.
const MAX_DEADLINE: u64 = 5_000;

/// The most times one packet may be asked for.
const MAX_ASKS: u8 = 8;

/// The fewest later packets that may stand for "this one is not coming".
///
/// One means the very next packet settles it, which is right for a path that
/// does not reorder and wasteful for one that does.
const MIN_REORDER: u64 = 1;

/// The most. Past this the wait before asking outlasts the repeat's usefulness.
const MAX_REORDER: u64 = 16;

/// The longest name Linux accepts for an interface, `IFNAMSIZ` less its NUL.
const IFNAME_MAX: usize = 15;

/// Checks that a name is one Linux would accept, and one that is safe to
/// interpolate.
///
/// Interface names reach `nft` inside a generated script, where a quote or a
/// newline would end the token early and let whatever follows be read as more
/// ruleset. Nothing but root can write this file, so this is not a privilege
/// boundary -- but the kernel would refuse most of these names anyway, and
/// refusing them here turns a strange firewall failure into a clear message
/// about the field that caused it.
fn interface_name(field: &'static str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(invalid(field, "an interface name cannot be empty"));
    }
    if name.len() > IFNAME_MAX {
        return Err(invalid(
            field,
            format!("`{name}` is longer than the {IFNAME_MAX} characters Linux allows"),
        ));
    }
    if name == "." || name == ".." {
        return Err(invalid(field, format!("`{name}` is not a usable name")));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return Err(invalid(
            field,
            format!(
                "`{name}` contains {bad:?}; interface names are letters, digits,                  and `_`, `-` or `.`"
            ),
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, problem: impl Into<String>) -> Error {
    Error::Invalid {
        field,
        problem: problem.into(),
    }
}

impl Config {
    /// Reads and validates a configuration file.
    ///
    /// # Errors
    /// Returns [`Error`] describing the first problem found.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text).map_err(|e| match e {
            Error::Parse { source, .. } => Error::Parse {
                path: path.display().to_string(),
                source,
            },
            other => other,
        })
    }

    /// Parses and validates configuration text.
    ///
    /// # Errors
    /// Returns [`Error`] describing the first problem found.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text).map_err(|source| Error::Parse {
            path: "<config>".to_owned(),
            source,
        })?;

        // Process settings sit at the top level in the new form and under
        // `[interface]` in the old one, so a converted file behaves the same
        // before and after conversion.
        let inherited = raw.interface.as_ref();
        let level = raw
            .log
            .clone()
            .or_else(|| inherited.and_then(|i| i.log.clone()))
            .unwrap_or_else(|| "info".to_owned());
        let log = crate::log::Level::parse(&level).ok_or_else(|| {
            invalid(
                "log",
                format!(
                    "unknown level {level:?}; known levels are {:?}",
                    crate::log::Level::ALL
                ),
            )
        })?;
        let health_interval = raw
            .health_interval
            .or_else(|| inherited.and_then(|i| i.health_interval))
            .unwrap_or(60);
        let manage_firewall = raw
            .manage_firewall
            .or_else(|| inherited.and_then(|i| i.manage_firewall))
            .unwrap_or(true);

        let tunnels = match (raw.interface, raw.peer, raw.tunnel) {
            (Some(iface), Some(peer), None) => {
                // Named for its device, which is what a log line would have to
                // call it otherwise.
                let name = iface.device.clone().unwrap_or_else(|| "paqetz0".to_owned());
                vec![Self::one(name, iface, peer, raw.socks5)?]
            }
            (None, None, Some(list)) if !list.is_empty() => {
                let mut out = Vec::with_capacity(list.len());
                for (i, t) in list.into_iter().enumerate() {
                    let name = t.name.unwrap_or_else(|| format!("tunnel{i}"));
                    out.push(Self::one(name, t.interface, t.peer, t.socks5)?);
                }
                out
            }
            (None, None, _) => {
                return Err(invalid(
                    "tunnel",
                    "nothing to run: write an [interface] and a [peer], or one or \
                     more [[tunnel]] sections",
                ));
            }
            _ => {
                return Err(invalid(
                    "tunnel",
                    "a top-level [interface] or [peer] alongside [[tunnel]] is \
                     ambiguous; use one form or the other",
                ));
            }
        };

        Self::distinct(&tunnels)?;
        Ok(Self {
            log,
            health_interval,
            manage_firewall,
            tunnels,
        })
    }

    /// Refuses tunnels that would fight each other.
    ///
    /// Two sharing a device, an inner address or a mark each undo the other's
    /// routing, and the symptom is whichever one lost — which looks nothing like
    /// a configuration mistake from the outside.
    fn distinct(tunnels: &[TunnelConfig]) -> Result<()> {
        for (i, a) in tunnels.iter().enumerate() {
            for b in tunnels.iter().skip(i + 1) {
                if a.name == b.name {
                    return Err(invalid(
                        "tunnel.name",
                        format!("{:?} appears twice", a.name),
                    ));
                }
                let clash = |what: &str, value: String| {
                    invalid(
                        "tunnel",
                        format!("{:?} and {:?} both use {what} {value}", a.name, b.name),
                    )
                };
                if a.interface.device == b.interface.device {
                    return Err(clash("device", a.interface.device.clone()));
                }
                if a.interface.address == b.interface.address {
                    return Err(clash("inner address", a.interface.address.to_string()));
                }
                if let (Some(x), Some(y)) = (a.interface.route_marked, b.interface.route_marked)
                    && x == y
                {
                    return Err(clash("mark", x.to_string()));
                }
                // The key is the identity. Two tunnels for one peer have
                // nothing to tell their traffic apart by, so each handshake
                // would take the session and the endpoint from the other and
                // the two would trade them every fifteen seconds -- which looks
                // like a flapping link and is a configuration error.
                if a.peer.public_key == b.peer.public_key {
                    return Err(clash("peer key", a.peer.public_key.to_string()));
                }
                // Zero is "pick one at start-up", and two tunnels both doing
                // that will pick differently. Only a port written down twice
                // is a clash.
                if a.interface.listen_port != 0
                    && a.interface.listen_port == b.interface.listen_port
                {
                    return Err(clash("outer port", a.interface.listen_port.to_string()));
                }
            }
        }
        Ok(())
    }

    /// Builds one tunnel from its sections.
    fn one(
        name: String,
        iface: RawInterface,
        peer_raw: RawPeer,
        socks5_raw: Option<RawSocks5>,
    ) -> Result<TunnelConfig> {
        let private_key = PrivateKey::from_base64(&iface.private_key)
            .map_err(|e| invalid("interface.private_key", e.to_string()))?;

        let (address, prefix) =
            parse_cidr(&iface.address).map_err(|p| invalid("interface.address", p))?;
        let netmask = mask_from_prefix(prefix);

        let mtu = iface.mtu.unwrap_or(paqetz_dp::tun::DEFAULT_MTU);
        if !(576..=9000).contains(&mtu) {
            return Err(invalid(
                "interface.mtu",
                format!("{mtu} is outside the usable range 576-9000"),
            ));
        }

        let profile_name = iface.profile.as_deref().unwrap_or("linux-6");
        let profile = paqetz_tcpwire::profile::by_name(profile_name).ok_or_else(|| {
            let known: Vec<&str> = paqetz_tcpwire::profile::ALL
                .iter()
                .map(|p| p.name)
                .collect();
            invalid(
                "interface.profile",
                format!("unknown profile {profile_name:?}; known profiles are {known:?}"),
            )
        })?;

        let carrier = match iface.carrier.as_deref().unwrap_or("midstream") {
            "midstream" => paqetz_tcpwire::Carrier::Midstream,
            "handshake" => paqetz_tcpwire::Carrier::Handshake,
            other => {
                return Err(invalid(
                    "interface.carrier",
                    format!("expected \"midstream\" or \"handshake\", got {other:?}"),
                ));
            }
        };

        let sequencing = match iface.sequencing.as_deref().unwrap_or("opaque") {
            "opaque" => paqetz_tcpwire::Sequencing::Opaque,
            "stream" => paqetz_tcpwire::Sequencing::Stream,
            other => {
                return Err(invalid(
                    "interface.sequencing",
                    format!("expected \"opaque\" or \"stream\", got {other:?}"),
                ));
            }
        };

        let datapath = match iface.datapath.as_deref().unwrap_or("simple") {
            "batched" => Datapath::Batched,
            "simple" => Datapath::Simple,
            other => {
                return Err(invalid(
                    "interface.datapath",
                    format!("expected \"batched\" or \"simple\", got {other:?}"),
                ));
            }
        };

        let transmit = match iface.transmit.as_deref().unwrap_or("raw") {
            "raw" => TransmitPath::Raw,
            "afpacket" => TransmitPath::AfPacket,
            other => {
                return Err(invalid(
                    "interface.transmit",
                    format!("expected \"raw\" or \"afpacket\", got {other:?}"),
                ));
            }
        };

        let public_key = PublicKey::from_base64(&peer_raw.public_key)
            .map_err(|e| invalid("peer.public_key", e.to_string()))?;

        let endpoint = match peer_raw.endpoint.as_deref() {
            None => None,
            Some(s) => Some(
                s.parse::<SocketAddrV4>()
                    .map_err(|e| invalid("peer.endpoint", format!("{s:?}: {e}")))?,
            ),
        };

        let tunnel_address: Ipv4Addr = peer_raw
            .tunnel_address
            .parse()
            .map_err(|e| invalid("peer.tunnel_address", format!("{e}")))?;

        // Derived rather than configured (D12): the inner address is one we
        // assign, so its /32 is implied and there is nothing to write down.
        let allowed_ips = match peer_raw.allowed_ips {
            None => vec![(tunnel_address, 32u8)],
            Some(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for e in entries {
                    if e == "any" {
                        out.push((Ipv4Addr::UNSPECIFIED, 0));
                        continue;
                    }
                    out.push(parse_cidr(&e).map_err(|p| invalid("peer.allowed_ips", p))?);
                }
                out
            }
        };

        let socks5 = match socks5_raw {
            None => None,
            Some(r) => {
                let listen: SocketAddr = r
                    .listen
                    .parse()
                    .map_err(|e| invalid("socks5.listen", format!("{:?}: {e}", r.listen)))?;
                let credentials = match (r.username, r.password) {
                    (None, None) => None,
                    (Some(u), Some(p)) => Some((u, p)),
                    _ => {
                        return Err(invalid(
                            "socks5",
                            "username and password must be given together, or neither",
                        ));
                    }
                };
                // Non-zero by default: a mark of zero means the connections are
                // not steered anywhere, so the proxy would work perfectly and
                // send everything out the ordinary route -- the failure that is
                // hardest to notice, because nothing appears wrong.
                // Through the tunnel by default. Resolving locally hands every
                // name to the network being tunnelled out of, and lets it
                // choose the answer -- which is a redirection to somewhere that
                // never replies, indistinguishable from a slow site.
                let dns = match r.dns.as_deref() {
                    None => Some(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
                    Some("system") => None,
                    Some(text) => Some(parse_resolver(text).map_err(|e| invalid("socks5.dns", e))?),
                };

                let mark = r.mark.unwrap_or(0x51);
                if mark == 0 {
                    return Err(invalid(
                        "socks5.mark",
                        "zero would leave connections on the host's normal route \
                         rather than steering them into the tunnel",
                    ));
                }
                Some(Socks5 {
                    dns,
                    listen,
                    mark,
                    table: r.table.unwrap_or(51),
                    credentials,
                })
            }
        };

        let listen_port = iface.listen_port.unwrap_or(0);
        if endpoint.is_none() && listen_port == 0 {
            return Err(invalid(
                "interface.listen_port",
                "the side without a peer endpoint must listen on a fixed port, \
                 or the peer has no stable address to reach it at",
            ));
        }

        Ok(TunnelConfig {
            name,
            socks5,
            interface: Interface {
                private_key,
                address,
                netmask,
                mtu,
                listen_port,
                device: {
                    let name = iface.device.unwrap_or_else(|| "paqetz0".to_owned());
                    interface_name("interface.device", &name)?;
                    name
                },
                profile,
                carrier,
                sequencing,
                datapath,
                transmit,
                // Both on unless declined. Each was measured on a live path
                // before being made the default, and each is one line to turn
                // off for a path that does not want it.
                repeat: {
                    // One source for the defaults, so "off" and "unset" cannot
                    // drift apart.
                    let defaults = crate::repeat::Limits::off();
                    // A packet is only worth holding until it can be asked for,
                    // so the useful capacity is the path's packet rate times
                    // the deadline. Beyond that the extra slots hold packets
                    // that are refused for age before anyone can ask.
                    // Whether to repeat at all, and how much to hold, are
                    // separate questions -- they were one setting only because
                    // a buffer of zero could stand in for "off", which meant
                    // turning it off threw away the size that had been chosen.
                    let (enabled, from_old_form) = match iface.retransmit {
                        None => (false, None),
                        Some(RawRetransmit::On(on)) => (on, None),
                        Some(RawRetransmit::Buffer(n)) => (n > 0, Some(n)),
                    };
                    if from_old_form.is_some() && iface.retransmit_buffer.is_some() {
                        return Err(invalid(
                            "interface.retransmit",
                            "given as a number and alongside `retransmit_buffer`, which are two \
                             ways of saying the same thing. Write `retransmit = true` and put \
                             the size in `retransmit_buffer`.",
                        ));
                    }
                    let capacity = match from_old_form.or(iface.retransmit_buffer) {
                        Some(n) if n > MAX_RETRANSMIT => {
                            return Err(invalid(
                                "interface.retransmit_buffer",
                                format!(
                                    "more than {MAX_RETRANSMIT} packets is megabytes held for \
                                     something worth repeating for a fraction of a second"
                                ),
                            ));
                        }
                        other => other.unwrap_or(DEFAULT_BUFFER),
                    };
                    // Off is expressed as holding nothing, which is what every
                    // path below already understands.
                    let capacity = if enabled { capacity } else { 0 };

                    let deadline = match iface.retransmit_deadline {
                        Some(ms) if !(MIN_DEADLINE..=MAX_DEADLINE).contains(&ms) => {
                            return Err(invalid(
                                "interface.retransmit_deadline",
                                format!(
                                    "expected {MIN_DEADLINE} to {MAX_DEADLINE} ms: below that a \
                                     repeat cannot complete a round trip, and above it the inner \
                                     protocol has long since recovered on its own"
                                ),
                            ));
                        }
                        other => other.unwrap_or(defaults.deadline),
                    };
                    let asks = match iface.retransmit_asks {
                        Some(0) => {
                            return Err(invalid(
                                "interface.retransmit_asks",
                                "asking zero times is what `retransmit = 0` already says",
                            ));
                        }
                        Some(n) if n > MAX_ASKS => {
                            return Err(invalid(
                                "interface.retransmit_asks",
                                format!(
                                    "more than {MAX_ASKS} attempts costs two packets each to save \
                                     one, on a path that is already dropping them"
                                ),
                            ));
                        }
                        other => other.unwrap_or(defaults.asks),
                    };
                    let reorder = match iface.retransmit_reorder {
                        Some(n) if !(MIN_REORDER..=MAX_REORDER).contains(&n) => {
                            return Err(invalid(
                                "interface.retransmit_reorder",
                                format!(
                                    "expected {MIN_REORDER} to {MAX_REORDER}: below one there is \
                                     nothing to tell reordering from loss, and above {MAX_REORDER} \
                                     the wait is longer than the repeat is worth"
                                ),
                            ));
                        }
                        other => other.unwrap_or(defaults.reorder),
                    };
                    crate::repeat::Limits {
                        capacity,
                        deadline,
                        asks,
                        reorder,
                    }
                },
                keepalive: iface.keepalive.unwrap_or(true),
                rotate: iface.rotate.unwrap_or(true),
                gateway: iface.gateway.unwrap_or(false),
                route_all: iface.route_all.unwrap_or(false),
                route_marked: match iface.route_marked {
                    Some(0) => {
                        return Err(invalid(
                            "interface.route_marked",
                            "zero is not a usable mark: an unmarked socket is every \
                             socket, so the rule would capture the host's own traffic",
                        ));
                    }
                    other => other,
                },
                route_table: iface.route_table.unwrap_or(51),
                egress: match iface.egress {
                    Some(name) => {
                        interface_name("interface.egress", &name)?;
                        Some(name)
                    }
                    None => None,
                },
                // wg-quick's own default when `Table` is set to a number for a
                // WARP profile, which is the usual reason to want this.
                egress_table: iface.egress_table.unwrap_or(51_820),
            },
            peer: Peer {
                public_key,
                endpoint,
                allowed_ips,
                tunnel_address,
            },
        })
    }
}

/// Parses `a.b.c.d/prefix`.
fn parse_cidr(s: &str) -> core::result::Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("{s:?} is missing a prefix length, e.g. \"10.7.0.1/24\""))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|e| format!("{addr:?} is not an IPv4 address: {e}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| format!("{prefix:?} is not a prefix length: {e}"))?;
    if prefix > 32 {
        return Err(format!("prefix length {prefix} exceeds 32"));
    }
    Ok((addr, prefix))
}

/// Turns a prefix length into a netmask.
fn mask_from_prefix(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let shift = 32 - u32::from(prefix.min(32));
    Ipv4Addr::from(u32::MAX.checked_shl(shift).unwrap_or(0).to_be_bytes())
}

#[cfg(test)]
mod tests {

    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// The client fixture with extra interface settings.
    fn with_interface(lines: &str) -> Result<TunnelConfig> {
        Config::parse(&CLIENT.replace("[peer]", &format!("{lines}\n\n[peer]")))
            .map(|c| c.into_only().expect("one tunnel"))
    }

    #[test]
    fn the_switch_and_the_size_are_separate_questions() {
        // They were one setting, so turning repeating off meant throwing away
        // the buffer size that had been measured for the path.
        let off = with_interface("retransmit_buffer = 1200").expect("parses");
        assert_eq!(
            off.interface.repeat.capacity, 0,
            "a size alone turns nothing on"
        );

        let on = with_interface("retransmit = true\nretransmit_buffer = 1200").expect("parses");
        assert_eq!(on.interface.repeat.capacity, 1200);

        // And off again, with the size still written down.
        let again = with_interface("retransmit = false\nretransmit_buffer = 1200").expect("parses");
        assert_eq!(again.interface.repeat.capacity, 0);

        // On, with no size chosen.
        let plain = with_interface("retransmit = true").expect("parses");
        assert_eq!(plain.interface.repeat.capacity, super::DEFAULT_BUFFER);
    }

    #[test]
    fn the_spelling_this_setting_used_to_have_still_loads() {
        // `retransmit = 1200` meant "hold twelve hundred", because the size was
        // also the switch. A configuration written against that version has to
        // keep working.
        let old = with_interface("retransmit = 1200").expect("parses");
        assert_eq!(old.interface.repeat.capacity, 1200);
        let old_off = with_interface("retransmit = 0").expect("parses");
        assert_eq!(old_off.interface.repeat.capacity, 0);

        // But not both ways at once, disagreeing.
        assert!(
            with_interface("retransmit = 1200\nretransmit_buffer = 512").is_err(),
            "two ways of saying the same thing were accepted"
        );
    }

    #[test]
    fn repeating_is_off_unless_asked_for() {
        let off = with_interface("").expect("parses");
        assert_eq!(off.interface.repeat.capacity, 0, "off by default");
        assert_eq!(
            off.interface.repeat.deadline,
            crate::repeat::DEFAULT_DEADLINE
        );
        assert_eq!(off.interface.repeat.asks, crate::repeat::DEFAULT_ASKS);

        let on =
            with_interface("retransmit = 1200\nretransmit_deadline = 700\nretransmit_asks = 3")
                .expect("parses");
        assert_eq!(on.interface.repeat.capacity, 1200);
        assert_eq!(on.interface.repeat.deadline, 700);
        assert_eq!(on.interface.repeat.asks, 3);
    }

    #[test]
    fn each_repeat_setting_refuses_what_it_cannot_honour() {
        // A capacity nobody could want, a deadline too short for a round trip
        // or long past the inner protocol's own recovery, and an ask count
        // whose every extra attempt costs two packets to save one.
        for line in [
            "retransmit = true\nretransmit_buffer = 8193",
            "retransmit_deadline = 49",
            "retransmit_deadline = 5001",
            "retransmit_asks = 0",
            "retransmit_asks = 9",
            "retransmit_reorder = 0",
            "retransmit_reorder = 17",
        ] {
            assert!(with_interface(line).is_err(), "{line} was accepted");
        }
        // And the edges of each are allowed.
        for line in [
            "retransmit = true\nretransmit_buffer = 8192",
            "retransmit_deadline = 50",
            "retransmit_deadline = 5000",
            "retransmit_asks = 1",
            "retransmit_asks = 8",
            "retransmit_reorder = 1",
            "retransmit_reorder = 16",
        ] {
            assert!(with_interface(line).is_ok(), "{line} was refused");
        }
    }
    // Panicking on an out-of-range index is exactly what a test should do.

    /// Three tunnels in one file, in the form that can say so.
    const THREE: &str = r#"
log = "debug"

[[tunnel]]
name = "de"
[tunnel.interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"
device = "paqetz0"
route_marked = 81
[tunnel.peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
endpoint = "203.0.113.5:8443"
tunnel_address = "10.7.0.1"

[[tunnel]]
name = "nl"
[tunnel.interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.8.0.2/24"
device = "paqetz1"
mtu = 1280
route_marked = 82
[tunnel.peer]
public_key = "TmwuUmwHVDe4Q0z0PmVEZ0wYyBIDN0kUq5xkQzk0T3E="
endpoint = "198.51.100.7:8443"
tunnel_address = "10.8.0.1"

[[tunnel]]
name = "us"
[tunnel.interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.9.0.2/24"
device = "paqetz2"
route_marked = 83
[tunnel.peer]
public_key = "V3hLZ0FQdG9wbFJlYzBuZFNlcnZlckszeUZvclRlc3Q="
endpoint = "192.0.2.9:8443"
tunnel_address = "10.9.0.1"
"#;

    const CLIENT: &str = r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"

[peer]
public_key = "SGVsbG9UaGlyZFNlcnZlcktleUZvclRlc3RzT25seTA="
endpoint = "203.0.113.5:9999"
tunnel_address = "10.7.0.1"
"#;

    const SERVER: &str = r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.1/24"
listen_port = 9999

[peer]
public_key = "Rm91cnRoU2VydmVyS2V5VXNlZE9ubHlJblRoZXNlVGU="
tunnel_address = "10.7.0.2"
"#;

    #[test]
    fn two_tunnels_cannot_share_one_peer() {
        // The key is the identity. Two tunnels for one peer have nothing to
        // tell their traffic apart by: each handshake takes the session and the
        // endpoint from the other, and the two trade them every fifteen
        // seconds. That looks like a flapping link and is a configuration
        // error, so it is refused rather than left to be diagnosed.
        let same_peer = THREE.replace(
            "public_key = \"TmwuUmwHVDe4Q0z0PmVEZ0wYyBIDN0kUq5xkQzk0T3E=\"",
            "public_key = \"Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo=\"",
        );
        let e = Config::parse(&same_peer).expect_err("two tunnels, one peer");
        assert!(e.to_string().contains("peer key"), "{e}");
    }

    #[test]
    fn two_tunnels_cannot_share_a_written_down_port() {
        let same_port = THREE.replace(
            "[tunnel.interface]",
            "[tunnel.interface]\nlisten_port = 8443",
        );
        let e = Config::parse(&same_port).expect_err("two tunnels, one port");
        assert!(e.to_string().contains("outer port"), "{e}");
    }

    #[test]
    fn tunnels_that_both_choose_a_port_at_start_up_do_not_clash() {
        // Zero is "pick one when you start", and two tunnels doing that will
        // pick differently. Refusing it would refuse the ordinary client.
        let c = Config::parse(THREE).expect("parses");
        assert!(
            c.tunnels.iter().all(|t| t.interface.listen_port == 0),
            "the fixture is meant to leave the port unset"
        );
        assert_eq!(c.tunnels.len(), 3);
    }

    #[test]
    fn several_tunnels_are_read_in_order() {
        let c = Config::parse(THREE).expect("parse");
        assert_eq!(
            c.tunnels
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            ["de", "nl", "us"]
        );
        assert_eq!(c.log, crate::log::Level::Debug, "read from the top level");
    }

    #[test]
    fn each_tunnel_keeps_its_own_settings() {
        // The point of the whole exercise: one client, several destinations,
        // chosen by mark. Sharing any of these would make two tunnels one.
        let c = Config::parse(THREE).expect("parse");
        let nl = c.named("nl").expect("nl");
        assert_eq!(nl.interface.device, "paqetz1");
        assert_eq!(nl.interface.mtu, 1280, "mtu is per tunnel");
        assert_eq!(nl.interface.route_marked, Some(82));
        assert_eq!(nl.peer.endpoint.expect("endpoint").port(), 8443);

        let de = c.named("de").expect("de");
        assert_eq!(
            de.interface.mtu,
            paqetz_dp::tun::DEFAULT_MTU,
            "and defaults per tunnel"
        );
        assert_ne!(de.interface.address, nl.interface.address);
    }

    #[test]
    fn the_old_form_is_still_one_tunnel_named_for_its_device() {
        let c = Config::parse(CLIENT).expect("parse");
        assert_eq!(c.tunnels.len(), 1);
        assert_eq!(c.tunnels[0].name, "paqetz0");
    }

    #[test]
    fn tunnels_that_would_fight_each_other_are_refused() {
        // Each of these leaves two tunnels undoing each other's routing, and the
        // symptom is whichever one lost -- which looks nothing like a
        // configuration mistake from the outside.
        for (what, from, to) in [
            ("device", "device = \"paqetz1\"", "device = \"paqetz0\""),
            ("mark", "route_marked = 82", "route_marked = 81"),
            (
                "address",
                "address = \"10.8.0.2/24\"",
                "address = \"10.7.0.2/24\"",
            ),
            ("name", "name = \"nl\"", "name = \"de\""),
        ] {
            let text = THREE.replace(from, to);
            let err = Config::parse(&text).expect_err(&format!("{what} clash must be refused"));
            assert!(
                err.to_string().contains("both use") || err.to_string().contains("appears twice"),
                "{what}: {err}"
            );
        }
    }

    #[test]
    fn the_two_forms_cannot_be_mixed() {
        // The tunnel sections only; a stray top-level key appended after
        // `[peer]` would belong to the peer table and fail for another reason.
        let text = format!("{CLIENT}\n{}", THREE.replace("log = \"debug\"\n", ""));
        let err = Config::parse(&text).expect_err("ambiguous");
        assert!(err.to_string().contains("ambiguous"), "got: {err}");
    }

    #[test]
    fn a_file_describing_nothing_says_so() {
        let err = Config::parse("log = \"info\"\n").expect_err("nothing to run");
        assert!(err.to_string().contains("nothing to run"), "got: {err}");
    }

    #[test]
    fn a_mistyped_key_inside_a_tunnel_is_still_caught() {
        // What nesting bought instead of flattening: serde cannot do both
        // `flatten` and `deny_unknown_fields`, and this is the property that
        // turns a typo into an error rather than a line quietly ignored.
        let text = THREE.replace("route_marked = 81", "route_marekd = 81");
        assert!(Config::parse(&text).is_err(), "a typo must not be ignored");
    }

    #[test]
    fn a_minimal_client_configuration_parses() {
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.address, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(c.interface.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert!(c.peer.is_initiator(), "an endpoint means we initiate");
        assert_eq!(c.interface.listen_port, 0, "ephemeral by default");
    }

    #[test]
    fn a_minimal_server_configuration_parses() {
        let c = Config::parse(SERVER)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(!c.peer.is_initiator(), "no endpoint means we wait");
        assert_eq!(c.interface.listen_port, 9999);
    }

    #[test]
    fn the_side_that_waits_must_have_a_fixed_port() {
        // Otherwise the peer has no stable address to reach it at, and the
        // failure would appear as a tunnel that silently never connects.
        let text = SERVER.replace("listen_port = 9999", "");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("listen_port"), "got: {err}");
    }

    #[test]
    fn defaults_are_applied() {
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.mtu, paqetz_dp::tun::DEFAULT_MTU);
        assert_eq!(c.interface.device, "paqetz0");
        assert_eq!(c.interface.profile.name, "linux-6");
        assert_eq!(c.interface.carrier, paqetz_tcpwire::Carrier::Midstream);
    }

    #[test]
    fn forwarding_and_routing_are_off_unless_asked_for() {
        // Both change the host's networking beyond the tunnel itself, so
        // neither happens because a config file was merely present.
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(!c.interface.gateway);
        assert!(!c.interface.route_all);
    }

    #[test]
    fn an_egress_interface_is_off_unless_named() {
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(c.interface.egress.is_none());
    }

    #[test]
    fn an_egress_interface_can_be_named() {
        let text = CLIENT.replace("[peer]", "egress = \"warp\"\n\n[peer]");
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.egress.as_deref(), Some("warp"));
        assert_eq!(c.interface.egress_table, 51_820);
    }

    #[test]
    fn a_mark_route_can_be_asked_for_without_socks5() {
        // The arrangement a proxy in front of the tunnel needs: only what it
        // marks goes through, so its own inbound connections are unaffected.
        let text = CLIENT.replace("[peer]", "route_marked = 81\n\n[peer]");
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.route_marked, Some(81));
        assert_eq!(c.interface.route_table, 51);
        assert!(c.socks5.is_none(), "no listener is needed for this");
        assert!(!c.interface.route_all, "and the whole host is not captured");
    }

    #[test]
    fn a_zero_mark_route_is_refused() {
        // Every socket is unmarked by default, so a rule on mark zero would
        // capture the host's own traffic -- including the tunnel's.
        let text = CLIENT.replace("[peer]", "route_marked = 0\n\n[peer]");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("every"), "got: {err}");
    }

    #[test]
    fn forwarding_and_routing_can_be_switched_on() {
        let text = CLIENT.replace("[peer]", "gateway = true\nroute_all = true\n\n[peer]");
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(c.interface.gateway);
        assert!(c.interface.route_all);
    }

    #[test]
    fn the_tunnel_subnet_is_derived_from_the_address() {
        // What the gateway's translation rule is scoped to.
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(
            c.tunnel_subnet(),
            (Ipv4Addr::new(10, 7, 0, 0), 24),
            "10.7.0.2/24 sits in 10.7.0.0/24"
        );
    }

    #[test]
    fn logging_defaults_to_info_with_a_health_line_every_minute() {
        // Process settings now, read from `[interface]` for a file written the
        // old way -- which is the whole of the compatibility promise.
        let c = Config::parse(CLIENT).expect("parse");
        assert_eq!(c.log, crate::log::Level::Info);
        assert_eq!(c.health_interval, 60);
        assert!(c.manage_firewall);
    }

    #[test]
    fn the_log_level_can_be_set_and_silenced() {
        for name in crate::log::Level::ALL {
            let text = CLIENT.replace("[peer]", &format!("log = \"{name}\"\n\n[peer]"));
            let c = Config::parse(&text).expect("parse");
            assert_eq!(c.log.name(), *name);
        }
    }

    #[test]
    fn an_unknown_log_level_lists_the_known_ones() {
        let text = CLIENT.replace("[peer]", "log = \"verbose\"\n\n[peer]");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("debug"), "got: {err}");
    }

    #[test]
    fn the_health_line_can_be_disabled() {
        let text = CLIENT.replace("[peer]", "health_interval = 0\n\n[peer]");
        assert_eq!(Config::parse(&text).expect("parse").health_interval, 0);
    }

    #[test]
    fn socks5_is_off_unless_configured() {
        assert!(
            Config::parse(CLIENT)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .socks5
                .is_none()
        );
    }

    #[test]
    fn a_socks5_section_is_read_with_sensible_defaults() {
        let text = format!("{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\n");
        let s = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel")
            .socks5
            .expect("socks5");
        assert_eq!(s.listen.port(), 1080);
        assert!(s.listen.ip().is_loopback());
        assert_ne!(s.mark, 0, "a zero mark would steer nothing");
        assert!(s.credentials.is_none());
    }

    #[test]
    fn names_resolve_through_the_tunnel_unless_that_is_declined() {
        let with = |line: &str| {
            let text = format!("{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\n{line}\n");
            Config::parse(&text)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .socks5
                .expect("socks5")
                .dns
        };

        assert_eq!(
            with(""),
            Some(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
            "the default has to be the safe one: resolving locally hands every \
             name to the network being tunnelled out of"
        );
        assert_eq!(
            with("dns = \"9.9.9.9\""),
            Some(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53))
        );
        assert_eq!(
            with("dns = \"9.9.9.9:5353\""),
            Some(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 5353)),
            "an unusual port can still be spelled out"
        );
        assert_eq!(with("dns = \"system\""), None, "opting out stays possible");
    }

    #[test]
    fn a_resolver_that_is_not_an_address_is_refused() {
        for bad in [
            "dns = \"\"",
            "dns = \"1.1.1.1.1\"",
            "dns = \"::1\"",
            "dns = \"resolver\"",
        ] {
            let text = format!("{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\n{bad}\n");
            assert!(Config::parse(&text).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_zero_socks5_mark_is_refused() {
        // It would produce a proxy that works and quietly bypasses the tunnel.
        let text = format!("{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\nmark = 0\n");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("normal route"), "got: {err}");
    }

    #[test]
    fn half_a_credential_pair_is_refused() {
        for half in ["username = \"a\"", "password = \"b\""] {
            let text = format!("{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\n{half}\n");
            assert!(
                Config::parse(&text).is_err(),
                "{half} alone should be rejected"
            );
        }
        let both = format!(
            "{CLIENT}\n[socks5]\nlisten = \"127.0.0.1:1080\"\nusername = \"a\"\npassword = \"b\"\n"
        );
        let s = Config::parse(&both)
            .expect("parse")
            .into_only()
            .expect("one tunnel")
            .socks5
            .expect("socks5");
        assert_eq!(s.credentials, Some(("a".to_owned(), "b".to_owned())));
    }

    #[test]
    fn the_datapath_and_transmit_defaults_are_the_recommended_ones() {
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(
            c.interface.datapath,
            Datapath::Simple,
            "batching showed no consistent gain, so the simpler path wins the tie"
        );
        assert_eq!(
            c.interface.transmit,
            TransmitPath::Raw,
            "the raw path has no hardware address to go stale, so it is the default"
        );
    }

    #[test]
    fn both_can_be_switched() {
        let text = CLIENT.replace(
            "[peer]",
            "datapath = \"simple\"\ntransmit = \"afpacket\"\n\n[peer]",
        );
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.datapath, Datapath::Simple);
        assert_eq!(c.interface.transmit, TransmitPath::AfPacket);
    }

    #[test]
    fn an_unknown_datapath_or_transmit_is_rejected() {
        for (field, value) in [("datapath", "turbo"), ("transmit", "carrier-pigeon")] {
            let text = CLIENT.replace("[peer]", &format!("{field} = \"{value}\"\n\n[peer]"));
            let err = Config::parse(&text).expect_err("must be rejected");
            assert!(err.to_string().contains(field), "got: {err}");
        }
    }

    #[test]
    fn allowed_ips_defaults_to_the_peers_own_address() {
        // D12: derived, not configured. There should be nothing to write.
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.peer.allowed_ips, vec![(Ipv4Addr::new(10, 7, 0, 1), 32)]);
        assert!(c.peer.permits(Ipv4Addr::new(10, 7, 0, 1)));
        assert!(!c.peer.permits(Ipv4Addr::new(10, 7, 0, 9)));
        assert!(!c.peer.permits(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn allowed_ips_can_be_widened_to_a_subnet() {
        let text = CLIENT.replace(
            "tunnel_address = \"10.7.0.1\"",
            "tunnel_address = \"10.7.0.1\"\nallowed_ips = [\"10.7.0.0/24\", \"192.168.9.0/24\"]",
        );
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(c.peer.permits(Ipv4Addr::new(10, 7, 0, 200)));
        assert!(c.peer.permits(Ipv4Addr::new(192, 168, 9, 1)));
        assert!(!c.peer.permits(Ipv4Addr::new(192, 168, 10, 1)));
    }

    #[test]
    fn allowed_ips_any_disables_the_check() {
        let text = CLIENT.replace(
            "tunnel_address = \"10.7.0.1\"",
            "tunnel_address = \"10.7.0.1\"\nallowed_ips = [\"any\"]",
        );
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(c.peer.permits(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(c.peer.permits(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        // A typo in a security-relevant field must not be silently discarded.
        let text = CLIENT.replace("address =", "adress =");
        assert!(Config::parse(&text).is_err());

        let text = format!("{CLIENT}\n[interface]\nnonsense = 1\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn a_bad_key_says_which_field() {
        let text = CLIENT.replace("private_key = \"", "private_key = \"not-base64!!");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(
            err.to_string().contains("interface.private_key"),
            "got: {err}"
        );
    }

    #[test]
    fn an_unknown_profile_lists_the_known_ones() {
        let text = CLIENT.replace("[peer]", "profile = \"plan9\"\n\n[peer]");
        let err = Config::parse(&text).expect_err("must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("linux-6"), "should list what is valid: {msg}");
        assert!(msg.contains("windows-11"), "got: {msg}");
    }

    #[test]
    fn an_interface_name_must_be_one_linux_would_accept() {
        // These reach `nft` inside a generated script, where a quote or a
        // newline ends the token early and what follows is read as ruleset.
        for bad in [
            "paqetz0\" ; drop",
            "paqetz0\nadd rule",
            "",
            "0123456789abcdef",
            "..",
            "eth0/1",
        ] {
            assert!(
                super::interface_name("interface.device", bad).is_err(),
                "{bad:?} was accepted"
            );
        }
        for good in ["paqetz0", "wg-1", "tun.0", "a", "0123456789abcde"] {
            assert!(
                super::interface_name("interface.device", good).is_ok(),
                "{good:?} was refused"
            );
        }
    }

    #[test]
    fn the_keepalive_and_rotation_are_on_unless_declined() {
        // A silent tunnel goes cold -- the first two seconds after an idle
        // period were lost on a live path -- and a five-tuple that never moves
        // gets classified and shaped. Both defaults were measured before being
        // chosen.
        let c = Config::parse(CLIENT)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(c.interface.keepalive);
        assert!(c.interface.rotate);
    }

    #[test]
    fn the_keepalive_and_rotation_can_be_turned_off() {
        for (line, keepalive) in [("keepalive = false", true), ("rotate = false", false)] {
            let text = CLIENT.replace("[peer]", &format!("{line}\n\n[peer]"));
            let c = Config::parse(&text)
                .expect("parse")
                .into_only()
                .expect("one tunnel");
            let off = if keepalive {
                c.interface.keepalive
            } else {
                c.interface.rotate
            };
            assert!(!off, "{line} should have taken effect");
        }
    }

    #[test]
    fn the_keepalive_and_rotation_can_be_turned_on() {
        for (line, get) in [("keepalive = true", true), ("rotate = true", false)] {
            let text = CLIENT.replace("[peer]", &format!("{line}\n\n[peer]"));
            let c = Config::parse(&text)
                .expect("parse")
                .into_only()
                .expect("one tunnel");
            let on = if get {
                c.interface.keepalive
            } else {
                c.interface.rotate
            };
            assert!(on, "{line} should have taken effect");
        }
    }

    #[test]
    fn segments_are_numbered_opaquely_unless_asked_otherwise() {
        assert_eq!(
            Config::parse(CLIENT)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .interface
                .sequencing,
            paqetz_tcpwire::Sequencing::Opaque,
            "byte-accurate numbering is checkable, and this carrier cannot keep \
             the promise it makes once a packet is lost"
        );
        let text = CLIENT.replace("[peer]", "sequencing = \"stream\"\n\n[peer]");
        assert_eq!(
            Config::parse(&text)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .interface
                .sequencing,
            paqetz_tcpwire::Sequencing::Stream
        );
    }

    #[test]
    fn an_unknown_sequencing_mode_is_rejected() {
        let text = CLIENT.replace("[peer]", "sequencing = \"honest\"\n\n[peer]");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn an_unknown_carrier_mode_is_rejected() {
        let text = CLIENT.replace("[peer]", "carrier = \"sideways\"\n\n[peer]");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("midstream"), "got: {err}");
    }

    #[test]
    fn the_carrier_mode_can_be_switched() {
        let text = CLIENT.replace("[peer]", "carrier = \"handshake\"\n\n[peer]");
        let c = Config::parse(&text)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(c.interface.carrier, paqetz_tcpwire::Carrier::Handshake);
    }

    #[test]
    fn an_address_without_a_prefix_says_so() {
        let text = CLIENT.replace("10.7.0.2/24", "10.7.0.2");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("prefix"), "got: {err}");
    }

    #[test]
    fn an_out_of_range_mtu_is_rejected() {
        for mtu in [0u32, 100, 575, 9001, 100_000] {
            let text = CLIENT.replace("[peer]", &format!("mtu = {mtu}\n\n[peer]"));
            assert!(
                Config::parse(&text).is_err(),
                "mtu {mtu} should be rejected"
            );
        }
        for mtu in [576u32, 1400, 9000] {
            let text = CLIENT.replace("[peer]", &format!("mtu = {mtu}\n\n[peer]"));
            assert!(Config::parse(&text).is_ok(), "mtu {mtu} should be accepted");
        }
    }

    #[test]
    fn a_malformed_endpoint_says_so() {
        let text = CLIENT.replace("203.0.113.5:9999", "203.0.113.5");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("peer.endpoint"), "got: {err}");
    }

    #[test]
    fn prefix_masks_are_correct() {
        assert_eq!(mask_from_prefix(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(mask_from_prefix(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(mask_from_prefix(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask_from_prefix(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn network_membership_is_exact_at_the_boundaries() {
        let net = Ipv4Addr::new(10, 7, 0, 0);
        assert!(in_network(Ipv4Addr::new(10, 7, 0, 0), net, 24));
        assert!(in_network(Ipv4Addr::new(10, 7, 0, 255), net, 24));
        assert!(!in_network(Ipv4Addr::new(10, 7, 1, 0), net, 24));
        assert!(!in_network(Ipv4Addr::new(10, 6, 255, 255), net, 24));

        // A /32 matches exactly one address, and /0 matches everything.
        let host = Ipv4Addr::new(10, 7, 0, 5);
        assert!(in_network(host, host, 32));
        assert!(!in_network(Ipv4Addr::new(10, 7, 0, 6), host, 32));
        assert!(in_network(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::UNSPECIFIED,
            0
        ));
    }
}
