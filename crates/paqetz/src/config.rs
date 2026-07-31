//! Configuration file parsing and validation.
//!
//! The shape follows WireGuard's, because that is what an operator setting up a
//! point-to-point tunnel already knows. Everything paqet required and this does
//! not is worth noting, since removing it was the point: no interface name, no
//! gateway MAC address, no cipher selection, no KCP tuning, no window sizes, no
//! buffer sizes, and no `role` field — which side initiates follows from
//! whether a peer has an endpoint.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

use paqetz_core::{PrivateKey, PublicKey};
use serde::Deserialize;

/// A parsed and validated configuration.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// This end's settings.
    pub(crate) interface: Interface,
    /// The peer. Exactly one, for now — the peer *table* exists so that
    /// supporting more is a configuration change rather than a rewrite, but a
    /// second entry is rejected until the routing work in phase 2 lands.
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
    /// Whether to manage firewall rules automatically.
    pub(crate) manage_firewall: bool,
    /// Whether to move packets in batches.
    pub(crate) datapath: Datapath,
    /// Which transmit path to use.
    pub(crate) transmit: TransmitPath,
}

/// How packets move between the device and the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Datapath {
    /// Up to 32 packets per syscall, drained from whatever is already queued.
    ///
    /// The default. Batching only ever takes packets that were waiting anyway,
    /// so it costs no latency: with one packet in flight it behaves exactly as
    /// the simple path does.
    #[default]
    Batched,
    /// One packet per syscall.
    ///
    /// Kept so the two can be measured against each other, and as somewhere to
    /// stand if the batched path ever misbehaves.
    Simple,
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
    /// Skips the route lookup and the netfilter `OUTPUT` chain. Possibly
    /// faster — measure it with `scripts/bench.sh` before adopting it.
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
    interface: RawInterface,
    peer: RawPeer,
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
    manage_firewall: Option<bool>,
    #[serde(default)]
    datapath: Option<String>,
    #[serde(default)]
    transmit: Option<String>,
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

        let private_key = PrivateKey::from_base64(&raw.interface.private_key)
            .map_err(|e| invalid("interface.private_key", e.to_string()))?;

        let (address, prefix) =
            parse_cidr(&raw.interface.address).map_err(|p| invalid("interface.address", p))?;
        let netmask = mask_from_prefix(prefix);

        let mtu = raw.interface.mtu.unwrap_or(paqetz_dp::tun::DEFAULT_MTU);
        if !(576..=9000).contains(&mtu) {
            return Err(invalid(
                "interface.mtu",
                format!("{mtu} is outside the usable range 576-9000"),
            ));
        }

        let profile_name = raw.interface.profile.as_deref().unwrap_or("linux-6");
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

        let carrier = match raw.interface.carrier.as_deref().unwrap_or("midstream") {
            "midstream" => paqetz_tcpwire::Carrier::Midstream,
            "handshake" => paqetz_tcpwire::Carrier::Handshake,
            other => {
                return Err(invalid(
                    "interface.carrier",
                    format!("expected \"midstream\" or \"handshake\", got {other:?}"),
                ));
            }
        };

        let datapath = match raw.interface.datapath.as_deref().unwrap_or("batched") {
            "batched" => Datapath::Batched,
            "simple" => Datapath::Simple,
            other => {
                return Err(invalid(
                    "interface.datapath",
                    format!("expected \"batched\" or \"simple\", got {other:?}"),
                ));
            }
        };

        let transmit = match raw.interface.transmit.as_deref().unwrap_or("raw") {
            "raw" => TransmitPath::Raw,
            "afpacket" => TransmitPath::AfPacket,
            other => {
                return Err(invalid(
                    "interface.transmit",
                    format!("expected \"raw\" or \"afpacket\", got {other:?}"),
                ));
            }
        };

        let public_key = PublicKey::from_base64(&raw.peer.public_key)
            .map_err(|e| invalid("peer.public_key", e.to_string()))?;

        let endpoint = match raw.peer.endpoint.as_deref() {
            None => None,
            Some(s) => Some(
                s.parse::<SocketAddrV4>()
                    .map_err(|e| invalid("peer.endpoint", format!("{s:?}: {e}")))?,
            ),
        };

        let tunnel_address: Ipv4Addr = raw
            .peer
            .tunnel_address
            .parse()
            .map_err(|e| invalid("peer.tunnel_address", format!("{e}")))?;

        // Derived rather than configured (D12): the inner address is one we
        // assign, so its /32 is implied and there is nothing to write down.
        let allowed_ips = match raw.peer.allowed_ips {
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

        let listen_port = raw.interface.listen_port.unwrap_or(0);
        if endpoint.is_none() && listen_port == 0 {
            return Err(invalid(
                "interface.listen_port",
                "the side without a peer endpoint must listen on a fixed port, \
                 or the peer has no stable address to reach it at",
            ));
        }

        Ok(Self {
            interface: Interface {
                private_key,
                address,
                netmask,
                mtu,
                listen_port,
                device: raw.interface.device.unwrap_or_else(|| "paqetz0".to_owned()),
                profile,
                carrier,
                manage_firewall: raw.interface.manage_firewall.unwrap_or(true),
                datapath,
                transmit,
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
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    const CLIENT: &str = r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"

[peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
endpoint = "203.0.113.5:9999"
tunnel_address = "10.7.0.1"
"#;

    const SERVER: &str = r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.1/24"
listen_port = 9999

[peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
tunnel_address = "10.7.0.2"
"#;

    #[test]
    fn a_minimal_client_configuration_parses() {
        let c = Config::parse(CLIENT).expect("parse");
        assert_eq!(c.interface.address, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(c.interface.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert!(c.peer.is_initiator(), "an endpoint means we initiate");
        assert_eq!(c.interface.listen_port, 0, "ephemeral by default");
    }

    #[test]
    fn a_minimal_server_configuration_parses() {
        let c = Config::parse(SERVER).expect("parse");
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
        let c = Config::parse(CLIENT).expect("parse");
        assert_eq!(c.interface.mtu, paqetz_dp::tun::DEFAULT_MTU);
        assert_eq!(c.interface.device, "paqetz0");
        assert_eq!(c.interface.profile.name, "linux-6");
        assert_eq!(c.interface.carrier, paqetz_tcpwire::Carrier::Midstream);
        assert!(c.interface.manage_firewall);
    }

    #[test]
    fn the_datapath_and_transmit_defaults_are_the_recommended_ones() {
        let c = Config::parse(CLIENT).expect("parse");
        assert_eq!(
            c.interface.datapath,
            Datapath::Batched,
            "batching costs nothing when there is one packet, so it is the default"
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
        let c = Config::parse(&text).expect("parse");
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
        let c = Config::parse(CLIENT).expect("parse");
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
        let c = Config::parse(&text).expect("parse");
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
        let c = Config::parse(&text).expect("parse");
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
    fn an_unknown_carrier_mode_is_rejected() {
        let text = CLIENT.replace("[peer]", "carrier = \"sideways\"\n\n[peer]");
        let err = Config::parse(&text).expect_err("must be rejected");
        assert!(err.to_string().contains("midstream"), "got: {err}");
    }

    #[test]
    fn the_carrier_mode_can_be_switched() {
        let text = CLIENT.replace("[peer]", "carrier = \"handshake\"\n\n[peer]");
        let c = Config::parse(&text).expect("parse");
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
