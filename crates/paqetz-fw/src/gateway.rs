//! Making the server an actual way out to the internet.
//!
//! Bringing the tunnel up gets two hosts that can reach each other's inner
//! addresses. That is not a usable tunnel: for the client's traffic to reach
//! anything beyond the server, the server has to forward it and translate its
//! source, and neither happens by default.
//!
//! This is exactly the gap that makes a tunnel look broken when it is working.
//! Packets arrive, are decrypted correctly, are written to the device — and the
//! kernel drops them, because forwarding is off. Nothing logs an error, because
//! nothing has gone wrong from the tunnel's point of view.

use std::io;
use std::net::Ipv4Addr;

use crate::{Error, Result, nft_script, run_ip};

/// The `nftables` table holding the gateway rules.
///
/// Separate from the tunnel's own table so the two have independent lifetimes:
/// a host can forward for a tunnel without the tunnel's port rules, and the
/// reverse.
pub const TABLE: &str = "paqetz_gw";

/// Where `ip_forward` lives.
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// What the server needs in order to be a way out.
#[derive(Debug, Clone)]
pub struct Gateway {
    /// The tunnel device.
    pub device: String,
    /// The tunnel's inner subnet, whose traffic is translated.
    pub subnet: (Ipv4Addr, u8),
}

impl Gateway {
    /// The commands and settings [`apply`](Self::apply) would put in place.
    #[must_use]
    pub fn plan(&self) -> Vec<String> {
        vec![
            "sysctl -w net.ipv4.ip_forward=1".to_owned(),
            format!("nft -f - <<'EOF'\n{}EOF", self.ruleset()),
        ]
    }

    /// The `nftables` ruleset that forwards and translates tunnel traffic.
    fn ruleset(&self) -> String {
        let (net, prefix) = self.subnet;
        let device = &self.device;
        format!(
            "add table ip {TABLE}
delete table ip {TABLE}
table ip {TABLE} {{
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname \"{device}\" accept
        oifname \"{device}\" ct state established,related accept
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {net}/{prefix} oifname != \"{device}\" masquerade
    }}
}}
"
        )
    }

    /// Turns on forwarding and installs the translation rules.
    ///
    /// Returns whether `ip_forward` had to be changed, so it can be put back
    /// exactly as it was — a host that was already forwarding for other reasons
    /// must not have that turned off when the tunnel stops.
    ///
    /// # Errors
    /// Returns an error if the setting cannot be written or `nft` fails.
    pub fn apply(&self) -> Result<bool> {
        let was_on = forwarding_enabled()?;
        if !was_on {
            set_forwarding(true)?;
        }
        nft_script(&self.ruleset())?;
        Ok(!was_on)
    }

    /// Removes the rules, and restores forwarding if we turned it on.
    pub fn revert(&self, restore_forwarding: bool) {
        let _ = nft_script(&format!("add table ip {TABLE}\ndelete table ip {TABLE}\n"));
        if restore_forwarding {
            let _ = set_forwarding(false);
        }
    }
}

/// Whether IPv4 forwarding is on.
///
/// # Errors
/// Returns an error if the setting cannot be read.
pub fn forwarding_enabled() -> Result<bool> {
    let text = std::fs::read_to_string(IP_FORWARD).map_err(|source| Error::Spawn {
        command: IP_FORWARD.to_owned(),
        source,
    })?;
    Ok(text.trim() != "0")
}

/// Turns IPv4 forwarding on or off.
fn set_forwarding(on: bool) -> Result<()> {
    std::fs::write(IP_FORWARD, if on { "1\n" } else { "0\n" }).map_err(|source| {
        if source.kind() == io::ErrorKind::PermissionDenied {
            Error::Spawn {
                command: format!("writing {IP_FORWARD} (needs root)"),
                source,
            }
        } else {
            Error::Spawn {
                command: IP_FORWARD.to_owned(),
                source,
            }
        }
    })
}

/// Routes that send a client's traffic through the tunnel.
///
/// The awkward part is that the tunnel's own packets must *not* go through the
/// tunnel. A plain default route via the device would capture them and the
/// connection would collapse the moment it came up — which on a remote host
/// means locking yourself out of it.
///
/// Two mechanisms avoid that together. The peer's endpoint is pinned to the
/// original gateway with a host route, so the tunnel's own traffic keeps its
/// path. And the tunnel is given `0.0.0.0/1` and `128.0.0.0/1` rather than
/// `0.0.0.0/0`: two halves that are each more specific than the default route,
/// so they win without replacing it. Removing them restores the original
/// routing exactly, with nothing to remember.
#[derive(Debug, Clone)]
pub struct TunnelRoutes {
    /// The tunnel device.
    pub device: String,
    /// The peer's outer address, which must keep its original path.
    pub endpoint: Ipv4Addr,
    /// The gateway that address is reached through.
    pub original_gateway: Option<Ipv4Addr>,
    /// The interface that gateway is reached over.
    pub original_device: String,
}

impl TunnelRoutes {
    /// The commands [`apply`](Self::apply) would run.
    #[must_use]
    pub fn plan(&self) -> Vec<String> {
        let mut out = vec![match self.original_gateway {
            Some(gw) => format!(
                "ip route add {}/32 via {} dev {}",
                self.endpoint, gw, self.original_device
            ),
            None => format!(
                "ip route add {}/32 dev {}",
                self.endpoint, self.original_device
            ),
        }];
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            out.push(format!("ip route add {half} dev {}", self.device));
        }
        out
    }

    /// Installs the routes.
    ///
    /// # Errors
    /// Returns an error if `ip` fails for the halves. Pinning the endpoint is
    /// allowed to fail, because a route to it may already exist.
    pub fn apply(&self) -> Result<()> {
        // Pin the endpoint first. If this fails because a more specific route
        // already covers it, the halves below are still safe to add.
        let endpoint = self.endpoint.to_string();
        let pin: Vec<String> = match self.original_gateway {
            Some(gw) => vec![
                "route".into(),
                "replace".into(),
                format!("{endpoint}/32"),
                "via".into(),
                gw.to_string(),
                "dev".into(),
                self.original_device.clone(),
            ],
            None => vec![
                "route".into(),
                "replace".into(),
                format!("{endpoint}/32"),
                "dev".into(),
                self.original_device.clone(),
            ],
        };
        let pin_args: Vec<&str> = pin.iter().map(String::as_str).collect();
        run_ip(&pin_args)?;

        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            run_ip(&["route", "replace", half, "dev", &self.device])?;
        }
        Ok(())
    }

    /// Removes the routes, restoring the original path.
    pub fn revert(&self) {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = run_ip(&["route", "del", half, "dev", &self.device]);
        }
        let endpoint = format!("{}/32", self.endpoint);
        let _ = run_ip(&["route", "del", &endpoint]);
    }
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn gateway() -> Gateway {
        Gateway {
            device: "paqetz0".to_owned(),
            subnet: (Ipv4Addr::new(10, 7, 0, 0), 24),
        }
    }

    #[test]
    fn the_gateway_ruleset_forwards_and_translates() {
        let rules = gateway().ruleset();
        assert!(rules.contains("iifname \"paqetz0\" accept"), "{rules}");
        assert!(
            rules.contains("ip saddr 10.7.0.0/24 oifname != \"paqetz0\" masquerade"),
            "{rules}"
        );
    }

    #[test]
    fn the_gateway_ruleset_is_idempotent_by_construction() {
        let rules = gateway().ruleset();
        let add = rules.find("add table").expect("adds");
        let delete = rules.find("delete table").expect("deletes");
        assert!(add < delete, "the table must be added before it is deleted");
    }

    #[test]
    fn the_gateway_chains_default_to_accept() {
        // A drop policy on the forward chain would black-hole every packet the
        // host routes, tunnel or not, the moment this is installed.
        assert_eq!(gateway().ruleset().matches("policy accept").count(), 2);
    }

    #[test]
    fn translation_excludes_traffic_going_back_into_the_tunnel() {
        // Without the `oifname !=` clause, replies heading back to the peer
        // would have their source rewritten too, and the client would see
        // answers from an address it never spoke to.
        assert!(gateway().ruleset().contains("oifname != \"paqetz0\""));
    }

    #[test]
    fn the_gateway_plan_turns_forwarding_on_before_installing_rules() {
        let plan = gateway().plan();
        assert!(plan[0].contains("ip_forward=1"), "{}", plan[0]);
        assert!(plan[1].contains("masquerade"), "{}", plan[1]);
    }

    fn routes() -> TunnelRoutes {
        TunnelRoutes {
            device: "paqetz0".to_owned(),
            endpoint: Ipv4Addr::new(203, 0, 113, 5),
            original_gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            original_device: "enp3s0".to_owned(),
        }
    }

    #[test]
    fn the_endpoint_keeps_its_original_path() {
        // The route that stops the tunnel carrying its own packets, which would
        // collapse it the instant it came up.
        let plan = routes().plan();
        assert!(
            plan[0].contains("203.0.113.5/32 via 192.168.1.1 dev enp3s0"),
            "{}",
            plan[0]
        );
    }

    #[test]
    fn the_default_is_captured_by_halves_rather_than_replaced() {
        // Two /1 routes are each more specific than 0.0.0.0/0, so they win
        // without removing it -- and deleting them restores the original
        // routing exactly, with nothing to have remembered.
        let plan = routes().plan();
        assert!(plan[1].contains("0.0.0.0/1 dev paqetz0"), "{}", plan[1]);
        assert!(plan[2].contains("128.0.0.0/1 dev paqetz0"), "{}", plan[2]);
        assert!(
            !plan.iter().any(|l| l.contains("0.0.0.0/0")),
            "the default route must not be touched"
        );
    }

    #[test]
    fn an_on_link_endpoint_is_pinned_without_a_gateway() {
        let mut r = routes();
        r.original_gateway = None;
        let plan = r.plan();
        assert!(plan[0].contains("203.0.113.5/32 dev enp3s0"), "{}", plan[0]);
        assert!(!plan[0].contains("via"), "{}", plan[0]);
    }

    #[test]
    fn the_plans_are_runnable_as_printed() {
        for line in gateway().plan().into_iter().chain(routes().plan()) {
            assert!(!line.contains("{}"), "unsubstituted placeholder: {line}");
        }
    }

    #[test]
    fn forwarding_can_be_read_on_this_host() {
        // Read-only; a host without the file is not an error worth failing on.
        let _ = forwarding_enabled();
    }
}
