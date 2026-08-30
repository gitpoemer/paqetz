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
    /// Send the peer's traffic out this interface rather than the default
    /// route, translating it to that interface's address.
    ///
    /// The reason to want this is that the tunnel's own address is the one the
    /// destination sees, and it is a datacentre address belonging to whoever
    /// runs the server. Routing the forwarded traffic out something else — a
    /// Cloudflare WARP interface being the usual choice — changes what the far
    /// side sees without changing anything the client does.
    ///
    /// Bringing that interface up is not this program's job. It checks the
    /// interface exists and says so if it does not.
    pub egress: Option<Egress>,
}

/// An interface the forwarded traffic leaves by.
#[derive(Debug, Clone)]
pub struct Egress {
    /// The interface name, e.g. `warp`.
    pub interface: String,
    /// The routing table holding that interface's default route.
    ///
    /// `wg-quick` with `Table = <n>` puts it there rather than in the main
    /// table, which is exactly what makes this arrangement possible: the host's
    /// own traffic is unaffected, and only what is directed at this table goes
    /// out that way.
    pub table: u32,
}

/// Priority of the source rule that sends the tunnel subnet to the egress
/// table. Below the SOCKS5 mark rule so the two do not interleave.
const EGRESS_RULE_PRIORITY: u32 = 9100;

impl Gateway {
    /// The commands and settings [`apply`](Self::apply) would put in place.
    #[must_use]
    pub fn plan(&self) -> Vec<String> {
        vec![
            "sysctl -w net.ipv4.ip_forward=1".to_owned(),
            format!("nft -f - <<'EOF'\n{}EOF", self.ruleset()),
        ]
    }

    /// Whether the egress interface exists on this host.
    #[must_use]
    pub fn egress_present(&self) -> bool {
        self.egress.as_ref().is_none_or(|e| {
            std::path::Path::new(&format!("/sys/class/net/{}", e.interface)).exists()
        })
    }

    /// The `nftables` ruleset that forwards and translates tunnel traffic.
    fn ruleset(&self) -> String {
        let (net, prefix) = self.subnet;
        let device = &self.device;
        // Translate to whichever interface the traffic actually leaves by, so
        // the source address matches the path it took.
        let masquerade = self.egress.as_ref().map_or_else(
            || format!("ip saddr {net}/{prefix} oifname != \"{device}\" masquerade"),
            |e| {
                format!(
                    "ip saddr {net}/{prefix} oifname \"{}\" masquerade",
                    e.interface
                )
            },
        );
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
        {masquerade}
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

        // Source-based routing, so only the peer's traffic takes the egress
        // interface. A default route would take the host's own traffic with
        // it, including the tunnel's, which would collapse the tunnel.
        if let Some(e) = self.egress.as_ref() {
            let (net, prefix) = self.subnet;
            let from = format!("{net}/{prefix}");
            let table = e.table.to_string();
            let prio = EGRESS_RULE_PRIORITY.to_string();
            // Removed first, so a repeat leaves one rule rather than a stack.
            while run_ip(&[
                "rule", "del", "from", &from, "lookup", &table, "priority", &prio,
            ])
            .is_ok()
            {}
            run_ip(&[
                "rule", "add", "from", &from, "lookup", &table, "priority", &prio,
            ])?;
        }
        Ok(!was_on)
    }

    /// Removes the rules, and restores forwarding if we turned it on.
    pub fn revert(&self, restore_forwarding: bool) {
        if let Some(e) = self.egress.as_ref() {
            let (net, prefix) = self.subnet;
            let from = format!("{net}/{prefix}");
            let table = e.table.to_string();
            let prio = EGRESS_RULE_PRIORITY.to_string();
            while run_ip(&[
                "rule", "del", "from", &from, "lookup", &table, "priority", &prio,
            ])
            .is_ok()
            {}
        }
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

/// Points a firewall mark at a routing table, without touching its routes.
///
/// Distinct from the policy route the tunnel installs for its own device, which
/// also puts a route *in* the table. Here the table belongs to something else --
/// a `wg-quick` profile, usually -- and writing into it would fight whatever
/// brought it up.
///
/// Removed before it is added, because `ip rule add` is not idempotent: run
/// twice it installs the rule twice, and the duplicate is invisible until
/// somebody reads `ip rule` and wonders.
///
/// # Errors
/// Returns the tool's failure.
pub fn point_mark_at(mark: u32, table: u32, priority: u32) -> Result<()> {
    let mark = format!("{mark:#x}");
    let table = table.to_string();
    let priority = priority.to_string();
    let spec = [
        "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &priority,
    ];
    while run_ip(&spec).is_ok() {}
    run_ip(&[
        "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &priority,
    ])
}

/// Removes such a rule.
pub fn unpoint_mark(mark: u32, table: u32, priority: u32) {
    let mark = format!("{mark:#x}");
    let table = table.to_string();
    let priority = priority.to_string();
    while run_ip(&[
        "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &priority,
    ])
    .is_ok()
    {}
}

/// Priority of a lane's rule.
///
/// Above the blanket egress rule, so a lane is consulted before anything that
/// would sweep all the tunnel's traffic one way.
pub const LANE_RULE_PRIORITY: u32 = 9_000;

/// The routing table holding a default route out of `interface`.
///
/// Derived rather than configured, because an operator keeping a table number
/// in step with a `wg-quick` profile by hand gets a lane that looks configured,
/// finds an empty table, falls through to the main one, and sends the traffic
/// out the ordinary way. That failure is silent at every layer: the rules are
/// installed, the counters move, and the packets leave by the wrong interface.
///
/// # Errors
/// Returns a message naming what was found when there is no such route, or
/// when there is more than one and the choice is not this function's to make.
pub fn table_for(interface: &str) -> core::result::Result<u32, String> {
    let listed = std::process::Command::new("ip")
        .args(["route", "show", "table", "all"])
        .output()
        .map_err(|e| format!("could not run `ip route show table all`: {e}"))?;
    table_in(&String::from_utf8_lossy(&listed.stdout), interface)
}

/// The same decision, over text a test can supply.
fn table_in(text: &str, interface: &str) -> core::result::Result<u32, String> {
    let mut found: Vec<u32> = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("default") {
            continue;
        }
        let fields: Vec<&str> = fields.collect();
        let pair = |key: &str| {
            fields
                .windows(2)
                .find_map(|w| (w.first() == Some(&key)).then(|| w.get(1).copied())?)
        };
        let leaves_by = pair("dev") == Some(interface);
        if !leaves_by {
            continue;
        }
        // Absent, the route is in `main`, which is the one table a lane must
        // not use: everything already looks there, so it would not select.
        let table = pair("table").and_then(|t| t.parse::<u32>().ok());
        match table {
            Some(t) if !found.contains(&t) => found.push(t),
            Some(_) => {}
            None => {
                return Err(format!(
                    "{interface} has its default route in the main table, so nothing can be \
                     steered to it -- every lookup already ends there. Bring it up with a table \
                     of its own (`Table = 51820` in a wg-quick profile)."
                ));
            }
        }
    }
    match found.as_slice() {
        [] => Err(format!(
            "no default route leaves by {interface}. Bring the interface up first, with a table \
             of its own, and check `ip route show table all`."
        )),
        [one] => Ok(*one),
        many => Err(format!(
            "{interface} has default routes in {} tables ({}), so which one a lane should use is \
             not derivable. Write it down as `table`.",
            many.len(),
            many.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
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
            egress: None,
        }
    }

    fn with_egress() -> Gateway {
        Gateway {
            egress: Some(Egress {
                interface: "warp".to_owned(),
                table: 51_820,
            }),
            ..gateway()
        }
    }

    #[test]
    fn the_table_a_lane_needs_is_read_off_the_routes() {
        // Taken from a live host: wg-quick with `Table = 51820` puts WARP's
        // default there, main keeps the host's own, and a paqetz tunnel adds
        // its own table for marked traffic.
        let routes = "\
default via 185.31.8.1 dev eth0 proto static onlink
default dev warp table 51820 scope link
default dev paqetz0 table 81 scope link metric 1
blackhole default table 81 metric 100
10.7.0.0/24 dev paqetz0 proto kernel scope link src 10.7.0.1
";
        assert_eq!(table_in(routes, "warp"), Ok(51_820));
        assert_eq!(table_in(routes, "paqetz0"), Ok(81));
    }

    #[test]
    fn a_route_in_the_main_table_cannot_be_steered_to() {
        // Every lookup already ends in main, so a rule pointing there selects
        // nothing -- and the traffic leaves the ordinary way while the rules,
        // the counters and the logs all look correct.
        let routes = "default via 185.31.8.1 dev eth0 proto static onlink\n";
        let err = table_in(routes, "eth0").expect_err("main is not steerable");
        assert!(err.contains("main table"), "{err}");
    }

    #[test]
    fn an_interface_that_is_not_up_says_so_rather_than_guessing() {
        let routes = "default dev warp table 51820 scope link\n";
        let err = table_in(routes, "wg0").expect_err("no such route");
        assert!(err.contains("no default route"), "{err}");
        assert!(err.contains("wg0"), "{err}");
    }

    #[test]
    fn two_tables_for_one_interface_is_not_a_choice_to_make_here() {
        // Picking one would be picking where somebody's traffic goes, on
        // evidence that does not decide it.
        let routes = "\
default dev warp table 51820 scope link
default dev warp table 90 scope link
";
        let err = table_in(routes, "warp").expect_err("ambiguous");
        assert!(err.contains("51820") && err.contains("90"), "{err}");
        assert!(err.contains("Write it down"), "{err}");
    }

    #[test]
    fn an_egress_interface_changes_what_the_translation_targets() {
        // Without it, traffic is translated on whatever it leaves by. With it,
        // only traffic leaving by that interface is translated -- so the source
        // address always matches the path the packet actually took.
        let rules = with_egress().ruleset();
        assert!(rules.contains("oifname \"warp\" masquerade"), "{rules}");
        assert!(
            !rules.contains("oifname != "),
            "the default-route form should be gone: {rules}"
        );
    }

    #[test]
    fn an_absent_egress_interface_is_detected() {
        assert!(gateway().egress_present(), "no egress is always present");
        let mut g = with_egress();
        g.egress = Some(Egress {
            interface: "definitely-not-real".to_owned(),
            table: 1,
        });
        assert!(!g.egress_present());
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
