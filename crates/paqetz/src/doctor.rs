//! `paqetz doctor` — check a host before blaming the tunnel.
//!
//! paqet's failure mode was that almost every setup mistake produced the same
//! symptom: a tunnel that comes up and carries nothing. A wrong gateway MAC, a
//! missing `iptables` rule, a port the kernel was already listening on, an MTU
//! too large for the path — all of them look identical from the outside, and its
//! troubleshooting section is a list of things to check by hand.
//!
//! Every check here is **read-only**. Nothing is created, changed, or removed,
//! so this is safe to run on a production host at any time.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::config::{Config, TunnelConfig};

/// How a check turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing wrong.
    Pass,
    /// Works, but something is worth knowing.
    Warn,
    /// The tunnel will not work until this is fixed.
    Fail,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "\x1b[32m ok \x1b[0m"),
            Self::Warn => write!(f, "\x1b[33mwarn\x1b[0m"),
            Self::Fail => write!(f, "\x1b[31mFAIL\x1b[0m"),
        }
    }
}

/// One check's outcome.
#[derive(Debug, Clone)]
pub(crate) struct Finding {
    /// What was checked.
    pub(crate) what: String,
    /// How it went.
    pub(crate) verdict: Verdict,
    /// What was observed.
    pub(crate) detail: String,
    /// What to do about it, when there is something to do.
    pub(crate) remedy: Option<String>,
}

impl Finding {
    fn pass(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            verdict: Verdict::Pass,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn warn(what: impl Into<String>, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            verdict: Verdict::Warn,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    fn fail(what: impl Into<String>, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            verdict: Verdict::Fail,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
}

/// Runs every check and prints a report. Returns false if anything failed.
pub(crate) fn run(path: &Path) -> bool {
    let mut findings = Vec::new();

    let cfg = match Config::load(path) {
        Ok(cfg) => {
            findings.push(Finding::pass(
                "configuration",
                format!("{} parses", path.display()),
            ));
            Some(cfg)
        }
        Err(e) => {
            findings.push(Finding::fail(
                "configuration",
                e.to_string(),
                "fix the file, or start from example/client.toml",
            ));
            None
        }
    };

    findings.push(check_capabilities());
    findings.push(check_tun_device());
    findings.push(check_default_route());
    findings.push(check_firewall_backend());
    findings.push(check_service());
    findings.push(check_networkd(cfg.as_ref()));

    // Every tunnel is checked, because a process may carry several and the one
    // that is wrong is not necessarily the first.
    for t in cfg.iter().flat_map(|c| c.tunnels.iter()) {
        findings.push(check_device_free(&t.interface.device));
        // Both are about a port, and a carrier that has none would be told
        // about one nothing uses.
        if t.interface.shape.has_ports() {
            findings.push(check_port_free(t.interface.listen_port));
            findings.push(check_standard_port(t.interface.listen_port));
        }
        findings.push(check_mtu(t.interface.mtu, t.interface.shape));
        findings.push(check_peer_route(t));
        findings.push(check_inner_addresses(t));
        if t.interface.gateway {
            findings.push(check_forwarding_allowed(&t.interface.device));
        }
    }

    print(&findings)
}

/// Prints the report, returning whether everything is usable.
fn print(findings: &[Finding]) -> bool {
    let mut worst_ok = true;
    for f in findings {
        println!("[{}] {:<22} {}", f.verdict, f.what, f.detail);
        if let Some(remedy) = &f.remedy {
            println!("       └─ {remedy}");
        }
        if f.verdict == Verdict::Fail {
            worst_ok = false;
        }
    }

    let fails = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Fail)
        .count();
    let warns = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Warn)
        .count();
    println!();
    if fails > 0 {
        println!("{fails} problem(s) will stop the tunnel working.");
    } else if warns > 0 {
        println!("Nothing blocking, {warns} thing(s) worth knowing.");
    } else {
        println!("Everything checks out.");
    }
    worst_ok
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// Whether we hold the capabilities the datapath needs.
fn check_capabilities() -> Finding {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return Finding::warn(
            "capabilities",
            "could not read /proc/self/status",
            "check manually that the process has CAP_NET_ADMIN and CAP_NET_RAW",
        );
    };
    let Some(eff) = effective_caps(&status) else {
        return Finding::warn(
            "capabilities",
            "no CapEff line in /proc/self/status",
            "check manually",
        );
    };

    let missing = missing_caps(eff);
    if missing.is_empty() {
        Finding::pass("capabilities", "CAP_NET_ADMIN and CAP_NET_RAW are held")
    } else {
        Finding::fail(
            "capabilities",
            format!("missing {}", missing.join(" and ")),
            "run as root, or grant the binary the capabilities with \
             `setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/paqetz`",
        )
    }
}

/// Whether the TUN driver is present and reachable.
fn check_tun_device() -> Finding {
    if Path::new("/dev/net/tun").exists() {
        Finding::pass("TUN driver", "/dev/net/tun is present")
    } else {
        Finding::fail(
            "TUN driver",
            "/dev/net/tun does not exist",
            "load the module with `modprobe tun`",
        )
    }
}

/// Whether there is a default route to send outer traffic over.
fn check_default_route() -> Finding {
    match std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|t| default_route_interface(&t))
    {
        Some(iface) => Finding::pass("default route", format!("via {iface}")),
        None => Finding::fail(
            "default route",
            "no default route",
            "the tunnel needs one to know which interface to capture on",
        ),
    }
}

/// Whether a firewall tool is available to install the rules.
fn check_firewall_backend() -> Finding {
    for (name, tool) in [("nftables", "nft"), ("iptables", "iptables")] {
        if which(tool).is_some() {
            return Finding::pass("firewall tool", format!("{name} ({tool}) is available"));
        }
    }
    Finding::fail(
        "firewall tool",
        "neither nft nor iptables was found",
        "install one; without the NOTRACK and RST-drop rules the kernel will \
         reset the tunnel. `paqetz firewall plan` prints what to apply by hand.",
    )
}

/// Whether anything is going to drop the traffic this gateway forwards.
///
/// The failure this catches costs an afternoon to find by hand, because every
/// visible sign says the tunnel is healthy: the handshake completes, the peer
/// answers a ping to its inner address, `ip_forward` is on, the masquerade rule
/// is there, and both ends' counters are clean. What is happening is that the
/// packets are forwarded into a `FORWARD` chain whose policy is `DROP`, so they
/// die between the tunnel and the world, and the only trace is that the far
/// side has nothing to send back.
///
/// paqetz cannot fix this itself. Every chain registered on a hook runs, so an
/// `accept` in our own table does not stop a `DROP` in another one -- the rule
/// has to go in the chain that owns the policy, which on these hosts is managed
/// by `iptables` and is not ours to edit.
fn check_forwarding_allowed(device: &str) -> Finding {
    let Some(rules) = capture("iptables", &["-S", "FORWARD"]) else {
        return Finding::pass(
            "forwarding",
            "no iptables FORWARD chain to inspect".to_owned(),
        );
    };
    match forward_verdict(&rules, device) {
        Forwarding::Allowed => Finding::pass("forwarding", "the FORWARD chain permits it"),
        Forwarding::PolicyAccept => Finding::pass("forwarding", "FORWARD policy is ACCEPT"),
        Forwarding::Blocked => Finding::fail(
            "forwarding",
            "FORWARD policy is DROP and no rule mentions {device}".replace("{device}", device),
            format!(
                "traffic will reach this host and go no further, while every other sign \
                 says the tunnel is fine. Allow just this tunnel:\n       \
                 sudo iptables -I FORWARD -i {device} -j ACCEPT\n       \
                 sudo iptables -I FORWARD -o {device} -m conntrack \
                 --ctstate RELATED,ESTABLISHED -j ACCEPT\n       \
                 then persist it, or it is gone at the next reboot."
            ),
        ),
    }
}

/// What the `FORWARD` chain will do with this device's traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forwarding {
    /// The policy is `ACCEPT`; nothing here will drop it.
    PolicyAccept,
    /// The policy drops, but a rule names this device.
    Allowed,
    /// The policy drops and nothing names this device.
    Blocked,
}

/// Reads `iptables -S FORWARD` output.
///
/// Split from the command so the parsing is testable without a firewall, and so
/// what counts as "allowed" is written down rather than implied.
pub(crate) fn forward_verdict(rules: &str, device: &str) -> Forwarding {
    let policy_drops = rules
        .lines()
        .any(|l| matches!(l.trim(), "-P FORWARD DROP" | "-P FORWARD REJECT"));
    if !policy_drops {
        return Forwarding::PolicyAccept;
    }
    // Any rule naming the device is taken as deliberate. A narrower reading --
    // insisting on a matching -j ACCEPT -- would misjudge the many shapes an
    // operator's rules can take, and a false alarm on a working host is worse
    // than staying quiet about one that an operator has clearly considered.
    let mentions_device = rules
        .lines()
        .filter(|l| !l.trim_start().starts_with("-P "))
        .any(|l| {
            l.split_whitespace()
                .zip(l.split_whitespace().skip(1))
                .any(|(flag, value)| matches!(flag, "-i" | "-o") && value == device)
        });
    if mentions_device {
        Forwarding::Allowed
    } else {
        Forwarding::Blocked
    }
}

/// Whether the tunnel is installed as a service.
///
/// Not a problem either way — plenty of hosts run it by hand — but "it stopped
/// after I closed the terminal" and "it did not come back after a reboot" are
/// common enough that the answer is worth stating.
fn check_service() -> Finding {
    if !crate::service::has_systemd() {
        return Finding::pass("service", "no systemd on this host");
    }
    if crate::service::unit_enabled("paqetz") {
        Finding::pass("service", "installed and enabled; it will start at boot")
    } else {
        Finding::warn(
            "service",
            "not installed as a service",
            "fine if you run it by hand; `paqetz service install` if it should \
             start at boot and restart on failure",
        )
    }
}

/// Whether networkd will delete routing this host depends on.
///
/// Asked whenever this host installs a rule or a route of its own, which is not
/// only the client. A server sending forwarded traffic out an egress interface
/// installs `ip rule from <subnet> lookup <table>`, and `route_all` installs
/// routes rather than rules — networkd manages foreign routes by default too.
/// Only a plain point-to-point tunnel, with no proxy in front and no way out
/// behind, has nothing of ours for it to remove.
fn check_networkd(cfg: Option<&Config>) -> Finding {
    // Any tunnel needing routing of its own is enough: networkd removes rules
    // by mark, and does not care which tunnel put them there.
    let needs_rule = cfg.is_some_and(|c| {
        c.tunnels.iter().any(|t| {
            t.interface.route_marked.is_some()
                || t.socks5.is_some()
                || t.interface.route_all
                || t.interface.egress.is_some()
        })
    });
    if !needs_rule {
        return Finding::pass("networkd", "this host installs no rule or route of its own");
    }
    match crate::networkd::status() {
        crate::networkd::Status::Absent => {
            Finding::pass("networkd", "not running; nothing removes the routing")
        }
        crate::networkd::Status::LeavesRulesAlone => {
            Finding::pass("networkd", "configured to leave our routing alone")
        }
        // Deliberately a failure rather than a warning. It does not break the
        // tunnel visibly -- it sends the traffic out unprotected while
        // everything still appears to work, which is worse than an outage on a
        // host whose whole reason for existing is that its traffic is not
        // visible where it sits.
        crate::networkd::Status::WillDeleteRules => Finding::fail(
            "networkd",
            "will delete the routing this host installs when an interface changes \
             or it restarts",
            "losing it does not stop traffic, it sends it out unprotected: run \
             `paqetz networkd protect --restart`",
        ),
    }
}

/// Whether the configured device name is already taken.
fn check_device_free(name: &str) -> Finding {
    if Path::new(&format!("/sys/class/net/{name}")).exists() {
        Finding::warn(
            "device name",
            format!("{name} already exists"),
            "it will be reused; rename it in the configuration if that is not intended",
        )
    } else {
        Finding::pass("device name", format!("{name} is free"))
    }
}

/// Whether the kernel is already listening on our outer port.
///
/// This is the subtlest of the failures worth catching. A kernel socket on the
/// same port does not stop the tunnel receiving — the capture socket sees the
/// frames regardless — but it does mean the kernel answers them too, and the
/// firewall rules cannot silence it without breaking the other service.
fn check_port_free(port: u16) -> Finding {
    if port == 0 {
        return Finding::pass("outer port", "ephemeral, chosen at start-up");
    }
    let mut found = false;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table)
            && port_in_use(&text, port)
        {
            found = true;
        }
    }
    if found {
        Finding::fail(
            "outer port",
            format!("something is already bound to TCP port {port}"),
            "choose a port nothing else uses; the kernel would otherwise answer \
             traffic meant for the tunnel",
        )
    } else {
        Finding::pass("outer port", format!("TCP port {port} is free"))
    }
}

/// Whether the outer port is one the firewall rules would disturb.
fn check_standard_port(port: u16) -> Finding {
    // The rules are scoped by port and apply in both directions, so on a
    // standard port they would also catch the host's own traffic.
    const STANDARD: &[u16] = &[
        22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432,
    ];
    if port != 0 && STANDARD.contains(&port) {
        Finding::warn(
            "port choice",
            format!("{port} is a standard service port"),
            "the NOTRACK and RST-drop rules are scoped to this port in both \
             directions, so they would also affect the host's own traffic on it",
        )
    } else {
        Finding::pass("port choice", "not a standard service port")
    }
}

/// Whether the inner MTU leaves room for the tunnel's overhead.
///
/// The overhead is the carrier's, not a number written down here. Fixed at the
/// fake-TCP figure, this called a correctly-sized GRE tunnel too large by the
/// difference between the two headers and told the operator to shrink an MTU
/// that already fit -- a check reporting a fault it had invented.
fn check_mtu(inner: u32, shape: crate::config::Shape) -> Finding {
    // One source, shared with the default this compares against, so the two
    // cannot drift into disagreeing about the same packet.
    let overhead =
        u32::try_from(shape.overhead() + paqetz_core::framing::OVERHEAD).unwrap_or(u32::MAX);
    let path = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|t| default_route_interface(&t))
        .and_then(|iface| std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu")).ok())
        .and_then(|s| s.trim().parse::<u32>().ok());

    match path {
        Some(path_mtu) if inner + overhead > path_mtu => Finding::fail(
            "MTU",
            format!(
                "inner {inner} + {overhead} overhead = {} exceeds the path's {path_mtu}",
                inner + overhead
            ),
            format!(
                "set interface.mtu to {} or less",
                path_mtu.saturating_sub(overhead)
            ),
        ),
        Some(path_mtu) => Finding::pass(
            "MTU",
            format!("inner {inner} + {overhead} overhead fits the path's {path_mtu}"),
        ),
        None => Finding::warn(
            "MTU",
            format!("inner {inner}; could not read the path MTU"),
            // Was a literal: the braces were never interpolated, so this
            // printed the placeholder and a number belonging to another
            // carrier.
            format!(
                "check that the outbound interface's MTU is at least {}",
                inner + overhead
            ),
        ),
    }
}

/// Whether there is a route to the peer.
fn check_peer_route(cfg: &TunnelConfig) -> Finding {
    let Some(endpoint) = cfg.peer.endpoint else {
        return Finding::pass(
            "peer endpoint",
            "none configured; this end waits to be contacted",
        );
    };
    // Connecting a UDP socket performs a route lookup and sends nothing, so
    // this tests reachability of the route without touching the network.
    match std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|s| s.connect(endpoint).map(|()| s))
        .and_then(|s| s.local_addr())
    {
        Ok(local) => Finding::pass(
            "peer endpoint",
            format!("{endpoint} is routable, from {}", local.ip()),
        ),
        Err(e) => Finding::fail(
            "peer endpoint",
            format!("no route to {endpoint}: {e}"),
            "check the address and the host's routing",
        ),
    }
}

/// Whether the inner addresses make sense together.
fn check_inner_addresses(cfg: &TunnelConfig) -> Finding {
    let ours = cfg.interface.address;
    let theirs = cfg.peer.tunnel_address;

    if ours == theirs {
        return Finding::fail(
            "inner addresses",
            format!("both ends are configured as {ours}"),
            "give each end a distinct address inside the tunnel",
        );
    }
    if !cfg.peer.permits(theirs) {
        return Finding::fail(
            "inner addresses",
            format!("{theirs} is not inside the peer's allowed range"),
            "widen peer.allowed_ips, or correct peer.tunnel_address",
        );
    }
    let mask = u32::from_be_bytes(cfg.interface.netmask.octets());
    let same_subnet =
        (u32::from_be_bytes(ours.octets()) & mask) == (u32::from_be_bytes(theirs.octets()) & mask);
    if same_subnet {
        Finding::pass("inner addresses", format!("{ours} ↔ {theirs}"))
    } else {
        Finding::warn(
            "inner addresses",
            format!("{ours} and {theirs} are in different subnets"),
            "traffic will need an explicit route; usually both should share one subnet",
        )
    }
}

// ---------------------------------------------------------------------------
// Pure helpers, so the parsing is testable without a host to inspect
// ---------------------------------------------------------------------------

/// Extracts the effective capability mask from `/proc/self/status`.
fn effective_caps(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

/// Names the capabilities the datapath needs that are absent from `eff`.
fn missing_caps(eff: u64) -> Vec<&'static str> {
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;
    let mut missing = Vec::new();
    if eff & (1u64 << CAP_NET_ADMIN) == 0 {
        missing.push("CAP_NET_ADMIN");
    }
    if eff & (1u64 << CAP_NET_RAW) == 0 {
        missing.push("CAP_NET_RAW");
    }
    missing
}

/// Names the interface carrying the default route, given `/proc/net/route`.
fn default_route_interface(table: &str) -> Option<String> {
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(dest), Some(_gw), Some(flags)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).unwrap_or(0) & 0x0001 != 0;
        if dest == "00000000" && up {
            return Some(iface.to_owned());
        }
    }
    None
}

/// Whether `/proc/net/tcp`-style content shows a socket on `port`.
fn port_in_use(table: &str, port: u16) -> bool {
    table.lines().skip(1).any(|line| {
        line.split_whitespace()
            .nth(1)
            .and_then(|local| local.rsplit(':').next())
            .and_then(|p| u16::from_str_radix(p, 16).ok())
            .is_some_and(|p| p == port)
    })
}

/// Runs a read-only command and returns its output, or `None` if it cannot run.
///
/// A missing tool is not a failure to report: a host with no `iptables` has no
/// `iptables` policy to fall foul of.
fn capture(tool: &str, args: &[&str]) -> Option<String> {
    which(tool)?;
    let out = std::process::Command::new(tool).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Finds an executable on `PATH`.
fn which(tool: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn a_dropping_forward_chain_with_no_rule_for_us_is_a_failure() {
        // The case that cost an afternoon: everything else says the tunnel is
        // healthy, and the packets die on the way out of the host.
        let rules = "\
-P FORWARD DROP
-A FORWARD -j DOCKER-USER
-A FORWARD -o docker0 -j ACCEPT
";
        assert_eq!(
            super::forward_verdict(rules, "paqetz0"),
            super::Forwarding::Blocked
        );
    }

    #[test]
    fn a_rule_naming_the_device_is_taken_as_deliberate() {
        let rules = "\
-P FORWARD DROP
-A FORWARD -i paqetz0 -j ACCEPT
-A FORWARD -o paqetz0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
";
        assert_eq!(
            super::forward_verdict(rules, "paqetz0"),
            super::Forwarding::Allowed
        );
        // And a rule for a *different* device does not count as one for ours.
        assert_eq!(
            super::forward_verdict(rules, "paqetz1"),
            super::Forwarding::Blocked
        );
    }

    #[test]
    fn an_accepting_policy_needs_no_rule_at_all() {
        assert_eq!(
            super::forward_verdict("-P FORWARD ACCEPT\n", "paqetz0"),
            super::Forwarding::PolicyAccept
        );
        // The policy line is the only one that decides this; a device named in
        // a rule must not be mistaken for the policy itself.
        assert_eq!(
            super::forward_verdict("-A FORWARD -i paqetz0 -j DROP\n", "paqetz0"),
            super::Forwarding::PolicyAccept
        );
    }

    #[test]
    fn a_rejecting_policy_counts_as_dropping() {
        assert_eq!(
            super::forward_verdict("-P FORWARD REJECT\n", "paqetz0"),
            super::Forwarding::Blocked
        );
    }

    #[test]
    fn effective_capabilities_are_parsed() {
        let status = "Name:\tpaqetz\nCapEff:\t0000000000003000\nThreads:\t4\n";
        assert_eq!(effective_caps(status), Some(0x3000));
    }

    #[test]
    fn a_status_without_capeff_yields_nothing() {
        assert_eq!(effective_caps("Name:\tpaqetz\n"), None);
    }

    #[test]
    fn the_two_needed_capabilities_are_recognised() {
        // Bits 12 and 13 are CAP_NET_ADMIN and CAP_NET_RAW.
        assert!(missing_caps(0x3000).is_empty());
        assert_eq!(missing_caps(0x2000), vec!["CAP_NET_ADMIN"]);
        assert_eq!(missing_caps(0x1000), vec!["CAP_NET_RAW"]);
        assert_eq!(missing_caps(0), vec!["CAP_NET_ADMIN", "CAP_NET_RAW"]);
        // Root holds everything.
        assert!(missing_caps(u64::MAX).is_empty());
    }

    #[test]
    fn the_default_route_is_found_among_others() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask
enp3s0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF
enp3s0\t00000000\t01A8C0\t0003\t0\t0\t100\t00000000
";
        assert_eq!(default_route_interface(table), Some("enp3s0".to_owned()));
    }

    #[test]
    fn a_down_default_route_is_not_used() {
        // Flags without the "up" bit mean the route is not usable.
        let table = "Iface\tDestination\tGateway\tFlags\nenp3s0\t00000000\t01A8C0\t0002\n";
        assert_eq!(default_route_interface(table), None);
    }

    #[test]
    fn a_table_with_no_default_route_yields_nothing() {
        let table = "Iface\tDestination\tGateway\tFlags\nenp3s0\t0000A8C0\t00000000\t0001\n";
        assert_eq!(default_route_interface(table), None);
    }

    #[test]
    fn malformed_route_tables_do_not_panic() {
        for table in ["", "header only\n", "a\n", "a\tb\n", "a\tb\tc\n", "\n\n\n"] {
            let _ = default_route_interface(table);
        }
    }

    #[test]
    fn a_bound_port_is_detected() {
        // /proc/net/tcp writes the local address as HEX_ADDR:HEX_PORT.
        // 270F is 9999.
        let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
";
        assert!(port_in_use(table, 9999));
        assert!(!port_in_use(table, 9998));
    }

    #[test]
    fn an_ipv6_style_local_address_is_handled() {
        // The address half is longer but the port still follows the last colon.
        let table = "  sl  local_address\n   0: 00000000000000000000000000000000:01BB\n";
        assert!(port_in_use(table, 443));
    }

    #[test]
    fn malformed_socket_tables_do_not_panic() {
        for table in ["", "header\n", "  0:\n", "  0: nonsense\n", "  0: ab:zz\n"] {
            let _ = port_in_use(table, 9999);
        }
    }

    #[test]
    fn standard_ports_are_flagged_and_others_are_not() {
        assert_eq!(check_standard_port(443).verdict, Verdict::Warn);
        assert_eq!(check_standard_port(22).verdict, Verdict::Warn);
        assert_eq!(check_standard_port(9999).verdict, Verdict::Pass);
        assert_eq!(check_standard_port(0).verdict, Verdict::Pass);
    }

    #[test]
    fn a_common_tool_is_found_on_the_path() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-tool-xyz").is_none());
    }

    #[test]
    fn every_carriers_own_default_mtu_passes_its_own_check() {
        // The failure this exists for: the check held the fake-TCP overhead as
        // a constant, so a GRE tunnel at the size paqetz itself had chosen was
        // reported as 28 bytes too large for a 1500-byte path, with advice to
        // shrink an MTU that already fit. A check and a default that disagree
        // about the same packet is worse than no check.
        use crate::config::Shape;
        use paqetz_tcpwire::rawip::Shell;

        for shape in [
            Shape::Tcp(paqetz_tcpwire::Carrier::Midstream),
            Shape::Raw(Shell::Gre),
            Shape::Raw(Shell::Bare(143)),
        ] {
            let total =
                shape.default_mtu() as usize + shape.overhead() + paqetz_core::framing::OVERHEAD;
            assert!(
                total <= 1500,
                "{shape:?}: its own default is {total} bytes on a 1500-byte path"
            );
        }

        // And the capped default, for the shape that clears Don't Fragment.
        for shape in [
            Shape::Tcp(paqetz_tcpwire::Carrier::Midstream),
            Shape::Raw(Shell::Gre),
            Shape::Raw(Shell::Bare(143)),
        ] {
            let total = shape.fragment_free_mtu() as usize
                + shape.overhead()
                + paqetz_core::framing::OVERHEAD;
            assert!(total <= 1280, "{shape:?}: capped default is {total} bytes");
        }
    }

    #[test]
    fn every_failure_carries_a_remedy() {
        // A diagnostic that says something is wrong without saying what to do
        // is barely better than the symptom it replaces.
        let findings = vec![
            check_standard_port(443),
            check_port_free(0),
            check_tun_device(),
            check_firewall_backend(),
            check_capabilities(),
            check_mtu(
                1400,
                crate::config::Shape::Tcp(paqetz_tcpwire::Carrier::Midstream),
            ),
        ];
        for f in findings {
            if f.verdict != Verdict::Pass {
                assert!(f.remedy.is_some(), "{} has no remedy", f.what);
            }
        }
    }
}
