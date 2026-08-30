//! Rule generation, kept free of process execution so it can be tested.
//!
//! Nothing here runs a command or touches the system. [`crate::Firewall`] does
//! that; this module only decides what *would* be run, which is also what the
//! `firewall plan` subcommand prints.

/// The name of the `nftables` table this program owns.
///
/// Owning a whole table is what makes the `nftables` path cleanly idempotent:
/// applying is "replace the table", reverting is "delete the table", and
/// neither has to reason about which individual rules are already present.
pub const TABLE: &str = "paqetz";

/// A comment attached to each `iptables` rule.
///
/// `iptables` has no equivalent of owning a table, so rules are tagged instead.
/// Without this, a rule left behind by a crashed run is indistinguishable from
/// one an operator added deliberately.
pub const COMMENT: &str = "paqetz-tunnel";

/// The `nftables` ruleset that installs everything, as a single script.
///
/// The `add`-then-`delete`-then-define sequence is the idiomatic way to make an
/// `nftables` script idempotent: `add table` succeeds whether or not the table
/// exists, which guarantees the following `delete table` has something to
/// remove, and the definition then starts from a known-empty state. Running it
/// twice leaves exactly the same ruleset as running it once.
///
/// `nft -f` applies the whole script in one transaction, so a syntax error part
/// way through leaves the system untouched rather than half-configured.
/// Every tunnel in this process shares the table, because they share a
/// lifetime: one process starts them all and removes the rules for all of them
/// on the way out. A table per tunnel would mean inventing unique names for
/// something created and destroyed as a unit, and this whole-table replace
/// would become a per-tunnel replace that has to avoid disturbing its
/// neighbours. One table, one transaction, every port.
#[must_use]
pub fn nft_apply(guard: &Guard) -> String {
    let (pre, out, rst) = match guard {
        Guard::Ports(ports) => {
            let lines =
                |f: &dyn Fn(u16) -> String| -> String { ports.iter().map(|p| f(*p)).collect() };
            (
                lines(&|p| format!("        tcp dport {p} notrack\n")),
                lines(&|p| format!("        tcp sport {p} notrack\n")),
                lines(&|p| format!("        tcp sport {p} tcp flags & rst == rst drop\n")),
            )
        }
        Guard::Protocol(proto) => (
            format!("        ip protocol {proto} notrack\n"),
            format!("        ip protocol {proto} notrack\n"),
            // The kernel's answer to a protocol nothing is listening for, and
            // this carrier's equivalent of the reset: an ICMP destination
            // unreachable with code 2. Left to escape it announces to anyone
            // watching that the host received something it could not handle,
            // which is precisely what the flow is trying not to look like.
            //
            // Broader than the reset rule, which names its ports: there is no
            // port here to name, so this suppresses the message for every
            // unhandled protocol rather than only ours. A host that legitimately
            // wants to refuse some other protocol out loud will stop doing so.
            "        icmp type destination-unreachable icmp code prot-unreachable drop\n"
                .to_owned(),
        ),
    };
    format!(
        "add table ip {TABLE}
delete table ip {TABLE}
table ip {TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority raw; policy accept;
{pre}    }}
    chain output_notrack {{
        type filter hook output priority raw; policy accept;
{out}    }}
    chain output_quiet {{
        type filter hook output priority mangle; policy accept;
{rst}    }}
}}
"
    )
}

/// The `nftables` script that removes everything.
///
/// Same `add`-before-`delete` trick, so reverting when nothing is installed
/// succeeds rather than failing — which matters because revert runs on the
/// shutdown path, where an error is noise at best.
#[must_use]
pub fn nft_revert() -> String {
    format!(
        "add table ip {TABLE}
delete table ip {TABLE}
"
    )
}

/// One `iptables` rule, as the arguments following the command name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesRule {
    /// Arguments identifying the table and chain, and matching the traffic.
    ///
    /// The operation (`-A`, `-D`, `-C`) is substituted separately, so the same
    /// specification serves to add, delete, and check.
    pub spec: Vec<String>,
}

impl IptablesRule {
    /// The full argument list for an operation on this rule.
    #[must_use]
    pub fn args(&self, op: Op) -> Vec<String> {
        let mut out = Vec::with_capacity(self.spec.len() + 3);
        let mut parts = self.spec.iter();
        // The table selector must precede the operation.
        if let (Some(dash_t), Some(table)) = (parts.next(), parts.next()) {
            out.push(dash_t.clone());
            out.push(table.clone());
        }
        out.push(op.flag().to_owned());
        out.extend(parts.cloned());
        out
    }
}

/// What to do with a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Append it.
    Append,
    /// Delete it.
    Delete,
    /// Test whether it is present, without changing anything.
    Check,
}

impl Op {
    /// The `iptables` flag for this operation.
    #[must_use]
    pub const fn flag(self) -> &'static str {
        match self {
            Self::Append => "-A",
            Self::Delete => "-D",
            Self::Check => "-C",
        }
    }
}

/// Every `iptables` rule the tunnel needs, in the order they should be added.
///
/// These are the three rules paqet's README instructs the operator to enter by
/// hand, with two changes. They carry a comment so they can be identified
/// later, and the chain name follows the operation rather than preceding it so
/// that one specification can be added, deleted, or checked.
///
/// # Why each is needed
///
/// The first two exempt the port from connection tracking. Without them the
/// kernel builds state for a flow it does not own, and `conntrack` then treats
/// our segments as invalid.
///
/// The third stops the kernel emitting a `RST`. It has no socket listening on
/// the port, so its correct response to an inbound segment is to reset it —
/// which tears down the flow and, worse, corrupts the NAT state that
/// middleboxes along the path are holding.
#[must_use]
pub fn iptables_rules(guard: &Guard) -> Vec<IptablesRule> {
    match guard {
        Guard::Ports(ports) => ports.iter().flat_map(|p| rules_for(*p)).collect(),
        Guard::Protocol(proto) => rules_for_protocol(*proto),
    }
}

/// What the rules are protecting: a set of ports, or a protocol number.
///
/// Owned rather than borrowed because a [`crate::Firewall`] outlives the call
/// that made it and has to be able to revert what it installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guard {
    /// The fake-TCP carrier's outer ports.
    Ports(Vec<u16>),
    /// An IP protocol number, for a carrier with no ports.
    Protocol(u8),
}

/// The three rules covering one protocol.
///
/// The same shape as the per-port rules: exempt both directions from
/// connection tracking, then stop the kernel announcing that it received
/// something it has no handler for. For TCP that announcement is a reset; for
/// an unclaimed protocol it is an ICMP destination-unreachable with code 2.
fn rules_for_protocol(proto: u8) -> Vec<IptablesRule> {
    let proto = proto.to_string();
    let build = |parts: &[&str]| -> IptablesRule {
        let mut spec: Vec<String> = parts.iter().map(|s| (*s).to_owned()).collect();
        spec.extend(
            ["-m", "comment", "--comment", COMMENT]
                .iter()
                .map(|s| (*s).to_owned()),
        );
        IptablesRule { spec }
    };
    vec![
        build(&["-t", "raw", "PREROUTING", "-p", &proto, "-j", "NOTRACK"]),
        build(&["-t", "raw", "OUTPUT", "-p", &proto, "-j", "NOTRACK"]),
        build(&[
            "-t",
            "mangle",
            "OUTPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "protocol-unreachable",
            "-j",
            "DROP",
        ]),
    ]
}

/// The three rules covering one port.
fn rules_for(port: u16) -> Vec<IptablesRule> {
    let port = port.to_string();
    let comment = |v: &mut Vec<String>| {
        v.extend(
            ["-m", "comment", "--comment", COMMENT]
                .iter()
                .map(|s| (*s).to_owned()),
        );
    };

    let mut rules = Vec::with_capacity(3);

    // Inbound: do not track our port.
    let mut spec: Vec<String> = ["-t", "raw", "PREROUTING", "-p", "tcp", "--dport"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    spec.push(port.clone());
    spec.extend(["-j", "NOTRACK"].iter().map(|s| (*s).to_owned()));
    comment(&mut spec);
    rules.push(IptablesRule { spec });

    // Outbound: likewise.
    let mut spec: Vec<String> = ["-t", "raw", "OUTPUT", "-p", "tcp", "--sport"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    spec.push(port.clone());
    spec.extend(["-j", "NOTRACK"].iter().map(|s| (*s).to_owned()));
    comment(&mut spec);
    rules.push(IptablesRule { spec });

    // Outbound: swallow the kernel's resets.
    let mut spec: Vec<String> = ["-t", "mangle", "OUTPUT", "-p", "tcp", "--sport"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    spec.push(port);
    spec.extend(
        ["--tcp-flags", "RST", "RST", "-j", "DROP"]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    comment(&mut spec);
    rules.push(IptablesRule { spec });

    rules
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn a_sending_end_tags_and_a_forwarding_end_reads() {
        // A firewall mark cannot cross a tunnel, so the intent travels in the
        // inner header's DSCP -- a byte already present, already zero, and
        // inside the AEAD, so the outer packet is unchanged in size and shape.
        let lanes = vec![Lane {
            class: 10,
            mark: Some(79),
            egress: None,
            route_mark: 0x10a,
        }];
        let script = lane_script("paqetz0", &lanes);
        assert!(
            script.contains("oifname \"paqetz0\" meta mark 0x4f counter ip dscp set 10"),
            "{script}"
        );
        // The sending end names no way out, so it installs none.
        assert!(!script.contains("masquerade"), "{script}");

        let lanes = vec![Lane {
            class: 10,
            mark: None,
            egress: Some("warp".to_owned()),
            route_mark: 0x10a,
        }];
        let script = lane_script("paqetz0", &lanes);
        assert!(
            script.contains("iifname \"paqetz0\" ip dscp 10 counter meta mark set 0x10a"),
            "{script}"
        );
        assert!(
            script.contains("oifname \"warp\" counter masquerade"),
            "{script}"
        );
        // Cleared on the way out: it was written to be read on this host, and
        // carrying it onward tells the destination something for no gain.
        assert!(
            script.contains("oifname \"warp\" counter ip dscp set 0"),
            "{script}"
        );
        assert!(
            !script.contains("meta mark 0x"),
            "nothing to tag here: {script}"
        );
    }

    #[test]
    fn several_classes_leaving_one_way_translate_once() {
        // A masquerade rule per lane would translate the same packet once for
        // every class that happens to name the same interface.
        let lanes = vec![
            Lane {
                class: 10,
                mark: None,
                egress: Some("warp".to_owned()),
                route_mark: 0x10a,
            },
            Lane {
                class: 11,
                mark: None,
                egress: Some("warp".to_owned()),
                route_mark: 0x10b,
            },
            Lane {
                class: 12,
                mark: None,
                egress: Some("wg0".to_owned()),
                route_mark: 0x10c,
            },
        ];
        let script = lane_script("paqetz0", &lanes);
        assert_eq!(
            script
                .matches("oifname \"warp\" counter masquerade")
                .count(),
            1,
            "{script}"
        );
        assert_eq!(
            script.matches("oifname \"wg0\" counter masquerade").count(),
            1,
            "{script}"
        );
        // But every class still gets its own mark, or two lanes leaving by one
        // interface would be indistinguishable to the routing.
        for (dscp, mark) in [(10, "0x10a"), (11, "0x10b"), (12, "0x10c")] {
            assert!(
                script.contains(&format!("ip dscp {dscp} counter meta mark set {mark}")),
                "{script}"
            );
        }
    }

    #[test]
    fn no_lanes_is_an_empty_table_rather_than_absent_rules() {
        // The table is still replaced, so a file that had lanes and no longer
        // does leaves nothing of them behind.
        let script = lane_script("paqetz0", &[]);
        assert!(script.starts_with(&format!(
            "add table inet {LANE_TABLE}\ndelete table inet {LANE_TABLE}\n"
        )));
        assert!(!script.contains("dscp"), "{script}");
        assert!(!script.contains("masquerade"), "{script}");
    }

    #[test]
    fn a_protocol_guard_covers_both_directions_and_the_kernels_answer() {
        // The same three jobs as the per-port rules: exempt each direction
        // from connection tracking, then stop the kernel announcing that it
        // received something it has no handler for. For TCP that announcement
        // is a reset; for an unclaimed protocol it is ICMP code 2.
        let script = nft_apply(&Guard::Protocol(47));
        assert!(script.contains("ip protocol 47 notrack"), "{script}");
        assert_eq!(
            script.matches("ip protocol 47 notrack").count(),
            2,
            "inbound and outbound both, or conntrack builds state one way"
        );
        assert!(
            script.contains("icmp code prot-unreachable drop"),
            "the kernel's answer to an unclaimed protocol must not escape: {script}"
        );
        // Nothing about ports leaks into a shape that has none.
        assert!(!script.contains("tcp dport"), "{script}");
        assert!(!script.contains("tcp sport"), "{script}");
        assert!(!script.contains("flags & rst"), "{script}");
    }

    #[test]
    fn a_protocol_guard_produces_the_same_three_iptables_rules() {
        let rules = iptables_rules(&Guard::Protocol(47));
        assert_eq!(rules.len(), 3);
        let all: Vec<String> = rules.iter().map(|r| r.spec.join(" ")).collect();
        assert!(
            all.iter()
                .any(|r| r.contains("raw PREROUTING -p 47 -j NOTRACK")),
            "{all:?}"
        );
        assert!(
            all.iter()
                .any(|r| r.contains("raw OUTPUT -p 47 -j NOTRACK")),
            "{all:?}"
        );
        assert!(
            all.iter()
                .any(|r| r.contains("--icmp-type protocol-unreachable -j DROP")),
            "{all:?}"
        );
        // Every rule carries the comment, or revert cannot find its own work.
        for rule in &all {
            assert!(rule.contains(COMMENT), "{rule}");
        }
        // `iptables -A CHAIN -t table` is rejected; the table must come first.
        for rule in &rules {
            assert_eq!(rule.spec.first().map(String::as_str), Some("-t"));
        }
    }

    #[test]
    fn several_tunnels_share_one_table() {
        // They share a lifetime -- one process starts them and removes the rules
        // for all of them on the way out -- so a table each would mean inventing
        // unique names for something created and destroyed as a unit.
        let script = nft_apply(&Guard::Ports(vec![1111, 2222, 3333]));
        assert_eq!(
            script.matches("table ip paqetz").count(),
            3,
            "add, delete, define"
        );
        for port in [1111, 2222, 3333] {
            assert!(
                script.contains(&format!("tcp dport {port} notrack")),
                "{script}"
            );
            assert!(
                script.contains(&format!("tcp sport {port} notrack")),
                "{script}"
            );
            assert!(
                script.contains(&format!("tcp sport {port} tcp flags & rst == rst drop")),
                "{script}"
            );
        }
    }

    #[test]
    fn every_port_gets_every_iptables_rule() {
        let rules = iptables_rules(&Guard::Ports(vec![1111, 2222]));
        assert_eq!(rules.len(), 6, "three rules for each of two ports");
        for port in ["1111", "2222"] {
            assert!(rules.iter().any(|r| r.spec.contains(&port.to_string())));
        }
    }

    fn joined(rule: &IptablesRule, op: Op) -> String {
        rule.args(op).join(" ")
    }

    #[test]
    fn the_nft_script_is_idempotent_by_construction() {
        let script = nft_apply(&Guard::Ports(vec![9999]));
        let add = script.find("add table").expect("adds the table");
        let delete = script.find("delete table").expect("deletes the table");
        assert!(
            add < delete,
            "the table must be added before it is deleted, or deleting an \
             absent table fails and the script aborts"
        );
    }

    #[test]
    fn the_nft_script_covers_all_three_rules() {
        let script = nft_apply(&Guard::Ports(vec![9999]));
        assert!(script.contains("tcp dport 9999 notrack"));
        assert!(script.contains("tcp sport 9999 notrack"));
        assert!(script.contains("tcp sport 9999 tcp flags & rst == rst drop"));
    }

    #[test]
    fn the_nft_script_hooks_the_right_priorities() {
        let script = nft_apply(&Guard::Ports(vec![9999]));
        // Connection tracking is exempted at raw priority, which runs before
        // conntrack; the reset is dropped at mangle, which runs after routing.
        assert!(script.contains("hook prerouting priority raw"));
        assert!(script.contains("hook output priority raw"));
        assert!(script.contains("hook output priority mangle"));
    }

    #[test]
    fn the_nft_chains_default_to_accept() {
        // A base chain with a drop policy would black-hole unrelated traffic
        // the moment it is installed.
        let script = nft_apply(&Guard::Ports(vec![9999]));
        assert_eq!(script.matches("policy accept").count(), 3);
    }

    #[test]
    fn reverting_an_absent_table_still_succeeds() {
        let script = nft_revert();
        assert!(script.contains("add table"), "must not fail when absent");
        assert!(script.contains("delete table"));
    }

    #[test]
    fn the_port_appears_everywhere_it_should() {
        for port in [1u16, 443, 9999, 65535] {
            let script = nft_apply(&Guard::Ports(vec![port]));
            assert_eq!(
                script.matches(&port.to_string()).count(),
                3,
                "port {port} should appear in all three rules"
            );
            for rule in iptables_rules(&Guard::Ports(vec![port])) {
                assert!(
                    rule.spec.contains(&port.to_string()),
                    "port {port} missing from {rule:?}"
                );
            }
        }
    }

    #[test]
    fn iptables_rules_match_what_paqet_documents() {
        let rules = iptables_rules(&Guard::Ports(vec![9999]));
        assert_eq!(rules.len(), 3);
        assert_eq!(
            joined(&rules[0], Op::Append),
            "-t raw -A PREROUTING -p tcp --dport 9999 -j NOTRACK \
             -m comment --comment paqetz-tunnel"
        );
        assert_eq!(
            joined(&rules[1], Op::Append),
            "-t raw -A OUTPUT -p tcp --sport 9999 -j NOTRACK \
             -m comment --comment paqetz-tunnel"
        );
        assert_eq!(
            joined(&rules[2], Op::Append),
            "-t mangle -A OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP \
             -m comment --comment paqetz-tunnel"
        );
    }

    #[test]
    fn the_table_selector_precedes_the_operation() {
        // `iptables -A CHAIN -t table` is rejected; the table must come first.
        for rule in iptables_rules(&Guard::Ports(vec![9999])) {
            for op in [Op::Append, Op::Delete, Op::Check] {
                let args = rule.args(op);
                assert_eq!(args.first().map(String::as_str), Some("-t"));
                assert_eq!(args.get(2).map(String::as_str), Some(op.flag()));
            }
        }
    }

    #[test]
    fn one_specification_serves_add_delete_and_check() {
        // Delete and check must match the rule exactly as added, or a revert
        // silently leaves rules behind.
        for rule in iptables_rules(&Guard::Ports(vec![9999])) {
            let add = rule.args(Op::Append);
            for op in [Op::Delete, Op::Check] {
                let other = rule.args(op);
                assert_eq!(add.len(), other.len());
                for (i, (a, b)) in add.iter().zip(other.iter()).enumerate() {
                    if i == 2 {
                        continue; // the operation flag itself
                    }
                    assert_eq!(a, b, "argument {i} differs between add and {op:?}");
                }
            }
        }
    }

    #[test]
    fn every_rule_is_tagged_so_it_can_be_identified_later() {
        for rule in iptables_rules(&Guard::Ports(vec![9999])) {
            assert!(
                rule.spec.iter().any(|a| a == COMMENT),
                "untagged rule: {rule:?}"
            );
        }
    }
}

/// One numbered path through the tunnel, as the firewall sees it.
///
/// The two ends install different halves. The sending end tags what carries
/// `mark` with `class`, in the inner packet's DSCP; the forwarding end matches
/// that class and steers it to `egress`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    /// The class carried in the inner header's DSCP.
    pub class: u8,
    /// Whose traffic travels in it, on the sending end.
    pub mark: Option<u32>,
    /// Where it leaves by, on the forwarding end.
    pub egress: Option<String>,
    /// The internal mark the forwarding end routes it under.
    pub route_mark: u32,
}

/// The nftables table lanes own.
pub const LANE_TABLE: &str = "paqetz_lane";

/// The script that installs whatever halves these lanes describe.
///
/// One table, one transaction, `add` then `delete` then define, as everything
/// here is written: the same result whether or not anything was there before,
/// and no lane can be half-installed.
///
/// Both directions carry counters. Without them "is this lane working" has no
/// answer, and on a feature whose entire job is to send *some* traffic
/// elsewhere that is the only question anyone will ask.
///
/// The forwarding end clears the class on the way out. It was written into the
/// packet to be read on this host; leaving it set would carry a marking to the
/// destination and every network between, which says something about the
/// traffic to anyone who looks and does nothing for anybody.
#[must_use]
pub fn lane_script(device: &str, lanes: &[Lane]) -> String {
    let mut tag = String::new();
    let mut pick = String::new();
    let mut out = String::new();
    let mut seen: Vec<&str> = Vec::new();
    for lane in lanes {
        let dscp = lane.class;
        if let Some(mark) = lane.mark {
            tag.push_str(&format!(
                "        oifname \"{device}\" meta mark {mark:#x} counter ip dscp set {dscp}\n"
            ));
        }
        if let Some(egress) = lane.egress.as_deref() {
            pick.push_str(&format!(
                "        iifname \"{device}\" ip dscp {dscp} counter meta mark set {:#x}\n",
                lane.route_mark
            ));
            // One rule per interface however many classes leave by it, or a
            // packet is translated once per lane that names the same way out.
            if !seen.contains(&egress) {
                seen.push(egress);
                out.push_str(&format!(
                    "        oifname \"{egress}\" counter ip dscp set 0\n\
                     \x20       oifname \"{egress}\" counter masquerade\n"
                ));
            }
        }
    }
    format!(
        "add table inet {LANE_TABLE}
delete table inet {LANE_TABLE}
table inet {LANE_TABLE} {{
    chain tag {{
        type filter hook postrouting priority mangle; policy accept;
{tag}    }}
    chain pick {{
        type filter hook prerouting priority mangle; policy accept;
{pick}    }}
    chain leave {{
        type nat hook postrouting priority srcnat; policy accept;
{out}    }}
}}
"
    )
}

/// The script that removes them.
#[must_use]
pub fn lane_revert() -> String {
    format!("add table inet {LANE_TABLE}\ndelete table inet {LANE_TABLE}\n")
}
