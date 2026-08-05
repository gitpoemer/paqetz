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
pub fn nft_apply(ports: &[u16]) -> String {
    let lines = |f: &dyn Fn(u16) -> String| -> String { ports.iter().map(|p| f(*p)).collect() };
    let pre = lines(&|p| format!("        tcp dport {p} notrack\n"));
    let out = lines(&|p| format!("        tcp sport {p} notrack\n"));
    let rst = lines(&|p| format!("        tcp sport {p} tcp flags & rst == rst drop\n"));
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
    chain output_drop_rst {{
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
pub fn iptables_rules(ports: &[u16]) -> Vec<IptablesRule> {
    ports.iter().flat_map(|p| rules_for(*p)).collect()
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
    fn several_tunnels_share_one_table() {
        // They share a lifetime -- one process starts them and removes the rules
        // for all of them on the way out -- so a table each would mean inventing
        // unique names for something created and destroyed as a unit.
        let script = nft_apply(&[1111, 2222, 3333]);
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
        let rules = iptables_rules(&[1111, 2222]);
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
        let script = nft_apply(&[9999]);
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
        let script = nft_apply(&[9999]);
        assert!(script.contains("tcp dport 9999 notrack"));
        assert!(script.contains("tcp sport 9999 notrack"));
        assert!(script.contains("tcp sport 9999 tcp flags & rst == rst drop"));
    }

    #[test]
    fn the_nft_script_hooks_the_right_priorities() {
        let script = nft_apply(&[9999]);
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
        let script = nft_apply(&[9999]);
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
            let script = nft_apply(&[port]);
            assert_eq!(
                script.matches(&port.to_string()).count(),
                3,
                "port {port} should appear in all three rules"
            );
            for rule in iptables_rules(&[port]) {
                assert!(
                    rule.spec.contains(&port.to_string()),
                    "port {port} missing from {rule:?}"
                );
            }
        }
    }

    #[test]
    fn iptables_rules_match_what_paqet_documents() {
        let rules = iptables_rules(&[9999]);
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
        for rule in iptables_rules(&[9999]) {
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
        for rule in iptables_rules(&[9999]) {
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
        for rule in iptables_rules(&[9999]) {
            assert!(
                rule.spec.iter().any(|a| a == COMMENT),
                "untagged rule: {rule:?}"
            );
        }
    }
}
