//! The policy-routing rule that makes a marked socket use the tunnel.
//!
//! `SO_MARK` on a socket does nothing by itself. It becomes meaningful only
//! when a rule says which routing table marked traffic should consult, and that
//! table has a default route through the tunnel device:
//!
//! ```text
//! ip rule  add fwmark <mark> lookup <table>
//! ip route add default dev <device> table <table>
//! ```
//!
//! Installed and removed by the binary for the same reason the firewall rules
//! are (D9): forgetting them produces a SOCKS5 proxy that works perfectly and
//! sends every connection out the ordinary route, which is the failure hardest
//! to notice, because everything appears to function.

use std::io;
use std::process::Command;

/// The rule's priority. High enough to sit above the main table's own rules,
/// low enough not to displace anything an operator is likely to have added.
const PRIORITY: u32 = 9000;

/// Describes the routing this front end needs.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// The mark stamped on sockets that should use the tunnel.
    pub mark: u32,
    /// The routing table the rule points at.
    pub table: u32,
}

impl Policy {
    /// The commands [`apply`](Self::apply) would run, for display.
    #[must_use]
    pub fn plan(&self, device: &str) -> Vec<String> {
        vec![
            format!(
                "ip rule add fwmark {} lookup {} priority {}",
                self.mark, self.table, PRIORITY
            ),
            format!("ip route add default dev {} table {}", device, self.table),
        ]
    }

    /// Installs the rule and route. Safe to call when they already exist.
    ///
    /// # Errors
    /// Returns an error if `ip` cannot be run or reports failure.
    pub fn apply(&self, device: &str) -> io::Result<()> {
        // Removed first so a repeat leaves one of each rather than a stack of
        // duplicates, which `ip rule` will happily accumulate.
        self.revert(device);
        run(&[
            "rule",
            "add",
            "fwmark",
            &self.mark.to_string(),
            "lookup",
            &self.table.to_string(),
            "priority",
            &PRIORITY.to_string(),
        ])?;
        run(&[
            "route",
            "add",
            "default",
            "dev",
            device,
            "table",
            &self.table.to_string(),
        ])
    }

    /// Removes the rule and route. Safe to call when they are absent.
    pub fn revert(&self, device: &str) {
        // Deleted repeatedly: an earlier run killed before its cleanup may have
        // left several copies, and one delete removes one.
        while run(&[
            "rule",
            "del",
            "fwmark",
            &self.mark.to_string(),
            "lookup",
            &self.table.to_string(),
            "priority",
            &PRIORITY.to_string(),
        ])
        .is_ok()
        {}
        let _ = run(&[
            "route",
            "del",
            "default",
            "dev",
            device,
            "table",
            &self.table.to_string(),
        ]);
    }
}

/// Runs one `ip` command.
fn run(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("could not run `ip {}`: {e}", args.join(" ")),
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "`ip {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn the_plan_names_the_mark_the_table_and_the_device() {
        let plan = Policy {
            mark: 0x51,
            table: 51,
        }
        .plan("paqetz0");
        assert_eq!(plan.len(), 2);
        assert!(plan[0].contains("fwmark 81"), "got: {}", plan[0]);
        assert!(plan[0].contains("lookup 51"), "got: {}", plan[0]);
        assert!(plan[1].contains("dev paqetz0"), "got: {}", plan[1]);
        assert!(plan[1].contains("table 51"), "got: {}", plan[1]);
    }

    #[test]
    fn the_plan_is_runnable_as_printed() {
        for line in (Policy { mark: 1, table: 2 }).plan("tun0") {
            assert!(line.starts_with("ip "), "got: {line}");
            assert!(!line.contains("{}"), "unsubstituted placeholder: {line}");
        }
    }

    #[test]
    fn the_priority_leaves_room_above_and_below() {
        // Below 32766, where the main and default tables sit, so the rule is
        // consulted first; well above 0, so an operator can pre-empt it.
        const { assert!(PRIORITY > 0 && PRIORITY < 32_766) }
    }
}
