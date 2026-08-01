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
//!
//! # Why the table also holds a blackhole
//!
//! Installing the route once is not enough, because the kernel deletes routes
//! that name a device when that device goes away. If that happens the rule
//! survives, the table it points at is empty, and a lookup that finds nothing
//! simply moves on to the next rule — the main table, the ordinary route, out
//! of the host in the clear. Marked traffic then leaves *unprotected* and
//! nothing reports it, which is the same silent failure as never installing the
//! rule at all, arriving hours later.
//!
//! So the table carries a second, worse-metric default that goes nowhere. While
//! the device exists its route wins on metric; if the device disappears the
//! blackhole is what remains, the lookup terminates there, and marked
//! connections fail instead of escaping. Failing closed is the only safe
//! direction for this particular rule: an outage on a host inside the network
//! being tunnelled out of is recoverable, and traffic leaving that host in the
//! clear because a lookup quietly moved on to the next table is not.

use std::io;
use std::process::Command;

/// The rule's priority. High enough to sit above the main table's own rules,
/// low enough not to displace anything an operator is likely to have added.
const PRIORITY: u32 = 9000;

/// Metric of the route through the tunnel device. Lower wins, so this is the
/// one in force whenever the device exists.
const DEVICE_METRIC: u32 = 1;

/// Metric of the blackhole that remains when the device route does not.
const BLACKHOLE_METRIC: u32 = 100;

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
            format!(
                "ip route replace default dev {} table {} metric {}",
                device, self.table, DEVICE_METRIC
            ),
            format!(
                "ip route replace blackhole default table {} metric {}",
                self.table, BLACKHOLE_METRIC
            ),
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
            "replace",
            "default",
            "dev",
            device,
            "table",
            &self.table.to_string(),
            "metric",
            &DEVICE_METRIC.to_string(),
        ])?;
        // The fallback that makes a vanished device fail closed rather than
        // silently route around the tunnel.
        run(&[
            "route",
            "replace",
            "blackhole",
            "default",
            "table",
            &self.table.to_string(),
            "metric",
            &BLACKHOLE_METRIC.to_string(),
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
        let _ = run(&[
            "route",
            "del",
            "blackhole",
            "default",
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
        assert_eq!(plan.len(), 3);
        assert!(plan[0].contains("fwmark 81"), "got: {}", plan[0]);
        assert!(plan[0].contains("lookup 51"), "got: {}", plan[0]);
        assert!(plan[1].contains("dev paqetz0"), "got: {}", plan[1]);
        assert!(plan[1].contains("table 51"), "got: {}", plan[1]);
        assert!(plan[2].contains("blackhole"), "got: {}", plan[2]);
        assert!(plan[2].contains("table 51"), "got: {}", plan[2]);
    }

    #[test]
    fn the_blackhole_loses_to_the_device_but_outlives_it() {
        // The whole reason it is there: while the device exists its route wins
        // on metric, and when the kernel removes that route with the device the
        // blackhole is what a lookup finds. Without it the lookup finds nothing,
        // falls through to the main table, and marked traffic leaves the host in
        // the clear -- which is the failure this module exists to prevent,
        // arriving hours after start-up instead of at it.
        const { assert!(DEVICE_METRIC < BLACKHOLE_METRIC) }

        let plan = Policy {
            mark: 0x51,
            table: 51,
        }
        .plan("paqetz0");
        assert!(
            plan[1].contains(&format!("metric {DEVICE_METRIC}")),
            "got: {}",
            plan[1]
        );
        assert!(
            plan[2].contains(&format!("metric {BLACKHOLE_METRIC}")),
            "got: {}",
            plan[2]
        );
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
