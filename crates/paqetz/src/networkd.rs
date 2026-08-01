//! Stopping `systemd-networkd` from deleting the policy rule out from under us.
//!
//! `SO_MARK` on a socket is only a number. It means something because a routing
//! policy rule says which table marked traffic should consult — and that rule
//! lives in the kernel, not in this process, where anything with `CAP_NET_ADMIN`
//! may remove it.
//!
//! `systemd-networkd` does exactly that. It assumes it is the only thing
//! managing routes and rules on the host, so whenever an interface comes up or
//! goes down, or the service is restarted, it deletes every policy rule that is
//! not declared in its own configuration. `ManageForeignRoutingPolicyRules`
//! defaults to `yes`, and ours is by definition foreign.
//!
//! The failure that produces is the worst shape available. The rule goes and the
//! route stays, because the tunnel device is not one networkd manages. A lookup
//! that finds an empty table does not fail — it falls through to the next rule,
//! to the main table, to the ordinary route. So marked traffic keeps flowing and
//! keeps working, in the clear, out of a host inside the network it was supposed
//! to be tunnelling out of, while the tunnel stays up and its counters sit
//! perfectly still. Observed as four hours of correct operation followed by
//! silence.
//!
//! Xray sets its own mark on its own sockets, so it must have the rule; there is
//! no binding-to-the-device escape for traffic this process does not originate.
//! The documented fix is to tell networkd to leave foreign rules alone, which is
//! what this module writes.
//!
//! Reported against several tools that manage their own rules, so this is
//! networkd's normal behaviour rather than anything unusual about this one.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the drop-in goes. A drop-in rather than `networkd.conf` itself, so
/// nothing an operator wrote is overwritten and removing the file is a complete
/// undo.
const DROP_IN: &str = "/etc/systemd/networkd.conf.d/10-paqetz.conf";

/// What networkd is doing about foreign rules on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// networkd is not running, so nothing here applies.
    Absent,
    /// Running, and will delete the policy rule when it next reconfigures.
    WillDeleteRules,
    /// Running, and configured to leave foreign rules alone.
    LeavesRulesAlone,
}

/// What the drop-in contains.
pub(crate) fn drop_in() -> String {
    "# Written by paqetz.\n\
     #\n\
     # networkd deletes routing policy rules it did not create whenever an\n\
     # interface changes state or the service restarts. The rule that makes a\n\
     # marked socket use the tunnel is one of those, and losing it does not\n\
     # break the tunnel loudly: the lookup falls through to the main table and\n\
     # the traffic leaves in the clear instead.\n\
     #\n\
     # Removing this file restores the default.\n\
     [Network]\n\
     ManageForeignRoutingPolicyRules=no\n\
     ManageForeignRoutes=no\n"
        .to_owned()
}

/// The file this would write.
pub(crate) fn drop_in_path() -> PathBuf {
    PathBuf::from(DROP_IN)
}

/// Whether networkd is running and what it will do to our rule.
pub(crate) fn status() -> Status {
    if !running() {
        return Status::Absent;
    }
    if disabled_somewhere() {
        Status::LeavesRulesAlone
    } else {
        Status::WillDeleteRules
    }
}

/// Whether `systemd-networkd` is active.
fn running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-networkd"])
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether any configuration file turns the behaviour off.
///
/// Read from the files rather than asked of networkd, which offers no way to
/// report an effective setting.
fn disabled_somewhere() -> bool {
    let mut files = vec![PathBuf::from("/etc/systemd/networkd.conf")];
    for dir in [
        "/etc/systemd/networkd.conf.d",
        "/run/systemd/networkd.conf.d",
        "/usr/lib/systemd/networkd.conf.d",
    ] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            files.extend(
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "conf")),
            );
        }
    }
    files.iter().any(|p| says_no(p))
}

/// Whether one file turns foreign-rule management off.
fn says_no(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| l.split_once('='))
        .any(|(k, v)| {
            k.trim()
                .eq_ignore_ascii_case("ManageForeignRoutingPolicyRules")
                && matches!(v.trim().to_ascii_lowercase().as_str(), "no" | "false" | "0")
        })
}

/// Writes the drop-in, and restarts networkd only if asked.
///
/// `networkctl reload` is not enough and it would be misleading to run it:
/// reload re-reads `.network` and `.netdev` files, not `networkd.conf` or its
/// drop-ins. Nothing short of restarting the service picks this up.
///
/// Which is why the restart is a decision rather than something done quietly. It
/// reconfigures every interface on the host, and the host in question is usually
/// remote and reached over one of them. The setting can equally wait for the
/// next reboot: until then the policy rule is still re-asserted every few
/// seconds and the table still fails closed, so the exposure is bounded either
/// way.
///
/// # Errors
/// Returns an error if the file cannot be written, or if a requested restart
/// fails.
pub(crate) fn apply(restart: bool) -> io::Result<()> {
    let path = drop_in_path();
    if let Some(dir) = path.parent() {
        crate::service::run_elevated("mkdir", &["-p", &dir.display().to_string()])?;
    }
    crate::service::write_file(&path, &drop_in(), 0o644)?;

    if restart {
        crate::service::run_elevated("systemctl", &["restart", "systemd-networkd"])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_drop_in_sets_what_it_needs_to() {
        let text = drop_in();
        assert!(text.contains("[Network]"));
        assert!(text.contains("ManageForeignRoutingPolicyRules=no"));
        assert!(
            text.contains("Removing this file restores the default"),
            "an operator finding this later must be able to undo it"
        );
    }

    #[test]
    fn it_is_a_drop_in_rather_than_the_file_itself() {
        // Overwriting networkd.conf would discard whatever else is in it.
        let p = drop_in_path();
        assert!(p.starts_with("/etc/systemd/networkd.conf.d"), "{p:?}");
        assert_ne!(p, Path::new("/etc/systemd/networkd.conf"));
    }

    #[test]
    fn a_setting_is_read_whatever_it_is_spelled_like() {
        let dir = std::env::temp_dir().join(format!("paqetz-networkd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        for (body, expected) in [
            ("[Network]\nManageForeignRoutingPolicyRules=no\n", true),
            ("[Network]\nmanageforeignroutingpolicyrules = No\n", true),
            ("[Network]\nManageForeignRoutingPolicyRules=false\n", true),
            ("[Network]\nManageForeignRoutingPolicyRules=yes\n", false),
            ("[Network]\n#ManageForeignRoutingPolicyRules=no\n", false),
            ("[Network]\nManageForeignRoutes=no\n", false),
            ("", false),
        ] {
            let f = dir.join("t.conf");
            std::fs::write(&f, body).expect("write");
            assert_eq!(says_no(&f), expected, "for {body:?}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_that_is_not_there_does_not_count_as_disabled() {
        assert!(!says_no(Path::new("/nonexistent/paqetz/networkd.conf")));
    }
}
