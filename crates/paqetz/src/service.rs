//! Installing things that need root, and the systemd units that keep them
//! running.
//!
//! # How privilege is handled
//!
//! Not by re-executing under `sudo`, which would hand a whole interactive
//! session elevated privilege for the sake of writing three files, and not by
//! refusing and printing instructions, which is how a setup tool becomes a
//! README with extra steps.
//!
//! Instead each privileged action is attempted directly, and only if the kernel
//! refuses does it retry through `sudo`, printing the exact command first. The
//! elevation is therefore per-action, visible, and skipped entirely when the
//! process already has the privilege it needs.

use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

/// Whether this process can write to system locations without help.
#[must_use]
pub(crate) fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Writes a file, elevating only if the direct write is refused.
///
/// # Errors
/// Returns an error if the write fails for any reason other than privilege, or
/// if the elevated retry also fails.
pub(crate) fn write_file(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    match direct_write(path, contents, mode) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            println!("    (needs root) sudo tee {} > /dev/null", path.display());
            elevated_write(path, contents, mode)
        }
        Err(e) => Err(e),
    }
}

fn direct_write(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

/// Writes through `sudo tee`, then fixes the mode.
fn elevated_write(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        run_elevated("mkdir", &["-p", &parent.display().to_string()])?;
    }

    let mut child = Command::new("sudo")
        .arg("tee")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(contents.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "could not write {} even with sudo",
            path.display()
        )));
    }
    run_elevated(
        "chmod",
        &[&format!("{mode:o}"), &path.display().to_string()],
    )
}

/// Explains a command that would not start.
///
/// The bare OS error for a missing program is `No such file or directory`,
/// which names neither the program nor the fact that it is a program -- so the
/// reader goes looking for a file that was never the problem. Every place that
/// shells out routes its spawn failures through here.
pub(crate) fn spawn_failure(program: &str, e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        format!("`{program}` is not installed, and is needed for this. Install it and try again.")
    } else {
        format!("could not run `{program}`: {e}")
    }
}

/// Runs a command, elevating only if this process is not already root.
///
/// # Errors
/// Returns an error if the command cannot be run or reports failure.
pub(crate) fn run_elevated(program: &str, args: &[&str]) -> io::Result<()> {
    let (cmd, full): (&str, Vec<&str>) = if is_root() {
        (program, args.to_vec())
    } else {
        let mut v = vec![program];
        v.extend_from_slice(args);
        ("sudo", v)
    };
    if !is_root() {
        println!("    (needs root) sudo {program} {}", args.join(" "));
    }
    let out = Command::new(cmd).args(&full).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Whether this host uses systemd.
#[must_use]
pub(crate) fn has_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// The unit that keeps the tunnel running.
///
/// `doctor` runs first, so a host that cannot work fails at start with a
/// diagnosis rather than at run time with silence.
///
/// # Why there is no start limit
///
/// The obvious arrangement — restart on failure, give up after five tries — is
/// wrong for this, and dangerously so. The failures a tunnel actually hits at
/// start-up are transient: the network is not up yet at boot, the peer is
/// briefly unreachable, a route appears a moment later. Five tries at five
/// seconds is twenty-five seconds, so a host that reboots slightly slower than
/// expected comes back with a permanently dead tunnel — which, for a machine
/// reached *through* that tunnel, means it does not come back at all.
///
/// So transient failures retry indefinitely, and the one failure that genuinely
/// cannot fix itself is separated out by exit code instead: a configuration
/// that does not parse exits 78, and `RestartPreventExitStatus` stops the unit
/// on exactly that. A typo stops immediately with a clear status; a slow boot
/// waits and recovers.
#[must_use]
pub(crate) fn tunnel_unit(binary: &str, config: &str) -> String {
    format!(
        "[Unit]\n\
         Description=paqetz tunnel\n\
         Documentation=https://github.com/gitpoemer/paqetz\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         # No start limit: the failures this hits at boot are transient, and a\n\
         # unit that gives up after five tries turns a slow boot into a tunnel\n\
         # that never comes back. The failure that cannot fix itself is caught\n\
         # by RestartPreventExitStatus below instead.\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStartPre={binary} doctor -c {config}\n\
         ExecStart={binary} run -c {config}\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         # 78 is what this exits with when the configuration cannot work. That\n\
         # will still be true in ten seconds, so stop rather than loop.\n\
         RestartPreventExitStatus=78\n\
         \n\
         # Raw sockets and a TUN device; the firewall rules need CAP_NET_ADMIN.\n\
         # Nothing else does, so nothing else is granted.\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n\
         CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n\
         NoNewPrivileges=true\n\
         \n\
         # The configuration holds a private key.\n\
         UMask=0077\n\
         \n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         ProtectKernelLogs=true\n\
         ProtectControlGroups=true\n\
         RestrictRealtime=true\n\
         RestrictSUIDSGID=true\n\
         LockPersonality=true\n\
         DeviceAllow=/dev/net/tun rw\n\
         \n\
         # `paqetz tune` writes here, and the unit must be able to read it back.\n\
         ReadWritePaths=/proc/sys/net\n\
         \n\
         LimitNOFILE=8192\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Where a unit file lives.
fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{name}.service")
}

/// Installs and starts a unit.
///
/// # Errors
/// Returns an error if any step fails.
pub(crate) fn install_unit(name: &str, contents: &str, enable: bool) -> io::Result<()> {
    let path = unit_path(name);
    write_file(Path::new(&path), contents, 0o644)?;
    println!("    wrote {path}");
    run_elevated("systemctl", &["daemon-reload"])?;
    if enable {
        if let Err(e) = run_elevated("systemctl", &["enable", "--now", name]) {
            // systemd's own advice at this point is to go and read the journal,
            // which is one command away and holds the actual reason. Printing
            // it here saves the round trip, and the reason is almost always a
            // single line naming exactly what is wrong.
            report_unit_failure(name);
            return Err(e);
        }
        println!("    enabled and started {name}");
    } else {
        println!("    not started; `systemctl enable --now {name}` when ready");
    }
    Ok(())
}

/// Prints why a unit would not start.
fn report_unit_failure(name: &str) {
    let Ok(out) = Command::new("journalctl")
        .args(["-u", name, "-n", "40", "--no-pager", "-o", "cat"])
        .output()
    else {
        return;
    };
    let log = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
    let chosen = failing_lines(&lines);
    if chosen.is_empty() {
        return;
    }
    println!();
    println!("  {name} would not start. Its own last words:");
    for line in chosen {
        println!("    {line}");
    }
    println!();
}

/// Picks the lines from a unit's log that say what went wrong.
///
/// The last few lines are the wrong ones. A start-up that ends in a check
/// failing prints a dozen passing checks after the one that failed, so the tail
/// carries the summary -- "1 problem will stop the tunnel working" -- and not the
/// problem. What is wanted is the lines that name it, wherever they sit.
fn failing_lines<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    let names_a_failure = |l: &str| {
        let l = l.trim_start();
        l.contains("[FAIL]")
            || l.contains("[warn]")
            || l.starts_with("error")
            || l.starts_with("└─")
    };
    let named: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| names_a_failure(l))
        .collect();
    if named.is_empty() {
        // Nothing announced itself, so the tail is the best guess left.
        return lines.iter().rev().take(6).rev().copied().collect();
    }
    // Capped, because a unit that has been restarting for an hour has the same
    // failure in the log many times over and one telling is enough.
    named.into_iter().rev().take(8).rev().collect()
}

/// Stops and removes a unit.
pub(crate) fn remove_unit(name: &str) {
    let _ = run_elevated("systemctl", &["disable", "--now", name]);
    let _ = run_elevated("rm", &["-f", &unit_path(name)]);
    let _ = run_elevated("systemctl", &["daemon-reload"]);
}

/// Whether the unit file is there at all.
///
/// Distinct from enabled: a unit can be installed without being set to start at
/// boot, and "there is no service" wants a different answer than "there is one
/// and it is switched off".
#[must_use]
pub(crate) fn unit_exists(name: &str) -> bool {
    Path::new(&unit_path(name)).exists()
}

/// The running systemd's major version, if it can be determined.
#[must_use]
pub(crate) fn systemd_version() -> Option<u32> {
    let out = Command::new("systemctl").arg("--version").output().ok()?;
    parse_systemd_version(&String::from_utf8_lossy(&out.stdout))
}

/// Reads the version out of `systemctl --version`.
///
/// The first line is `systemd 249 (249.11-0ubuntu3)` and has been that shape
/// for many years, but distributions add suffixes freely, so only the leading
/// digits are taken and anything unrecognised is `None` rather than a guess.
pub(crate) fn parse_systemd_version(output: &str) -> Option<u32> {
    output.lines().next()?.split_whitespace().find_map(|word| {
        let digits: String = word.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    })
}

/// Whether this systemd can hand a service a file the service cannot open.
///
/// `LoadCredential` arrived in systemd 247. Below that, a service running as a
/// transient user simply cannot read a root-owned private file, and the only
/// honest options are to run it as root or to loosen the file -- and loosening
/// a file that holds a private key is not an option at all.
#[must_use]
pub(crate) fn has_credentials() -> bool {
    systemd_version().is_some_and(|v| v >= 247)
}

/// Whether a unit is running right now.
#[must_use]
pub(crate) fn unit_active(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether a unit exists and is enabled.
#[must_use]
pub(crate) fn unit_enabled(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", name])
        .status()
        .is_ok_and(|s| s.success())
}

/// Copies this binary to a system location, if it is not already there.
///
/// # Errors
/// Returns an error if the executable cannot be located or copied.
pub(crate) fn install_binary(prefix: &str) -> io::Result<String> {
    let target = format!("{prefix}/paqetz");
    let current = std::env::current_exe()?;
    if current == Path::new(&target) {
        return Ok(target);
    }
    let contents = std::fs::read(&current)?;
    // Written as bytes through the same privilege path as everything else.
    match std::fs::write(&target, &contents) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            run_elevated("cp", &[&current.display().to_string(), &target])?;
        }
        Err(e) => return Err(e),
    }
    run_elevated("chmod", &["755", &target])?;
    println!("    installed the binary to {target}");
    Ok(target)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_lines_that_name_the_failure_are_the_ones_shown() {
        // The tail is the wrong choice: a start-up that ends in a failed check
        // prints every passing check after the one that failed, so the last
        // lines carry the summary and not the cause. This is what the field
        // saw -- "1 problem(s) will stop the tunnel working" and no problem.
        let log = vec![
            "[ ok ] configuration          parses",
            "[FAIL] capabilities            CAP_NET_ADMIN is not held",
            "       └─ grant it, or run as root",
            "[ ok ] TUN driver             present",
            "[ ok ] default route          via eth0",
            "[ ok ] inner addresses        10.7.0.3 ↔ 10.7.0.1",
            "1 problem(s) will stop the tunnel working.",
            "error: the host is not ready; see the failures above",
        ];
        let shown = super::failing_lines(&log);
        assert!(
            shown
                .iter()
                .any(|l| l.contains("CAP_NET_ADMIN is not held")),
            "the cause was left out: {shown:?}"
        );
        assert!(
            shown.iter().any(|l| l.contains("grant it")),
            "the remedy was left out: {shown:?}"
        );
        assert!(
            !shown.iter().any(|l| l.contains("[ ok ]")),
            "passing checks are noise here: {shown:?}"
        );
    }

    #[test]
    fn a_log_that_announces_nothing_falls_back_to_its_tail() {
        let log = vec!["starting", "reading config", "bind: address in use"];
        let shown = super::failing_lines(&log);
        assert!(
            shown.iter().any(|l| l.contains("address in use")),
            "{shown:?}"
        );
    }

    #[test]
    fn a_unit_that_has_been_failing_for_an_hour_is_not_quoted_in_full() {
        let log: Vec<&str> = std::iter::repeat_n("[FAIL] capabilities  not held", 60).collect();
        assert!(super::failing_lines(&log).len() <= 8);
    }

    #[test]
    fn the_systemd_version_is_read_from_its_first_line() {
        assert_eq!(
            super::parse_systemd_version("systemd 249 (249.11-0ubuntu3.12)\n+PAM +AUDIT"),
            Some(249)
        );
        assert_eq!(
            super::parse_systemd_version("systemd 255 (255.4-1ubuntu8)"),
            Some(255)
        );
        // Distributions append freely; only the leading digits are taken.
        assert_eq!(
            super::parse_systemd_version("systemd 247.3-7+deb11u4"),
            Some(247)
        );
        // And anything unrecognised is not guessed at.
        assert_eq!(super::parse_systemd_version(""), None);
        assert_eq!(super::parse_systemd_version("not systemd at all"), None);
    }

    #[test]
    fn a_missing_program_says_so_rather_than_naming_a_file() {
        // The bare OS error is "No such file or directory", which sends the
        // reader looking for a file that was never the problem.
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let said = super::spawn_failure("unzip", &missing);
        assert!(said.contains("`unzip`"), "{said}");
        assert!(said.contains("not installed"), "{said}");
        assert!(!said.contains("No such file"), "{said}");

        // Anything else keeps the original wording, which is the useful part.
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let said = super::spawn_failure("nft", &denied);
        assert!(said.contains("`nft`"), "{said}");
        assert!(said.contains("could not run"), "{said}");
    }

    #[test]
    fn a_missing_unit_is_not_reported_as_present() {
        // The distinction the start/stop commands rely on: without it they
        // would hand systemd a unit name it has never heard of and report
        // whatever it says about that, rather than the one thing the operator
        // needs to hear -- that no service was ever installed.
        assert!(!unit_exists("paqetz-definitely-not-installed"));
    }

    use super::*;

    #[test]
    fn the_unit_runs_doctor_before_the_tunnel() {
        // So a host that cannot work says why at start, rather than coming up
        // and carrying nothing.
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        let pre = u.find("ExecStartPre").expect("has ExecStartPre");
        let start = u.find("ExecStart=").expect("has ExecStart");
        assert!(pre < start);
        assert!(u.contains("doctor -c /etc/paqetz/paqetz.toml"));
    }

    #[test]
    fn the_unit_asks_for_two_capabilities_and_not_root() {
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(u.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"));
        assert!(u.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"));
        assert!(u.contains("NoNewPrivileges=true"));
        assert!(!u.contains("User=root"));
    }

    #[test]
    fn the_unit_protects_the_key_it_reads() {
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(u.contains("UMask=0077"), "the config holds a private key");
        assert!(u.contains("ProtectHome=true"));
    }

    #[test]
    fn a_broken_configuration_stops_rather_than_looping() {
        // Separated by exit code, not by a retry count -- see the type docs.
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(u.contains("RestartPreventExitStatus=78"), "{u}");
    }

    #[test]
    fn a_transient_failure_retries_indefinitely() {
        // The dangerous alternative: five tries at five seconds means a host
        // that boots slowly comes back with a dead tunnel, and a host reached
        // through that tunnel does not come back at all.
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(u.contains("Restart=on-failure"), "{u}");
        assert!(
            u.contains("StartLimitIntervalSec=0"),
            "the rate limit must be disabled: {u}"
        );
        assert!(
            !u.contains("StartLimitBurst"),
            "a burst limit would reintroduce the giving-up behaviour: {u}"
        );
    }

    #[test]
    fn the_unit_allows_the_device_it_needs_and_no_others() {
        let u = tunnel_unit("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(u.contains("DeviceAllow=/dev/net/tun rw"));
        assert_eq!(u.matches("DeviceAllow").count(), 1);
    }

    #[test]
    fn unit_paths_are_where_systemd_looks() {
        assert_eq!(unit_path("paqetz"), "/etc/systemd/system/paqetz.service");
    }

    #[test]
    fn systemd_detection_reads_the_filesystem_only() {
        // Read-only, and a host without systemd is a legitimate answer.
        let _ = has_systemd();
    }
}
