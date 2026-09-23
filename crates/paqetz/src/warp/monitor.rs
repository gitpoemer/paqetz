//! Watching WARP, and falling back when it stops carrying traffic.
//!
//! WARP can stop delivering past Cloudflare's edge while everything about it
//! still looks up: the interface is there, it handshakes, and the tunnel's
//! forwarded connections open and hang. Nobody is watching a server when that
//! happens, so this does what an operator would, in the order an operator
//! would: restart WARP, then replace its account, and when neither brings it
//! back, take WARP out of the path so the tunnel keeps working through this
//! server's own address.
//!
//! It never puts WARP back. That is a judgement about whether Cloudflare can be
//! trusted again, made by someone who has looked, and a monitor that undid its
//! own fallback would flap between the two for as long as WARP did.

use std::path::Path;
use std::time::Duration;

use super::{Handshake, IFACE, Reach, STATE_DIR};

/// The systemd units, without their suffixes.
const UNIT: &str = "paqetz-warp-monitor";

/// How recently a replacement account has to have been made for its failure
/// to count against the account rather than against WARP.
///
/// A fresh account that stops working within the hour is not the account, and
/// replacing it again every few minutes would only burn registrations until
/// Cloudflare refuses them too, which would take away the fix that does work
/// when it is the account.
const REREGISTER_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// Written above the line this turns off, where the operator will find it.
const NOTE: &str = "# Turned off by `paqetz warp monitor`: WARP stopped carrying traffic past \
                    Cloudflare\n# and a new registration did not bring it back. Put the line \
                    back and restart paqetz\n# once `paqetz warp status` shows WARP reaching \
                    past Cloudflare.";

/// Installs the timer, checking every `minutes`.
///
/// # Errors
/// Returns an error if the configuration names no WARP egress, or the units
/// cannot be installed.
pub(crate) fn enable(config: &Path, minutes: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !(1..=1440).contains(&minutes) {
        return Err("--minutes has to be between 1 and 1440".into());
    }
    let cfg = crate::config::Config::load(config)?;
    if !watched(&cfg) {
        return Err(format!(
            "no tunnel in {} has egress = \"{IFACE}\", so there is nothing to watch: the \
             monitor's last resort is turning that line off.",
            config.display()
        )
        .into());
    }
    // Absolute, because the unit runs from wherever systemd starts it.
    let config = std::fs::canonicalize(config)?;
    let binary = std::env::current_exe()?.display().to_string();
    let (service, timer) = units(&binary, &config.display().to_string(), minutes);
    let dir = std::env::temp_dir();
    for (name, text) in [("service", service), ("timer", timer)] {
        let staged = dir.join(format!("{UNIT}.{name}"));
        std::fs::write(&staged, text)?;
        crate::service::run_elevated(
            "install",
            &[
                "-m",
                "0644",
                &staged.display().to_string(),
                &format!("/etc/systemd/system/{UNIT}.{name}"),
            ],
        )?;
        let _ = std::fs::remove_file(&staged);
    }
    crate::service::run_elevated("systemctl", &["daemon-reload"])?;
    // Restarted as well as enabled, so a changed interval takes effect now
    // rather than after the check already scheduled.
    crate::service::run_elevated("systemctl", &["enable", &format!("{UNIT}.timer")])?;
    crate::service::run_elevated("systemctl", &["restart", &format!("{UNIT}.timer")])?;
    println!("WARP is checked every {minutes} minutes. `journalctl -u {UNIT}` shows what each");
    println!("check found and did.");
    Ok(())
}

/// Removes the timer. Changes nothing else.
///
/// # Errors
/// Never in practice: each step is attempted whether or not the one before it
/// found anything to remove.
pub(crate) fn disable() -> Result<(), Box<dyn std::error::Error>> {
    remove_units();
    println!("WARP is no longer checked.");
    Ok(())
}

/// Takes the units out, whatever state they are in. Shared with `warp revert`.
pub(super) fn remove_units() {
    let _ =
        crate::service::run_elevated("systemctl", &["disable", "--now", &format!("{UNIT}.timer")]);
    for suffix in ["timer", "service"] {
        let _ = crate::service::run_elevated(
            "rm",
            &["-f", &format!("/etc/systemd/system/{UNIT}.{suffix}")],
        );
    }
    let _ = crate::service::run_elevated("systemctl", &["daemon-reload"]);
}

/// Whether the timer is running.
pub(super) fn enabled() -> bool {
    crate::service::unit_active(&format!("{UNIT}.timer"))
}

/// The service and timer units.
fn units(binary: &str, config: &str, minutes: u32) -> (String, String) {
    let service = format!(
        "[Unit]\n\
         Description=Check that WARP still carries traffic, and fall back if not\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={binary} warp monitor check -c {config}\n"
    );
    // Counted from when the last check finished rather than when it started,
    // so one that spent a minute re-registering is not followed by another
    // straight away.
    let timer = format!(
        "[Unit]\n\
         Description=Check WARP every {minutes} minutes\n\
         \n\
         [Timer]\n\
         OnActiveSec={minutes}min\n\
         OnUnitInactiveSec={minutes}min\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    );
    (service, timer)
}

/// One check, and whatever it takes when WARP has stopped carrying traffic.
///
/// # Errors
/// Returns an error when it cannot act: not root, a configuration that does not
/// load, or a fallback that could not be written.
pub(crate) fn check(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !crate::service::is_root() {
        return Err(
            "the check fetches through WARP and may replace its account, so it \
                    needs root"
                .into(),
        );
    }
    let cfg = crate::config::Config::load(config)?;
    if !watched(&cfg) {
        println!("egress is not {IFACE}, so there is nothing to watch");
        return Ok(());
    }
    match carrying() {
        Some(true) => {
            println!("WARP carries traffic past Cloudflare");
            return Ok(());
        }
        None => {
            println!("could not tell whether WARP carries traffic, so it was left alone");
            return Ok(());
        }
        Some(false) => {}
    }

    println!("WARP is not carrying traffic past Cloudflare; restarting it");
    let restarted = super::revive_interface().and_then(|()| super::confirm_handshake());
    if restarted.is_ok() && carrying() == Some(true) {
        println!("WARP is back after a restart");
        return Ok(());
    }

    if reregistered_within(REREGISTER_COOLDOWN) {
        println!(
            "the account was replaced less than an hour ago and has failed already, so \
             another would not be the fix"
        );
        return fall_back(config);
    }
    println!("replacing the WARP account");
    match super::reregister(config) {
        Ok(()) => {
            let _ = std::fs::write(stamp(), "");
            Ok(())
        }
        Err(e) => {
            println!("a new registration did not bring WARP back: {e}");
            fall_back(config)
        }
    }
}

/// Whether any tunnel sends everything it forwards through WARP.
fn watched(cfg: &crate::config::Config) -> bool {
    cfg.tunnels
        .iter()
        .any(|t| t.interface.egress.as_deref() == Some(IFACE))
}

/// Whether WARP carries traffic past Cloudflare right now. `None` when that
/// cannot be told from here, which is never a reason to act.
fn carrying() -> Option<bool> {
    if !super::interface_exists(IFACE) {
        return Some(false);
    }
    match super::handshake_age() {
        Handshake::Never => return Some(false),
        Handshake::Unknown => return None,
        Handshake::Ago(_) => {}
    }
    match super::reach() {
        Reach::Beyond => Some(true),
        Reach::OnlyCloudflare | Reach::Nothing => Some(false),
        Reach::Unknown => None,
    }
}

/// Where the time of the last replacement is kept, as the file's own mtime.
fn stamp() -> String {
    format!("{STATE_DIR}/monitor-reregistered")
}

/// Whether the monitor replaced the account less than `window` ago.
fn reregistered_within(window: Duration) -> bool {
    std::fs::metadata(stamp())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < window)
}

/// Takes WARP out of the path: turns off `egress = "warp"` and restarts the
/// tunnel, which then forwards through this server's own address.
fn fall_back(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // The file itself, so a configuration reached through a link stays one.
    let path = std::fs::canonicalize(config)?;
    let text = std::fs::read_to_string(&path)?;
    let Some(edited) = without_egress(&text) else {
        return Err(format!(
            "no `egress = \"{IFACE}\"` line was found in {} to turn off. Take WARP out of \
             the path by hand.",
            path.display()
        )
        .into());
    };
    // Checked before anything is replaced: a file the tunnel cannot read back
    // is a tunnel that does not start.
    let parsed = crate::config::Config::parse(&edited)?;
    if watched(&parsed) {
        return Err(format!(
            "{} still sends traffic through WARP after the edit, so it was left as it \
             was. Take WARP out of the path by hand.",
            path.display()
        )
        .into());
    }
    replace_file(&path, &edited)?;
    println!("turned egress off in {}", path.display());
    if crate::service::unit_active("paqetz") {
        crate::service::run_elevated("systemctl", &["restart", "paqetz"])?;
        println!(
            "paqetz restarted: the tunnel forwards through this server's own address until \
             egress is put back"
        );
    } else {
        println!("paqetz is not running as a service; restart it to use the change");
    }
    Ok(())
}

/// Replaces `path` with `contents` in one step, keeping its permissions.
///
/// The configuration holds a private key. It is written beside the original,
/// created unreadable by anyone else before a byte goes in, and renamed over
/// it, so there is never a moment where the key is in a looser file or the
/// tunnel could read half a configuration.
fn replace_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let staged = std::path::PathBuf::from(format!("{}.paqetz-new", path.display()));
    let _ = std::fs::remove_file(&staged);
    crate::setup::write_private(&staged, contents)?;
    std::fs::set_permissions(&staged, std::fs::metadata(path)?.permissions())?;
    std::fs::rename(&staged, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })
}

/// Comments out every `egress = "warp"` in an `[interface]` or
/// `[tunnel.interface]` table, with a note saying why. `None` when there is
/// none to turn off.
///
/// Only those tables: a lane's `egress` names a way out for one class of
/// traffic, and taking it away is not this monitor's call.
fn without_egress(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len() + NOTE.len() + 8);
    let mut table = String::new();
    let mut changed = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            trimmed
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default()
                .trim()
                .clone_into(&mut table);
        }
        if matches!(table.as_str(), "interface" | "tunnel.interface") && is_warp_egress(trimmed) {
            out.push_str(NOTE);
            out.push_str("\n# ");
            changed = true;
        }
        out.push_str(line);
        out.push('\n');
    }
    changed.then_some(out)
}

/// Whether a line reads `egress = "warp"`, however it is quoted or commented.
fn is_warp_egress(line: &str) -> bool {
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    key.trim() == "egress"
        && value
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            == IFACE
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "\
[interface]
private_key = \"QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y=\"
address = \"10.7.0.1/24\"
listen_port = 9999
egress = \"warp\"

[peer]
public_key = \"Rm91cnRoU2VydmVyS2V5VXNlZE9ubHlJblRoZXNlVGU=\"
tunnel_address = \"10.7.0.2\"

[[lane]]
class = 10
egress = \"warp\"
";

    #[test]
    fn the_tunnel_s_egress_is_turned_off_and_a_lane_s_is_not() {
        let out = without_egress(SERVER).expect("there is one to turn off");
        let cfg = crate::config::Config::parse(&out).expect("still a configuration");
        let tunnel = cfg.tunnels.first().expect("a tunnel");
        assert_eq!(tunnel.interface.egress, None, "{out}");
        assert_eq!(
            tunnel.lanes.first().and_then(|l| l.egress.as_deref()),
            Some("warp"),
            "{out}"
        );
        assert!(
            out.contains("paqetz warp monitor"),
            "no note of who did it: {out}"
        );
    }

    #[test]
    fn nothing_else_in_the_file_is_touched() {
        // Take away the note and the comment marker, and it is the file it was.
        let out = without_egress(SERVER).expect("there is one to turn off");
        let restored: String = out
            .lines()
            .filter(|l| !NOTE.lines().any(|n| n == *l))
            .map(|l| {
                let line = l
                    .strip_prefix("# ")
                    .filter(|r| is_warp_egress(r))
                    .unwrap_or(l);
                format!("{line}\n")
            })
            .collect();
        assert_eq!(restored, SERVER);
    }

    #[test]
    fn every_tunnel_leaving_by_warp_is_turned_off() {
        let two = "\
[[tunnel]]
name = \"one\"
[tunnel.interface]
private_key = \"QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y=\"
address = \"10.7.0.1/24\"
listen_port = 9999
egress = 'warp'   # through Cloudflare
[tunnel.peer]
public_key = \"Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo=\"
tunnel_address = \"10.7.0.2\"

[[tunnel]]
name = \"two\"
[tunnel.interface]
private_key = \"QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y=\"
address = \"10.8.0.1/24\"
listen_port = 9998
device = \"paqetz1\"
egress = \"warp\"
[tunnel.peer]
public_key = \"TmwuUmwHVDe4Q0z0PmVEZ0wYyBIDN0kUq5xkQzk0T3E=\"
tunnel_address = \"10.8.0.2\"
";
        let out = without_egress(two).expect("there are two to turn off");
        let cfg = crate::config::Config::parse(&out).expect("still a configuration");
        assert!(!watched(&cfg), "{out}");
    }

    #[test]
    fn a_file_already_turned_off_is_left_alone() {
        let out = without_egress(SERVER).expect("there is one to turn off");
        assert_eq!(without_egress(&out), None);
        assert_eq!(
            without_egress(&SERVER.replace("egress = \"warp\"\n\n[peer]", "\n[peer]")),
            None
        );
    }

    #[test]
    fn the_timer_counts_from_the_end_of_the_last_check() {
        let (service, timer) = units("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml", 15);
        assert!(
            service.contains(
                "ExecStart=/usr/local/bin/paqetz warp monitor check -c /etc/paqetz/paqetz.toml"
            ),
            "{service}"
        );
        assert!(timer.contains("OnUnitInactiveSec=15min"), "{timer}");
    }
}
