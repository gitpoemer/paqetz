//! Cloudflare WARP as a second way out for the server.
//!
//! The server's own address is a datacentre one, and plenty of destinations
//! refuse those outright -- Tor relays being the case this was built for, since
//! most hosting providers are blocked from reaching them. Sending only those
//! destinations out through WARP changes what they see without changing
//! anything the client does and without moving the rest of the traffic.
//!
//! # Which side
//!
//! The server, always. It is the end that speaks to the internet; WARP on the
//! client would sit behind the tunnel and change nothing about what any
//! destination sees.
//!
//! # Two shapes, and why they use different machinery
//!
//! *Everything* out through WARP is the [`crate::config::Interface::egress`]
//! setting that already exists: one source rule sending the tunnel's subnet to
//! WARP's table, and masquerade on the way out. Nothing here is needed for it
//! beyond bringing the interface up.
//!
//! *Some destinations* cannot be a source rule, because the thing being
//! selected on is where the packet is going. So this installs its own table:
//! a set of destinations, a rule marking packets bound for them, and a policy
//! route sending marked packets to WARP's table. The two shapes are exclusive
//! -- a blanket source rule would swallow the selective one -- and `setup`
//! refuses to leave both in place.
//!
//! # Why each step checks before it acts
//!
//! Every step here can fail on a host it does not control: a download, a
//! registration with Cloudflare, a systemd unit, a routing table. A wizard that
//! cannot be run twice turns any one of those into "start again from nothing",
//! and starting again from nothing is what an operator does at three in the
//! morning on a tunnel that is already down.
//!
//! # Why there is a repair as well as a setup
//!
//! Skipping what is already done makes the wizard safe to re-run, but it also
//! means a step that half-succeeded is skipped rather than corrected: a profile
//! whose route went into the wrong table, an interface that comes up and never
//! handshakes, a keepalive that was never written. Every one of those looks
//! installed and carries nothing, and from the tunnel's side they are
//! indistinguishable from a tunnel that is working. [`diagnose`] names them and
//! [`repair`] puts them right.
//!
//! So each step asks whether it has already been done and skips if so, which
//! makes the whole thing resumable by re-running it. Nothing is rolled back on
//! failure: a half-built WARP is closer to a working one than no WARP, and
//! tearing down an interface that other things may already be using is a worse
//! surprise than leaving it. `revert` undoes it deliberately.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::setup::{ask, yes_no};

pub(crate) mod monitor;

/// Where wgcf's account and profile live.
const STATE_DIR: &str = "/etc/paqetz/warp";

/// Where the wgcf binary is installed.
const WGCF_BIN: &str = "/usr/local/bin/wgcf";

/// The repository wgcf is published from.
const WGCF_REPO: &str = "ViRb3/wgcf";

/// The interface name, and the `wg-quick` unit instance that carries it.
pub(crate) const IFACE: &str = "warp";

/// The routing table holding WARP's default route.
///
/// `wg-quick` puts the route there rather than in the main table when the
/// profile carries `Table = <n>`, which is the whole reason this arrangement is
/// safe: the host's own traffic is untouched, and only what is deliberately
/// directed at this table leaves that way. 51820 is WireGuard's port, used as a
/// table number by convention.
const TABLE: u32 = 51_820;

/// The firewall mark on packets bound for a WARP destination.
///
/// Checked against the marks the configuration already uses before anything is
/// installed: two features writing the same mark is one of them silently
/// stealing the other's traffic.
const MARK: u32 = 0x57;

/// Priority of the policy rule sending marked packets to WARP's table.
///
/// Below the SOCKS5 mark rule and the blanket egress rule, so a host running
/// several of these has an order that does not depend on insertion time.
const RULE_PRIORITY: u32 = 9_050;

/// The nftables table this owns, entirely.
const NFT_TABLE: &str = "paqetz_warp";

/// Where the running relay list comes from.
const ONIONOO: &str =
    "https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses";

/// Reads the IPv4 addresses out of an onionoo `or_addresses` response.
///
/// Parsed by scanning for quoted `address:port` tokens rather than by decoding
/// the document, because the query asks for one field and that is the only
/// shape in it. Anything that is not an IPv4 address and port is skipped, so a
/// changed response yields fewer relays rather than nonsense -- and IPv6
/// addresses, which appear in the same field in brackets, fall out here because
/// the tunnel carries IPv4.
///
/// Returns them sorted and deduplicated: the same list twice must produce the
/// same ruleset, or a refresh that changed nothing still looks like a change.
pub(crate) fn parse_relays(body: &str) -> BTreeSet<Ipv4Addr> {
    body.split('"')
        .filter_map(|token| {
            let (host, port) = token.rsplit_once(':')?;
            // Both halves must parse, so that a bare address or a fragment of
            // some other field cannot be mistaken for a relay.
            port.parse::<u16>().ok()?;
            let addr: Ipv4Addr = host.parse().ok()?;
            // A relay on one of these would be unreachable anyway, and routing
            // a private range out through WARP would take the host's own
            // traffic with it.
            (!addr.is_private()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_unspecified()
                && !addr.is_broadcast()
                && !addr.is_multicast())
            .then_some(addr)
        })
        .collect()
}

/// The nftables script that installs the table, its set, and its rules.
///
/// Both rules carry a counter. Without one there is no way to answer "is this
/// working", which on a feature whose whole job is to send *some* traffic
/// elsewhere is the only question anyone will ask: a zero on the mark rule says
/// nothing is being selected, and a zero on the translation says nothing is
/// leaving that way.
///
/// `add` then `delete` then define, which is how every ruleset here is written:
/// one transaction, the same result whether or not anything was there before,
/// and a refresh is the identical script with different elements rather than a
/// separate code path that could disagree with this one.
pub(crate) fn nft_script(device: &str, destinations: &BTreeSet<String>) -> String {
    let elements = if destinations.is_empty() {
        String::new()
    } else {
        let joined = destinations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        format!("        elements = {{ {joined} }}\n")
    };
    format!(
        "add table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    set dest4 {{
        type ipv4_addr
        flags interval
        auto-merge
{elements}    }}
    chain paqetz_mark {{
        type filter hook prerouting priority mangle; policy accept;
        iifname \"{device}\" ip daddr @dest4 counter meta mark set {MARK:#x}
    }}
    chain paqetz_nat {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"{IFACE}\" counter masquerade
    }}
}}
"
    )
}

/// The script that removes everything the one above installed.
pub(crate) fn nft_revert() -> String {
    format!("add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n")
}

/// A mark already spoken for, if this one is.
///
/// Two features writing the same mark is one of them silently stealing the
/// other's traffic, and the symptom is traffic leaving by the wrong interface
/// with every counter looking healthy.
pub(crate) fn mark_taken(mark: u32, cfg: &crate::config::Config) -> Option<String> {
    for tunnel in &cfg.tunnels {
        if tunnel.interface.route_marked == Some(mark) {
            return Some(format!("{}'s route_marked", tunnel.name));
        }
        if tunnel.socks5.as_ref().is_some_and(|s| s.mark == mark) {
            return Some(format!("{}'s socks5 mark", tunnel.name));
        }
    }
    None
}

/// Rewrites a wgcf profile so it does not take over the host.
///
/// Two changes, both about not being a default VPN. `Table` puts WARP's route
/// in its own table, so nothing reaches it that was not sent there on purpose
/// -- without it, `wg-quick` installs a default route and the host's traffic,
/// including the tunnel's own carrier and the SSH session running this, leaves
/// through Cloudflare. And the `PostUp` rules wgcf writes install their own
/// masquerade and rule set, which would sit alongside the ones here doing
/// almost but not quite the same thing.
pub(crate) fn profile_for_table(profile: &str, table: u32) -> String {
    let mut out = String::with_capacity(profile.len() + 32);
    let mut in_interface = false;
    let mut wrote_table = false;
    for line in profile.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            // Leaving the [Interface] section is the last chance to add what it
            // was missing.
            if in_interface && !wrote_table {
                out.push_str(&format!("Table = {table}\n"));
                wrote_table = true;
            }
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
        }
        let key = trimmed
            .split_once('=')
            .map(|(k, _)| k.trim().to_ascii_lowercase());
        match key.as_deref() {
            Some("table") if in_interface => {
                out.push_str(&format!("Table = {table}\n"));
                wrote_table = true;
                continue;
            }
            Some("postup" | "predown" | "postdown") if in_interface => continue,
            _ => {}
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_interface && !wrote_table {
        out.push_str(&format!("Table = {table}\n"));
    }
    out
}

/// Runs a command, returning its standard output.
fn capture(program: &str, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| crate::service::spawn_failure(program, &e))?;
    if !out.status.success() {
        return Err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether a systemd unit is loaded and running.
fn unit_active(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether an interface exists on this host.
fn interface_exists(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// The architecture suffix wgcf publishes for this machine.
fn arch_name() -> Result<&'static str, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("uname").arg("-m").output()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "x86_64" | "amd64" => Ok("amd64"),
        "aarch64" | "arm64" => Ok("arm64"),
        "armv7l" => Ok("armv7"),
        other => Err(format!("no wgcf build published for this architecture ({other})").into()),
    }
}

/// Everything this needs from the host, checked before anything is changed.
///
/// The same rule the Xray install follows: finding out that the thing which
/// brings the interface up is missing, having already downloaded a binary and
/// registered an account with Cloudflare, is a worse way to learn it. Each
/// entry names the package, because "wg-quick is missing" and "install
/// wireguard-tools" are not the same sentence to somebody who has not met
/// WireGuard before.
fn preflight() -> Result<(), Box<dyn std::error::Error>> {
    for (tool, package, why) in [
        ("curl", "curl", "fetch wgcf and the relay list"),
        ("sha256sum", "coreutils", "verify the download"),
        ("nft", "nftables", "install the destination rules"),
        ("wg-quick", "wireguard-tools", "bring the WARP interface up"),
    ] {
        let found = std::process::Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !found {
            return Err(format!(
                "`{tool}` is missing, and is needed to {why}.\n\
                 Install it and run this again:\n\n    \
                 apt install -y {package}\n\n\
                 Nothing has been changed on this host."
            )
            .into());
        }
    }
    Ok(())
}

/// Step one: put the wgcf binary in place.
///
/// Skipped when it is already there. The digest is not optional -- a release
/// whose checksum cannot be fetched is one that cannot be verified, and this
/// binary is about to be run as root.
fn install_wgcf() -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(WGCF_BIN).exists() {
        println!("  wgcf is already installed");
        return Ok(());
    }
    let arch = arch_name()?;
    let body = capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "20",
            &format!("https://api.github.com/repos/{WGCF_REPO}/releases/latest"),
        ],
    )?;
    let version = body
        .split('"')
        .skip_while(|s| *s != "tag_name")
        .nth(2)
        .ok_or("could not read the latest wgcf version from GitHub")?
        .to_owned();

    let base = format!("https://github.com/{WGCF_REPO}/releases/download/{version}");
    let file = format!("wgcf_{}_linux_{arch}", version.trim_start_matches('v'));
    let tmp = std::env::temp_dir().join(&file);
    let tmp_path = tmp.display().to_string();

    println!("  fetching {base}/{file}");
    capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "120",
            "-o",
            &tmp_path,
            &format!("{base}/{file}"),
        ],
    )?;

    println!("  fetching the checksums");
    let sums = capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "60",
            &format!("{base}/checksums.txt"),
        ],
    )
    .map_err(|e| -> Box<dyn std::error::Error> {
        format!(
            "could not fetch the checksums for wgcf: {e}\n\
             Refusing to install an unverified binary."
        )
        .into()
    })?;
    let expected = sums
        .lines()
        .find(|l| l.ends_with(&file))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| format!("the checksum file carries no line for {file}"))?
        .to_ascii_lowercase();
    let actual = capture("sha256sum", &[&tmp_path])?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if expected != actual {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "the wgcf download does not match its published digest.\n  \
             expected {expected}\n  got      {actual}"
        )
        .into());
    }

    crate::service::run_elevated("install", &["-m", "0755", &tmp_path, WGCF_BIN])?;
    let _ = std::fs::remove_file(&tmp);
    println!("  installed wgcf {version}");
    Ok(())
}

/// Step two: register a free WARP account, if there is not one already.
///
/// The account file is the identity: registering again produces a different
/// one and orphans the first, so this never runs twice.
fn register(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let account = dir.join("wgcf-account.toml");
    if account.exists() {
        println!("  a WARP account is already registered");
        return Ok(());
    }
    println!("  registering a free WARP account with Cloudflare");
    let out = std::process::Command::new(WGCF_BIN)
        .args(["register", "--accept-tos"])
        .current_dir(dir)
        .output()
        .map_err(|e| crate::service::spawn_failure(WGCF_BIN, &e))?;
    if !out.status.success() {
        return Err(format!(
            "`wgcf register` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    // Readable only by root: it is the credential for the account.
    let _ = std::fs::set_permissions(
        &account,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    Ok(())
}

/// Step three: generate the WireGuard profile and put it where wg-quick reads.
fn generate_profile(dir: &Path, inner_mtu: u32) -> Result<(), Box<dyn std::error::Error>> {
    let installed = format!("/etc/wireguard/{IFACE}.conf");
    if Path::new(&installed).exists() {
        println!("  {installed} is already in place");
        return Ok(());
    }
    let profile = dir.join("wgcf-profile.conf");
    if !profile.exists() {
        let out = std::process::Command::new(WGCF_BIN)
            .arg("generate")
            .current_dir(dir)
            .output()
            .map_err(|e| crate::service::spawn_failure(WGCF_BIN, &e))?;
        if !out.status.success() {
            return Err(format!(
                "`wgcf generate` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )
            .into());
        }
    }
    let text = std::fs::read_to_string(&profile)?;
    let adjusted = without_narrow_mtu(
        &with_keepalive(&profile_for_table(&text, TABLE), KEEPALIVE),
        inner_mtu,
    );
    let staged = dir.join("warp.conf");
    std::fs::write(&staged, &adjusted)?;
    let _ = std::fs::set_permissions(&staged, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    crate::service::run_elevated("install", &["-d", "-m", "0700", "/etc/wireguard"])?;
    crate::service::run_elevated(
        "install",
        &["-m", "0600", &staged.display().to_string(), &installed],
    )?;
    println!("  wrote {installed} with Table = {TABLE}");
    Ok(())
}

/// Step four: bring the interface up, and keep it up across reboots.
fn bring_up() -> Result<(), Box<dyn std::error::Error>> {
    let unit = format!("wg-quick@{IFACE}");
    if unit_active(&unit) && interface_exists(IFACE) {
        println!("  {IFACE} is already up");
        return Ok(());
    }
    crate::service::run_elevated("systemctl", &["enable", "--now", &unit]).map_err(|e| {
        format!(
            "{e}\n\n\
             If it says the unit does not exist, `wg-quick@.service` comes from \
             wireguard-tools:\n\n    apt install -y wireguard-tools\n\n\
             Then run `paqetz warp setup` again -- what is already done is \
             detected and skipped."
        )
    })?;
    if !interface_exists(IFACE) {
        return Err(format!(
            "`{unit}` started but there is no {IFACE} interface. \
             `journalctl -u {unit}` will say why; `wireguard-tools` \
             (`apt install wireguard-tools`) is the usual missing piece."
        )
        .into());
    }
    println!("  {IFACE} is up");
    Ok(())
}

/// Step five: the policy rule that sends marked packets to WARP's table.
///
/// Deleted before it is added, because `ip rule add` is not idempotent: run
/// twice it installs the rule twice, and the duplicate is invisible until
/// somebody reads `ip rule` and wonders.
fn install_rule() -> Result<(), Box<dyn std::error::Error>> {
    let mark = format!("{MARK:#x}");
    let table = TABLE.to_string();
    let priority = RULE_PRIORITY.to_string();
    let args = [
        "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &priority,
    ];
    // Failure here is the ordinary case: there was nothing to delete.
    let _ = std::process::Command::new("ip").args(args).output();
    crate::service::run_elevated(
        "ip",
        &[
            "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &priority,
        ],
    )?;
    println!("  marked packets ({mark}) now look up table {table}");
    Ok(())
}

/// Removes that rule.
fn remove_rule() {
    let mark = format!("{MARK:#x}");
    let table = TABLE.to_string();
    let priority = RULE_PRIORITY.to_string();
    let _ = std::process::Command::new("ip")
        .args([
            "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &priority,
        ])
        .output();
}

/// Fetches the running Tor relays.
fn fetch_relays() -> Result<BTreeSet<Ipv4Addr>, Box<dyn std::error::Error>> {
    println!("  fetching the running relay list");
    let body = capture("curl", &["-fsSL", "--max-time", "60", ONIONOO])?;
    let relays = parse_relays(&body);
    if relays.is_empty() {
        return Err("the relay list came back with no usable addresses".into());
    }
    println!("  {} relays", relays.len());
    Ok(relays)
}

/// Where the destinations that are not relays are remembered.
///
/// Kept because a refresh replaces the whole set in one transaction, and one
/// that dropped whatever was added by hand would quietly stop routing it.
fn extras_path() -> String {
    format!("{STATE_DIR}/destinations")
}

/// Reads them back.
fn read_extras() -> BTreeSet<String> {
    std::fs::read_to_string(extras_path())
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Loads the set, whatever it should now contain, in one transaction.
///
/// The refresh path and the setup path are the same call, so a list that
/// changed daily cannot drift away from what was installed once.
fn load_set(
    device: &str,
    destinations: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    paqetz_fw::nft_script(&nft_script(device, destinations))?;
    println!(
        "  {} destinations routed through {IFACE}",
        destinations.len()
    );
    Ok(())
}

/// The unit and timer that keep the relay list current.
///
/// A timer that only re-downloaded a file would be doing nothing: the set the
/// kernel matches on is what has to change, so the unit runs `warp refresh`,
/// which fetches *and* reloads the table in one transaction.
fn timer_units(binary: &str, config: &str) -> (String, String) {
    let service = format!(
        "[Unit]\n\
         Description=Refresh the destinations routed through WARP\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={binary} warp refresh -c {config}\n"
    );
    let timer = "[Unit]\n\
         Description=Refresh the destinations routed through WARP\n\
         \n\
         [Timer]\n\
         OnCalendar=daily\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
        .to_owned();
    (service, timer)
}

/// Installs those units and starts the timer.
fn install_timer(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let binary = std::env::current_exe()?.display().to_string();
    let (service, timer) = timer_units(&binary, &config.display().to_string());
    let dir = std::env::temp_dir();
    let s = dir.join("paqetz-warp-refresh.service");
    let t = dir.join("paqetz-warp-refresh.timer");
    std::fs::write(&s, service)?;
    std::fs::write(&t, timer)?;
    for (from, to) in [
        (&s, "/etc/systemd/system/paqetz-warp-refresh.service"),
        (&t, "/etc/systemd/system/paqetz-warp-refresh.timer"),
    ] {
        crate::service::run_elevated("install", &["-m", "0644", &from.display().to_string(), to])?;
    }
    crate::service::run_elevated("systemctl", &["daemon-reload"])?;
    crate::service::run_elevated(
        "systemctl",
        &["enable", "--now", "paqetz-warp-refresh.timer"],
    )?;
    println!("  the relay list will refresh daily");
    Ok(())
}

/// The whole thing, one question at a time.
///
/// # Errors
/// Returns the first step that failed. Everything before it stays in place and
/// is skipped on the next run, so the fix is to address what it said and run
/// this again rather than to start over.
pub(crate) fn setup(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::Config::load(config)?;
    let tunnel = cfg
        .tunnels
        .first()
        .ok_or("the configuration has no tunnel in it")?;

    // The client end has nothing to gain: it already sends everything to the
    // server, and what a destination sees is decided there.
    if tunnel.peer.endpoint.is_some() {
        return Err(
            "this is the client end -- it reaches the internet through the server, so \
                    routing it through WARP would change nothing any destination sees. Run \
                    this on the server."
                .into(),
        );
    }
    if let Some(owner) = mark_taken(MARK, &cfg) {
        return Err(format!(
            "mark {MARK:#x} is already {owner}. Two features writing one mark means one of \
             them silently takes the other's traffic; change that setting first."
        )
        .into());
    }

    println!("Cloudflare WARP gives this server a second address to leave by.");
    println!("Destinations that refuse datacentre addresses -- Tor relays being");
    println!("the usual case -- see WARP's instead.\n");

    let all = yes_no(
        "1. Send everything the tunnel forwards out through WARP?\n   \
         No routes only the destinations you choose, and leaves everything\n   \
         else on this server's own address.",
        false,
    )?;

    let mut destinations = read_extras();
    let mut tor = false;
    if !all {
        tor = yes_no(
            "\n2. Include the Tor relays?\n   \
             Most hosting providers cannot reach them, which is what this\n   \
             works around. The list is fetched now and refreshed daily.",
            true,
        )?;
        let more = ask(
            "\n3. Any other addresses or ranges, comma separated (blank for none)",
            "",
        )?;
        for entry in more.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            validate_destination(entry)?;
            destinations.insert(entry.to_owned());
        }
        if !tor && destinations.is_empty() {
            return Err("nothing was chosen to route through WARP".into());
        }
    }

    preflight()?;

    println!("\n--- installing ---");
    let dir = Path::new(STATE_DIR);
    crate::service::run_elevated("install", &["-d", "-m", "0700", STATE_DIR])?;
    install_wgcf()?;
    register(dir)?;
    generate_profile(dir, tunnel.interface.mtu)?;
    bring_up()?;
    confirm_handshake()?;
    confirm_reach()?;

    if all {
        // The blanket shape is the existing `egress` setting, whose source rule
        // would swallow anything selective anyway.
        paqetz_fw::nft_script(&nft_revert())?;
        remove_rule();
        println!("\nWARP is up. Add this to the server's [tunnel.interface] and restart:");
        println!("\n    egress = \"{IFACE}\"\n");
        println!("paqetz installs the rule and the translation for it from there.");
        return Ok(());
    }

    if !destinations.is_empty() {
        std::fs::write(
            extras_path(),
            destinations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        )?;
    }
    let mut all_destinations = destinations.clone();
    if tor {
        all_destinations.extend(fetch_relays()?.iter().map(ToString::to_string));
        std::fs::write(format!("{STATE_DIR}/tor"), "")?;
    }
    load_set(&tunnel.interface.device, &all_destinations)?;
    install_rule()?;
    if tor {
        install_timer(config)?;
    }

    println!("\nDone. `paqetz warp status` shows what is in place;");
    println!("`paqetz warp revert` takes it all out again.");
    Ok(())
}

/// Refuses a destination that would take more than it was meant to.
fn validate_destination(entry: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (host, prefix) = match entry.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (entry, None),
    };
    let addr: Ipv4Addr = host
        .parse()
        .map_err(|_| format!("{entry:?} is not an IPv4 address or range"))?;
    if let Some(prefix) = prefix {
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("{entry:?} has a prefix that is not a number"))?;
        if bits > 32 {
            return Err(format!("{entry:?} has a prefix longer than an address").into());
        }
        // A short prefix here is how "route Tor through WARP" becomes "route
        // everything through WARP" by accident, which is a different decision
        // and one the first question already offered.
        if bits < 8 {
            return Err(format!(
                "{entry:?} covers {} addresses. Routing that much through WARP is the \
                 first question, not this one.",
                1u64 << (32 - u32::from(bits))
            )
            .into());
        }
    }
    if addr.is_private() || addr.is_loopback() {
        return Err(format!(
            "{entry:?} is a private range. Sending it out through WARP would take this \
             host's own traffic with it."
        )
        .into());
    }
    Ok(())
}

/// Re-fetches the relay list and reloads the set.
///
/// # Errors
/// Returns the fetch or the reload failure. The set in the kernel is left as it
/// was until the new one is complete, because the whole table is replaced in
/// one transaction rather than emptied and refilled.
pub(crate) fn refresh(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::Config::load(config)?;
    let device = cfg
        .tunnels
        .first()
        .map(|t| t.interface.device.clone())
        .ok_or("the configuration has no tunnel in it")?;
    let mut destinations = read_extras();
    if Path::new(&format!("{STATE_DIR}/tor")).exists() {
        destinations.extend(fetch_relays()?.iter().map(ToString::to_string));
    }
    if destinations.is_empty() {
        // Not an error: this is what the daily timer runs, and a server that
        // sends everything through WARP has no list to keep current. Failing
        // here would put a red unit on the host every day for a tunnel that is
        // working exactly as configured.
        let blanket = cfg
            .tunnels
            .first()
            .is_some_and(|t| t.interface.egress.as_deref() == Some(IFACE));
        if blanket {
            println!(
                "Everything the tunnel forwards already goes through WARP (`egress = \"{IFACE}\"`),"
            );
            println!("so there is no destination list to refresh.");
        } else {
            println!("Nothing is configured to route through WARP.");
            println!("`paqetz warp setup` chooses what goes through it.");
        }
        return Ok(());
    }
    load_set(&device, &destinations)?;
    Ok(())
}

/// What is in place.
///
/// The shape is printed first, because the two shapes want different things
/// installed: reading "destination table present ... no" without knowing that
/// this server sends everything through WARP is reading a correct arrangement
/// as a broken one.
pub(crate) fn status(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match crate::config::Config::load(config) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            // Which shape is configured is read from the file, so a file that
            // does not parse makes every line below it a guess.
            println!("  {}: {e}", config.display());
            println!("  the shape below is what is installed, not what was asked for\n");
            None
        }
    };
    let tunnel = cfg.as_ref().and_then(|c| c.tunnels.first());
    let blanket = tunnel.is_some_and(|t| t.interface.egress.as_deref() == Some(IFACE));
    // Read once: the reach check fetches through WARP, and a broken one takes
    // seconds to say so.
    let want = tunnel.map_or(
        Want {
            table: TABLE,
            blanket: false,
            inner_mtu: 0,
            ipv6: false,
        },
        want_of,
    );
    let seen = observe(&want);

    let say = |name: &str, yes: bool| println!("  {name:.<38} {}", if yes { "yes" } else { "no" });
    let destinations = read_extras().len();
    println!(
        "  {:.<38} {}",
        "shape",
        if blanket {
            format!("everything the tunnel forwards (egress = \"{IFACE}\")")
        } else if destinations > 0 || Path::new(&format!("{STATE_DIR}/tor")).exists() {
            "selected destinations".to_owned()
        } else {
            "nothing routed through WARP yet".to_owned()
        }
    );
    say("wgcf installed", Path::new(WGCF_BIN).exists());
    say(
        "WARP account registered",
        Path::new(&format!("{STATE_DIR}/wgcf-account.toml")).exists(),
    );
    say(
        "profile installed",
        Path::new(&format!("/etc/wireguard/{IFACE}.conf")).exists(),
    );
    say("interface up", seen.interface);
    say("comes back after a reboot", seen.unit_enabled);
    say("watched by `warp monitor`", monitor::enabled());
    println!(
        "  {:.<38} {}",
        "last handshake",
        match seen.handshake {
            Handshake::Never => "never".to_owned(),
            Handshake::Ago(age) => format!("{age}s ago"),
            Handshake::Unknown => "cannot tell without root".to_owned(),
        }
    );
    println!(
        "  {:.<38} {}",
        "reaches past Cloudflare",
        match seen.reach {
            Reach::Beyond => "yes",
            Reach::OnlyCloudflare => "no, only Cloudflare answers",
            Reach::Nothing => "no, nothing answers",
            Reach::Unknown if !crate::service::is_root() => "cannot tell without root",
            Reach::Unknown => "not checked",
        }
    );

    if blanket {
        let rules = capture("ip", &["rule", "show"]).unwrap_or_default();
        say(
            "tunnel steered into WARP's table",
            rules.contains(&format!(
                "lookup {}",
                tunnel.map_or(TABLE, |t| t.interface.egress_table)
            )),
        );
    } else {
        let listed = capture("nft", &["list", "table", "inet", NFT_TABLE]).unwrap_or_default();
        say("destination table present", !listed.is_empty());
        let elements = listed
            .split_once("elements = {")
            .map_or(0, |(_, rest)| rest.matches(',').count() + 1);
        println!("  {:.<38} {elements}", "destinations");
        let rules = capture("ip", &["rule", "show"]).unwrap_or_default();
        say(
            "policy rule installed",
            rules.contains(&format!("lookup {TABLE}")),
        );
        say(
            "refresh timer enabled",
            unit_active("paqetz-warp-refresh.timer"),
        );
    }

    if tunnel.is_some() {
        let wrong = diagnose(&seen, &want);
        if !wrong.is_empty() {
            println!("\n{} thing(s) are not right:", wrong.len());
            for a in &wrong {
                println!(
                    "  {} {}",
                    if a.blocking { "[FAIL]" } else { "[warn]" },
                    a.detail
                );
            }
            println!("\n`paqetz warp repair` fixes what can be fixed from here.");
        }
    }
    Ok(())
}

/// Takes it all out again.
///
/// The account and the binary are left alone unless `purge`: the account is an
/// identity that cannot be recovered once discarded, and the binary is inert
/// where it sits.
pub(crate) fn revert(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _ = paqetz_fw::nft_script(&nft_revert());
    remove_rule();
    for unit in ["paqetz-warp-refresh.timer", &format!("wg-quick@{IFACE}")] {
        let _ = crate::service::run_elevated("systemctl", &["disable", "--now", unit]);
    }
    for file in [
        "/etc/systemd/system/paqetz-warp-refresh.timer",
        "/etc/systemd/system/paqetz-warp-refresh.service",
        &format!("/etc/wireguard/{IFACE}.conf"),
    ] {
        let _ = crate::service::run_elevated("rm", &["-f", file]);
    }
    let _ = crate::service::run_elevated("systemctl", &["daemon-reload"]);
    monitor::remove_units();
    println!("Routing, interface and timers removed.");
    if purge {
        let _ = crate::service::run_elevated("rm", &["-rf", STATE_DIR]);
        let _ = crate::service::run_elevated("rm", &["-f", WGCF_BIN]);
        println!("The WARP account and wgcf are gone as well.");
    } else {
        println!("The WARP account and wgcf were left in place; --purge removes them.");
        println!("If the server config still has `egress`, take that out and restart.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Diagnosis and repair
// ---------------------------------------------------------------------------

/// The keepalive written into the profile.
///
/// WireGuard sends nothing when there is nothing to send, so a WARP session
/// that goes quiet loses whatever mapping the path was holding for it. The
/// first packet after that is dropped, and the tunnel it was forwarded from
/// sees a stall rather than a refusal.
const KEEPALIVE: u32 = 25;

/// Endpoints tried when the configured one never answers.
///
/// Cloudflare answers WARP on one anycast address across many ports, and a
/// network that drops 2408 usually leaves the others alone. The first that
/// completes a handshake is written back to the profile.
const ENDPOINTS: [&str; 8] = [
    "162.159.192.1:2408",
    "162.159.192.1:500",
    "162.159.192.1:1701",
    "162.159.192.1:4500",
    "162.159.193.10:2408",
    "162.159.195.1:928",
    "188.114.98.224:2408",
    "188.114.99.7:955",
];

/// What the arrangement is meant to be, read from the configuration.
#[derive(Debug, Clone)]
pub(crate) struct Want {
    /// The table the configuration steers the tunnel's traffic into.
    pub(crate) table: u32,
    /// Whether everything the tunnel forwards goes through WARP.
    pub(crate) blanket: bool,
    /// The tunnel's inner MTU.
    pub(crate) inner_mtu: u32,
    /// Whether the tunnel carries IPv6.
    pub(crate) ipv6: bool,
}

/// The installed profile, or why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Profile {
    /// Its text.
    Read(String),
    /// There is none.
    Absent,
    /// Whether there is one cannot be told: /etc/wireguard is root-only, so a
    /// process that is not root cannot tell absent from unreadable.
    Unreadable,
}

/// When WARP last completed a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handshake {
    /// Never, so anything sent into the interface is discarded.
    Never,
    /// This many seconds ago.
    Ago(u64),
    /// `wg` could not be asked, usually for want of privilege.
    Unknown,
}

/// How far past Cloudflare WARP carries traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Sites outside Cloudflare answer through it.
    Beyond,
    /// Cloudflare answers through it and nothing else does: the edge accepts
    /// each connection and never delivers it.
    OnlyCloudflare,
    /// Nothing answers through it, Cloudflare included.
    Nothing,
    /// Not asked: no interface, no handshake, no root, or no curl.
    Unknown,
}

/// What one request through the interface came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Answered,
    Silent,
    /// Could not be asked, for a reason that is this host's rather than WARP's.
    Unrunnable,
}

/// What the host shows about WARP right now. Gathered by reading only.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    /// Whether the interface exists.
    pub(crate) interface: bool,
    /// Whether the unit is enabled, so the interface returns after a reboot.
    pub(crate) unit_enabled: bool,
    /// The installed profile.
    pub(crate) profile: Profile,
    /// When the last handshake was.
    pub(crate) handshake: Handshake,
    /// `ip -4 route show table <n>`.
    pub(crate) routes: String,
    /// The same for IPv6.
    pub(crate) routes6: String,
    /// The interface's MTU.
    pub(crate) mtu: Option<u32>,
    /// Whether the selective destination table is installed.
    pub(crate) selective: bool,
    /// How many destinations are written down for the selective shape.
    pub(crate) destinations: usize,
    /// Whether anything past Cloudflare answers through it.
    pub(crate) reach: Reach,
}

/// Something a repair can put right.
///
/// Ordered as they must be applied: a profile is rewritten before the
/// interface is restarted to read it, and an endpoint is only worth trying on
/// an interface that is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Fix {
    /// Rewrite the profile: its table, and the keepalive it was missing.
    Profile,
    /// Bring the interface up, and keep it up across reboots.
    Interface,
    /// Try Cloudflare's other endpoints until one answers.
    Endpoint,
    /// Take out the selective shape, which the blanket one has replaced.
    Selective,
    /// Load the destinations that are written down but not installed.
    Destinations,
}

/// One thing that is not as it should be.
#[derive(Debug, Clone)]
pub(crate) struct Ailment {
    /// What was checked.
    pub(crate) what: &'static str,
    /// What was observed.
    pub(crate) detail: String,
    /// What to do about it.
    pub(crate) remedy: String,
    /// Whether traffic is lost until it is fixed.
    pub(crate) blocking: bool,
    /// What `repair` would do, when it can do anything.
    pub(crate) fix: Option<Fix>,
}

impl Ailment {
    fn blocking(
        what: &'static str,
        detail: impl Into<String>,
        remedy: impl Into<String>,
        fix: Option<Fix>,
    ) -> Self {
        Self {
            what,
            detail: detail.into(),
            remedy: remedy.into(),
            blocking: true,
            fix,
        }
    }

    fn worth_knowing(
        what: &'static str,
        detail: impl Into<String>,
        remedy: impl Into<String>,
        fix: Option<Fix>,
    ) -> Self {
        Self {
            what,
            detail: detail.into(),
            remedy: remedy.into(),
            blocking: false,
            fix,
        }
    }
}

/// Reads a `Key = value` out of a wg-quick profile.
///
/// The key appears once in the sections wgcf writes, and which section it is in
/// is not ambiguous for any key asked about here.
fn profile_value(profile: &str, key: &str) -> Option<String> {
    profile.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().to_owned())
    })
}

/// Whether `ip route show table <n>` holds a default route by `interface`.
fn has_default(routes: &str, interface: &str) -> bool {
    routes.lines().any(|line| {
        line.split_whitespace().next() == Some("default")
            && line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| w.first() == Some(&"dev") && w.get(1) == Some(&interface))
    })
}

/// What is wrong with the WARP arrangement, given what the host shows.
///
/// Pure, so the awkward states -- a profile naming no table, an interface that
/// is up but has never handshaked -- are reachable by a test rather than only
/// by a host that is already in them.
pub(crate) fn diagnose(seen: &Seen, want: &Want) -> Vec<Ailment> {
    let mut out = Vec::new();

    let profile = match &seen.profile {
        Profile::Read(text) => Some(text.as_str()),
        Profile::Absent => {
            out.push(Ailment::blocking(
                "WARP profile",
                format!("/etc/wireguard/{IFACE}.conf is not there"),
                "run `paqetz warp setup`: there is nothing installed to repair",
                None,
            ));
            None
        }
        Profile::Unreadable => {
            out.push(Ailment::worth_knowing(
                "WARP profile",
                "not checked: /etc/wireguard is readable only by root",
                "run this as root to have the profile checked as well",
                None,
            ));
            None
        }
    };

    if let Some(profile) = profile {
        match profile_value(profile, "Table") {
            Some(t) if t.parse::<u32>() == Ok(want.table) => {}
            Some(t) => out.push(Ailment::blocking(
                "WARP routing table",
                format!(
                    "the profile routes into table {t}, the configuration steers into {}",
                    want.table
                ),
                format!(
                    "`paqetz warp repair` rewrites the profile to Table = {}",
                    want.table
                ),
                Some(Fix::Profile),
            )),
            None => out.push(Ailment::blocking(
                "WARP routing table",
                "the profile names no table, so wg-quick puts WARP's default route in main",
                "`paqetz warp repair` rewrites the profile. Until then everything this host \
                 sends, the tunnel's own carrier and the session reading this included, leaves \
                 through Cloudflare",
                Some(Fix::Profile),
            )),
        }
        if profile_value(profile, "PersistentKeepalive").is_none() {
            out.push(Ailment::worth_knowing(
                "WARP keepalive",
                "the profile sets no PersistentKeepalive",
                format!(
                    "`paqetz warp repair` adds PersistentKeepalive = {KEEPALIVE}. Without it a \
                     quiet WARP session loses whatever mapping the path held for it, and the \
                     traffic that wakes it is dropped rather than refused"
                ),
                Some(Fix::Profile),
            ));
        }
    }

    if !seen.interface {
        out.push(Ailment::blocking(
            "WARP interface",
            format!("there is no {IFACE} interface, so every packet steered into it is discarded"),
            "`paqetz warp repair` brings it up",
            Some(Fix::Interface),
        ));
        // Everything below is about an interface that is not there.
        return out;
    }

    if !seen.unit_enabled {
        out.push(Ailment::worth_knowing(
            "WARP after a reboot",
            format!("wg-quick@{IFACE} is not enabled, so {IFACE} does not come back on its own"),
            "`paqetz warp repair` enables it. Until then a reboot leaves the tunnel forwarding \
             into an interface that is gone",
            Some(Fix::Interface),
        ));
    }

    if !has_default(&seen.routes, IFACE) {
        out.push(Ailment::blocking(
            "WARP route",
            format!("table {} holds no default route by {IFACE}", want.table),
            format!(
                "`paqetz warp repair` restarts {IFACE}, which reinstalls it. A lookup that finds \
                 an empty table falls through to main, so the traffic leaves by this server's own \
                 address instead"
            ),
            Some(Fix::Interface),
        ));
    }
    if want.ipv6 && !has_default(&seen.routes6, IFACE) {
        out.push(Ailment::blocking(
            "WARP route (IPv6)",
            format!(
                "the tunnel carries IPv6 but table {} holds no IPv6 default by {IFACE}",
                want.table
            ),
            "check that this host has IPv6 enabled, then `paqetz warp repair`",
            Some(Fix::Interface),
        ));
    }

    match seen.handshake {
        Handshake::Never => out.push(Ailment::blocking(
            "WARP handshake",
            "WARP has never completed a handshake, so anything sent into it is discarded",
            "`paqetz warp repair` tries Cloudflare's other endpoints. A network that drops 2408 \
             usually leaves the rest alone",
            Some(Fix::Endpoint),
        )),
        // Only suspicious when something should have been keeping it fresh: an
        // idle session with no keepalive is meant to go quiet, and handshakes
        // again by itself as soon as there is a packet to carry.
        Handshake::Ago(age)
            if age > u64::from(KEEPALIVE) * 8
                && matches!(&seen.profile, Profile::Read(p) if profile_value(p, "PersistentKeepalive").is_some()) =>
        {
            out.push(Ailment::worth_knowing(
                "WARP handshake",
                format!("the last handshake was {age}s ago, with a keepalive set that should have refreshed it"),
                "`paqetz warp repair` tries Cloudflare's other endpoints",
                Some(Fix::Endpoint),
            ));
        }
        Handshake::Ago(_) | Handshake::Unknown => {}
    }

    match seen.reach {
        Reach::OnlyCloudflare => out.push(Ailment::blocking(
            "WARP egress",
            "WARP reaches Cloudflare and nothing past it: the edge accepts each connection \
             and never delivers it",
            "every forwarded connection opens and then hangs, so turn egress off to stay \
             online while this lasts. Whether Cloudflare is limiting this account or refusing \
             what it carries, a fresh registration is the way to find out: \
             `paqetz warp reregister`",
            None,
        )),
        Reach::Nothing => out.push(Ailment::blocking(
            "WARP egress",
            "WARP has handshaked and carries nothing, not even to Cloudflare",
            format!("`paqetz warp repair` restarts {IFACE}"),
            Some(Fix::Interface),
        )),
        Reach::Beyond | Reach::Unknown => {}
    }

    if let Some(mtu) = seen.mtu
        && mtu < want.inner_mtu
    {
        let detail = format!(
            "{IFACE} carries {mtu}, the tunnel carries {}",
            want.inner_mtu
        );
        let symptom = format!(
            "a forwarded packet larger than {mtu} is discarded on the way into WARP, which is \
             why a connection opens and then stops"
        );
        let narrow_uplink = format!(
            "this host's uplink is what is narrow, and the tunnel has to fit inside it: set \
             interface.mtu = {mtu} at both ends and restart both. Check it with `ping -M do -s \
             <mtu minus 28> -I <this end\'s tunnel address> 1.1.1.1`, because an MTU set too \
             large is discarded in silence rather than refused"
        );
        let pinned = match &seen.profile {
            Profile::Read(p) => profile_value(p, "MTU")
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|pin| *pin < want.inner_mtu),
            Profile::Absent | Profile::Unreadable => None,
        };
        out.push(match (pinned, &seen.profile) {
            (Some(pin), _) => Ailment::blocking(
                "WARP MTU",
                format!("{detail}, because the profile pins MTU = {pin}"),
                format!(
                    "`paqetz warp repair` removes the pin, so wg-quick sizes {IFACE} from this \
                     host's uplink: 1420 on an ordinary 1500 link. Until then {symptom}"
                ),
                Some(Fix::Profile),
            ),
            (None, Profile::Read(_)) => Ailment::blocking(
                "WARP MTU",
                detail,
                format!("{symptom}. The profile pins nothing, so {narrow_uplink}"),
                None,
            ),
            (None, _) => Ailment::blocking(
                "WARP MTU",
                detail,
                format!(
                    "{symptom}. If /etc/wireguard/{IFACE}.conf pins an MTU, `paqetz warp repair` \
                     removes it. If not, {narrow_uplink}"
                ),
                None,
            ),
        });
    }

    if want.blanket && (seen.selective || seen.destinations > 0) {
        out.push(Ailment::worth_knowing(
            "WARP shape",
            "everything the tunnel forwards goes through WARP, and the selective destination \
             table is still installed",
            "`paqetz warp repair` removes it. The blanket source rule already covers everything \
             it was matching, and the daily refresh has nothing left to refresh",
            Some(Fix::Selective),
        ));
    }
    if !want.blanket && seen.destinations > 0 && !seen.selective {
        out.push(Ailment::blocking(
            "WARP destinations",
            format!(
                "{} destinations are written down but no table is installed, so none of them \
                 leave by WARP",
                seen.destinations
            ),
            "`paqetz warp repair` loads the set",
            Some(Fix::Destinations),
        ));
    }

    out
}

/// What the configuration asks for.
fn want_of(tunnel: &crate::config::TunnelConfig) -> Want {
    Want {
        table: tunnel.interface.egress_table,
        blanket: tunnel.interface.egress.as_deref() == Some(IFACE),
        inner_mtu: tunnel.interface.mtu,
        ipv6: tunnel.carries_ipv6(),
    }
}

/// Reads the host. Changes nothing.
fn observe(want: &Want) -> Seen {
    let table = want.table.to_string();
    let path = format!("/etc/wireguard/{IFACE}.conf");
    let profile = match std::fs::read_to_string(&path) {
        Ok(text) => Profile::Read(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Profile::Absent,
        // Permission denied, and also the denial that reading /etc/wireguard
        // itself produces for a process that is not root.
        Err(_) => Profile::Unreadable,
    };
    let interface = interface_exists(IFACE);
    let handshake = handshake_age();
    Seen {
        interface,
        unit_enabled: unit_enabled(&format!("wg-quick@{IFACE}")),
        profile,
        handshake,
        routes: capture("ip", &["-4", "route", "show", "table", &table]).unwrap_or_default(),
        routes6: capture("ip", &["-6", "route", "show", "table", &table]).unwrap_or_default(),
        mtu: std::fs::read_to_string(format!("/sys/class/net/{IFACE}/mtu"))
            .ok()
            .and_then(|s| s.trim().parse().ok()),
        selective: capture("nft", &["list", "table", "inet", NFT_TABLE]).is_ok(),
        destinations: read_extras().len(),
        // Only asked of a link that could answer. A silent probe waits out its
        // timeout, and the checks before this one already say why a missing or
        // never-handshaked interface carries nothing.
        reach: if interface && matches!(handshake, Handshake::Ago(_)) {
            reach()
        } else {
            Reach::Unknown
        },
    }
}

/// Fetched through WARP to see whether it reaches past Cloudflare.
///
/// Neither is on Cloudflare's network, which is the point: anything that is
/// answers from the same edge that terminates the tunnel. Two operators, so
/// one having a bad day is not reported as WARP having one. Plain HTTP, since
/// any answer at all proves the path.
const BEYOND: [&str; 2] = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://detectportal.firefox.com/success.txt",
];

/// The control: Cloudflare's own edge, by address so no lookup is involved.
const CLOUDFLARE: &str = "http://1.1.1.1/";

/// Whether WARP carries anything past Cloudflare's edge.
///
/// A handshake proves only the leg to Cloudflare. The edge terminates each
/// connection itself, so a WARP that has stopped delivering still completes
/// every connect at once and then says nothing: to the tunnel, a forwarded
/// connection that opens and hangs. Only fetching something that is not
/// Cloudflare's shows it.
fn reach() -> Reach {
    // Binding to an interface can need privilege, and when it is refused curl
    // falls back to binding the interface's address, which routes out this
    // host's own uplink and answers a different question.
    if !crate::service::is_root() {
        return Reach::Unknown;
    }
    let mut beyond = Vec::with_capacity(BEYOND.len());
    for url in BEYOND {
        let answer = probe(url);
        if answer == Probe::Answered {
            return Reach::Beyond;
        }
        beyond.push(answer);
    }
    reach_of(&beyond, probe(CLOUDFLARE))
}

/// What the answers add up to.
fn reach_of(beyond: &[Probe], cloudflare: Probe) -> Reach {
    if beyond.contains(&Probe::Answered) {
        return Reach::Beyond;
    }
    if beyond.iter().all(|p| *p == Probe::Unrunnable) {
        return Reach::Unknown;
    }
    match cloudflare {
        Probe::Answered => Reach::OnlyCloudflare,
        Probe::Silent => Reach::Nothing,
        Probe::Unrunnable => Reach::Unknown,
    }
}

/// One request through the interface, reading only whether anything answered.
fn probe(url: &str) -> Probe {
    let Ok(out) = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-m",
            "5",
            "-w",
            "%{http_code}",
            "--interface",
            IFACE,
            url,
        ])
        .output()
    else {
        return Probe::Unrunnable;
    };
    match (
        String::from_utf8_lossy(&out.stdout).trim(),
        out.status.code(),
    ) {
        (code, _) if !code.is_empty() && code != "000" => Probe::Answered,
        // The name did not resolve, or the interface could not be bound: both
        // about this host rather than about WARP.
        (_, Some(6 | 45)) => Probe::Unrunnable,
        _ => Probe::Silent,
    }
}

/// Whether a systemd unit is enabled, which is a different question from
/// whether it is running now.
fn unit_enabled(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-enabled", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// Seconds since WARP last completed a handshake.
fn handshake_age() -> Handshake {
    let Ok(listed) = capture("wg", &["show", IFACE, "latest-handshakes"]) else {
        return Handshake::Unknown;
    };
    let newest = listed
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        .max()
        .unwrap_or(0);
    if newest == 0 {
        return Handshake::Never;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Handshake::Ago(now.saturating_sub(newest))
}

/// What a host in this state needs done, in the order it must be done.
fn fixes(ailments: &[Ailment]) -> Vec<Fix> {
    let mut out: Vec<Fix> = ailments.iter().filter_map(|a| a.fix).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Checks the WARP arrangement without changing anything.
///
/// Used by `paqetz doctor`, which is read-only by contract.
pub(crate) fn examine(tunnel: &crate::config::TunnelConfig) -> Vec<Ailment> {
    let want = want_of(tunnel);
    diagnose(&observe(&want), &want)
}

/// Puts the profile back the way this program installs it.
fn rewrite_profile(want: &Want) -> Result<(), Box<dyn std::error::Error>> {
    let path = format!("/etc/wireguard/{IFACE}.conf");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {path}: {e}. This needs root."))?;
    let fixed = without_narrow_mtu(
        &with_keepalive(&profile_for_table(&text, want.table), KEEPALIVE),
        want.inner_mtu,
    );
    if fixed == text {
        return Ok(());
    }
    let staged = std::env::temp_dir().join("paqetz-warp-repair.conf");
    std::fs::write(&staged, &fixed)?;
    let _ = std::fs::set_permissions(&staged, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    crate::service::run_elevated(
        "install",
        &["-m", "0600", &staged.display().to_string(), &path],
    )?;
    let _ = std::fs::remove_file(&staged);
    println!("  rewrote {path}");
    // The running interface still holds what the old file said.
    restart_interface()
}

/// Brings the interface up, enables it, and restarts it if it was already up.
fn revive_interface() -> Result<(), Box<dyn std::error::Error>> {
    let unit = format!("wg-quick@{IFACE}");
    crate::service::run_elevated("systemctl", &["enable", &unit])?;
    if unit_active(&unit) && interface_exists(IFACE) {
        return restart_interface();
    }
    crate::service::run_elevated("systemctl", &["start", &unit])?;
    if !interface_exists(IFACE) {
        return Err(format!(
            "`{unit}` started but there is no {IFACE} interface. `journalctl -u {unit}` will say \
             why."
        )
        .into());
    }
    println!("  {IFACE} is up, and enabled for the next boot");
    Ok(())
}

/// Restarts the interface so it reads the profile again.
fn restart_interface() -> Result<(), Box<dyn std::error::Error>> {
    crate::service::run_elevated("systemctl", &["restart", &format!("wg-quick@{IFACE}")])?;
    println!("  {IFACE} restarted");
    Ok(())
}

/// Adds a keepalive to the peer section, leaving one that is already there.
/// Drops an MTU the profile pins below what the tunnel carries.
///
/// wgcf writes 1280, which is what Cloudflare's own client picks for networks
/// it knows nothing about, and narrower than a tunnel carrying 1400: every
/// forwarded packet between the two sizes is discarded on the way in. Without
/// the line, wg-quick sizes the interface from the route to the endpoint, less
/// 80 for WireGuard over IPv6, which is 1420 on an ordinary 1500 uplink. A pin
/// at or above what the tunnel carries was put there on purpose, and stays.
pub(crate) fn without_narrow_mtu(profile: &str, inner_mtu: u32) -> String {
    let mut out = String::with_capacity(profile.len());
    let mut in_interface = false;
    for line in profile.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
        }
        let narrow = in_interface
            && trimmed.split_once('=').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("mtu")
                    && v.trim().parse::<u32>().is_ok_and(|m| m < inner_mtu)
            });
        if !narrow {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub(crate) fn with_keepalive(profile: &str, every: u32) -> String {
    if profile_value(profile, "PersistentKeepalive").is_some() {
        return profile.to_owned();
    }
    let mut out = String::with_capacity(profile.len() + 32);
    let mut in_peer = false;
    let mut written = false;
    for line in profile.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_peer && !written {
                out.push_str(&format!("PersistentKeepalive = {every}\n"));
                written = true;
            }
            in_peer = trimmed.eq_ignore_ascii_case("[peer]");
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_peer && !written {
        out.push_str(&format!("PersistentKeepalive = {every}\n"));
    }
    out
}

/// Replaces the peer's endpoint.
pub(crate) fn with_endpoint(profile: &str, endpoint: &str) -> String {
    let mut out = String::with_capacity(profile.len() + 32);
    for line in profile.lines() {
        if line
            .split_once('=')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("Endpoint"))
        {
            out.push_str(&format!("Endpoint = {endpoint}\n"));
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Tries Cloudflare's other endpoints until one completes a handshake.
///
/// The endpoint is changed on the running interface rather than through the
/// profile, so a candidate that does not answer costs one `wg set` instead of
/// an interface that goes down and comes back. Only the one that works is
/// written to the file.
fn rotate_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let peers = capture("wg", &["show", IFACE, "peers"])?;
    let peer = peers
        .split_whitespace()
        .next()
        .ok_or("the WARP interface has no peer to move")?
        .to_owned();
    let current = capture("wg", &["show", IFACE, "endpoints"])
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();

    for candidate in ENDPOINTS {
        if candidate == current {
            continue;
        }
        println!("  trying {candidate}");
        if crate::service::run_elevated(
            "wg",
            &[
                "set",
                IFACE,
                "peer",
                &peer,
                "persistent-keepalive",
                &KEEPALIVE.to_string(),
                "endpoint",
                candidate,
            ],
        )
        .is_err()
        {
            continue;
        }
        if handshake_within(std::time::Duration::from_secs(6)) {
            println!("  {candidate} answered");
            let path = format!("/etc/wireguard/{IFACE}.conf");
            if let Ok(text) = std::fs::read_to_string(&path) {
                let staged = std::env::temp_dir().join("paqetz-warp-endpoint.conf");
                std::fs::write(&staged, with_endpoint(&text, candidate))?;
                let _ = std::fs::set_permissions(
                    &staged,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                );
                crate::service::run_elevated(
                    "install",
                    &["-m", "0600", &staged.display().to_string(), &path],
                )?;
                let _ = std::fs::remove_file(&staged);
                println!("  written to {path}");
            }
            return Ok(());
        }
    }
    Err(format!(
        "none of {} Cloudflare endpoints completed a handshake. WARP is reachable from this host \
         on none of them, which is a property of the path rather than of this configuration. \
         `egress` will black-hole the tunnel's traffic until that changes.",
        ENDPOINTS.len()
    )
    .into())
}

/// Refuses to call the install finished until WARP has actually answered.
///
/// An interface that is up and has never handshaked discards everything sent
/// into it, and every other check in `status` says yes. Learning that after
/// `egress` has been wired up means learning it as a tunnel that stopped
/// carrying traffic, which is the failure this whole file exists to avoid.
fn confirm_handshake() -> Result<(), Box<dyn std::error::Error>> {
    if matches!(handshake_age(), Handshake::Ago(_)) {
        println!("  WARP has handshaked");
        return Ok(());
    }
    println!("  waiting for WARP to handshake");
    if handshake_within(std::time::Duration::from_secs(8)) {
        println!("  WARP has handshaked");
        return Ok(());
    }
    println!("  no answer on the configured endpoint; trying the others");
    rotate_endpoint()
}

/// Refuses to finish on a WARP that carries nothing past Cloudflare, which
/// would otherwise be found as a tunnel whose connections open and hang.
fn confirm_reach() -> Result<(), Box<dyn std::error::Error>> {
    match reach() {
        Reach::Beyond => {
            println!("  WARP reaches past Cloudflare");
            Ok(())
        }
        Reach::Unknown => {
            println!("  could not check whether WARP reaches past Cloudflare");
            Ok(())
        }
        Reach::OnlyCloudflare => Err("WARP reaches Cloudflare and nothing past it, so anything \
             forwarded into it would open and hang.\n  A fresh registration is the way to \
             find out whether it is this account: `paqetz warp reregister`."
            .into()),
        Reach::Nothing => Err(format!(
            "WARP has handshaked but carries nothing, not even to Cloudflare. \
             Try `paqetz warp repair`, which restarts {IFACE}."
        )
        .into()),
    }
}

/// Nudges the interface and waits for a handshake, for at most `patience`.
fn handshake_within(patience: std::time::Duration) -> bool {
    // A handshake only starts when there is something to send.
    let _ = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "-I", IFACE, "1.1.1.1"])
        .output();
    let deadline = std::time::Instant::now() + patience;
    while std::time::Instant::now() < deadline {
        if matches!(handshake_age(), Handshake::Ago(age) if age < 30) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Takes out the selective shape, which the blanket one has replaced.
fn drop_selective() -> Result<(), Box<dyn std::error::Error>> {
    let _ = paqetz_fw::nft_script(&nft_revert());
    remove_rule();
    let _ = crate::service::run_elevated(
        "systemctl",
        &["disable", "--now", "paqetz-warp-refresh.timer"],
    );
    let _ = std::fs::remove_file(format!("{STATE_DIR}/tor"));
    let _ = std::fs::remove_file(extras_path());
    println!("  the destination table, its rule and the daily refresh are gone");
    Ok(())
}

/// Fixes what can be fixed, and says what is left.
///
/// # Errors
/// Returns the first repair that failed. What was repaired before it stays
/// repaired, and running this again resumes from there.
pub(crate) fn repair(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::Config::load(config)?;
    let tunnel = cfg
        .tunnels
        .first()
        .ok_or("the configuration has no tunnel in it")?;
    if tunnel.peer.endpoint.is_some() {
        return Err(
            "this is the client end. WARP belongs on the server, which is the end that speaks to \
             the internet."
                .into(),
        );
    }

    let want = want_of(tunnel);
    let ailments = diagnose(&observe(&want), &want);
    if ailments.is_empty() {
        println!("Nothing to repair.");
        return Ok(());
    }

    println!("Found:");
    for a in &ailments {
        println!(
            "  {} {}",
            if a.blocking { "[FAIL]" } else { "[warn]" },
            a.detail
        );
    }

    let todo = fixes(&ailments);
    if todo.is_empty() {
        println!("\nNothing here can be repaired automatically:");
        for a in &ailments {
            println!("  {}", a.remedy);
        }
        return Ok(());
    }

    println!("\n--- repairing ---");
    for fix in todo {
        match fix {
            Fix::Profile => rewrite_profile(&want)?,
            Fix::Interface => revive_interface()?,
            Fix::Endpoint => rotate_endpoint()?,
            Fix::Selective => drop_selective()?,
            Fix::Destinations => {
                let mut destinations = read_extras();
                if Path::new(&format!("{STATE_DIR}/tor")).exists() {
                    destinations.extend(fetch_relays()?.iter().map(ToString::to_string));
                }
                load_set(&tunnel.interface.device, &destinations)?;
                install_rule()?;
            }
        }
    }

    let left = diagnose(&observe(&want), &want);
    println!();
    if left.is_empty() {
        println!("WARP is in order.");
    } else {
        println!("Still wrong:");
        for a in &left {
            println!("  {}\n    {}", a.detail, a.remedy);
        }
    }
    if want.blanket {
        println!("\nThe tunnel installs its source rule when it starts, so restart it:");
        println!("    systemctl restart paqetz");
    }
    Ok(())
}

/// Replaces the WARP account with a fresh one.
///
/// Cloudflare can stop carrying an account's traffic past its own edge while
/// the account still handshakes, and a new registration is what brings it
/// back. The old files are kept one registration deep, and put back if the new
/// one cannot be brought up at all, so a refused registration costs nothing
/// but the attempt.
pub(crate) fn reregister(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Up front rather than per step: a run that could move the old account
    // aside but not register a new one would leave nothing working.
    if !crate::service::is_root() {
        return Err("this replaces WARP's credentials, so it needs root: \
                    sudo paqetz warp reregister"
            .into());
    }
    let cfg = crate::config::Config::load(config)?;
    let tunnel = cfg
        .tunnels
        .first()
        .ok_or("the configuration has no tunnel in it")?;
    let files = registration_files();
    if !files
        .iter()
        .any(|f| f.ends_with("wgcf-account.toml") && Path::new(f).exists())
    {
        return Err(
            "there is no WARP registration to replace. `paqetz warp setup` makes the \
                    first one."
                .into(),
        );
    }
    preflight()?;
    install_wgcf()?;

    let unit = format!("wg-quick@{IFACE}");
    let previous = Path::new(STATE_DIR).join("previous");
    // One step back, not a history: an account that has been replaced is not
    // coming back into use.
    let _ = std::fs::remove_dir_all(&previous);
    std::fs::create_dir_all(&previous)?;
    let _ = crate::service::run_elevated("systemctl", &["stop", &unit]);
    set_aside(&files, &previous)?;
    println!("  the old registration is in {}", previous.display());

    let fresh = || -> Result<(), Box<dyn std::error::Error>> {
        let dir = Path::new(STATE_DIR);
        register(dir)?;
        generate_profile(dir, tunnel.interface.mtu)?;
        bring_up()?;
        confirm_handshake()
    };
    if let Err(e) = fresh() {
        let _ = crate::service::run_elevated("systemctl", &["stop", &unit]);
        put_back(&files, &previous)?;
        crate::service::run_elevated("systemctl", &["start", &unit])?;
        return Err(format!(
            "{e}\n  The previous registration is back in place, and {IFACE} is running on it."
        )
        .into());
    }

    match reach() {
        Reach::Beyond => println!("\nWARP has a new registration, and reaches past Cloudflare."),
        Reach::Unknown => println!(
            "\nWARP has a new registration. Whether it reaches past Cloudflare could not be \
             checked."
        ),
        // Kept rather than rolled back: the old one was being replaced for
        // failing the same way, and a fresh account is no worse.
        Reach::OnlyCloudflare => {
            return Err(format!(
                "the new registration reaches only Cloudflare as well, so it is not the \
                 account: Cloudflare is not carrying what this server sends through it. Turn \
                 egress off to stay online. The previous registration is in {}.",
                previous.display()
            )
            .into());
        }
        Reach::Nothing => {
            return Err(
                "the new registration handshakes and carries nothing. `paqetz warp repair` \
                 restarts it."
                    .into(),
            );
        }
    }
    Ok(())
}

/// The files one registration consists of: the account, the profile wgcf
/// generated from it, and the profile wg-quick reads.
fn registration_files() -> [String; 3] {
    [
        format!("{STATE_DIR}/wgcf-account.toml"),
        format!("{STATE_DIR}/wgcf-profile.conf"),
        format!("/etc/wireguard/{IFACE}.conf"),
    ]
}

/// Moves each of `files` that exists into `into`, under its own name.
fn set_aside(files: &[String], into: &Path) -> std::io::Result<()> {
    for file in files {
        let from = Path::new(file);
        if let Some(name) = from.file_name()
            && from.exists()
        {
            move_file(from, &into.join(name))?;
        }
    }
    Ok(())
}

/// Undoes [`set_aside`]: whatever is at each path now goes, and the kept copy
/// comes back. A file the attempt created where there was none before goes too,
/// or it would sit beside an account it does not belong to.
fn put_back(files: &[String], from: &Path) -> std::io::Result<()> {
    for file in files {
        let to = Path::new(file);
        let _ = std::fs::remove_file(to);
        if let Some(name) = to.file_name() {
            let kept = from.join(name);
            if kept.exists() {
                move_file(&kept, to)?;
            }
        }
    }
    Ok(())
}

/// A rename, or a copy and delete where the two paths are on different
/// filesystems and a rename cannot cross.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to).or_else(|_| {
        std::fs::copy(from, to)?;
        std::fs::remove_file(from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_registration_puts_the_old_one_back_exactly() {
        let root = std::env::temp_dir().join(format!("paqetz-rereg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let previous = root.join("previous");
        std::fs::create_dir_all(&previous).expect("temp dir");
        let at = |name: &str| root.join(name).display().to_string();
        let files = [
            at("wgcf-account.toml"),
            at("wgcf-profile.conf"),
            at("warp.conf"),
        ];
        std::fs::write(&files[0], "old account").expect("write");
        std::fs::write(&files[2], "old profile").expect("write");

        set_aside(&files, &previous).expect("set aside");
        assert!(!Path::new(&files[0]).exists() && !Path::new(&files[2]).exists());

        // The attempt got as far as a new account and a wgcf profile.
        std::fs::write(&files[0], "new account").expect("write");
        std::fs::write(&files[1], "new wgcf profile").expect("write");

        put_back(&files, &previous).expect("put back");
        let read = |f: &String| std::fs::read_to_string(f).expect("read");
        assert_eq!(read(&files[0]), "old account");
        assert_eq!(read(&files[2]), "old profile");
        assert!(
            !Path::new(&files[1]).exists(),
            "a profile generated for the refused account was left beside the old one"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn profile() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = abc\n\
             Address = 172.16.0.2/32\n\
             Table = {TABLE}\n\
             \n\
             [Peer]\n\
             PublicKey = def\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = engage.cloudflareclient.com:2408\n\
             PersistentKeepalive = {KEEPALIVE}\n"
        )
    }

    fn healthy() -> Seen {
        Seen {
            interface: true,
            unit_enabled: true,
            profile: Profile::Read(profile()),
            handshake: Handshake::Ago(12),
            routes: format!("default dev {IFACE} scope link\n"),
            routes6: format!("default dev {IFACE} metric 1024 pref medium\n"),
            mtu: Some(1280),
            selective: false,
            destinations: 0,
            reach: Reach::Beyond,
        }
    }

    fn blanket() -> Want {
        Want {
            table: TABLE,
            blanket: true,
            inner_mtu: 1280,
            ipv6: false,
        }
    }

    fn only(seen: &Seen, want: &Want) -> Ailment {
        let mut found = diagnose(seen, want);
        assert_eq!(found.len(), 1, "{found:#?}");
        found.remove(0)
    }

    #[test]
    fn a_warp_that_answers_only_for_cloudflare_is_found() {
        // What a Stockholm server showed: 1.1.1.1 answered through WARP,
        // Telegram and every website opened a connection and heard nothing.
        let found = only(
            &Seen {
                reach: Reach::OnlyCloudflare,
                ..healthy()
            },
            &blanket(),
        );
        assert!(found.blocking);
        assert!(found.detail.contains("nothing past it"), "{found:?}");
        assert!(found.remedy.contains("warp reregister"), "{found:?}");
    }

    #[test]
    fn what_the_probes_add_up_to() {
        use Probe::{Answered, Silent, Unrunnable};
        assert_eq!(reach_of(&[Silent, Answered], Silent), Reach::Beyond);
        assert_eq!(reach_of(&[Silent, Silent], Answered), Reach::OnlyCloudflare);
        assert_eq!(reach_of(&[Silent, Silent], Silent), Reach::Nothing);
        // A host whose own resolver is broken has not shown anything about
        // WARP, and saying WARP is broken would send the operator the wrong way.
        assert_eq!(
            reach_of(&[Unrunnable, Unrunnable], Answered),
            Reach::Unknown
        );
        assert_eq!(reach_of(&[Silent, Silent], Unrunnable), Reach::Unknown);
    }

    #[test]
    fn a_reach_that_could_not_be_checked_is_not_reported() {
        let seen = Seen {
            reach: Reach::Unknown,
            ..healthy()
        };
        assert!(diagnose(&seen, &blanket()).is_empty());
    }

    #[test]
    fn a_working_arrangement_has_nothing_to_say() {
        assert!(diagnose(&healthy(), &blanket()).is_empty());
    }

    #[test]
    fn a_profile_that_names_no_table_is_the_one_that_takes_the_host_with_it() {
        // wg-quick with no Table installs a default route in main, and then the
        // tunnel's own carrier -- and the session reading the output -- leave
        // through Cloudflare. Nothing else matters until it is fixed.
        let seen = Seen {
            profile: Profile::Read(profile().replace(&format!("Table = {TABLE}\n"), "")),
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Profile));
        assert!(found.detail.contains("names no table"), "{found:?}");
    }

    #[test]
    fn a_profile_routing_into_a_table_nothing_looks_in_is_found() {
        let seen = Seen {
            profile: Profile::Read(profile().replace(&format!("Table = {TABLE}"), "Table = 200")),
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Profile));
        assert!(found.detail.contains("200"), "{found:?}");
        assert!(found.detail.contains(&TABLE.to_string()), "{found:?}");
    }

    #[test]
    fn a_handshake_that_never_happened_is_a_black_hole_not_a_quiet_link() {
        // The whole failure this exists for: the interface is up, the routing
        // is right, and every packet steered into it is dropped because
        // Cloudflare's endpoint is unreachable from this network.
        let seen = Seen {
            handshake: Handshake::Never,
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Endpoint));
    }

    #[test]
    fn an_idle_session_without_a_keepalive_is_not_reported_as_broken() {
        // WireGuard sends nothing when there is nothing to send, so an old
        // handshake on a quiet link is what working looks like. Reporting it
        // would be inventing a fault.
        let quiet = profile().replace(&format!("PersistentKeepalive = {KEEPALIVE}\n"), "");
        let seen = Seen {
            profile: Profile::Read(quiet),
            handshake: Handshake::Ago(9_000),
            ..healthy()
        };
        let found = diagnose(&seen, &blanket());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(
            found.first().map(|a| a.what),
            Some("WARP keepalive"),
            "{found:#?}"
        );
    }

    #[test]
    fn an_idle_session_with_a_keepalive_that_should_have_refreshed_it_is_reported() {
        let seen = Seen {
            handshake: Handshake::Ago(9_000),
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(!found.blocking);
        assert_eq!(found.fix, Some(Fix::Endpoint));
    }

    #[test]
    fn wgcf_s_narrow_mtu_is_repaired_rather_than_worked_around() {
        let seen = Seen {
            mtu: Some(1280),
            profile: Profile::Read(profile().replace(
                "Address = 172.16.0.2/32\n",
                "Address = 172.16.0.2/32\nMTU = 1280\n",
            )),
            ..healthy()
        };
        let want = Want {
            inner_mtu: 1400,
            ..blanket()
        };
        let found = only(&seen, &want);
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Profile));
        assert!(found.detail.contains("MTU = 1280"), "{found:?}");
    }

    #[test]
    fn only_an_mtu_narrower_than_the_tunnel_is_taken_out() {
        let pinned = |mtu: &str| {
            format!(
                "[Interface]\nPrivateKey = abc\nMTU = {mtu}\n\n[Peer]\nPublicKey = def\nMTU = 1\n"
            )
        };
        let out = without_narrow_mtu(&pinned("1280"), 1400);
        assert!(!out.contains("MTU = 1280"), "{out}");
        // An operator's own wider value was chosen on purpose.
        assert_eq!(without_narrow_mtu(&pinned("1420"), 1400), pinned("1420"));
        // Only [Interface] sets the interface's MTU; a key of the same name
        // elsewhere is not this program's to touch.
        assert!(out.contains("MTU = 1\n"), "{out}");
        assert!(out.contains("PrivateKey = abc"), "{out}");
        // Run again, it changes nothing, so a repair does not restart WARP
        // for no reason.
        assert_eq!(without_narrow_mtu(&out, 1400), out);
    }

    #[test]
    fn a_tunnel_wider_than_warp_is_told_the_number_to_write() {
        // The symptom is a connection that opens and then stops: the handshake
        // fits, the first full-size packet does not.
        let seen = Seen {
            mtu: Some(1280),
            ..healthy()
        };
        let want = Want {
            inner_mtu: 1400,
            ..blanket()
        };
        let found = only(&seen, &want);
        assert!(found.blocking);
        assert!(found.remedy.contains("interface.mtu = 1280"), "{found:?}");
    }

    #[test]
    fn nothing_downstream_of_a_missing_interface_is_reported() {
        // An interface that is not there has no route, no handshake and no
        // MTU, and saying so three more times buries the one thing to do.
        let seen = Seen {
            interface: false,
            unit_enabled: false,
            handshake: Handshake::Never,
            routes: String::new(),
            routes6: String::new(),
            mtu: None,
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert_eq!(found.fix, Some(Fix::Interface));
        assert!(found.blocking);
    }

    #[test]
    fn an_empty_table_is_a_fall_through_to_the_servers_own_address() {
        // The quiet one. The rule matches, the lookup finds nothing, and the
        // traffic leaves by the address WARP was installed to avoid.
        let seen = Seen {
            routes: String::new(),
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Interface));
    }

    #[test]
    fn the_ipv6_half_is_only_asked_about_when_the_tunnel_carries_it() {
        let seen = Seen {
            routes6: String::new(),
            ..healthy()
        };
        assert!(diagnose(&seen, &blanket()).is_empty());
        let want = Want {
            ipv6: true,
            ..blanket()
        };
        let found = only(&seen, &want);
        assert!(found.blocking);
    }

    #[test]
    fn a_selective_table_left_behind_by_the_blanket_shape_is_taken_out() {
        let seen = Seen {
            selective: true,
            destinations: 3,
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(!found.blocking, "it steals no traffic, it only confuses");
        assert_eq!(found.fix, Some(Fix::Selective));
    }

    #[test]
    fn destinations_written_down_but_never_installed_are_a_fault() {
        let want = Want {
            blanket: false,
            ..blanket()
        };
        let seen = Seen {
            selective: false,
            destinations: 4,
            ..healthy()
        };
        let found = only(&seen, &want);
        assert!(found.blocking);
        assert_eq!(found.fix, Some(Fix::Destinations));
    }

    #[test]
    fn a_profile_that_cannot_be_read_is_not_a_profile_that_is_missing() {
        // doctor runs as whoever ran it, and /etc/wireguard is root-only.
        // "run this as root" and "run setup" are not the same sentence.
        let seen = Seen {
            profile: Profile::Unreadable,
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(!found.blocking);
        assert_eq!(found.fix, None);
        assert!(found.remedy.contains("root"), "{found:?}");
    }

    #[test]
    fn a_missing_profile_says_to_install_rather_than_to_repair() {
        let seen = Seen {
            profile: Profile::Absent,
            ..healthy()
        };
        let found = only(&seen, &blanket());
        assert!(found.blocking);
        assert_eq!(found.fix, None, "there is nothing installed to repair");
        assert!(found.remedy.contains("warp setup"), "{found:?}");
    }

    #[test]
    fn repairs_run_in_an_order_that_does_not_undo_itself() {
        // The profile is rewritten before the interface restarts to read it,
        // and an endpoint is only worth trying on an interface that is up.
        let ailments = vec![
            Ailment::blocking("c", "", "", Some(Fix::Endpoint)),
            Ailment::blocking("a", "", "", Some(Fix::Interface)),
            Ailment::blocking("b", "", "", Some(Fix::Profile)),
            Ailment::worth_knowing("d", "", "", Some(Fix::Profile)),
            Ailment::worth_knowing("e", "", "", None),
        ];
        assert_eq!(
            fixes(&ailments),
            vec![Fix::Profile, Fix::Interface, Fix::Endpoint]
        );
    }

    #[test]
    fn a_keepalive_goes_in_the_peer_section_where_wg_quick_reads_it() {
        let bare =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = def\nAllowedIPs = 0.0.0.0/0\n";
        let out = with_keepalive(bare, KEEPALIVE);
        assert_eq!(out.matches("PersistentKeepalive").count(), 1, "{out}");
        let at = out.find("PersistentKeepalive").expect("a keepalive");
        assert!(at > out.find("[Peer]").expect("a peer section"), "{out}");
        // And it lands in the section it belongs to rather than at the end of
        // the file, which is the same place only while [Peer] happens to be
        // last.
        let trailing = format!("{bare}\n[Interface]\nPrivateKey = ghi\n");
        let out = with_keepalive(&trailing, KEEPALIVE);
        let at = out.find("PersistentKeepalive").expect("a keepalive");
        assert!(
            at < out.rfind("[Interface]").expect("the later section"),
            "{out}"
        );
        // One that is already there was chosen by somebody, and is left.
        let already = with_keepalive(bare, KEEPALIVE).replace(&format!("= {KEEPALIVE}"), "= 15");
        let chosen = with_keepalive(&already, KEEPALIVE);
        assert!(chosen.contains("PersistentKeepalive = 15"), "{chosen}");
        assert_eq!(chosen.matches("PersistentKeepalive").count(), 1, "{chosen}");
    }

    #[test]
    fn moving_the_endpoint_replaces_the_line_rather_than_adding_one() {
        let out = with_endpoint(&profile(), "162.159.192.1:500");
        assert_eq!(out.matches("Endpoint =").count(), 1, "{out}");
        assert!(out.contains("Endpoint = 162.159.192.1:500"), "{out}");
        assert!(!out.contains("engage.cloudflareclient.com"), "{out}");
        // And nothing else moves.
        assert!(out.contains("PrivateKey = abc"), "{out}");
        assert!(out.contains(&format!("Table = {TABLE}")), "{out}");
    }

    #[test]
    fn every_endpoint_tried_is_an_address_and_a_port() {
        // A name that has to be resolved is one more thing that can fail on a
        // network where the usual endpoint is already unreachable.
        for candidate in ENDPOINTS {
            let parsed: std::net::SocketAddr = candidate
                .parse()
                .unwrap_or_else(|e| panic!("{candidate}: {e}"));
            assert!(parsed.port() > 0, "{candidate}");
        }
        let unique: BTreeSet<&str> = ENDPOINTS.iter().copied().collect();
        assert_eq!(unique.len(), ENDPOINTS.len(), "a candidate is listed twice");
    }

    #[test]
    fn a_default_route_is_read_off_the_device_it_names() {
        assert!(has_default("default dev warp scope link\n", "warp"));
        assert!(has_default(
            "default via 10.0.0.1 dev warp proto static\n",
            "warp"
        ));
        // Another interface's default in the same table is not this one's.
        assert!(!has_default("default dev eth0\n", "warp"));
        // Nor is a route to somewhere in particular that happens to use it.
        assert!(!has_default("1.1.1.1 dev warp scope link\n", "warp"));
        assert!(!has_default("", "warp"));
    }

    #[test]
    fn relays_are_read_out_of_what_onionoo_returns() {
        let body = r#"{"relays":[
            {"or_addresses":["45.66.35.10:9001","[2a0b:f4c1::1]:9001"]},
            {"or_addresses":["185.220.101.4:9000"]},
            {"or_addresses":["45.66.35.10:9001"]}
        ]}"#;
        let got = parse_relays(body);
        assert_eq!(got.len(), 2, "the repeat is one relay, not two");
        assert!(got.contains(&Ipv4Addr::new(45, 66, 35, 10)));
        assert!(got.contains(&Ipv4Addr::new(185, 220, 101, 4)));
    }

    #[test]
    fn nothing_that_is_not_a_routable_address_is_taken_for_a_relay() {
        // The response is parsed by shape rather than decoded, so anything that
        // is not an address and port has to fall out here -- and a private one
        // reaching the set would send this host's own traffic out through WARP.
        let body = r#"{"relays":[
            {"or_addresses":["10.0.0.1:9001","127.0.0.1:9001","192.168.1.1:9001",
                             "169.254.1.1:9001","0.0.0.0:9001","224.0.0.1:9001",
                             "not-an-address:9001","1.2.3.4:notaport","1.2.3.4",
                             "[2a0b:f4c1::1]:9001"]}
        ]}"#;
        assert!(parse_relays(body).is_empty(), "{:?}", parse_relays(body));
    }

    #[test]
    fn the_ruleset_selects_on_destination_and_leaves_everything_else() {
        let mut dests = BTreeSet::new();
        dests.insert("45.66.35.10".to_owned());
        dests.insert("185.220.101.0/24".to_owned());
        let script = nft_script("paqetz0", &dests);

        assert!(
            script.contains("elements = { 185.220.101.0/24, 45.66.35.10 }"),
            "{script}"
        );
        // Only what the tunnel forwards: the host's own traffic to the same
        // destination is not this feature's business.
        assert!(
            script.contains("iifname \"paqetz0\" ip daddr @dest4 counter meta mark set 0x57"),
            "{script}"
        );
        assert!(
            script.contains("oifname \"warp\" counter masquerade"),
            "{script}"
        );
        // The counters are the only way to answer "is this working", which is
        // the only question anyone asks of a feature that sends some traffic
        // elsewhere.
        assert_eq!(script.matches("counter").count(), 2, "{script}");
        // Add then delete then define: the same result whether or not anything
        // was there, in one transaction.
        assert!(
            script.starts_with(&format!(
                "add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n"
            )),
            "{script}"
        );
    }

    #[test]
    fn a_refresh_is_the_same_script_with_different_elements() {
        // The timer exists to change what the kernel matches on. If a refresh
        // took a different path from the install, the two could disagree about
        // everything except the elements.
        let empty = nft_script("paqetz0", &BTreeSet::new());
        let one: BTreeSet<String> = ["45.66.35.10".to_owned()].into_iter().collect();
        let full = nft_script("paqetz0", &one);
        let strip = |s: &str| {
            s.lines()
                .filter(|l| !l.trim_start().starts_with("elements ="))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&empty), strip(&full), "only the elements may differ");
        assert!(
            !empty.contains("elements"),
            "an empty set names no elements"
        );
    }

    #[test]
    fn the_profile_is_kept_out_of_the_main_routing_table() {
        // Without this, wg-quick installs a default route and every packet the
        // host sends -- the tunnel's own carrier, and the session running the
        // setup -- leaves through Cloudflare.
        let profile = "[Interface]\n\
                       PrivateKey = abc\n\
                       Address = 172.16.0.2/32\n\
                       DNS = 1.1.1.1\n\
                       PostUp = iptables -t nat -A POSTROUTING -j MASQUERADE\n\
                       \n\
                       [Peer]\n\
                       PublicKey = def\n\
                       AllowedIPs = 0.0.0.0/0\n\
                       Endpoint = engage.cloudflareclient.com:2408\n";
        let out = profile_for_table(profile, TABLE);

        assert!(out.contains(&format!("Table = {TABLE}")), "{out}");
        assert_eq!(out.matches("Table =").count(), 1, "exactly one: {out}");
        // In the interface section, not appended after the peer, where
        // wg-quick would not read it.
        let table_at = out.find("Table =").expect("a table line");
        assert!(
            table_at < out.find("[Peer]").expect("a peer section"),
            "{out}"
        );
        // wgcf's own masquerade would sit alongside the one installed here,
        // doing almost the same thing.
        assert!(!out.contains("PostUp"), "{out}");
        // And nothing else is disturbed.
        assert!(out.contains("PrivateKey = abc"));
        assert!(out.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(out.contains("Endpoint = engage.cloudflareclient.com:2408"));
    }

    #[test]
    fn a_profile_that_already_names_a_table_is_corrected_rather_than_doubled() {
        let profile = "[Interface]\nPrivateKey = abc\nTable = off\n\n[Peer]\nPublicKey = def\n";
        let out = profile_for_table(profile, TABLE);
        assert_eq!(out.matches("Table =").count(), 1, "{out}");
        assert!(out.contains(&format!("Table = {TABLE}")), "{out}");
        assert!(!out.contains("Table = off"), "{out}");
    }

    #[test]
    fn a_destination_that_would_take_more_than_asked_is_refused() {
        // The difference between "route Tor through WARP" and "route everything
        // through WARP" is a prefix length, and the second is the first
        // question rather than this one.
        for entry in [
            "0.0.0.0/0",
            "1.0.0.0/1",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "127.0.0.1",
        ] {
            assert!(validate_destination(entry).is_err(), "{entry} was accepted");
        }
        for entry in ["45.66.35.10", "185.220.101.0/24", "1.2.3.4/32"] {
            assert!(validate_destination(entry).is_ok(), "{entry} was refused");
        }
    }

    #[test]
    fn the_timer_reloads_the_table_rather_than_only_fetching() {
        // A timer that re-downloaded a file and stopped would leave the kernel
        // matching yesterday's relays for ever.
        let (service, timer) = timer_units("/usr/local/bin/paqetz", "/etc/paqetz/paqetz.toml");
        assert!(
            service.contains(
                "ExecStart=/usr/local/bin/paqetz warp refresh -c /etc/paqetz/paqetz.toml"
            ),
            "{service}"
        );
        assert!(timer.contains("OnCalendar=daily"), "{timer}");
        // Persistent, or a server that was off at the appointed hour waits a
        // whole day with a list that has already rotted.
        assert!(timer.contains("Persistent=true"), "{timer}");
        assert!(timer.contains("WantedBy=timers.target"), "{timer}");
    }

    #[test]
    #[ignore = "needs privilege: `nft -c` initialises a netlink cache"]
    fn nft_accepts_the_generated_ruleset() {
        // `mark` and `out` are keywords in nft's grammar, so naming chains
        // after what they do produced a ruleset that only failed on the host it
        // was meant for -- after the account had been registered and the
        // interface brought up. Nothing in a unit test catches that; only nft
        // can say whether nft will take it.
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut dests = BTreeSet::new();
        dests.insert("45.66.35.10".to_owned());
        // Overlapping on purpose: a range somebody adds by hand will sooner or
        // later contain a relay, and an interval set refuses that without
        // auto-merge.
        dests.insert("45.66.35.0/24".to_owned());
        dests.insert("185.220.101.4".to_owned());

        for script in [nft_script("paqetz0", &dests), nft_revert()] {
            let mut child = Command::new("nft")
                .args(["-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("nft");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(script.as_bytes())
                .expect("write");
            let out = child.wait_with_output().expect("wait");
            assert!(
                out.status.success(),
                "nft refused this:\n{script}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn every_tool_the_install_needs_is_named_with_its_package() {
        // The failure this exists for: wgcf downloaded, an account registered
        // with Cloudflare, a profile written -- and then `wg-quick@warp` does
        // not exist, because wireguard-tools was never installed. The check
        // belongs before the first change, and has to name the package: "wg-quick
        // is missing" is not a sentence anyone can act on.
        //
        // Asserted against the source of the check itself, because what matters
        // is that each tool carries a package name, and a tool added later
        // without one would pass any test written against a copy of the list.
        let source = include_str!("warp.rs");
        let table = source
            .split_once("fn preflight()")
            .expect("a preflight")
            .1
            .split_once("] {")
            .expect("a table of tools")
            .0;
        for tool in ["curl", "sha256sum", "nft", "wg-quick"] {
            assert!(
                table.contains(&format!("(\"{tool}\"")),
                "{tool} is not checked for"
            );
        }
        assert!(
            table.contains("wireguard-tools"),
            "the package is not named"
        );
        // Every entry is a triple of tool, package and reason, so a tool added
        // later without a package to install shows up as a short row.
        let entries = table.matches("(\"").count();
        assert!(entries >= 4, "the table lost an entry: {table}");
        assert!(
            table.matches(',').count() >= entries * 2,
            "each tool needs a package and a reason: {table}"
        );
    }

    #[test]
    fn a_mark_another_feature_already_uses_is_found() {
        let text = "[[tunnel]]\nname = \"one\"\n\
                    [tunnel.interface]\n\
                    private_key = \"QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y=\"\n\
                    address = \"10.7.0.1/24\"\n\
                    listen_port = 8443\n\
                    route_marked = 87\n\
                    route_table = 87\n\
                    [tunnel.peer]\n\
                    public_key = \"Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo=\"\n\
                    tunnel_address = \"10.7.0.2\"\n";
        let cfg = crate::config::Config::parse(text).expect("parse");
        assert_eq!(
            mark_taken(0x57, &cfg).as_deref(),
            Some("one's route_marked")
        );
        assert_eq!(mark_taken(0x99, &cfg), None);
    }
}
