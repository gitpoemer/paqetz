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
//! So each step asks whether it has already been done and skips if so, which
//! makes the whole thing resumable by re-running it. Nothing is rolled back on
//! failure: a half-built WARP is closer to a working one than no WARP, and
//! tearing down an interface that other things may already be using is a worse
//! surprise than leaving it. `revert` undoes it deliberately.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::setup::{ask, yes_no};

/// Where wgcf's account and profile live.
const STATE_DIR: &str = "/etc/paqetz/warp";

/// Where the wgcf binary is installed.
const WGCF_BIN: &str = "/usr/local/bin/wgcf";

/// The repository wgcf is published from.
const WGCF_REPO: &str = "ViRb3/wgcf";

/// The interface name, and the `wg-quick` unit instance that carries it.
const IFACE: &str = "warp";

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
fn generate_profile(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    let adjusted = profile_for_table(&text, TABLE);
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
    generate_profile(dir)?;
    bring_up()?;

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
        return Err("there is nothing configured to route through WARP".into());
    }
    load_set(&device, &destinations)?;
    Ok(())
}

/// What is in place.
pub(crate) fn status() -> Result<(), Box<dyn std::error::Error>> {
    let say = |name: &str, yes: bool| println!("  {name:.<38} {}", if yes { "yes" } else { "no" });
    say("wgcf installed", Path::new(WGCF_BIN).exists());
    say(
        "WARP account registered",
        Path::new(&format!("{STATE_DIR}/wgcf-account.toml")).exists(),
    );
    say(
        "profile installed",
        Path::new(&format!("/etc/wireguard/{IFACE}.conf")).exists(),
    );
    say("interface up", interface_exists(IFACE));
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
    println!("Routing, interface and timer removed.");
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

#[cfg(test)]
mod tests {
    use super::*;

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
