//! `paqetz init` and `paqetz setup` — getting from nothing to a working tunnel.
//!
//! The failure this exists to prevent is the one every keypair-based tunnel
//! has: two `keygen` runs produce four values, and *your private* goes in *your*
//! file while *your public* goes in *theirs*. Transpose any of it and the result
//! is silence — no error, no log line, because from each end's point of view
//! nothing arrived and nothing is wrong.
//!
//! So the keys are never handed over loose. Both pairs are generated at once and
//! written straight into two finished configuration files, with the addresses
//! already mirrored and each file labelled with the host it belongs on.
//!
//! Which leaves the second host. Whichever end runs `setup` first produces both
//! files; running it again on the other end must *use* the file it was handed
//! rather than generate a second pair, or it replaces the key the first host was
//! told to expect and produces exactly the silence described above. So `setup`
//! looks for that file, and offers to take it pasted in if it is not on disk
//! yet. Neither end is privileged here: either may go first.

use std::fmt::Write as _;
use std::io::{self, BufRead as _, Write as _};
use std::net::Ipv4Addr;
use std::path::Path;

use paqetz_core::KeyPair;

/// What a generated tunnel is called.
///
/// The device name, which is what `config migrate` names a converted file after
/// too — so a file written by `setup` and one converted from the original form
/// come out identical rather than differing by a label nobody chose.
const DEFAULT_NAME: &str = "paqetz0";

/// Everything the two configuration files are generated from.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// Where the client reaches the server.
    pub(crate) endpoint: String,
    /// The outer port the server listens on.
    pub(crate) port: u16,
    /// The server's address inside the tunnel.
    pub(crate) server_inner: Ipv4Addr,
    /// The client's address inside the tunnel.
    pub(crate) client_inner: Ipv4Addr,
    /// The tunnel subnet's prefix length.
    pub(crate) prefix: u8,
    /// Whether the server forwards and translates the client's traffic.
    pub(crate) gateway: bool,
    /// Whether the client sends all its traffic through the tunnel.
    pub(crate) route_all: bool,
    /// A SOCKS5 listener on the client, if wanted.
    pub(crate) socks5: Option<String>,
    /// An interface the server sends the forwarded traffic out by.
    pub(crate) egress: Option<String>,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            port: 9999,
            server_inner: Ipv4Addr::new(10, 7, 0, 1),
            client_inner: Ipv4Addr::new(10, 7, 0, 2),
            prefix: 24,
            gateway: true,
            route_all: false,
            socks5: None,
            egress: None,
        }
    }
}

/// Which end of the tunnel this host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Waits to be contacted.
    Server,
    /// Connects out.
    Client,
}

impl Role {
    /// The generated file this end runs.
    const fn file(self) -> &'static str {
        match self {
            Self::Server => "server.toml",
            Self::Client => "client.toml",
        }
    }
}

/// Whether this host should be offered the client's Xray inbound.
///
/// Everywhere but the server. That inbound carries a REALITY private key, and
/// it is the key for the leg between a user and the client host — the server
/// has no use for it, cannot answer the questions that produce it, and would be
/// left holding a copy after it was moved to where it belongs. `None` keeps the
/// offer, since generating both ends on a third machine is exactly what that
/// answer means.
const fn generates_client_inbound(role: Option<Role>) -> bool {
    !matches!(role, Some(Role::Server))
}

/// The two finished configuration files.
#[derive(Debug, Clone)]
pub(crate) struct Pair {
    /// Goes on the server.
    pub(crate) server: String,
    /// Goes on the client.
    pub(crate) client: String,
}

/// Generates both keypairs and renders both files.
///
/// # Errors
/// Returns an error if key generation fails.
pub(crate) fn render(plan: &Plan) -> Result<Pair, Box<dyn std::error::Error>> {
    let server = KeyPair::generate()?;
    let client = KeyPair::generate()?;

    let mut s = String::new();
    writeln!(
        s,
        "# paqetz — SERVER. This file belongs on the host with the"
    )?;
    writeln!(s, "# stable address, the one the client connects to.\n")?;
    // The form that can hold several tunnels, written even for one. A file that
    // grows a second destination later should not have to change shape first,
    // and one shape means one thing for everyone to learn.
    writeln!(s, "[[tunnel]]")?;
    writeln!(s, "name = {DEFAULT_NAME:?}\n")?;
    writeln!(s, "[tunnel.interface]")?;
    writeln!(s, "private_key = \"{}\"", server.private.to_base64())?;
    writeln!(s, "address = \"{}/{}\"", plan.server_inner, plan.prefix)?;
    writeln!(s, "listen_port = {}", plan.port)?;
    if plan.gateway {
        writeln!(s, "\n# Forward and translate the client's traffic to the")?;
        writeln!(s, "# internet. Without this the two ends can reach each")?;
        writeln!(s, "# other and nothing beyond.")?;
        writeln!(s, "gateway = true")?;
    }
    if let Some(iface) = plan.egress.as_ref() {
        writeln!(
            s,
            "\n# Send the forwarded traffic out this interface, so the"
        )?;
        writeln!(s, "# destination sees its address rather than this host's.")?;
        writeln!(s, "# Bringing it up is not paqetz's job.")?;
        writeln!(s, "egress = \"{iface}\"")?;
    }
    writeln!(s, "\n[tunnel.peer]")?;
    writeln!(s, "# The client's public key.")?;
    writeln!(s, "public_key = \"{}\"", client.public.to_base64())?;
    writeln!(s, "tunnel_address = \"{}\"", plan.client_inner)?;

    let mut c = String::new();
    writeln!(c, "# paqetz — CLIENT. This file belongs on the host that")?;
    writeln!(c, "# connects out.\n")?;
    writeln!(c, "[[tunnel]]")?;
    writeln!(c, "name = {DEFAULT_NAME:?}\n")?;
    writeln!(c, "[tunnel.interface]")?;
    writeln!(c, "private_key = \"{}\"", client.private.to_base64())?;
    writeln!(c, "address = \"{}/{}\"", plan.client_inner, plan.prefix)?;
    if plan.route_all {
        writeln!(c, "\n# Send this host's traffic through the tunnel. The")?;
        writeln!(c, "# tunnel's own packets are excepted automatically, so")?;
        writeln!(c, "# turning this on does not cut the connection.")?;
        writeln!(c, "route_all = true")?;
    }
    writeln!(c, "\n[tunnel.peer]")?;
    writeln!(c, "# The server's public key.")?;
    writeln!(c, "public_key = \"{}\"", server.public.to_base64())?;
    writeln!(c, "endpoint = \"{}\"", plan.endpoint)?;
    writeln!(c, "tunnel_address = \"{}\"", plan.server_inner)?;
    if plan.gateway {
        writeln!(
            c,
            "\n# What this peer may use as an inner source address. It defaults"
        )?;
        writeln!(
            c,
            "# to the peer's own address, which is right for a tunnel"
        )?;
        writeln!(
            c,
            "# between two hosts and wrong for one that is a way out:"
        )?;
        writeln!(
            c,
            "# replies arrive carrying the address of whatever site was"
        )?;
        writeln!(c, "# reached, not the server's, and would all be refused.")?;
        writeln!(c, "allowed_ips = [\"0.0.0.0/0\"]")?;
    }
    if let Some(listen) = plan.socks5.as_ref() {
        writeln!(c, "\n# A SOCKS5 listener, for pointing one program at the")?;
        writeln!(c, "# tunnel without routing the whole host through it.")?;
        writeln!(c, "[tunnel.socks5]")?;
        writeln!(c, "listen = \"{listen}\"")?;
        writeln!(
            c,
            "\n# Names are resolved through the tunnel, by this server,"
        )?;
        writeln!(
            c,
            "# rather than by whatever resolver this host is pointed at."
        )?;
        writeln!(c, "# The local network then learns neither what is being")?;
        writeln!(
            c,
            "# reached nor gets to choose the answer. `system` opts out."
        )?;
        writeln!(c, "dns = \"1.1.1.1\"")?;
    }

    Ok(Pair {
        server: s,
        client: c,
    })
}

/// `paqetz init` — writes both files without asking anything.
///
/// # Errors
/// Returns an error if the files cannot be written.
pub(crate) fn init(
    endpoint: &str,
    dir: &Path,
    gateway: bool,
    route_all: bool,
    socks5: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port) = split_endpoint(endpoint)?;
    let plan = Plan {
        endpoint: format!("{host}:{port}"),
        port,
        gateway,
        route_all,
        socks5,
        ..Plan::default()
    };
    let pair = render(&plan)?;

    std::fs::create_dir_all(dir)?;
    let server_path = dir.join("server.toml");
    let client_path = dir.join("client.toml");
    write_private(&server_path, &pair.server)?;
    write_private(&client_path, &pair.client)?;

    println!("Wrote two configurations:\n");
    println!("  {}   → copy to the SERVER", server_path.display());
    println!("  {}   → copy to the CLIENT", client_path.display());
    println!("\nThe keys are already matched. Do not swap the files.");
    println!("Each holds a private key, so both are mode 0600.\n");
    println!("On each host: paqetz doctor -c <file>, then paqetz run -c <file>.");
    Ok(())
}

/// Writes a file only the owner can read, since it holds a private key.
fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

/// Splits `host:port`, defaulting the port.
fn split_endpoint(s: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((host.to_owned(), port.parse()?)),
        _ => Err(format!("expected an endpoint like \"203.0.113.5:9999\", got {s:?}").into()),
    }
}

/// `paqetz setup` — the same thing, one question at a time.
///
/// # Errors
/// Returns an error if input cannot be read or the files cannot be written.
pub(crate) fn interactive(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("paqetz setup\n");
    println!("This asks a few questions and writes two configuration files —");
    println!("one for each end. Anything that changes this host is asked for");
    println!("separately, and shows the command it runs.\n");

    if !crate::service::is_root() {
        println!("Running unprivileged. Steps that need root will use sudo for");
        println!("that step only, printing each command first.\n");
    }

    // Asked first, because it decides which of the later questions apply and
    // which configuration this host will actually run.
    println!("0. Which end is this host?");
    println!("   [s] the server — stable address, the client connects to it");
    println!("   [c] the client — connects out");
    println!("   [n] neither — just generating the files to copy elsewhere");
    println!("   [q] quit");
    let role = loop {
        match ask("   ", "c")?.to_ascii_lowercase().as_str() {
            "s" | "server" => break Some(Role::Server),
            "c" | "client" => break Some(Role::Client),
            "n" | "neither" => break None,
            // Offered here because this is the last moment at which leaving is
            // free: nothing has been generated, written, or installed yet, so
            // there is nothing to undo and nothing to warn about.
            "q" | "quit" | "exit" => {
                println!("   Nothing was changed.");
                return Ok(());
            }
            _ => println!("   Please answer s, c, n or q.\n"),
        }
    };

    // Before anything is generated: if this host already has its file, or the
    // operator is holding it, that is the one to use. Generating would mint a
    // new keypair and overwrite the copy, leaving the two ends with keys that
    // do not match.
    let egress = match adopt(dir, role)? {
        Some(t) => t.interface.egress.clone(),
        None => generate(dir, role)?,
    };

    // Keeping the tunnel running, for the host that will actually run one.
    if let Some(role) = role {
        let source = dir.join(role.file());
        if crate::service::has_systemd() {
            if yes_no(
                &format!(
                    "\n5. Install paqetz as a system service on this host,\n   \
                     running {}, so it starts at boot and restarts on failure?",
                    role.file()
                ),
                true,
            )? {
                let binary = crate::service::install_binary("/usr/local/bin")?;
                let config = "/etc/paqetz/paqetz.toml";
                let contents = std::fs::read_to_string(&source)?;
                crate::service::write_file(std::path::Path::new(config), &contents, 0o600)?;
                println!("    wrote {config}");
                crate::service::install_unit(
                    "paqetz",
                    &crate::service::tunnel_unit(&binary, config),
                    true,
                )?;
                println!("\n   Check it with: systemctl status paqetz");
                println!("   Follow it with: journalctl -u paqetz -f");
            }
        } else {
            println!("\n5. No systemd on this host, so nothing to install.");
            println!("   Run it however this system starts things:");
            println!("     paqetz run -c {}", source.display());
        }

        // WARP, if the server was configured to egress through it, is brought
        // up by wg-quick rather than by us -- but enabling its unit is one
        // command and forgetting it is the obvious mistake.
        if let Some(iface) = egress.as_ref()
            && crate::service::has_systemd()
            && yes_no(
                &format!(
                    "\n   Enable wg-quick@{iface} so the egress interface comes\n   \
                     up at boot? It must already be configured; paqetz does not\n   \
                     create it."
                ),
                false,
            )?
        {
            match crate::service::run_elevated(
                "systemctl",
                &["enable", "--now", &format!("wg-quick@{iface}")],
            ) {
                Ok(()) => println!("    enabled wg-quick@{iface}"),
                Err(e) => println!("    could not enable it: {e}"),
            }
        }
    }

    // networkd, if it is running and would take the policy rule away. Asked for
    // the host that will run a tunnel, since that is the host with a rule to
    // lose. The restart it needs is deferred to the end of setup: it
    // reconfigures every interface, and doing that halfway through would be
    // done to the connection this is being typed over.
    let mut networkd_written = false;
    if role.is_some()
        && crate::networkd::status() == crate::networkd::Status::WillDeleteRules
        && yes_no(
            "\nsystemd-networkd on this host deletes routing policy rules it did\n   \
             not create, which includes the one that puts marked traffic in the\n   \
             tunnel. When it goes the traffic does not stop -- it leaves this\n   \
             host unprotected instead, while the tunnel still looks healthy.\n   \
             Tell networkd to leave it alone?",
            true,
        )?
    {
        match crate::networkd::apply(false) {
            Ok(()) => {
                println!("   Wrote {}", crate::networkd::drop_in_path().display());
                networkd_written = true;
            }
            Err(e) => println!("   Could not write it: {e}"),
        }
    }

    // The one step that changes this host, asked for separately and last.
    // Only the settings this host will actually use: the NAT-shaped ones tune
    // nothing on a client, and offering them there is how a host acquires
    // settings nobody can justify later. Read from the file this host will run,
    // which covers the adopted configuration as well as the generated one.
    let forwards = role
        .and_then(|r| std::fs::read_to_string(dir.join(r.file())).ok())
        .and_then(|t| crate::config::Config::parse(&t).ok())
        .is_some_and(|c| c.tunnels.iter().any(|t| t.interface.gateway));
    // A gateway that cannot forward looks exactly like a healthy tunnel from
    // both ends -- handshake fine, peer answers a ping, counters clean -- and
    // the packets die on the way out of this host. Worth saying here, while the
    // operator is still holding the shell, rather than leaving it to be found.
    if forwards {
        warn_forwarding_blocked();
    }

    let pending = paqetz_fw::tune::pending(forwards);
    if pending.is_empty() {
        println!("This host's kernel settings already suit a tunnel.");
    } else {
        println!(
            "6. This host has {} kernel setting(s) worth changing",
            pending.len()
        );
        println!("   for a tunnel. `paqetz tune` shows each one and why.");
        if yes_no("   Apply them now?", false)? {
            paqetz_fw::tune::apply(forwards)?;
            println!("   Applied, and written to {}.", paqetz_fw::tune::PATH);
        } else {
            println!("   Skipped. Run `paqetz tune --apply` later if you want them.");
        }
    }

    // Last, and on purpose. Everything above is finished and written, so if
    // this restart does interrupt the session there is nothing left half-done.
    if networkd_written {
        println!("\n---\n");
        println!("One thing left. The networkd setting above is written but not in");
        println!("force: only restarting networkd re-reads it, and until then it will");
        println!("still remove the policy rule when an interface changes state.");
        println!("Restarting reconfigures every interface on this host, so if you are");
        println!("reading this over one of them there is a brief risk to the session.");
        println!("A reboot does the same job whenever it next happens.\n");
        if yes_no("   Restart networkd now?", false)? {
            match crate::service::run_elevated("systemctl", &["restart", "systemd-networkd"]) {
                Ok(()) => println!("   Restarted; the setting is in force."),
                Err(e) => println!("   Could not restart it: {e}"),
            }
        } else {
            println!("   Left alone. `systemctl restart systemd-networkd` when you are");
            println!("   ready, or it applies at the next reboot.");
        }
    }

    println!("\nOn the other host:");
    println!("  paqetz doctor -c <file>     # checks, changes nothing");
    println!("  paqetz run    -c <file>");
    println!("\nOr copy paqetz there and run `paqetz setup` again, answering");
    println!("with the other end at step 0.");
    Ok(())
}

/// Whether a configuration is the one for this end.
///
/// The client is the side that knows where to connect; the server waits to be
/// contacted. That is the structural difference between the two files, and it
/// is enough to catch one being pasted onto the wrong host — which leaves both
/// ends believing they are the same one, and no tunnel.
fn is_for(cfg: &crate::config::TunnelConfig, role: Role) -> bool {
    cfg.peer.endpoint.is_some() == matches!(role, Role::Client)
}

/// Reads a pasted configuration, ending at a line holding only a full stop.
///
/// Not end-of-file: the questions that follow still need stdin, and closing it
/// here would take the rest of the wizard with it.
fn read_pasted() -> io::Result<String> {
    let stdin = io::stdin();
    let mut text = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if stdin.lock().read_line(&mut line)? == 0 || line.trim() == "." {
            break;
        }
        text.push_str(&line);
    }
    Ok(text)
}

/// A configuration for this host to use instead of generating a new pair.
///
/// Whichever end runs `setup` first writes both files; the second end should
/// use the one it was handed rather than mint another. Generating on the second
/// host replaces the keypair the first one was told to expect, and because a
/// responder stays silent toward a peer it does not know — deliberately, so it
/// cannot be probed — the result is a tunnel that never comes up and gives no
/// reason. This is symmetric: it does not matter which end went first.
fn adopt(
    dir: &Path,
    role: Option<Role>,
) -> Result<Option<crate::config::TunnelConfig>, Box<dyn std::error::Error>> {
    // `neither` is generating files for other hosts, so there is nothing here
    // to adopt and nothing this host would run.
    let Some(role) = role else { return Ok(None) };
    let path = dir.join(role.file());

    let found = match std::fs::read_to_string(&path) {
        Ok(text) => crate::config::Config::parse(&text)
            .ok()
            .and_then(crate::config::Config::into_only),
        Err(_) => None,
    };

    if let Some(cfg) = found {
        println!("\n   {} is already here, and it is a valid", path.display());
        println!("   configuration for this end. If it came from the other");
        println!("   host, this is the one to use — generating would replace");
        println!("   the key that host expects.");
        if !is_for(&cfg, role) {
            println!("\n   Careful: it looks like the file for the OTHER end.");
        }
        if yes_no("   Use it?", true)? {
            return Ok(Some(cfg));
        }
        println!("   Generating a new pair instead. The other host will need");
        println!("   its new file too.");
        return Ok(None);
    }

    if !yes_no(
        &format!(
            "\n   Do you already have this host's {}, from setup on the\n   \
             other end? Say yes to paste it in rather than generate a new\n   \
             pair that would not match.",
            role.file()
        ),
        false,
    )? {
        return Ok(None);
    }

    loop {
        println!("\n   Paste it, then a line holding only a full stop.");
        let text = read_pasted()?;
        match crate::config::Config::parse(&text).map(crate::config::Config::into_only) {
            // A file describing several tunnels is not an answer to "is this
            // this host's configuration", so it is treated as unusable here
            // rather than having one of them picked out of it.
            Ok(Some(cfg)) => {
                if !is_for(&cfg, role)
                    && !yes_no(
                        "\n   That looks like the OTHER end's file. Use it anyway?",
                        false,
                    )?
                {
                    return Ok(None);
                }
                write_private(&path, &text)?;
                println!("   Wrote {}", path.display());
                return Ok(Some(cfg));
            }
            Ok(None) => {
                println!("\n   That describes more than one tunnel, so it is not");
                println!("   this host's own configuration.");
                if !yes_no("   Paste it again?", true)? {
                    return Ok(None);
                }
            }
            Err(e) => {
                println!("\n   That does not parse: {e}");
                if !yes_no("   Paste it again?", true)? {
                    return Ok(None);
                }
            }
        }
    }
}

/// Asks the questions that produce a fresh pair, and writes both files.
///
/// Returns the server's egress interface, if one was chosen, since enabling it
/// at boot is asked about later.
fn generate(dir: &Path, role: Option<Role>) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let endpoint = loop {
        let answer = ask(
            "1. Where will the client reach the server?\n   \
             Its public address and port, e.g. 203.0.113.5:9999",
            "",
        )?;
        match split_endpoint(&answer) {
            Ok((host, port)) => break format!("{host}:{port}"),
            Err(e) => println!("   {e}\n"),
        }
    };
    let port = split_endpoint(&endpoint).map(|(_, p)| p)?;

    println!(
        "\n   A note on the port: the firewall rules are scoped to it and\n   \
         apply in both directions, so a standard port like 443 would\n   \
         disturb this host's own traffic on it.\n"
    );

    // Not asked. Both had one answer that fits almost every deployment and one
    // that fits an arrangement most people setting this up do not have, and a
    // question whose answer is the same every time is a question that only
    // creates a chance to get it wrong. Both remain settings in the file, which
    // is where an unusual arrangement belongs.
    let gateway = true;
    let route_all = false;
    println!(
        "   Assuming the usual arrangement: the server is a way out to the\n   \
         internet, and the client sends only what you point at the tunnel\n   \
         rather than everything. Both are settings in the files if you want\n   \
         the other shape -- `gateway` on the server, `route_all` on the client.\n"
    );

    let socks5 = {
        let want = yes_no(
            "2. Add a SOCKS5 listener on the client?\n   \
             This is how you point one program — Xray, a browser, curl —\n   \
             at the tunnel while the rest of the host carries on as normal.",
            true,
        )?;
        if want {
            Some(ask("   Listen where?", "127.0.0.1:1080")?)
        } else {
            None
        }
    };

    // The server's egress. Only sensible when it is a way out at all.
    let egress = if gateway {
        let want = yes_no(
            "\n3. Should the server send the forwarded traffic out a different\n   \
             interface than its own?\n   \
             The usual reason is a Cloudflare WARP tunnel: the destination\n   \
             then sees WARP's address rather than the server's datacentre\n   \
             one. paqetz routes and translates for it but does not bring it\n   \
             up — use wgcf and wg-quick for that, with `Table = 51820` in\n   \
             the profile.",
            false,
        )?;
        if want {
            Some(ask("   Which interface?", "warp")?)
        } else {
            None
        }
    } else {
        None
    };

    let plan = Plan {
        endpoint,
        port,
        gateway,
        route_all,
        socks5: socks5.clone(),
        egress: egress.clone(),
        ..Plan::default()
    };
    let pair = render(&plan)?;

    std::fs::create_dir_all(dir)?;
    let server_path = dir.join("server.toml");
    let client_path = dir.join("client.toml");
    write_private(&server_path, &pair.server)?;
    write_private(&client_path, &pair.client)?;

    println!("\n---\n");
    println!("Wrote:");
    println!("  {}   → the SERVER", server_path.display());
    println!("  {}   → the CLIENT", client_path.display());
    println!("\nThe keys in them are already matched. Do not swap the files.\n");

    // An Xray inbound, for the arrangement where users connect to the client
    // host and their traffic leaves through the tunnel.
    if !generates_client_inbound(role) {
        println!(
            "The client's Xray inbound is not generated here. It contains a\n\
             REALITY private key for the leg between a user and the client\n\
             host, which is not this one — run `paqetz setup` or `paqetz xray`\n\
             there, so the key is only ever on the host that uses it.\n"
        );
    } else if yes_no(
        "4. Generate an Xray REALITY inbound for the client host?\n   \
         This is how users reach the tunnel: they connect to Xray, and\n   \
         Xray forwards what it receives through paqetz.",
        false,
    )? {
        let public = ask("   What address will users reach the client host at?", "")?;
        println!(
            "\n   REALITY impersonates a real site. It must speak TLS 1.3, sit on\n                a large network, and not itself be blocked where this runs.\n                Suggestions: {}",
            crate::xray::SUGGESTED_DESTINATIONS.join(", ")
        );
        let dest = ask("   Which site?", "www.microsoft.com")?;

        // Match the upstream to what the tunnel was configured for, rather
        // than asking the same question twice in different words.
        let upstream = socks5
            .as_ref()
            .map_or(crate::xray::Upstream::Marked(81), |listen| {
                crate::xray::Upstream::Socks5(listen.clone())
            });
        if socks5.is_none() {
            println!(
                "\n   No SOCKS5 listener was configured, so Xray will mark its\n                    outbound sockets instead. Add `route_marked = 81` to the\n                    client's [interface] for the rule that steers them."
            );
        }

        let generated = crate::xray::generate(&crate::xray::Plan {
            listen_port: 443,
            dest,
            upstream,
            public_address: public,
        })?;

        // The REALITY private key is in here, so it gets the same treatment as
        // the tunnel's own configuration rather than whatever the umask says.
        let config_path = dir.join("xray-config.json");
        write_private(&config_path, &generated.config)?;
        let unit_path = dir.join("xray.service");
        std::fs::write(
            &unit_path,
            crate::xray::service_unit("/usr/local/bin", "/etc/xray/config.json"),
        )?;

        println!("\n   Wrote {}", config_path.display());
        println!("   Wrote {}", unit_path.display());
        println!("\n   Give this to a user:\n\n   {}\n", generated.uri);
        println!(
            "   The private key is in the configuration, not in that URI.\n                Its public half is {}.",
            generated.public_key
        );

        // Only offered to the host that would run it, and phrased by what is
        // actually there: asking "install?" of a machine that already has it,
        // or generating a configuration for software the host does not have,
        // are both ways of wasting the reader's attention.
        if role == Some(Role::Client) {
            let installed = crate::xray::installed_version(crate::xray::DEFAULT_PREFIX);
            let wanted = match installed.as_deref() {
                None => yes_no(
                    "\n   Xray is not installed on this host. Install it?\n   \
                     The download is verified against the checksum published\n   \
                     with the release, and aborts if that checksum cannot be\n   \
                     fetched.",
                    // Defaults to yes: a configuration was just generated for
                    // it, so the answer to "and shall I install the thing that
                    // reads it" is almost always the same answer.
                    true,
                )?,
                Some(v) => yes_no(
                    &format!(
                        "\n   Xray {v} is already installed. Update it to the\n   \
                         latest release?"
                    ),
                    false,
                )?,
            };

            if wanted {
                match crate::xray::install(None, crate::xray::DEFAULT_PREFIX) {
                    Ok(v) => println!("   Now at {v}."),
                    Err(e) => println!("   Could not install: {e}"),
                }
            }

            // Put the generated configuration where a service would read it,
            // and keep it running — whether it was installed just now or was
            // already here.
            if crate::xray::installed_version(crate::xray::DEFAULT_PREFIX).is_some() {
                if yes_no("   Put this in place and start Xray with it?", true)? {
                    // Shared with `paqetz xray setup`, so a configuration is
                    // applied the same way whichever route got here -- and an
                    // Xray that is already running is restarted rather than
                    // left on the settings it started with.
                    crate::xray::apply(&generated.config, crate::xray::DEFAULT_PREFIX)?;
                }
            } else {
                println!(
                    "\n   Xray is not installed, so the configuration above is\n   \
                     the file to give it once it is: `paqetz xray install`."
                );
            }
        }
    }

    Ok(egress)
}

/// Reads one answer, treating a closed stdin as an error rather than as an
/// empty line.
///
/// Several of the questions here re-ask until the answer is valid. If
/// end-of-file reported itself as an empty answer, those loops would never
/// finish — the wizard would sit there re-printing a prompt nobody can answer.
fn read_answer() -> io::Result<String> {
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no more input: setup needs a terminal, or answers on stdin",
        ));
    }
    Ok(line)
}

/// Asks a question, returning the default when the answer is empty.
pub(crate) fn ask(prompt: &str, default: &str) -> io::Result<String> {
    if default.is_empty() {
        print!("{prompt}\n   > ");
    } else {
        print!("{prompt}\n   [{default}] > ");
    }
    io::stdout().flush()?;
    let line = read_answer()?;
    let answer = line.trim();
    Ok(if answer.is_empty() {
        default.to_owned()
    } else {
        answer.to_owned()
    })
}

/// Asks a yes-or-no question.
pub(crate) fn yes_no(prompt: &str, default: bool) -> io::Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        print!("{prompt}\n   [{hint}] > ");
        io::stdout().flush()?;
        let line = read_answer()?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("   Please answer y or n.\n"),
        }
    }
}

/// Says so when this host's firewall will drop what the tunnel forwards.
///
/// paqetz cannot fix it: every chain on a hook runs, so accepting in our own
/// table does not stop another one dropping, and the chain that owns the policy
/// belongs to `iptables`.
fn warn_forwarding_blocked() {
    let Some(rules) = std::process::Command::new("iptables")
        .args(["-S", "FORWARD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    else {
        return;
    };
    if crate::doctor::forward_verdict(&rules, "paqetz0") != crate::doctor::Forwarding::Blocked {
        return;
    }
    println!();
    println!("!  This host's FORWARD policy is DROP, and nothing permits the tunnel.");
    println!("   Traffic will arrive here and go no further, while every other sign");
    println!("   says the tunnel is working. Allow just this tunnel:");
    println!("     sudo iptables -I FORWARD -i paqetz0 -j ACCEPT");
    println!("     sudo iptables -I FORWARD -o paqetz0 -m conntrack \\");
    println!("       --ctstate RELATED,ESTABLISHED -j ACCEPT");
    println!("   Then persist it, or it is gone at the next reboot.");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            endpoint: "203.0.113.5:9999".to_owned(),
            ..Plan::default()
        }
    }

    #[test]
    fn both_generated_files_parse() {
        let pair = render(&plan()).expect("render");
        crate::config::Config::parse(&pair.server)
            .expect("server config should parse")
            .into_only()
            .expect("one tunnel");
        crate::config::Config::parse(&pair.client)
            .expect("client config should parse")
            .into_only()
            .expect("one tunnel");
    }

    #[test]
    fn each_end_holds_its_own_private_key_and_the_others_public() {
        // The mistake this whole module exists to prevent.
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");

        let server_public =
            paqetz_core::keys::public_from_private(server.interface.private_key.as_bytes());
        let client_public =
            paqetz_core::keys::public_from_private(client.interface.private_key.as_bytes());

        assert_eq!(
            client.peer.public_key, server_public,
            "the client must name the server's public key"
        );
        assert_eq!(
            server.peer.public_key, client_public,
            "the server must name the client's public key"
        );
    }

    #[test]
    fn the_inner_addresses_mirror_each_other() {
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");

        assert_eq!(server.interface.address, client.peer.tunnel_address);
        assert_eq!(client.interface.address, server.peer.tunnel_address);
        assert_ne!(server.interface.address, client.interface.address);
    }

    #[test]
    fn only_the_client_has_an_endpoint() {
        // Which is what decides who initiates.
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(client.peer.is_initiator());
        assert!(!server.peer.is_initiator());
        assert_eq!(server.interface.listen_port, 9999);
    }

    #[test]
    fn two_runs_never_produce_the_same_keys() {
        let a = render(&plan()).expect("render");
        let b = render(&plan()).expect("render");
        assert_ne!(a.server, b.server);
        assert_ne!(a.client, b.client);
    }

    #[test]
    fn the_gateway_and_routing_choices_reach_the_files() {
        let pair = render(&Plan {
            gateway: true,
            route_all: true,
            ..plan()
        })
        .expect("render");
        assert!(
            crate::config::Config::parse(&pair.server)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .interface
                .gateway
        );
        assert!(
            crate::config::Config::parse(&pair.client)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .interface
                .route_all
        );

        let neither = render(&Plan {
            gateway: false,
            route_all: false,
            ..plan()
        })
        .expect("render");
        assert!(
            !crate::config::Config::parse(&neither.server)
                .expect("parse")
                .into_only()
                .expect("one tunnel")
                .interface
                .gateway
        );
    }

    #[test]
    fn an_egress_interface_reaches_the_server_file() {
        let pair = render(&Plan {
            egress: Some("warp".to_owned()),
            ..plan()
        })
        .expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(server.interface.egress.as_deref(), Some("warp"));
        // And never the client's, which has nothing to forward.
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(client.interface.egress.is_none());
    }

    #[test]
    fn a_socks5_listener_is_included_when_asked_for() {
        let pair = render(&Plan {
            socks5: Some("127.0.0.1:1080".to_owned()),
            ..plan()
        })
        .expect("render");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert_eq!(client.socks5.expect("socks5").listen.port(), 1080);
    }

    #[test]
    fn what_is_generated_is_the_form_we_keep() {
        // One shape for everyone to learn, and a file that grows a second
        // destination later does not have to change shape first.
        let pair = render(&plan()).expect("render");
        for (which, text) in [("server", &pair.server), ("client", &pair.client)] {
            assert!(text.contains("[[tunnel]]"), "{which}: {text}");
            assert!(text.contains("[tunnel.interface]"), "{which}: {text}");
            assert!(text.contains("[tunnel.peer]"), "{which}: {text}");
            assert!(!text.contains("\n[interface]"), "{which}: {text}");
            assert!(!text.contains("\n[peer]"), "{which}: {text}");
        }
    }

    #[test]
    fn a_generated_file_and_a_migrated_one_agree() {
        // `config migrate` names a converted tunnel after its device, and this
        // names a generated one the same, so the two routes to a file do not
        // differ by a label nobody chose.
        let pair = render(&plan()).expect("render");
        let c = crate::config::Config::parse(&pair.client).expect("parse");
        let t = c.tunnels.first().expect("one tunnel");
        assert_eq!(c.tunnels.len(), 1);
        assert_eq!(t.name, DEFAULT_NAME);
        assert_eq!(t.interface.device, DEFAULT_NAME);
    }

    #[test]
    fn a_socks5_listener_lands_inside_the_tunnel() {
        let pair = render(&Plan {
            socks5: Some("127.0.0.1:1080".to_owned()),
            ..plan()
        })
        .expect("render");
        assert!(pair.client.contains("[tunnel.socks5]"), "{}", pair.client);
        assert!(!pair.client.contains("\n[socks5]"), "{}", pair.client);
    }

    #[test]
    fn a_gateway_peer_is_allowed_to_send_from_anywhere() {
        // The whole point of a way out: replies carry the address of the site
        // that was reached, so a peer restricted to its own address drops all
        // of them and the tunnel looks up while nothing crosses it.
        let pair = render(&Plan {
            gateway: true,
            ..plan()
        })
        .expect("render");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(client.peer.permits(Ipv4Addr::new(149, 154, 167, 91)));
        assert!(client.peer.permits(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn a_peer_that_is_not_a_way_out_stays_restricted_to_its_own_address() {
        let pair = render(&Plan {
            gateway: false,
            ..plan()
        })
        .expect("render");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(client.peer.permits(Ipv4Addr::new(10, 7, 0, 1)));
        assert!(
            !client.peer.permits(Ipv4Addr::new(1, 1, 1, 1)),
            "cryptokey routing still applies when there is nothing to forward"
        );
    }

    #[test]
    fn the_server_never_widens_what_the_client_may_send_from() {
        // Only one direction needs it. The client's inner source is always its
        // own address, so widening here would give away the check for nothing.
        let pair = render(&Plan {
            gateway: true,
            ..plan()
        })
        .expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        assert!(server.peer.permits(Ipv4Addr::new(10, 7, 0, 2)));
        assert!(!server.peer.permits(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn each_file_is_recognised_by_the_end_it_belongs_to() {
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("parse")
            .into_only()
            .expect("one tunnel");
        let client = crate::config::Config::parse(&pair.client)
            .expect("parse")
            .into_only()
            .expect("one tunnel");

        assert!(is_for(&client, Role::Client));
        assert!(is_for(&server, Role::Server));
        assert!(
            !is_for(&server, Role::Client),
            "adopting the server's file on the client leaves both ends waiting \
             to be contacted, and neither one connecting"
        );
        assert!(!is_for(&client, Role::Server));
    }

    #[test]
    fn the_server_is_never_offered_the_client_inbound() {
        assert!(
            !generates_client_inbound(Some(Role::Server)),
            "its REALITY private key would be written to a host with no use \
             for it, and left there after being copied to the one that has"
        );
        assert!(generates_client_inbound(Some(Role::Client)));
        assert!(
            generates_client_inbound(None),
            "generating both ends on a third machine is what `neither` means"
        );
    }

    #[test]
    fn files_holding_a_private_key_are_readable_only_by_their_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("paqetz-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        for (name, contents) in [
            ("a.toml", "private_key = \"x\""),
            ("b.json", "\"privateKey\": \"x\""),
        ] {
            let path = dir.join(name);
            write_private(&path, contents).expect("write");
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} is {mode:o}, and holds a private key");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_file_says_which_host_it_belongs_on() {
        let pair = render(&plan()).expect("render");
        assert!(pair.server.contains("SERVER"), "{}", pair.server);
        assert!(pair.client.contains("CLIENT"), "{}", pair.client);
    }

    #[test]
    fn endpoints_are_parsed_and_bad_ones_explained() {
        assert_eq!(
            split_endpoint("203.0.113.5:9999").expect("parse"),
            ("203.0.113.5".to_owned(), 9999)
        );
        for bad in ["203.0.113.5", "", ":9999", "host:notaport"] {
            assert!(split_endpoint(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
