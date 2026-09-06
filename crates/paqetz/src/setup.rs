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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use paqetz_core::KeyPair;

/// What a generated tunnel is called.
///
/// The device name, which is what `config migrate` names a converted file after
/// too — so a file written by `setup` and one converted from the original form
/// come out identical rather than differing by a label nobody chose.
const DEFAULT_NAME: &str = "paqetz0";

/// The inner IPv6 addresses, when the tunnel carries IPv6: a unique-local
/// prefix mirroring the IPv4 one, server first.
const SERVER_INNER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0, 1);
const CLIENT_INNER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0, 2);
const PREFIX6: u8 = 64;

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
    /// The firewall mark a policy route steers into the tunnel, if any.
    pub(crate) route_marked: Option<u32>,
    /// An interface the server sends the forwarded traffic out by.
    pub(crate) egress: Option<String>,
    /// Whether the tunnel carries IPv6 inside as well as IPv4.
    pub(crate) ipv6: bool,
    /// Whether the end that connects out is the way out to the internet.
    ///
    /// The ordinary arrangement is the other way round: users reach the client
    /// host, and the server they are forwarded to is the one with a way out.
    /// Reversed, the host that must be findable is the entrance and the host
    /// that connects to it is the exit -- which is what you want when the exit
    /// has no address anyone can reach, because it is behind a NAT, on a
    /// dynamic connection, or somewhere that does not accept connections.
    ///
    /// Who initiates does not change: the entrance still waits, the exit still
    /// connects out. What moves is which file carries `gateway` and which
    /// carries the knobs a proxy uses to get in.
    pub(crate) reverse: bool,
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
            route_marked: None,
            egress: None,
            ipv6: false,
            reverse: false,
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

/// Whether this host should be offered the Xray inbound.
///
/// Only the end users connect to. That inbound carries a REALITY private key
/// for the leg between a user and that host; the other end has no use for it,
/// cannot answer the questions that produce it, and would be left holding a
/// copy after it was moved to where it belongs. `None` keeps the offer, since
/// generating both ends on a third machine is exactly what that answer means.
///
/// Which end that is follows `reverse`, not the file's name: reversed, the
/// entrance is the host that waits.
const fn generates_inbound(role: Option<Role>, reverse: bool) -> bool {
    match role {
        None => true,
        Some(Role::Server) => reverse,
        Some(Role::Client) => !reverse,
    }
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
    writeln!(s, "# stable address, the one the client connects to.")?;
    if plan.reverse {
        writeln!(
            s,
            "# It is the way IN: users reach the tunnel here, and what"
        )?;
        writeln!(s, "# they send leaves by the client.")?;
    }
    writeln!(s)?;
    // Written into both files, commented out, and not offered as a question.
    // Which of these a path carries is a property of that path and cannot be
    // discovered from here -- so the value is left where someone who has
    // measured their own path can find it, and nowhere more prominent.
    // Everything the questions above do not ask about, listed commented with
    // the value already in force. Values only: what each one does, and what it
    // costs, is not written here. A configuration file that explains the
    // behaviour of the thing it configures is a description of that behaviour
    // sitting on every host that runs it, and these hosts are not the only
    // ones reading. Units where a bare number would be ambiguous, nothing else.
    //
    // `initiator` because rotation is the initiating side's alone: the side
    // that waits has to be findable, so its port cannot move.
    let tuning = |t: &mut String, initiator: bool, exit: bool| -> std::fmt::Result {
        writeln!(
            t,
            "\n# --- Optional. Values shown are the ones in force. ---"
        )?;
        writeln!(
            t,
            "# carrier = \"midstream\"       # midstream | gre | rawip"
        )?;
        writeln!(t, "# carrier_protocol = 143")?;
        writeln!(
            t,
            "# profile = \"linux-6\"         # linux-6 | windows-11 | android-14"
        )?;
        writeln!(t, "# fragment = \"never\"          # never | path")?;
        writeln!(t, "# mtu = 1400")?;
        writeln!(t, "# keepalive = true")?;
        writeln!(t, "# persistent_keepalive = 25   # seconds")?;
        writeln!(t, "#")?;
        writeln!(t, "# retransmit = false")?;
        writeln!(t, "# retransmit_buffer = 1024     # packets")?;
        writeln!(t, "# retransmit_deadline = 400    # ms")?;
        writeln!(t, "# retransmit_asks = 2")?;
        writeln!(t, "# retransmit_reorder = 3       # packets")?;
        if initiator {
            writeln!(t, "#")?;
            writeln!(t, "# rotate = true")?;
            writeln!(t, "# rotate_after = 900           # seconds")?;
            writeln!(t, "# rotate_jitter = 300          # seconds")?;
            writeln!(t, "# rotate_ports = 20")?;
            writeln!(t, "# rotate_after_unanswered = 4")?;
        }
        writeln!(t, "#")?;
        writeln!(t, "# datapath = \"simple\"         # simple | batched")?;
        writeln!(t, "# transmit = \"raw\"            # raw | afpacket")?;
        writeln!(t, "# manage_firewall = true")?;
        writeln!(
            t,
            "# log = \"info\"                # off | error | warn | info | debug"
        )?;
        writeln!(t, "# health_interval = 60         # seconds")?;
        writeln!(t, "#")?;
        writeln!(t, "# [[tunnel.lane]]")?;
        writeln!(t, "# class  = 10")?;
        // A lane's `mark` names whose traffic travels in it, on the end that
        // sends; its `egress` names where that traffic leaves by, on the end
        // that forwards. So the hint follows the way out, not the handshake.
        if exit {
            writeln!(t, "# egress = \"warp\"")
        } else {
            writeln!(t, "# mark   = 79")
        }
    };

    // The knobs that belong to the end which is the way out, and the ones that
    // belong to the end a proxy gets in by. Which file each lands in is the
    // only thing `reverse` changes.
    let mut exit_iface = String::new();
    if plan.gateway {
        exit_iface.push_str(
            "\n# Forward and translate the peer's traffic to the\n\
             # internet. Without this the two ends can reach each\n\
             # other and nothing beyond.\ngateway = true\n",
        );
    }
    if let Some(iface) = plan.egress.as_ref() {
        exit_iface.push_str(&format!(
            "\n# Send the forwarded traffic out this interface, so the\n\
             # destination sees its address rather than this host's.\n\
             # Bringing it up is not paqetz's job.\negress = \"{iface}\"\n"
        ));
    }

    let mut entry_iface = String::new();
    if plan.route_all {
        entry_iface.push_str(
            "\n# Send this host's traffic through the tunnel. The\n\
             # tunnel's own packets are excepted automatically, so\n\
             # turning this on does not cut the connection.\nroute_all = true\n",
        );
    }
    if let Some(mark) = plan.route_marked {
        entry_iface.push_str(&format!(
            "\n# Sockets stamped with this mark are steered into the tunnel by a\n\
             # policy route, so a program can opt in without the host doing so.\n\
             route_marked = {mark}\nroute_table  = {mark}\n"
        ));
    }

    // The end that is not the way out is the one whose peer answers from
    // anywhere: replies arrive carrying the address of whatever site was
    // reached, not the peer's own, and the default range would refuse them all.
    let mut entry_peer = String::new();
    if plan.gateway {
        let ranges = if plan.ipv6 {
            "[\"0.0.0.0/0\", \"::/0\"]"
        } else {
            "[\"0.0.0.0/0\"]"
        };
        entry_peer.push_str(&format!(
            "\n# What this peer may use as an inner source address. It defaults\n\
             # to the peer's own address, which is right for a tunnel\n\
             # between two hosts and wrong for one that is a way out:\n\
             # replies arrive carrying the address of whatever site was\n\
             # reached, not the peer's, and would all be refused.\n\
             allowed_ips = {ranges}\n"
        ));
    }

    let mut entry_socks5 = String::new();
    if let Some(listen) = plan.socks5.as_ref() {
        entry_socks5.push_str(&format!(
            "\n# A SOCKS5 listener, for pointing one program at the\n\
             # tunnel without routing the whole host through it.\n\
             [tunnel.socks5]\nlisten = \"{listen}\"\n\
             \n# Names are resolved through the tunnel, by the far end,\n\
             # rather than by whatever resolver this host is pointed at.\n\
             # The local network then learns neither what is being\n\
             # reached nor gets to choose the answer. `system` opts out.\n\
             dns = \"1.1.1.1\"\n"
        ));
    }

    // The server waits and the client connects out, always. `reverse` moves
    // only which of them is the way out.
    let (server_iface, client_iface) = if plan.reverse {
        (&entry_iface, &exit_iface)
    } else {
        (&exit_iface, &entry_iface)
    };
    let (server_peer, client_peer) = if plan.reverse {
        (entry_peer.as_str(), "")
    } else {
        ("", entry_peer.as_str())
    };
    let (server_socks5, client_socks5) = if plan.reverse {
        (entry_socks5.as_str(), "")
    } else {
        ("", entry_socks5.as_str())
    };

    // The form that can hold several tunnels, written even for one. A file that
    // grows a second destination later should not have to change shape first,
    // and one shape means one thing for everyone to learn.
    writeln!(s, "[[tunnel]]")?;
    writeln!(s, "name = {DEFAULT_NAME:?}\n")?;
    writeln!(s, "[tunnel.interface]")?;
    writeln!(s, "private_key = \"{}\"", server.private.to_base64())?;
    writeln!(s, "address = \"{}/{}\"", plan.server_inner, plan.prefix)?;
    if plan.ipv6 {
        writeln!(s, "address6 = \"{SERVER_INNER6}/{PREFIX6}\"")?;
    } else {
        writeln!(s, "# address6 = \"{SERVER_INNER6}/{PREFIX6}\"")?;
    }
    writeln!(s, "listen_port = {}", plan.port)?;
    s.push_str(server_iface);
    tuning(&mut s, false, !plan.reverse)?;
    writeln!(s, "\n[tunnel.peer]")?;
    writeln!(s, "# The client's public key.")?;
    writeln!(s, "public_key = \"{}\"", client.public.to_base64())?;
    writeln!(s, "tunnel_address = \"{}\"", plan.client_inner)?;
    if plan.ipv6 {
        writeln!(s, "tunnel_address6 = \"{CLIENT_INNER6}\"")?;
    } else {
        writeln!(s, "# tunnel_address6 = \"{CLIENT_INNER6}\"")?;
    }
    s.push_str(server_peer);
    s.push_str(server_socks5);

    let mut c = String::new();
    writeln!(c, "# paqetz — CLIENT. This file belongs on the host that")?;
    writeln!(c, "# connects out.")?;
    if plan.reverse {
        writeln!(c, "# It is the way OUT: what arrives through the tunnel")?;
        writeln!(c, "# reaches the internet from here.")?;
    }
    writeln!(c)?;
    writeln!(c, "[[tunnel]]")?;
    writeln!(c, "name = {DEFAULT_NAME:?}\n")?;
    writeln!(c, "[tunnel.interface]")?;
    writeln!(c, "private_key = \"{}\"", client.private.to_base64())?;
    writeln!(c, "address = \"{}/{}\"", plan.client_inner, plan.prefix)?;
    if plan.ipv6 {
        writeln!(c, "address6 = \"{CLIENT_INNER6}/{PREFIX6}\"")?;
    } else {
        writeln!(c, "# address6 = \"{CLIENT_INNER6}/{PREFIX6}\"")?;
    }
    c.push_str(client_iface);
    tuning(&mut c, true, plan.reverse)?;
    writeln!(c, "\n[tunnel.peer]")?;
    writeln!(c, "# The server's public key.")?;
    writeln!(c, "public_key = \"{}\"", server.public.to_base64())?;
    writeln!(c, "endpoint = \"{}\"", plan.endpoint)?;
    writeln!(c, "tunnel_address = \"{}\"", plan.server_inner)?;
    if plan.ipv6 {
        writeln!(c, "tunnel_address6 = \"{SERVER_INNER6}\"")?;
    } else {
        writeln!(c, "# tunnel_address6 = \"{SERVER_INNER6}\"")?;
    }
    c.push_str(client_peer);
    c.push_str(client_socks5);

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
    ipv6: bool,
    reverse: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port) = split_endpoint(endpoint)?;
    let plan = Plan {
        endpoint: format!("{host}:{port}"),
        port,
        gateway,
        route_all,
        socks5,
        ipv6,
        reverse,
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
                    "\n8. Install paqetz as a system service on this host,\n   \
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
                // Reported, not propagated. A service that will not start is
                // a thing to fix afterwards -- the unit and the configuration
                // are both written by now -- and abandoning the rest of setup
                // over it leaves the host half-configured, which is a worse
                // place to be than configured with one service down.
                match crate::service::install_unit(
                    "paqetz",
                    &crate::service::tunnel_unit(&binary, config),
                    true,
                ) {
                    Ok(()) => {
                        println!("\n   Check it with: systemctl status paqetz");
                        println!("   Follow it with: journalctl -u paqetz -f");
                    }
                    Err(e) => {
                        println!("\n   The service is installed but did not start: {e}");
                        println!("   `paqetz doctor -c {config}` says what it is unhappy about.");
                        println!("   Fix that, then: systemctl start paqetz");
                        println!("\n   Carrying on with the rest of the setup.");
                    }
                }
            }
        } else {
            println!("\n8. No systemd on this host, so nothing to install.");
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
        "   Assuming the usual arrangement in one respect: this end sends only\n   \
         what you point at the tunnel rather than everything. `route_all` is\n   \
         the setting for the other shape.\n"
    );

    // Asked before the questions it changes the meaning of: which host a proxy
    // gets in by, and which host the traffic leaves from, are opposite ends in
    // one arrangement and the same answer reversed in the other.
    let reverse = yes_no(
        "2. Is the host that CONNECTS OUT the way out to the internet?\n   \
         Normally no: users reach the client, and the server they are\n   \
         forwarded to has the way out. Answer yes for the reverse -- the\n   \
         server is the entrance users reach, and the client behind it is\n   \
         where traffic leaves for the internet. That is the arrangement for\n   \
         an exit with no address anyone can connect to: behind a NAT, on a\n   \
         dynamic connection, or anywhere that refuses inbound connections.",
        false,
    )?;
    let entrance = if reverse { "server" } else { "client" };
    let exit = if reverse { "client" } else { "server" };

    let socks5 = {
        let want = yes_no(
            &format!(
                "\n3. Add a SOCKS5 listener on the {entrance}?\n   \
                 This is how you point one program — Xray, a browser, curl —\n   \
                 at the tunnel while the rest of the host carries on as normal."
            ),
            true,
        )?;
        if want {
            Some(ask("   Listen where?", "127.0.0.1:1080")?)
        } else {
            None
        }
    };

    // Offered after SOCKS5 because the two are alternatives more often than
    // they are companions, and the second question reads differently once the
    // first has been answered.
    let route_marked = {
        let want = yes_no(
            &format!(
                "\n4. Steer marked sockets on the {entrance} into the tunnel as well?\n   \
                 A program that can stamp a mark on its own sockets — Xray can —\n   \
                 then reaches the tunnel without a proxy in between, which is one\n   \
                 less hop and one less thing to hold the traffic up."
            ),
            true,
        )?;
        if want {
            let raw = ask("   Which mark?", "81")?;
            match raw.trim().parse::<u32>() {
                Ok(0) | Err(_) => {
                    println!("   Not a usable mark; leaving it out.");
                    None
                }
                Ok(m) => Some(m),
            }
        } else {
            None
        }
    };

    // The server's egress. Only sensible when it is a way out at all.
    let egress = if gateway {
        let want = yes_no(
            &format!(
                "\n5. Should the {exit} send the forwarded traffic out a different\n   \
                 interface than its own?\n   \
                 The usual reason is a Cloudflare WARP tunnel: the destination\n   \
                 then sees WARP's address rather than that host's datacentre\n   \
                 one. paqetz routes and translates for it but does not bring it\n   \
                 up — use wgcf and wg-quick for that, with `Table = 51820` in\n   \
                 the profile."
            ),
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

    let ipv6 = yes_no(
        &format!(
            "\n6. Carry IPv6 inside the tunnel as well?\n   \
             Only useful when the {exit} has working IPv6 of its own to send\n   \
             it out by; without that, IPv6 destinations time out instead of\n   \
             being refused. Off, the tunnel carries IPv4 and Xray is told to\n   \
             refuse IPv6 rather than let it leave by the {entrance}'s own\n   \
             address."
        ),
        false,
    )?;

    let plan = Plan {
        endpoint,
        port,
        gateway,
        route_all,
        socks5: socks5.clone(),
        route_marked,
        egress: egress.clone(),
        ipv6,
        reverse,
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

    // An Xray inbound, for the host users connect to. Which host that is
    // follows the arrangement rather than the file's name.
    if !generates_inbound(role, reverse) {
        println!(
            "The Xray inbound is not generated here. It contains a REALITY\n\
             private key for the leg between a user and the {entrance}, which\n\
             is not this host — run `paqetz setup` or `paqetz xray` there, so\n\
             the key is only ever on the host that uses it.\n"
        );
    } else if yes_no(
        &format!(
            "7. Generate an Xray REALITY inbound for the {entrance}?\n   \
             This is how users reach the tunnel: they connect to Xray, and\n   \
             Xray forwards what it receives through paqetz."
        ),
        false,
    )? {
        let public = ask(
            &format!("   What address will users reach the {entrance} at?"),
            "",
        )?;
        println!(
            "\n   REALITY impersonates a real site. It must speak TLS 1.3, sit on\n                a large network, and not itself be blocked where this runs.\n                Suggestions: {}",
            crate::xray::SUGGESTED_DESTINATIONS.join(", ")
        );
        let dest = ask("   Which site?", "www.microsoft.com")?;

        // Match the upstream to what the tunnel was configured for, rather
        // than asking the same question twice in different words.
        // The mark wins when both are configured. A marked socket reaches the
        // tunnel through the kernel's routing; SOCKS5 reaches it through a
        // proxy that has to accept, parse, and relay every connection. Same
        // destination, one fewer thing in the way.
        let upstream = match (route_marked, socks5.as_ref()) {
            (Some(mark), _) => {
                println!("\n   Xray will mark its outbound sockets {mark}.");
                crate::xray::Upstream::Marked(mark)
            }
            (None, Some(listen)) => {
                println!("\n   Xray will forward through the SOCKS5 listener at {listen}.");
                crate::xray::Upstream::Socks5(listen.clone())
            }
            (None, None) => {
                println!(
                    "\n   Neither a mark nor a SOCKS5 listener was configured, so there\n   \
                     is nowhere for Xray to send what it receives. Add one and run\n   \
                     `paqetz xray setup`."
                );
                return Ok(egress);
            }
        };

        let block_domestic = yes_no(
            "\n   Keep Iranian destinations out of the tunnel?\n   \
             They are reachable without it, and sending them abroad and back\n   \
             is slower, more visible, and sometimes refused at the far end for\n   \
             arriving from the wrong country.",
            true,
        )?;
        // Defaults to whatever the tunnel can carry: refusing IPv6 on a
        // tunnel that forwards it wastes the setting, and allowing it on one
        // that does not lets it leave by this host's own address.
        let block_ipv6 = yes_no(
            "\n   Refuse IPv6 destinations?\n   \
             The tunnel's routing is per address family. An IPv6 address that\n   \
             Xray is handed would otherwise be dialled from this host's own\n   \
             IPv6, outside the tunnel, showing that address to the destination.",
            !ipv6,
        )?;

        let upstream_kind = upstream.clone();
        let generated = crate::xray::generate(&crate::xray::Plan {
            listen_port: 443,
            dest,
            upstream,
            public_address: public,
            block_domestic,
            block_ipv6,
        })?;

        // The REALITY private key is in here, so it gets the same treatment as
        // the tunnel's own configuration rather than whatever the umask says.
        let config_path = dir.join("xray-config.json");
        write_private(&config_path, &generated.config)?;
        let unit_path = dir.join("xray.service");
        std::fs::write(
            &unit_path,
            crate::xray::service_unit(
                "/usr/local/bin",
                crate::xray::CONFIG_PATH,
                crate::service::has_credentials(),
                matches!(upstream_kind, crate::xray::Upstream::Marked(_)),
            ),
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
        // Whichever end users reach: reversed, that is the one that waits.
        if role.is_some_and(|r| generates_inbound(Some(r), reverse)) {
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
                    crate::xray::apply(
                        &generated.config,
                        crate::xray::DEFAULT_PREFIX,
                        matches!(upstream_kind, crate::xray::Upstream::Marked(_)),
                    )?;
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

    #[test]
    fn the_generated_files_carry_every_setting_the_questions_do_not_ask() {
        // Left out entirely, the only way to find these is to read the source;
        // written as comments with their current values, the file is its own
        // reference and nothing is turned on by accident.
        let rendered = super::render(&plan()).expect("render");
        let (server, client) = (rendered.server, rendered.client);

        for (which, text) in [("server", &server), ("client", &client)] {
            for key in [
                "carrier",
                "carrier_protocol",
                "profile",
                "fragment",
                "mtu",
                "keepalive",
                "persistent_keepalive",
                "retransmit",
                "retransmit_buffer",
                "retransmit_deadline",
                "retransmit_asks",
                "retransmit_reorder",
                "datapath",
                "transmit",
                "log",
                "health_interval",
                "manage_firewall",
            ] {
                assert!(
                    text.contains(&format!("# {key} =")),
                    "{which} is missing {key}"
                );
            }
            // Commented, every one of them: a generated file that turned a
            // setting on would be deciding something it was never told.
            for line in text.lines() {
                let bare = line.trim_start();
                if bare.starts_with('#') || bare.is_empty() {
                    continue;
                }
                assert!(
                    !bare.starts_with("carrier")
                        && !bare.starts_with("retransmit")
                        && !bare.starts_with("rotate")
                        && !bare.starts_with("fragment"),
                    "{which} sets {bare:?} rather than showing it"
                );
            }
        }

        // Rotation is the initiating side's alone -- the side that waits has to
        // be findable, so its port cannot move -- and offering it in the server
        // file would be offering something that does nothing.
        for key in [
            "rotate",
            "rotate_after",
            "rotate_ports",
            "rotate_after_unanswered",
        ] {
            assert!(
                client.contains(&format!("# {key} =")),
                "client missing {key}"
            );
        }
        assert!(
            !server.contains("# rotate ="),
            "the server cannot rotate and should not be told it can"
        );
    }
    #[test]
    fn a_mark_reaches_the_clients_file_with_a_table_to_match() {
        // The mark alone steers nothing: the rule that acts on it points at a
        // table, and a table that does not exist is a rule that drops traffic.
        let pair = super::render(&Plan {
            route_marked: Some(81),
            ..plan()
        })
        .expect("render");
        assert!(pair.client.contains("route_marked = 81"), "{}", pair.client);
        assert!(pair.client.contains("route_table  = 81"), "{}", pair.client);
        let parsed = crate::config::Config::parse(&pair.client).expect("parses");
        let client = parsed.tunnels.first().expect("a tunnel");
        assert_eq!(client.interface.route_marked, Some(81));
        assert_eq!(client.interface.route_table, 81);
    }

    #[test]
    fn ipv6_is_written_to_both_ends_or_shown_to_neither() {
        let on = super::render(&Plan {
            ipv6: true,
            ..plan()
        })
        .expect("render");
        assert!(
            on.server.contains("address6 = \"fd00:7::1/64\""),
            "{}",
            on.server
        );
        assert!(
            on.server.contains("tunnel_address6 = \"fd00:7::2\""),
            "{}",
            on.server
        );
        assert!(
            on.client.contains("address6 = \"fd00:7::2/64\""),
            "{}",
            on.client
        );
        assert!(
            on.client.contains("tunnel_address6 = \"fd00:7::1\""),
            "{}",
            on.client
        );
        // The way out has to be allowed to answer from anywhere in both
        // families, or every IPv6 reply is refused.
        assert!(on.client.contains("\"::/0\""), "{}", on.client);
        for text in [&on.server, &on.client] {
            let parsed = crate::config::Config::parse(text).expect("parses");
            let t = parsed.tunnels.first().expect("a tunnel");
            assert!(t.carries_ipv6());
        }

        let off = super::render(&plan()).expect("render");
        for text in [&off.server, &off.client] {
            assert!(text.contains("# address6 ="), "{text}");
            assert!(text.contains("# tunnel_address6 ="), "{text}");
            let parsed = crate::config::Config::parse(text).expect("parses");
            assert!(!parsed.tunnels.first().expect("a tunnel").carries_ipv6());
        }
    }

    #[test]
    fn no_mark_leaves_the_file_without_one() {
        let pair = super::render(&plan()).expect("render");
        assert!(!pair.client.contains("route_marked"), "{}", pair.client);
    }

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
    fn only_the_host_users_reach_is_offered_the_inbound() {
        assert!(
            !generates_inbound(Some(Role::Server), false),
            "its REALITY private key would be written to a host with no use \
             for it, and left there after being copied to the one that has"
        );
        assert!(generates_inbound(Some(Role::Client), false));
        // Reversed, the entrance is the host that waits, so the offer moves
        // with it rather than staying on the file called "client".
        assert!(generates_inbound(Some(Role::Server), true));
        assert!(!generates_inbound(Some(Role::Client), true));
        for reverse in [true, false] {
            assert!(
                generates_inbound(None, reverse),
                "generating both ends on a third machine is what `neither` means"
            );
        }
    }

    #[test]
    fn reversing_moves_the_way_out_without_moving_who_connects() {
        let plan = Plan {
            route_marked: Some(81),
            socks5: Some("127.0.0.1:1080".to_owned()),
            egress: Some("warp".to_owned()),
            reverse: true,
            ..plan()
        };
        let pair = render(&plan).expect("render");

        // Who initiates is untouched: the server still waits, the client
        // still connects out. Only the way out moved.
        let server = crate::config::Config::parse(&pair.server)
            .expect("server parses")
            .into_only()
            .expect("one");
        let client = crate::config::Config::parse(&pair.client)
            .expect("client parses")
            .into_only()
            .expect("one");
        assert!(client.peer.is_initiator(), "the client still connects out");
        assert!(!server.peer.is_initiator(), "the server still waits");

        // The exit forwards and translates, and names the interface it leaves
        // by; the entrance does neither.
        assert!(client.interface.gateway, "{}", pair.client);
        assert!(!server.interface.gateway, "{}", pair.server);
        assert_eq!(client.interface.egress.as_deref(), Some("warp"));
        assert_eq!(server.interface.egress, None);

        // The entrance is where a proxy gets in, and where replies from
        // anywhere have to be allowed.
        assert_eq!(server.interface.route_marked, Some(81));
        assert_eq!(client.interface.route_marked, None);
        assert!(server.socks5.is_some(), "{}", pair.server);
        assert!(client.socks5.is_none(), "{}", pair.client);
        assert!(server.peer.permits("203.0.113.9".parse().expect("address")));
        assert!(!client.peer.permits("203.0.113.9".parse().expect("address")));

        // The lane hint follows the way out too, since `egress` belongs to the
        // end that forwards and `mark` to the end that sends.
        assert!(
            pair.client.contains("# egress = \"warp\""),
            "{}",
            pair.client
        );
        assert!(pair.server.contains("# mark   = 79"), "{}", pair.server);
    }

    #[test]
    fn the_ordinary_arrangement_is_unchanged() {
        // The reverse work moved where these are written from a fixed file to
        // a computed one. What the ordinary answer produces must not have
        // moved with it.
        let plan = Plan {
            route_marked: Some(81),
            socks5: Some("127.0.0.1:1080".to_owned()),
            egress: Some("warp".to_owned()),
            ..plan()
        };
        let pair = render(&plan).expect("render");
        let server = crate::config::Config::parse(&pair.server)
            .expect("server parses")
            .into_only()
            .expect("one");
        let client = crate::config::Config::parse(&pair.client)
            .expect("client parses")
            .into_only()
            .expect("one");
        assert!(server.interface.gateway);
        assert!(!client.interface.gateway);
        assert_eq!(server.interface.egress.as_deref(), Some("warp"));
        assert_eq!(client.interface.route_marked, Some(81));
        assert!(client.socks5.is_some());
        assert!(server.socks5.is_none());
        assert!(client.peer.permits("203.0.113.9".parse().expect("address")));
        assert!(pair.server.contains("# egress = \"warp\""));
        assert!(pair.client.contains("# mark   = 79"));
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
