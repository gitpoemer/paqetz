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

use std::fmt::Write as _;
use std::io::{self, BufRead as _, Write as _};
use std::net::Ipv4Addr;
use std::path::Path;

use paqetz_core::KeyPair;

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
    writeln!(s, "[interface]")?;
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
    writeln!(s, "\n[peer]")?;
    writeln!(s, "# The client's public key.")?;
    writeln!(s, "public_key = \"{}\"", client.public.to_base64())?;
    writeln!(s, "tunnel_address = \"{}\"", plan.client_inner)?;

    let mut c = String::new();
    writeln!(c, "# paqetz — CLIENT. This file belongs on the host that")?;
    writeln!(c, "# connects out.\n")?;
    writeln!(c, "[interface]")?;
    writeln!(c, "private_key = \"{}\"", client.private.to_base64())?;
    writeln!(c, "address = \"{}/{}\"", plan.client_inner, plan.prefix)?;
    if plan.route_all {
        writeln!(c, "\n# Send this host's traffic through the tunnel. The")?;
        writeln!(c, "# tunnel's own packets are excepted automatically, so")?;
        writeln!(c, "# turning this on does not cut the connection.")?;
        writeln!(c, "route_all = true")?;
    }
    writeln!(c, "\n[peer]")?;
    writeln!(c, "# The server's public key.")?;
    writeln!(c, "public_key = \"{}\"", server.public.to_base64())?;
    writeln!(c, "endpoint = \"{}\"", plan.endpoint)?;
    writeln!(c, "tunnel_address = \"{}\"", plan.server_inner)?;
    if let Some(listen) = plan.socks5.as_ref() {
        writeln!(c, "\n# A SOCKS5 listener, for pointing one program at the")?;
        writeln!(c, "# tunnel without routing the whole host through it.")?;
        writeln!(c, "[socks5]")?;
        writeln!(c, "listen = \"{listen}\"")?;
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
    println!("one for each end. Nothing is changed on this host until the last");
    println!("step, which asks first.\n");

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

    let gateway = yes_no(
        "2. Should the server be a way out to the internet for the client?\n   \
         This turns on forwarding and address translation there.\n   \
         Say no if you only want the two hosts to reach each other.",
        true,
    )?;

    let route_all = yes_no(
        "\n3. Should the client send all its traffic through the tunnel?\n   \
         The tunnel's own packets are excepted automatically, so this\n   \
         does not cut the connection it depends on.\n   \
         Say no if you will point one program at it instead.",
        false,
    )?;

    let socks5 = if route_all {
        None
    } else {
        let want = yes_no(
            "\n4. Add a SOCKS5 listener on the client?\n   \
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
            "\n5. Should the server send the forwarded traffic out a different\n                interface than its own?\n                The usual reason is a Cloudflare WARP tunnel: the destination then\n                sees WARP's address rather than the server's datacentre one.\n                paqetz routes and translates for it, but does not bring it up —\n                use wgcf and wg-quick for that, with `Table = 51820` in the profile.",
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
    if yes_no(
        "6. Generate an Xray REALITY inbound for the client host?\n            This is how users reach the tunnel: they connect to Xray, and Xray\n            forwards what it receives through paqetz.",
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

        let config_path = dir.join("xray-config.json");
        std::fs::write(&config_path, &generated.config)?;
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

        if yes_no(
            "\n   Install Xray on *this* host now?\n                Only say yes if this is the client host. The download is verified\n                against the checksum published with the release, and aborts if\n                that checksum cannot be fetched.",
            false,
        )? {
            match crate::xray::install(None, crate::xray::DEFAULT_PREFIX) {
                Ok(v) => println!("   Installed {v}."),
                Err(e) => println!("   Could not install: {e}"),
            }
        }
    }

    // The one step that changes this host, asked for separately and last.
    let pending = paqetz_fw::tune::pending();
    if pending.is_empty() {
        println!("This host's kernel settings already suit a tunnel.");
    } else {
        println!(
            "5. This host has {} kernel setting(s) worth changing",
            pending.len()
        );
        println!("   for a tunnel. `paqetz tune` shows each one and why.");
        if yes_no("   Apply them now?", false)? {
            paqetz_fw::tune::apply()?;
            println!("   Applied, and written to {}.", paqetz_fw::tune::PATH);
        } else {
            println!("   Skipped. Run `paqetz tune --apply` later if you want them.");
        }
    }

    println!("\nNext, on each host:");
    println!("  paqetz doctor -c <file>     # checks, changes nothing");
    println!("  paqetz run    -c <file>");
    Ok(())
}

/// Asks a question, returning the default when the answer is empty.
fn ask(prompt: &str, default: &str) -> io::Result<String> {
    if default.is_empty() {
        print!("{prompt}\n   > ");
    } else {
        print!("{prompt}\n   [{default}] > ");
    }
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim();
    Ok(if answer.is_empty() {
        default.to_owned()
    } else {
        answer.to_owned()
    })
}

/// Asks a yes-or-no question.
fn yes_no(prompt: &str, default: bool) -> io::Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        print!("{prompt}\n   [{hint}] > ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("   Please answer y or n.\n"),
        }
    }
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
        crate::config::Config::parse(&pair.server).expect("server config should parse");
        crate::config::Config::parse(&pair.client).expect("client config should parse");
    }

    #[test]
    fn each_end_holds_its_own_private_key_and_the_others_public() {
        // The mistake this whole module exists to prevent.
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server).expect("parse");
        let client = crate::config::Config::parse(&pair.client).expect("parse");

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
        let server = crate::config::Config::parse(&pair.server).expect("parse");
        let client = crate::config::Config::parse(&pair.client).expect("parse");

        assert_eq!(server.interface.address, client.peer.tunnel_address);
        assert_eq!(client.interface.address, server.peer.tunnel_address);
        assert_ne!(server.interface.address, client.interface.address);
    }

    #[test]
    fn only_the_client_has_an_endpoint() {
        // Which is what decides who initiates.
        let pair = render(&plan()).expect("render");
        let server = crate::config::Config::parse(&pair.server).expect("parse");
        let client = crate::config::Config::parse(&pair.client).expect("parse");
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
                .interface
                .gateway
        );
        assert!(
            crate::config::Config::parse(&pair.client)
                .expect("parse")
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
        let server = crate::config::Config::parse(&pair.server).expect("parse");
        assert_eq!(server.interface.egress.as_deref(), Some("warp"));
        // And never the client's, which has nothing to forward.
        let client = crate::config::Config::parse(&pair.client).expect("parse");
        assert!(client.interface.egress.is_none());
    }

    #[test]
    fn a_socks5_listener_is_included_when_asked_for() {
        let pair = render(&Plan {
            socks5: Some("127.0.0.1:1080".to_owned()),
            ..plan()
        })
        .expect("render");
        let client = crate::config::Config::parse(&pair.client).expect("parse");
        assert_eq!(client.socks5.expect("socks5").listen.port(), 1080);
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
