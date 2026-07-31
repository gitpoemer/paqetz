//! `paqetz` — point-to-point L3 tunnel over crafted TCP segments.
//!
//! See `docs/08-rewrite-plan.md` for the design and `docs/decisions/` for the
//! decisions that constrain it.

mod config;
mod doctor;
mod tunnel;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use paqetz_core::KeyPair;
use paqetz_fw::Firewall;

use crate::config::Config;
use crate::tunnel::Tunnel;

#[derive(Parser)]
#[command(name = "paqetz", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to the configuration file.
    ///
    /// Global, so it may be given before or after the subcommand. Putting it on
    /// individual subcommands means `firewall plan -c file` is rejected while
    /// `firewall -c file plan` is accepted, which is a distinction no one
    /// should have to remember.
    #[arg(short, long, global = true, default_value = "/etc/paqetz/paqetz.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a keypair.
    ///
    /// The private key is the only secret in the system; the public key is not
    /// sensitive and may be sent over any channel.
    Keygen,

    /// Print the public key belonging to a private key read from stdin.
    Pubkey,

    /// Run the tunnel.
    Run,

    /// Check the host for the things that stop a tunnel working.
    ///
    /// Read-only: creates, changes, and removes nothing.
    Doctor,

    /// Inspect or change the firewall rules the tunnel needs.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Print the commands that `apply` would run, without running them.
    Plan,
    /// Install the rules.
    Apply,
    /// Remove the rules.
    Revert,
    /// Report whether the rules are installed.
    Status,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::Pubkey => pubkey(),
        Command::Run => start(&cli.config),
        Command::Doctor => {
            if doctor::run(&cli.config) {
                Ok(())
            } else {
                Err("the host is not ready; see the failures above".into())
            }
        }
        Command::Firewall { action } => firewall(action, &cli.config),
    }
}

fn keygen() -> Result<(), Box<dyn std::error::Error>> {
    let kp = KeyPair::generate()?;
    // Printed as two labelled lines rather than one, because a bare key pasted
    // into the wrong field is a failure that surfaces only as a tunnel that
    // never connects.
    println!("private_key = \"{}\"", kp.private.to_base64());
    println!("public_key  = \"{}\"", kp.public.to_base64());
    Ok(())
}

fn pubkey() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let private = paqetz_core::PrivateKey::from_base64(text.trim())?;
    let public = paqetz_core::keys::public_from_private(private.as_bytes());
    println!("{public}");
    Ok(())
}

fn start(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(path)?;
    let manage_firewall = cfg.interface.manage_firewall;

    tunnel::install_signal_handlers();

    println!(
        "paqetz: {} at {} (mtu {}), peer {} {}",
        cfg.interface.device,
        cfg.interface.address,
        cfg.interface.mtu,
        cfg.peer.tunnel_address,
        cfg.peer.endpoint.map_or_else(
            || "waiting for connection".to_owned(),
            |e| format!("via {e}")
        ),
    );

    // Sockets and the device come up first, because the port the rules must
    // name is only settled here: the initiating side takes an ephemeral one.
    // Scoping the rules to anything else — the peer's port, say — would leave
    // the kernel free to reset the very traffic they exist to protect.
    let tunnel = Tunnel::start(cfg)?;
    let port = tunnel.local_port();
    println!("paqetz: outer port {port}");

    // The rules are load-bearing, not advisory (D9): without them the kernel
    // resets the flow. Installing them here means one less way for a setup to
    // fail silently.
    let fw = if manage_firewall {
        match Firewall::detect(port) {
            Ok(fw) => {
                fw.apply()?;
                Some(fw)
            }
            Err(e) => {
                eprintln!("warning: {e}");
                eprintln!("the tunnel will run, but the kernel may reset it");
                None
            }
        }
    } else {
        None
    };

    let result = tunnel.run();

    // Leave the host as we found it, whether or not the tunnel ended cleanly.
    if let Some(fw) = fw
        && let Err(e) = fw.revert()
    {
        eprintln!("warning: could not remove firewall rules: {e}");
    }

    result.map_err(Into::into)
}

fn firewall(
    action: FirewallAction,
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(path)?;
    let port = effective_port(&cfg).ok_or(
        "this end takes an ephemeral outer port at start-up, so its rules \
         cannot be named ahead of time. `run` installs them itself; to manage \
         them by hand, set interface.listen_port to a fixed port.",
    )?;

    // `plan` must work on a host with neither tool installed — printing what to
    // run by hand is exactly what it is for.
    if matches!(action, FirewallAction::Plan) {
        let fw = Firewall::detect(port)
            .unwrap_or_else(|_| Firewall::with_backend(paqetz_fw::Backend::Nft, port));
        for line in fw.plan() {
            println!("{line}");
        }
        return Ok(());
    }

    let fw = Firewall::detect(port)?;
    match action {
        FirewallAction::Plan => unreachable!("handled above"),
        FirewallAction::Apply => fw.apply()?,
        FirewallAction::Revert => fw.revert()?,
        FirewallAction::Status => println!("{:?}", fw.status()?),
    }
    Ok(())
}

/// The outer port the firewall rules must cover, when it is knowable.
///
/// The rules have to name the port *this* kernel would send resets from, which
/// is the port we receive on — not the peer's. An end that takes an ephemeral
/// port does not know it until start-up, so there is nothing to return.
const fn effective_port(cfg: &Config) -> Option<u16> {
    if cfg.interface.listen_port == 0 {
        None
    } else {
        Some(cfg.interface.listen_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_config_flag_works_on_either_side_of_the_subcommand() {
        for args in [
            vec!["paqetz", "firewall", "plan", "-c", "/tmp/x.toml"],
            vec!["paqetz", "firewall", "-c", "/tmp/x.toml", "plan"],
            vec!["paqetz", "-c", "/tmp/x.toml", "firewall", "plan"],
            vec!["paqetz", "run", "--config", "/tmp/x.toml"],
        ] {
            let cli = Cli::try_parse_from(&args)
                .unwrap_or_else(|e| panic!("{args:?} should parse, got: {e}"));
            assert_eq!(cli.config, PathBuf::from("/tmp/x.toml"), "{args:?}");
        }
    }

    #[test]
    fn the_effective_port_prefers_our_own_listen_port() {
        let cfg = Config::parse(
            r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.1/24"
listen_port = 9999

[peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
tunnel_address = "10.7.0.2"
"#,
        )
        .expect("parse");
        assert_eq!(effective_port(&cfg), Some(9999));
    }

    #[test]
    fn an_ephemeral_end_has_no_port_to_plan_for() {
        // The rules must name the port *this* kernel would send resets from.
        // With an ephemeral port that is unknown until start-up, so `firewall`
        // says so rather than printing rules for the peer's port, which would
        // protect nothing.
        let cfg = Config::parse(
            r#"
[interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"

[peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
endpoint = "203.0.113.5:9999"
tunnel_address = "10.7.0.1"
"#,
        )
        .expect("parse");
        assert_eq!(effective_port(&cfg), None);
    }
}
