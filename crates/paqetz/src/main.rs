//! `paqetz` — point-to-point L3 tunnel over crafted TCP segments.
//!
//! See `docs/08-rewrite-plan.md` for the design and `docs/decisions/` for the
//! decisions that constrain it.

mod config;
mod doctor;
mod log;
mod migrate;
mod networkd;
mod probe;
mod repeat;
mod service;
mod setup;
mod stats;
mod tunnel;
mod update;
mod warp;
mod xray;

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
    Doctor {
        /// Measure how the tunnel behaves while it is busy, rather than
        /// whether the host is ready for one.
        ///
        /// Times the round trip to the peer's inner address idle and again
        /// while saturating the tunnel, and reports both. Sends traffic;
        /// changes nothing. Requires a tunnel that is already running.
        #[arg(long)]
        under_load: bool,

        /// Which tunnel to probe, when more than one is configured.
        #[arg(long, requires = "under_load")]
        tunnel: Option<String>,

        /// Megabits per second to offer during the loaded run.
        ///
        /// Paced, because an unpaced sender fills a local queue faster than any
        /// link drains it and then drops the probes itself. Raise it to press
        /// harder; the achieved rate is reported either way.
        #[arg(long, requires = "under_load", default_value_t = probe::DEFAULT_RATE)]
        rate: f64,
    },

    /// Generate a matched pair of configuration files.
    ///
    /// Both keypairs at once, written straight into two finished files with
    /// the addresses already mirrored — so the keys are never handled loose,
    /// which is where they get transposed.
    Init {
        /// Where the client will reach the server, as `host:port`.
        endpoint: String,
        /// Where to write the two files.
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
        /// Do not make the server a way out to the internet.
        #[arg(long)]
        no_gateway: bool,
        /// Route all the client's traffic through the tunnel.
        #[arg(long)]
        route_all: bool,
        /// Add a SOCKS5 listener on the client at this address.
        #[arg(long, value_name = "ADDR")]
        socks5: Option<String>,
    },

    /// Set up a tunnel, one question at a time.
    Setup {
        /// Where to write the two files.
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
    },

    /// Set up Xray in front of the tunnel: install it, configure it, run it.
    Xray {
        #[command(subcommand)]
        action: XrayAction,
    },

    /// Set up Cloudflare WARP as a second way out for the server.
    ///
    /// Destinations that refuse datacentre addresses -- Tor relays being the
    /// case this exists for -- see WARP's address instead. Server side only:
    /// the client already reaches the internet through the server, so what any
    /// destination sees is decided there.
    Warp {
        #[command(subcommand)]
        action: WarpAction,
    },

    /// Install or remove the system service that keeps the tunnel running.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Work on the configuration file itself.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Download the latest release and replace this binary.
    ///
    /// Fetches the build matching this one, checks it against the digest
    /// published with the release, and refuses to install anything it cannot
    /// verify. Replacing the file does not replace the running process, so it
    /// offers to restart the service afterwards.
    Update {
        /// Answer yes to both questions: install it, and restart the service.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Start the tunnel service.
    Start,

    /// Stop the tunnel service.
    Stop,

    /// Restart the tunnel service.
    ///
    /// What to run after changing the configuration or replacing the binary:
    /// neither is picked up by a process that is already running.
    Restart,

    /// Stop systemd-networkd deleting the policy rule the tunnel needs.
    ///
    /// systemd-networkd assumes it is the only thing managing routes and
    /// routing policy rules. Whenever an interface changes state, or the
    /// service restarts, it deletes every policy rule it did not create --
    /// including the one that sends marked traffic into the tunnel.
    ///
    /// Losing that rule does not stop traffic, which is what makes it
    /// dangerous. The lookup finds an empty table, moves on to the main table,
    /// and what should have been tunnelled leaves this host in the clear, while
    /// the tunnel stays up and every counter still looks healthy.
    ///
    /// Start with `status`. If it says the rule is at risk, `protect --restart`
    /// is the one to run: `protect` alone writes the setting but nothing reads
    /// it until networkd restarts.
    Networkd {
        #[command(subcommand)]
        action: NetworkdAction,
    },

    /// Show kernel settings worth changing for a tunnel, and why.
    Tune {
        /// Apply them, rather than only printing them.
        #[arg(long)]
        apply: bool,
    },

    /// Inspect or change the firewall rules the tunnel needs.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
}

#[derive(Subcommand)]
enum WarpAction {
    /// Install WARP and the routing, one question at a time.
    ///
    /// Every step checks whether it has already been done, so running this
    /// again after a failure resumes rather than starting over. Nothing is
    /// rolled back on failure -- `revert` undoes it deliberately.
    Setup,
    /// Re-fetch the relay list and reload the destination set.
    ///
    /// What the daily timer runs. The whole table is replaced in one
    /// transaction, so the kernel is never matching against a half-built set.
    Refresh,
    /// Show what is in place.
    Status,
    /// Take the routing, interface and timer out again.
    Revert {
        /// Also discard the WARP account and remove wgcf.
        ///
        /// The account is an identity that cannot be recovered once discarded.
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install the unit, copy the binary and configuration into place, and
    /// start it.
    Install {
        /// Start it now and at boot, rather than only writing the unit.
        #[arg(long, default_value_t = true)]
        enable: bool,
    },
    /// Stop it, and remove the unit.
    Remove,
    /// Print the unit that `install` would write, without writing it.
    Show,
}

#[derive(Subcommand)]
enum XrayAction {
    /// Write a REALITY inbound configuration to a file and print the client URI.
    ///
    /// Writes and stops. Nothing is installed, nothing is placed where a
    /// running Xray would read it, and nothing is restarted — use `setup` for
    /// that.
    Config {
        /// The address users will reach this host at.
        public_address: String,
        /// The real site REALITY borrows a certificate from.
        #[arg(long, default_value = "www.microsoft.com")]
        dest: String,
        /// The port users connect to.
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Forward through the SOCKS5 listener at this address.
        #[arg(long, value_name = "ADDR", conflicts_with = "mark")]
        socks5: Option<String>,
        /// Forward directly, marking sockets so a policy route tunnels them.
        #[arg(long, conflicts_with = "socks5")]
        mark: Option<u32>,
        /// Keep Iranian destinations out of the tunnel.
        #[arg(long)]
        block_domestic: bool,
        /// Where to write the configuration.
        #[arg(short, long, default_value = "xray-config.json")]
        out: PathBuf,
    },
    /// Install Xray, configure it, and start it — all of it, on this host.
    ///
    /// `config` writes a file and stops there. This installs the binary if it
    /// is missing, puts the configuration where a running Xray reads it, and
    /// restarts the service so what is on disk is what is in force.
    Setup {
        /// The address users will reach this host at. Asked for if omitted.
        public_address: Option<String>,
        /// The real site REALITY borrows a certificate from.
        #[arg(long)]
        dest: Option<String>,
        /// The port users connect to.
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Where the binary lives.
        #[arg(long, default_value = xray::DEFAULT_PREFIX)]
        prefix: String,
        /// Keep Iranian destinations out of the tunnel. Asked for if omitted.
        #[arg(long)]
        block_domestic: Option<bool>,
    },
    /// Download and install Xray, verifying the published checksum.
    Install {
        /// A specific version, rather than the latest.
        #[arg(long)]
        version: Option<String>,
        /// Where to place the binary.
        #[arg(long, default_value = xray::DEFAULT_PREFIX)]
        prefix: String,
    },
    /// Install the latest version over whatever is there.
    Update {
        /// Where the binary lives.
        #[arg(long, default_value = xray::DEFAULT_PREFIX)]
        prefix: String,
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

/// Exit code for a configuration that cannot work, borrowed from `sysexits.h`.
///
/// Distinguished from every other failure so the service manager can tell the
/// two apart. A malformed configuration will be just as malformed in five
/// seconds, so restarting is pointless; a peer that is unreachable because the
/// network has not finished coming up will not be, so restarting is the whole
/// point. Returning the same code for both forces a choice between a service
/// that loops forever on a typo and one that gives up on a boot race.
const EXIT_CONFIG: u8 = 78;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if e.downcast_ref::<config::Error>().is_some() {
                ExitCode::from(EXIT_CONFIG)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    log::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::Pubkey => pubkey(),
        Command::Run => start(&cli.config),
        Command::Init {
            endpoint,
            out,
            no_gateway,
            route_all,
            socks5,
        } => setup::init(&endpoint, &out, !no_gateway, route_all, socks5),
        Command::Setup { out } => setup::interactive(&out),
        Command::Service { action } => service_command(action, &cli.config),
        Command::Xray { action } => xray_command(action, &cli.config),
        Command::Config { action } => match action {
            ConfigAction::Migrate { yes } => migrate::run(&cli.config, yes),
        },
        Command::Update { yes } => update::run(yes),
        Command::Start => unit_command("start"),
        Command::Stop => unit_command("stop"),
        Command::Restart => unit_command("restart"),
        Command::Networkd { action } => networkd_command(action),
        Command::Tune { apply } => tune(apply, &cli.config),
        Command::Doctor {
            under_load: true,
            tunnel,
            rate,
        } => {
            if rate <= 0.0 {
                return Err("--rate must be greater than zero".into());
            }
            probe::run(&cli.config, tunnel.as_deref(), rate)
        }
        Command::Doctor { .. } => {
            if doctor::run(&cli.config) {
                Ok(())
            } else {
                Err("the host is not ready; see the failures above".into())
            }
        }
        Command::Warp { action } => match action {
            WarpAction::Setup => warp::setup(&cli.config),
            WarpAction::Refresh => warp::refresh(&cli.config),
            WarpAction::Status => warp::status(),
            WarpAction::Revert { purge } => warp::revert(purge),
        },
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
    let process = Config::load(path)?;
    // `PAQETZ_LOG` overrides the file, so a level can be raised for one run
    // without editing anything.
    let level = std::env::var("PAQETZ_LOG")
        .ok()
        .and_then(|v| log::Level::parse(&v))
        .unwrap_or(process.log);
    log::set_level(level);

    tunnel::install_signal_handlers();

    // Named in the log only when there is more than one, so a single tunnel
    // reads exactly as it always has.
    let labelled = process.tunnels.len() > 1;

    // Every tunnel starts before anything is installed around them: the ports
    // the firewall rules must name are settled by binding, and one table covers
    // them all. Scoping a rule to anything else -- the peer's port, say -- would
    // leave the kernel free to reset the very traffic it exists to protect.
    let mut tunnels = Vec::with_capacity(process.tunnels.len());
    for cfg in &process.tunnels {
        log::info!(
            "{} at {} (mtu {}), peer {} {}",
            cfg.interface.device,
            cfg.interface.address,
            cfg.interface.mtu,
            cfg.peer.tunnel_address,
            cfg.peer.endpoint.map_or_else(
                || "waiting for connection".to_owned(),
                |e| format!("via {e}")
            ),
        );
        let mut tunnel = Tunnel::start(cfg.clone(), process.health_interval)?;
        if labelled {
            tunnel.set_label(cfg.name.clone());
        }
        tunnel.watch_config(path.to_path_buf());
        // A carrier with no ports has none to report, and naming one anyway
        // sends whoever reads this looking for it on the wire.
        if tunnel.shape().has_ports() {
            log::info!(
                "{}: outer port {}, log level {}",
                cfg.name,
                tunnel.local_port(),
                level.name()
            );
        } else {
            log::info!(
                "{}: outer protocol {}, log level {}",
                cfg.name,
                tunnel.shape().protocol(),
                level.name()
            );
        }
        tunnels.push(tunnel);
    }

    // Every port in every pool, not just the one in use. The carrier moves
    // between them while it runs, and a rule that named only the current one
    // would stop covering the flow the moment it moved -- leaving the kernel
    // free to reset the very traffic the rules exist to protect.
    //
    // A carrier with no ports names its protocol number instead, and the two
    // cannot be mixed: the rules for one say nothing about the other, so a
    // process carrying both shapes at once is refused when the configuration is
    // read rather than half-protected here.
    let guard = match tunnels.first().map(Tunnel::shape) {
        Some(shape) if !shape.has_ports() => paqetz_fw::rules::Guard::Protocol(shape.protocol()),
        _ => paqetz_fw::rules::Guard::Ports(
            tunnels.iter().flat_map(Tunnel::ports).copied().collect(),
        ),
    };

    // The rules are load-bearing, not advisory (D9): without them the kernel
    // resets the flow. One table names every port, in one transaction.
    let fw = if process.manage_firewall {
        match Firewall::detect(guard) {
            Ok(fw) => {
                fw.apply()?;
                Some(fw)
            }
            Err(e) => {
                log::warn_!("{e}");
                log::warn_!("the tunnel will run, but the kernel may reset it");
                None
            }
        }
    } else {
        None
    };

    let mut attached = Vec::with_capacity(tunnels.len());
    for (cfg, tunnel) in process.tunnels.iter().zip(&tunnels) {
        attached.push(attach(cfg, tunnel)?);
    }

    // Each tunnel blocks in its own loop until shutdown, so they run in
    // parallel and are waited on together. A signal stops all of them, because
    // the flag they watch is the process's.
    let mut running = Vec::with_capacity(tunnels.len());
    for (cfg, tunnel) in process.tunnels.iter().zip(tunnels) {
        let name = cfg.name.clone();
        running.push(
            std::thread::Builder::new()
                .name(format!("{name}/run"))
                .spawn(move || tunnel.run())?,
        );
    }

    let mut result = Ok(());
    for handle in running {
        match handle.join() {
            Ok(Err(e)) => {
                log::error!("tunnel stopped: {e}");
                result = Err(e);
            }
            Ok(Ok(())) => {}
            Err(_) => log::error!("a tunnel thread panicked"),
        }
    }

    for a in attached {
        a.revert();
    }

    // Leave the host as we found it, whether or not the tunnels ended cleanly.
    if let Some(fw) = fw
        && let Err(e) = fw.revert()
    {
        log::warn_!("could not remove firewall rules: {e}");
    }

    result.map_err(Into::into)
}

/// The host-level state one tunnel installs, so it can be undone.
struct Attached {
    device: String,
    marked: Option<paqetz_net4::route::Policy>,
    listener: Option<paqetz_net4::route::Policy>,
    gateway: Option<(paqetz_fw::gateway::Gateway, bool)>,
    routes: Option<paqetz_fw::gateway::TunnelRoutes>,
}

impl Attached {
    /// Leaves the host as it was found.
    fn revert(self) {
        if let Some(routes) = self.routes {
            routes.revert();
        }
        if let Some((gw, turned_on)) = self.gateway {
            gw.revert(turned_on);
        }
        if let Some(policy) = self.listener {
            policy.revert(&self.device);
        }
        if let Some(policy) = self.marked {
            policy.revert(&self.device);
        }
    }
}

/// Installs the routing, forwarding and front end one tunnel asks for.
///
/// Separate from starting the tunnel because the two happen at different times:
/// every tunnel binds its socket first, so the one firewall table can name every
/// port at once, and only then does each one arrange the host around itself.
fn attach(
    cfg: &config::TunnelConfig,
    tunnel: &Tunnel,
) -> Result<Attached, Box<dyn std::error::Error>> {
    // Sockets and the device come up first, because the port the rules must
    // name is only settled here: the initiating side takes an ephemeral one.
    // Scoping the rules to anything else — the peer's port, say — would leave
    // the kernel free to reset the very traffic they exist to protect.
    let mut socks5 = cfg.socks5.clone();
    let device = cfg.interface.device.clone();
    let want_gateway = cfg.interface.gateway;
    let mark_route = cfg
        .interface
        .route_marked
        .map(|mark| paqetz_net4::route::Policy {
            mark,
            table: cfg.interface.route_table,
        });
    // One rule per mark. `route_marked` and the SOCKS5 listener both steer by
    // mark, and both default to 0x51, so a host using both installed two rules
    // at one priority for one mark pointing at different tables. The second is
    // unreachable -- which of the two decides the route is settled by insertion
    // order -- and telling the operator to renumber their configuration would be
    // asking them to work around us.
    //
    // So the listener follows the interface's table when the marks agree. Its
    // own connections are pinned to the device and do not consult a table at
    // all; the rule exists for the traffic that is not ours.
    if let (Some(policy), Some(s5)) = (mark_route.as_ref(), socks5.as_mut())
        && s5.mark == policy.mark
        && s5.table != policy.table
    {
        log::info!(
            "socks5.table {} and interface.route_table {} both steer mark {}; \
             using {} for both, since one mark cannot use two tables",
            s5.table,
            policy.table,
            policy.mark,
            policy.table
        );
        s5.table = policy.table;
    }

    let want_routes = cfg.interface.route_all;
    let subnet = cfg.tunnel_subnet();
    let egress_choice = cfg
        .interface
        .egress
        .clone()
        .map(|interface| paqetz_fw::gateway::Egress {
            interface,
            table: cfg.interface.egress_table,
        });
    let peer_endpoint = cfg.peer.endpoint;

    // A policy route for marked sockets, if asked for. This is the L3 way to
    // send *some* of a host's traffic through the tunnel: whatever sets the
    // mark goes through, everything else does not — including the inbound
    // connections of a proxy sitting in front of it, which `route_all` would
    // capture and break.
    let marked = match mark_route {
        None => None,
        Some(policy) => match policy.apply(&device) {
            Ok(()) => {
                log::info!(
                    "sockets marked {} route through {device} (table {})",
                    policy.mark,
                    policy.table
                );
                Some(policy)
            }
            Err(e) => {
                log::error!("could not install the mark route: {e}");
                None
            }
        },
    };

    // The SOCKS5 front end, if asked for. Started after the device exists,
    // since the policy route it needs points at that device.
    let policy = match socks5 {
        None => None,
        Some(cfg) => {
            let policy = paqetz_net4::route::Policy {
                mark: cfg.mark,
                table: cfg.table,
            };
            // Already installed if `route_marked` asked for the same thing.
            // Applying it again would revert and reinstate the identical rule,
            // taking the routes with it for the moment in between.
            if marked != Some(policy) {
                policy.apply(&device)?;
            }

            let running = tunnel.running_flag();
            let listener = paqetz_net4::Config {
                listen: cfg.listen,
                mark: cfg.mark,
                credentials: cfg.credentials,
                // What actually carries these connections. The mark and its
                // policy rule are kept as well, for anything else pointed at
                // them, but nothing here now depends on state outside this
                // process staying where it was put.
                device: Some(device.clone()),
                // Marked the same way the proxied connections are, so the
                // query takes the tunnel rather than the local network.
                resolver: cfg.dns.map(|server| paqetz_net4::Resolver {
                    server,
                    mark: cfg.mark,
                    device: Some(device.clone()),
                }),
            };
            match cfg.dns {
                Some(server) => log::info!("socks5 resolves through the tunnel at {server}"),
                None => log::warn_!(
                    "socks5 resolves with this host's own resolver: names are \
                     visible to the local network, which also chooses the answers"
                ),
            }
            std::thread::Builder::new()
                .name("socks5-accept".to_owned())
                .spawn(move || {
                    if let Err(e) = paqetz_net4::serve(listener, running) {
                        log::error!("socks5: {e}");
                    }
                })?;
            Some(policy)
        }
    };

    // Forwarding and translation, so the peer's traffic can reach beyond this
    // host. Without it the two ends reach each other and nothing else, which
    // looks exactly like a broken tunnel while nothing is broken.
    let gateway = if want_gateway {
        let gw = paqetz_fw::gateway::Gateway {
            device: device.clone(),
            subnet,
            egress: egress_choice,
        };
        if !gw.egress_present() {
            log::error!(
                "the egress interface named in the configuration does not exist; \
                 bring it up first, or remove `egress` to use the default route"
            );
        }
        match gw.apply() {
            Ok(turned_on) => {
                log::info!(
                    "forwarding and address translation for {}/{}",
                    subnet.0,
                    subnet.1
                );
                Some((gw, turned_on))
            }
            Err(e) => {
                log::error!("could not set up forwarding: {e}");
                log::error!("the tunnel will carry traffic between the two ends only");
                None
            }
        }
    } else {
        None
    };

    // Routes that send this host's traffic through the tunnel, with the
    // tunnel's own endpoint excepted so it does not try to route through
    // itself and collapse.
    let routes = match (want_routes, peer_endpoint) {
        (true, Some(endpoint)) => {
            let (gw, dev) = default_route()?;
            let r = paqetz_fw::gateway::TunnelRoutes {
                device: device.clone(),
                endpoint: *endpoint.ip(),
                original_gateway: gw,
                original_device: dev,
            };
            match r.apply() {
                Ok(()) => {
                    log::info!("routing this host's traffic through {device}");
                    Some(r)
                }
                Err(e) => {
                    log::error!("could not install routes: {e}");
                    None
                }
            }
        }
        (true, None) => {
            log::warn_!("route_all needs a peer endpoint; this end waits to be contacted");
            None
        }
        (false, _) => None,
    };

    Ok(Attached {
        device,
        marked,
        listener: policy,
        gateway,
        routes,
    })
}

/// The gateway and interface of the host's default route.
fn default_route() -> Result<(Option<std::net::Ipv4Addr>, String), Box<dyn std::error::Error>> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (Some(iface), Some(dest), Some(gw), Some(flags)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).unwrap_or(0) & 0x0001 != 0;
        if dest != "00000000" || !up {
            continue;
        }
        // The address columns are little-endian hexadecimal.
        let raw = u32::from_str_radix(gw, 16).unwrap_or(0).swap_bytes();
        let gateway = if raw == 0 {
            None
        } else {
            Some(std::net::Ipv4Addr::from(raw.to_be_bytes()))
        };
        return Ok((gateway, iface.to_owned()));
    }
    Err("no default route, so there is nothing to route around".into())
}

fn service_command(
    action: ServiceAction,
    config: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ServiceAction::Show => {
            let binary = std::env::current_exe()?.display().to_string();
            print!(
                "{}",
                service::tunnel_unit(&binary, &config.display().to_string())
            );
            Ok(())
        }
        ServiceAction::Install { enable } => {
            if !service::has_systemd() {
                return Err("this host does not use systemd".into());
            }
            // Validate before installing anything: a unit pointing at a
            // configuration that does not parse would fail at start, which is
            // a worse place to find out.
            Config::load(config)?;

            let binary = service::install_binary("/usr/local/bin")?;
            let target = "/etc/paqetz/paqetz.toml";
            if config != std::path::Path::new(target) {
                let contents = std::fs::read_to_string(config)?;
                service::write_file(std::path::Path::new(target), &contents, 0o600)?;
                println!("    wrote {target}");
            }
            service::install_unit("paqetz", &service::tunnel_unit(&binary, target), enable)?;
            println!("\nCheck it with:  systemctl status paqetz");
            println!("Follow it with: journalctl -u paqetz -f");
            Ok(())
        }
        ServiceAction::Remove => {
            service::remove_unit("paqetz");
            println!("Removed. The configuration in /etc/paqetz was left alone.");
            Ok(())
        }
    }
}

/// `paqetz xray setup` — install, configure, and start Xray on this host.
///
/// The upstream is read from the tunnel's own configuration rather than asked
/// for again: whether Xray should hand traffic to a SOCKS5 listener or mark its
/// sockets is already decided by how the tunnel was set up, and asking the same
/// question twice in different words is how the two answers end up disagreeing.
fn xray_setup(
    public_address: Option<String>,
    dest: Option<String>,
    port: u16,
    prefix: &str,
    block_domestic: Option<bool>,
    config: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let tunnel = config::Config::load(config).ok().and_then(|c| {
        c.tunnels.first().map(|t| {
            (
                t.socks5.as_ref().map(|s| s.listen.to_string()),
                t.interface.route_marked,
            )
        })
    });
    // The mark wins when both are configured: a marked socket reaches the
    // tunnel through the kernel's routing, where SOCKS5 reaches it through a
    // proxy that must accept, parse and relay every connection first.
    let upstream = match &tunnel {
        Some((_, Some(mark))) => xray::Upstream::Marked(*mark),
        Some((Some(listen), None)) => xray::Upstream::Socks5(listen.clone()),
        _ => {
            return Err(format!(
                "read {} but found neither a socks5 listener nor route_marked, so there \
                 is nowhere for Xray to send what it receives. Configure one first.",
                config.display()
            )
            .into());
        }
    };
    match &upstream {
        xray::Upstream::Socks5(a) => {
            println!("Xray will forward through the SOCKS5 listener at {a}.")
        }
        xray::Upstream::Marked(m) => println!("Xray will mark its outbound sockets {m}."),
    }

    let public = match public_address {
        Some(a) => a,
        None => setup::ask("What address will users reach this host at?", "")?,
    };
    if public.trim().is_empty() {
        return Err("an address users can reach is needed for the client URI".into());
    }
    let dest = match dest {
        Some(d) => d,
        None => {
            println!(
                "\nREALITY impersonates a real site. It must speak TLS 1.3, sit on a\n\
                 large network, and not itself be blocked where this runs.\n\
                 Suggestions: {}",
                xray::SUGGESTED_DESTINATIONS.join(", ")
            );
            setup::ask("Which site?", "www.microsoft.com")?
        }
    };

    let upstream_kind = upstream.clone();
    let block_domestic = match block_domestic {
        Some(b) => b,
        None => setup::yes_no(
            "\nKeep Iranian destinations out of the tunnel? They are reachable\n\
             without it, and sending them abroad and back is slower, more\n\
             visible, and sometimes refused at the far end.",
            true,
        )?,
    };
    let generated = xray::generate(&xray::Plan {
        listen_port: port,
        dest,
        upstream,
        public_address: public,
        block_domestic,
    })?;

    // Install before applying, so the configuration is never written for
    // software that is not here to read it.
    match xray::installed_version(prefix) {
        None => {
            println!("\nXray is not installed here.");
            if setup::yes_no(
                "Install it? The download is checked against the published digest.",
                true,
            )? {
                let v = xray::install(None, prefix)?;
                println!("  installed {v}");
            } else {
                return Err("Xray is needed for this to do anything".into());
            }
        }
        Some(v) => println!("\nXray {v} is installed."),
    }

    xray::apply(
        &generated.config,
        prefix,
        matches!(upstream_kind, xray::Upstream::Marked(_)),
    )?;

    println!("\nGive this to a user:\n");
    println!("{}\n", generated.uri);
    println!("The private key is in the configuration, not in that URI.");
    println!("Its public half is {}.", generated.public_key);
    Ok(())
}

fn xray_command(
    action: XrayAction,
    config: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        XrayAction::Config {
            public_address,
            dest,
            port,
            socks5,
            mark,
            block_domestic,
            out,
        } => {
            let upstream = match (socks5, mark) {
                (Some(addr), _) => xray::Upstream::Socks5(addr),
                (None, Some(m)) => xray::Upstream::Marked(m),
                (None, None) => xray::Upstream::Socks5("127.0.0.1:1080".to_owned()),
            };
            let generated = xray::generate(&xray::Plan {
                listen_port: port,
                dest,
                upstream,
                public_address,
                block_domestic,
            })?;
            // Holds the REALITY private key.
            service::write_file(&out, &generated.config, 0o600)?;
            println!("Wrote {} (mode 0600)\n", out.display());
            println!("Give this to a client:\n");
            println!("{}\n", generated.uri);
            println!("The private key is in the configuration and not in that URI.");
            Ok(())
        }
        XrayAction::Setup {
            public_address,
            dest,
            port,
            prefix,
            block_domestic,
        } => xray_setup(public_address, dest, port, &prefix, block_domestic, config),
        XrayAction::Install { version, prefix } => {
            let v = xray::install(version.as_deref(), &prefix)?;
            println!("\nInstalled {v}.");
            Ok(())
        }
        XrayAction::Update { prefix } => {
            let before = xray::installed_version(&prefix);
            let after = xray::install(None, &prefix)?;
            match before {
                Some(b) if b == after => println!("\nAlready at {after}."),
                Some(b) => println!("\nUpdated {b} to {after}."),
                None => println!("\nInstalled {after}."),
            }
            Ok(())
        }
    }
}

/// `paqetz start`, `stop` and `restart`, which are systemd's with the unit name
/// filled in.
///
/// Thin on purpose. They exist because the unit is called `paqetz` and everyone
/// reaches for `paqetz restart` first, not because there is anything to add to
/// what systemd already does -- so the failures are systemd's, reported as
/// systemd reported them.
fn unit_command(verb: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !service::has_systemd() {
        return Err(format!(
            "no systemd on this host, so there is no service to {verb};              run `paqetz run -c <file>` however this system starts things"
        )
        .into());
    }
    if !service::unit_exists("paqetz") {
        return Err("no paqetz service is installed; `paqetz service install` writes one".into());
    }

    service::run_elevated("systemctl", &[verb, "paqetz"])?;
    if verb != "stop" {
        println!("Check it with:   systemctl status paqetz");
        println!("Follow it with:  journalctl -u paqetz -f");
    }
    Ok(())
}

/// Whether standard input is a terminal, and so whether asking is possible.
///
/// A question printed into a pipe is a hang, not a question.
fn at_a_terminal() -> bool {
    // SAFETY: isatty takes a descriptor and touches no memory.
    unsafe { libc::isatty(0) == 1 }
}

/// Asks a yes-or-no question, defaulting to no.
pub(crate) fn confirm(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};
    print!("{prompt} [y/N] > ");
    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// What `paqetz config` can do.
#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Convert a single-tunnel file to the form that can hold several.
    ///
    /// The two forms are the same file at different depths, so this moves
    /// `[interface]` and `[peer]` under a `[[tunnel]]` section and lifts the
    /// process-level settings to the top. Comments are kept, and nothing is
    /// written unless the result parses to the same configuration as the
    /// original.
    ///
    /// The old form keeps working indefinitely, so this is a convenience rather
    /// than something that has to be done.
    Migrate {
        /// Write it without asking.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

/// What `paqetz networkd` can do.
#[derive(Subcommand, Debug)]
enum NetworkdAction {
    /// Report whether networkd will delete the policy rule.
    ///
    /// Reads the configuration rather than asking networkd, which has no way to
    /// report an effective setting. Changes nothing.
    Status,

    /// Write the drop-in that tells it not to. Use --restart with this.
    ///
    /// Writes /etc/systemd/networkd.conf.d/10-paqetz.conf, setting
    /// ManageForeignRoutingPolicyRules=no. A drop-in rather than an edit to
    /// networkd.conf, so nothing you wrote is touched and `unprotect` is a
    /// complete undo.
    ///
    /// On its own this does not take effect. `networkctl reload` re-reads
    /// .network and .netdev files, not networkd.conf or its drop-ins, so
    /// nothing short of restarting networkd applies it -- which is what
    /// --restart does, and what makes it the recommended form. Without it the
    /// setting waits for the next reboot, and until then networkd still removes
    /// the rule when an interface changes state.
    Protect {
        /// Restart networkd so it takes effect now, rather than at the next
        /// reboot. This reconfigures every interface on the host.
        #[arg(long)]
        restart: bool,
    },
    /// Remove that drop-in, restoring networkd's default behaviour.
    ///
    /// Also needs a networkd restart to take effect.
    Unprotect,
}

/// `paqetz networkd`.
fn networkd_command(action: NetworkdAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        NetworkdAction::Status => {
            match networkd::status() {
                networkd::Status::Absent => {
                    println!("systemd-networkd is not running; nothing removes the policy rule.");
                }
                networkd::Status::LeavesRulesAlone => {
                    println!("systemd-networkd is running and leaves foreign policy rules alone.");
                }
                networkd::Status::WillDeleteRules => {
                    println!(
                        "systemd-networkd will delete the policy rule when an interface\n\
                         changes state or the service restarts.\n\n\
                         That does not stop traffic. The rule goes, the lookup falls through\n\
                         to the main table, and what should have been tunnelled leaves this\n\
                         host in the clear instead -- while the tunnel stays up and looks\n\
                         healthy.\n\n\
                         Fix it with: paqetz networkd protect"
                    );
                }
            }
            Ok(())
        }
        NetworkdAction::Protect { restart } => {
            println!("Writing {}:\n", networkd::drop_in_path().display());
            println!("{}", networkd::drop_in());
            networkd::apply(restart)?;

            let restart = restart
                || (at_a_terminal()
                    && {
                        println!(
                            "\nWritten, but nothing reads it until networkd restarts.\n\
                             Restarting reconfigures every interface on this host, so if\n\
                             you are reading this over one of them there is a brief risk\n\
                             to the session. A reboot does the same job later."
                        );
                        confirm("Restart systemd-networkd now?")
                    }
                    && {
                        service::run_elevated("systemctl", &["restart", "systemd-networkd"])?;
                        true
                    });

            if restart {
                println!("Written, and networkd restarted, so it is in force now.");
            } else {
                // Said plainly because the opposite -- believing a host is
                // protected when it is not -- is worse than knowing it is
                // exposed. `networkctl reload` does not help: it re-reads
                // .network and .netdev files, not networkd.conf or its drop-ins.
                println!(
                    "Written, but NOT yet in force: only restarting networkd re-reads\n\
                     this file. Either accept that it applies at the next reboot, or:\n\n\
                     \x20   sudo systemctl restart systemd-networkd\n\n\
                     which reconfigures every interface on this host -- worth thinking\n\
                     about if you are reading this over one of them. `paqetz networkd\n\
                     protect --restart` does it for you.\n\n\
                     Until networkd restarts it will still remove the rule when an\n\
                     interface changes state, and nothing here puts it back. The table\n\
                     fails closed, so that is an outage rather than traffic leaving in\n\
                     the clear -- `systemctl restart paqetz` ends it."
                );
            }
            println!("\n`paqetz networkd unprotect` removes it.");
            Ok(())
        }
        NetworkdAction::Unprotect => {
            let path = networkd::drop_in_path();
            service::run_elevated("rm", &["-f", &path.display().to_string()])?;
            println!("Removed {}.", path.display());
            Ok(())
        }
    }
}

fn tune(apply: bool, config: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // Whether this host forwards for its peer decides half the list. Read from
    // the configuration rather than asked, and assumed false when there is none
    // -- offering a client the settings a gateway needs is worse than offering
    // a gateway too few, since the first leaves settings behind that nobody can
    // explain and the second prints one more line.
    let gateway =
        config::Config::load(config).is_ok_and(|c| c.tunnels.iter().any(|t| t.interface.gateway));

    let pending = paqetz_fw::tune::pending(gateway);
    if pending.is_empty() {
        println!("Every setting already has the value a tunnel wants.");
        return Ok(());
    }

    println!("{} setting(s) would change:\n", pending.len());
    for (setting, current) in &pending {
        println!("  {} = {}", setting.key, setting.value);
        println!(
            "      now: {}",
            current.as_deref().unwrap_or("(not set on this kernel)")
        );
        println!("      why: {}\n", setting.reason);
    }

    if !apply {
        println!("Nothing was changed. Re-run with --apply to write them to");
        println!(
            "{}, which can be deleted to undo them.",
            paqetz_fw::tune::PATH
        );
        return Ok(());
    }
    paqetz_fw::tune::apply(gateway)?;
    println!("Applied, and written to {}.", paqetz_fw::tune::PATH);
    Ok(())
}

fn firewall(
    action: FirewallAction,
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(path)?;
    let guard = effective_guard(&cfg)?;

    // `plan` must work on a host with neither tool installed — printing what to
    // run by hand is exactly what it is for.
    if matches!(action, FirewallAction::Plan) {
        let fw = Firewall::detect(guard.clone())
            .unwrap_or_else(|_| Firewall::with_backend(paqetz_fw::Backend::Nft, guard));
        for line in fw.plan() {
            println!("{line}");
        }
        return Ok(());
    }

    let fw = Firewall::detect(guard)?;
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
/// What this configuration's firewall rules should name.
///
/// Follows the carrier, as `run` does. Built from a port unconditionally, a
/// port-less carrier was handed rules about TCP ports it never sends: they
/// protect nothing, and the kernel goes on answering its packets. The whole
/// point of this command is the host where `manage_firewall` is off, so being
/// wrong here is being wrong in the one place nothing else covers.
fn effective_guard(cfg: &Config) -> Result<paqetz_fw::rules::Guard, &'static str> {
    // Mixed shapes in one process are refused when the file is read, so the
    // first tunnel speaks for all of them.
    if let Some(shape) = cfg.tunnels.first().map(|t| t.interface.shape)
        && !shape.has_ports()
    {
        // Nameable whatever `listen_port` says: these rules are about a
        // protocol number, and that is fixed before anything is bound.
        return Ok(paqetz_fw::rules::Guard::Protocol(shape.protocol()));
    }
    effective_port(cfg)
        .map(|p| paqetz_fw::rules::Guard::Ports(vec![p]))
        .ok_or(
            "this end takes an ephemeral outer port at start-up, so its rules \
             cannot be named ahead of time. `run` installs them itself; to manage \
             them by hand, set interface.listen_port to a fixed port.",
        )
}

fn effective_port(cfg: &Config) -> Option<u16> {
    // The first tunnel with a fixed port. A process whose tunnels all take
    // ephemeral ones has nothing to report until they are bound.
    cfg.tunnels
        .iter()
        .map(|t| t.interface.listen_port)
        .find(|p| *p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_firewall_command_names_what_the_carrier_actually_sends() {
        // The command exists for the host where `manage_firewall` is off, so
        // being wrong here is being wrong in the one place nothing else covers.
        // Rules built from a port for a carrier that has none protect nothing,
        // and the kernel goes on answering its packets.
        let with = |lines: &str| {
            let text = format!(
                r#"
[[tunnel]]
name = "one"
[tunnel.interface]
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"
{lines}
[tunnel.peer]
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
endpoint = "203.0.113.5:8443"
tunnel_address = "10.7.0.1"
"#
            );
            effective_guard(&Config::parse(&text).expect("parse"))
        };

        assert_eq!(
            with("listen_port = 8443").expect("a fixed port is nameable"),
            paqetz_fw::rules::Guard::Ports(vec![8443])
        );
        assert_eq!(
            with("carrier = \"gre\"").expect("a protocol is always nameable"),
            paqetz_fw::rules::Guard::Protocol(47)
        );
        assert_eq!(
            with("carrier = \"rawip\"\ncarrier_protocol = 143").expect("likewise"),
            paqetz_fw::rules::Guard::Protocol(143)
        );
        // A port-less carrier is nameable whatever `listen_port` says, because
        // its rules were never about a port.
        assert_eq!(
            with("carrier = \"gre\"\nlisten_port = 0").expect("still nameable"),
            paqetz_fw::rules::Guard::Protocol(47)
        );
        // An ephemeral port genuinely is not, and says so rather than guessing.
        assert!(with("").is_err(), "an ephemeral port cannot be named early");
    }

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
