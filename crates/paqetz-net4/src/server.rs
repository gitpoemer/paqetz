//! The SOCKS5 listener.
//!
//! One thread per connection, which is the right shape for a debugging front
//! end and the wrong one for a production datapath — which is precisely why
//! this is not the production datapath. All the per-flow state the rest of the
//! design refuses to hold lives here, on the client only, and only when it is
//! switched on.

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::dial;
use crate::protocol::{self, Address, auth, cmd, reply};

/// How long a client has to complete the handshake before being dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a UDP association may sit idle before it is torn down.
///
/// UDP has no close, so without this an association leaks until the process
/// ends. Thirty seconds is under the usual NAT timeout, so a session that is
/// still alive will have refreshed it.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Relay buffer size.
const BUFFER: usize = 32 * 1024;

/// What the listener needs to know.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where to listen. Loopback unless there is a reason otherwise.
    pub listen: SocketAddr,
    /// Firewall mark stamped on outbound connections, steering them into the
    /// tunnel. Zero disables marking, which sends them out the normal route.
    pub mark: u32,
    /// Required credentials, if any.
    pub credentials: Option<(String, String)>,
    /// The tunnel device outbound connections are pinned to.
    ///
    /// This is what actually puts them in the tunnel. The mark above depends on
    /// a policy rule, which lives outside this process and can be removed by
    /// something else; binding to the device cannot.
    pub device: Option<String>,
    /// Where to resolve names, through the tunnel.
    ///
    /// `None` falls back to this host's own resolver, which is the network the
    /// tunnel exists to get out of — so the names are visible to it, and it
    /// decides what they resolve to. Kept only for a host where that is
    /// genuinely wanted.
    pub resolver: Option<crate::dns::Resolver>,
}

/// Runs the listener until `running` clears.
///
/// # Errors
/// Returns an error only if the listening socket cannot be bound; per-connection
/// failures are logged and the loop continues.
pub fn serve(config: Config, running: Arc<AtomicBool>) -> io::Result<()> {
    let listener = TcpListener::bind(config.listen)?;
    // A short accept timeout so shutdown is noticed without a second mechanism.
    listener.set_nonblocking(true)?;

    println!(
        "paqetz: SOCKS5 on {} (mark {}){}",
        config.listen,
        config.mark,
        if config.credentials.is_some() {
            ", authenticated"
        } else {
            ""
        }
    );

    let config = Arc::new(config);
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let config = Arc::clone(&config);
                let running = Arc::clone(&running);
                let spawned =
                    std::thread::Builder::new()
                        .name("socks5".to_owned())
                        .spawn(move || {
                            if let Err(e) = handle(stream, &config, &running) {
                                // A client that goes away mid-handshake is ordinary
                                // and not worth a line.
                                if e.kind() != io::ErrorKind::UnexpectedEof {
                                    eprintln!("socks5 {peer}: {e}");
                                }
                            }
                        });
                if let Err(e) = spawned {
                    eprintln!("socks5: could not start a thread: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("socks5 accept: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Ok(())
}

/// Handles one client connection through handshake and relay.
fn handle(mut client: TcpStream, config: &Config, running: &AtomicBool) -> io::Result<()> {
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    negotiate(&mut client, config)?;
    let request = protocol::read_request(&mut client)?;

    match request.command {
        cmd::CONNECT => connect(client, &request.address, config),
        cmd::UDP_ASSOCIATE => udp_associate(client, config, running),
        other => {
            let bound = Address::Socket(SocketAddr::from(([0, 0, 0, 0], 0)));
            protocol::write_reply(&mut client, reply::COMMAND_NOT_SUPPORTED, &bound)?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("socks5: command {other:#04x} is not supported"),
            ))
        }
    }
}

/// Performs method selection and, if configured, authentication.
fn negotiate(client: &mut TcpStream, config: &Config) -> io::Result<()> {
    let offered = protocol::read_greeting(client)?;
    let wanted = if config.credentials.is_some() {
        auth::USER_PASS
    } else {
        auth::NONE
    };

    if !offered.contains(&wanted) {
        protocol::write_method(client, auth::UNACCEPTABLE)?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5: the client offered no acceptable authentication method",
        ));
    }
    protocol::write_method(client, wanted)?;

    if let Some((user, pass)) = config.credentials.as_ref() {
        let (got_user, got_pass) = protocol::read_user_pass(client)?;
        // Compared in constant time: an attacker who can measure the difference
        // can otherwise recover the password one byte at a time.
        let ok = constant_time_eq(got_user.as_bytes(), user.as_bytes())
            & constant_time_eq(got_pass.as_bytes(), pass.as_bytes());
        protocol::write_user_pass_result(client, ok)?;
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5: credentials rejected",
            ));
        }
    }
    Ok(())
}

/// Compares two byte strings without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Relays a TCP connection.
fn connect(mut client: TcpStream, address: &Address, config: &Config) -> io::Result<()> {
    let target = match dial::connect_tcp(
        address,
        config.mark,
        config.device.as_deref(),
        config.resolver.as_ref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            let bound = Address::Socket(SocketAddr::from(([0, 0, 0, 0], 0)));
            protocol::write_reply(&mut client, protocol::reply_code_for(&e), &bound)?;
            return Err(e);
        }
    };

    let bound = Address::Socket(
        target
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
    );
    protocol::write_reply(&mut client, reply::SUCCESS, &bound)?;

    // The handshake deadlines must go before the relay: a connection that is
    // simply idle is not a connection that has failed.
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    relay(client, target)
}

/// Copies in both directions until either end finishes.
fn relay(client: TcpStream, target: TcpStream) -> io::Result<()> {
    let client_read = client.try_clone()?;
    let target_write = target.try_clone()?;

    let up = std::thread::Builder::new()
        .name("socks5-up".to_owned())
        .spawn(move || copy_then_shutdown(client_read, target_write))?;

    let down = copy_then_shutdown(target, client);
    let _ = up.join();
    down
}

/// Copies one direction, then half-closes so the other end sees the end.
///
/// Without the shutdown, a peer waiting for end-of-stream waits forever and the
/// connection leaks a thread — the same failure the L3 relay avoided by closing
/// both endpoints.
fn copy_then_shutdown(mut from: TcpStream, mut to: TcpStream) -> io::Result<()> {
    let mut buf = vec![0u8; BUFFER];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else { break };
                if to.write_all(chunk).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
    let _ = from.shutdown(std::net::Shutdown::Read);
    Ok(())
}

/// Runs a UDP association for as long as its control connection is open.
fn udp_associate(mut client: TcpStream, config: &Config, running: &AtomicBool) -> io::Result<()> {
    let relay_socket = dial::bind_udp(config.mark, config.device.as_deref())?;
    let local = relay_socket.local_addr()?;

    // The client is told where to send, on the address it reached us at — its
    // own view of us, which may not be the address we bound to.
    let advertised = SocketAddr::new(client.local_addr()?.ip(), local.port());
    protocol::write_reply(&mut client, reply::SUCCESS, &Address::Socket(advertised))?;

    // RFC 1928: the association lives exactly as long as the TCP connection
    // that requested it. A thread reading that connection notices it close.
    let alive = Arc::new(AtomicBool::new(true));
    let watcher = Arc::clone(&alive);
    std::thread::Builder::new()
        .name("socks5-udp-ctl".to_owned())
        .spawn(move || {
            let mut sink = [0u8; 64];
            client.set_read_timeout(None).ok();
            // Any result other than more data means the control connection has
            // ended, which ends the association.
            while matches!(client.read(&mut sink), Ok(n) if n > 0) {}
            watcher.store(false, Ordering::Relaxed);
        })?;

    relay_socket.set_read_timeout(Some(UDP_IDLE_TIMEOUT))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut peer: Option<SocketAddr> = None;

    while alive.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
        let (n, from) = match relay_socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // Idle. Nothing has gone wrong; check the control connection
                // and wait again.
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some(datagram) = buf.get(..n) else {
            continue;
        };

        // The first datagram fixes which client this association serves.
        // Without that, anything that can reach the port can inject traffic
        // into someone else's association.
        let from_client = match peer {
            None => {
                peer = Some(from);
                true
            }
            Some(p) => p == from,
        };

        if from_client {
            forward_outbound(&relay_socket, datagram, config)?;
        } else {
            forward_inbound(&relay_socket, datagram, from, peer)?;
        }
    }
    Ok(())
}

/// Sends a client's encapsulated datagram on to its real destination.
fn forward_outbound(sock: &UdpSocket, datagram: &[u8], config: &Config) -> io::Result<()> {
    let parsed = match protocol::parse_udp(datagram) {
        Ok(p) => p,
        Err(_) => return Ok(()), // malformed: drop, as UDP always may
    };
    let Ok(targets) = dial::resolve(&parsed.address, config.resolver.as_ref()) else {
        return Ok(());
    };
    // IPv4 only, for the reason the TCP side is: the relay socket is marked so
    // that the v4 policy route carries it, and a v6 destination would leave by
    // the host's ordinary route instead — around the tunnel rather than through
    // it. Dropped rather than sent, which is what UDP looks like anyway.
    let Some(target) = targets.iter().find(|t| t.is_ipv4()) else {
        return Ok(());
    };
    let _ = sock.send_to(parsed.payload, target);
    Ok(())
}

/// Wraps a reply from the outside world and returns it to the client.
fn forward_inbound(
    sock: &UdpSocket,
    datagram: &[u8],
    from: SocketAddr,
    peer: Option<SocketAddr>,
) -> io::Result<()> {
    let Some(client) = peer else { return Ok(()) };
    let wrapped = protocol::build_udp(&Address::Socket(from), datagram);
    let _ = sock.send_to(&wrapped, client);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_compare_without_an_early_exit() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn the_idle_timeout_is_under_the_usual_nat_timeout() {
        // A UDP association that is still in use will have refreshed a NAT
        // mapping well before this, so the timeout only reaps dead ones.
        assert!(UDP_IDLE_TIMEOUT <= Duration::from_secs(30));
    }
}
