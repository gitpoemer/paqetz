//! Making connections that go through the tunnel rather than around it.
//!
//! This is the whole trick that lets L4 mode exist without a userspace TCP
//! stack. The kernel already has one, and the tunnel is already a network
//! device — so a connection only needs to be *routed* into it. Stamping
//! `SO_MARK` on the socket and adding one policy-routing rule does that, and
//! the kernel does the TCP.
//!
//! The alternative — running a TCP stack in userspace to turn each SOCKS5
//! connection into IP packets — is several thousand lines, and was the one
//! serious argument for writing this program in Go, where gVisor's netstack
//! exists. It turned out not to be needed.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::time::Duration;

use crate::protocol::Address;

/// How long to wait for a target to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Stamps `SO_MARK` on a socket.
///
/// Requires `CAP_NET_ADMIN`.
fn set_mark(fd: RawFd, mark: u32) -> io::Result<()> {
    let value =
        libc::c_int::try_from(mark).map_err(|_| io::Error::other("mark does not fit in an int"))?;
    let len = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| io::Error::other("implausible option size"))?;
    // SAFETY: SO_MARK takes an int, and `value` is one, borrowed for the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&value).cast(),
            len,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::PermissionDenied {
            return Err(io::Error::new(
                e.kind(),
                "setting SO_MARK requires CAP_NET_ADMIN",
            ));
        }
        return Err(e);
    }
    Ok(())
}

/// Creates a socket of the given domain and type, marked before use.
fn marked_socket(domain: libc::c_int, ty: libc::c_int, mark: u32) -> io::Result<OwnedFd> {
    // SAFETY: no pointer arguments; returns a fresh descriptor or -1.
    let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, owned descriptor that nothing else holds.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if mark > 0 {
        set_mark(owned.as_raw_fd(), mark)?;
    }
    Ok(owned)
}

/// Resolves a SOCKS5 address to socket addresses.
///
/// Names are resolved *here*, on the side that will connect, which is what
/// `socks5h` in a client's proxy URL asks for. Resolving on the client would
/// leak the name to whatever DNS that side uses, and would resolve it against
/// the wrong vantage point.
///
/// # Errors
/// Returns an error if the name does not resolve.
pub fn resolve(address: &Address) -> io::Result<Vec<SocketAddr>> {
    match address {
        Address::Socket(a) => Ok(vec![*a]),
        // The resolver's own message says what went wrong but never which name
        // it was looking up, and one line of "Name has no usable address" among
        // many connections points nowhere. The name is the whole question here.
        Address::Domain(host, port) => (host.as_str(), *port)
            .to_socket_addrs()
            .map(Iterator::collect)
            .map_err(|e| io::Error::new(e.kind(), format!("could not resolve {host}: {e}"))),
    }
}

/// Keeps only the addresses this tunnel can actually carry.
///
/// IPv4, and deliberately so. The datapath carries IPv4, and the policy route
/// that steers a marked socket into the tunnel is an `ip rule` in the v4 table.
/// A marked AF_INET6 socket matches no such rule, so it would leave by the
/// host's ordinary route — outside the tunnel entirely, with this host's own
/// address visible to the destination rather than the far end's. Sending
/// traffic quietly around the tunnel is worse than refusing to carry it, so an
/// address that cannot be tunnelled is an error rather than a fallback.
///
/// A name that has both records still works: the v4 ones survive this. Only a
/// v6-only destination fails, and it fails visibly.
///
/// # Errors
/// Returns `Unsupported` when nothing IPv4 is left.
fn tunnelable(targets: Vec<SocketAddr>, address: &Address) -> io::Result<Vec<SocketAddr>> {
    let (v4, dropped): (Vec<_>, Vec<_>) = targets.into_iter().partition(SocketAddr::is_ipv4);
    if v4.is_empty() && !dropped.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "socks5: {address} is reachable only over IPv6, which this tunnel does not carry"
            ),
        ));
    }
    Ok(v4)
}

/// Opens a TCP connection to `address`, marked so it routes into the tunnel.
///
/// # Errors
/// Returns the last connection error, or a resolution failure.
pub fn connect_tcp(address: &Address, mark: u32) -> io::Result<TcpStream> {
    let targets = tunnelable(resolve(address)?, address)?;
    let mut last = io::Error::new(
        io::ErrorKind::NotFound,
        format!("socks5: {address} resolved to no addresses"),
    );

    for target in targets {
        let fd = match marked_socket(libc::AF_INET, libc::SOCK_STREAM, mark) {
            Ok(fd) => fd,
            Err(e) => {
                last = e;
                continue;
            }
        };

        // std's connect-with-timeout wants a TcpStream, and building one from a
        // raw descriptor is the only way to keep the mark that was set before
        // the connect. A mark applied afterwards would not affect the route
        // this connection has already chosen.
        // SAFETY: `fd` is an owned, unconnected stream socket, and ownership
        // moves into the `TcpStream`.
        let sock = unsafe { std::net::TcpStream::from_raw_fd(into_raw(fd)) };
        match connect_with_timeout(&sock, target, CONNECT_TIMEOUT) {
            Ok(()) => {
                sock.set_nodelay(true).ok();
                return Ok(sock);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Binds a UDP socket for a relay association, marked the same way.
///
/// # Errors
/// Returns the underlying OS error.
pub fn bind_udp(mark: u32) -> io::Result<UdpSocket> {
    let fd = marked_socket(libc::AF_INET, libc::SOCK_DGRAM, mark)?;
    // SAFETY: `fd` is an owned, unbound datagram socket; ownership moves in.
    let sock = unsafe { UdpSocket::from_raw_fd(into_raw(fd)) };
    sock.bind_any()?;
    Ok(sock)
}

/// Consumes an `OwnedFd`, yielding its descriptor without closing it.
fn into_raw(fd: OwnedFd) -> RawFd {
    let raw = fd.as_raw_fd();
    std::mem::forget(fd);
    raw
}

/// Extension so binding reads as one call.
trait BindAny {
    fn bind_any(&self) -> io::Result<()>;
}

impl BindAny for UdpSocket {
    fn bind_any(&self) -> io::Result<()> {
        let mut addr: libc::sockaddr_in =
            // SAFETY: `sockaddr_in` is plain old data; every field is set.
            unsafe { std::mem::zeroed() };
        addr.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets());
        let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
            .map_err(|_| io::Error::other("implausible address size"))?;
        // SAFETY: an AF_INET socket binds to a `sockaddr_in` of exactly `len`.
        let rc = unsafe { libc::bind(self.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Connects with a bound wait, without disturbing the socket's options.
fn connect_with_timeout(sock: &TcpStream, target: SocketAddr, timeout: Duration) -> io::Result<()> {
    // `TcpStream::connect_timeout` would create its own socket and lose the
    // mark, so the connect is issued directly and waited for with poll.
    sock.set_nonblocking(true)?;
    let result = raw_connect(sock.as_raw_fd(), target);
    match result {
        Ok(()) => {
            sock.set_nonblocking(false)?;
            return Ok(());
        }
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => {
            sock.set_nonblocking(false)?;
            return Err(e);
        }
    }

    let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one valid `pollfd`, borrowed for the duration of the call.
    let n = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, ms) };
    sock.set_nonblocking(false)?;
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("socks5: connecting to {target} timed out"),
        ));
    }
    // A finished connect reports success through SO_ERROR, not through poll.
    match sock.take_error()? {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// Issues a connect on a raw descriptor.
fn raw_connect(fd: RawFd, target: SocketAddr) -> io::Result<()> {
    let rc = match target {
        SocketAddr::V4(a) => {
            let mut addr: libc::sockaddr_in =
                // SAFETY: plain old data; every field is set below.
                unsafe { std::mem::zeroed() };
            addr.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
            addr.sin_port = a.port().to_be();
            addr.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>())
                .map_err(|_| io::Error::other("implausible address size"))?;
            // SAFETY: an AF_INET socket connects to a `sockaddr_in`.
            unsafe { libc::connect(fd, std::ptr::from_ref(&addr).cast(), len) }
        }
        SocketAddr::V6(a) => {
            let mut addr: libc::sockaddr_in6 =
                // SAFETY: plain old data; every field is set below.
                unsafe { std::mem::zeroed() };
            addr.sin6_family = u16::try_from(libc::AF_INET6).unwrap_or(10);
            addr.sin6_port = a.port().to_be();
            addr.sin6_addr.s6_addr = a.ip().octets();
            let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>())
                .map_err(|_| io::Error::other("implausible address size"))?;
            // SAFETY: an AF_INET6 socket connects to a `sockaddr_in6`.
            unsafe { libc::connect(fd, std::ptr::from_ref(&addr).cast(), len) }
        }
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_resolution_failure_names_the_host_it_was_looking_up() {
        let e = resolve(&Address::Domain("no-such-host.invalid".to_owned(), 443))
            .expect_err(".invalid never resolves");
        assert!(
            e.to_string().contains("no-such-host.invalid"),
            "a log line without the name points nowhere: {e}"
        );
    }

    #[test]
    fn a_dual_stack_name_keeps_only_its_v4_addresses() {
        let addr = Address::Domain("example.invalid".to_owned(), 443);
        let targets = vec![
            "[2001:db8::1]:443".parse().expect("v6"),
            "203.0.113.5:443".parse().expect("v4"),
        ];
        let kept = tunnelable(targets, &addr).expect("v4 survives");
        assert_eq!(kept, vec!["203.0.113.5:443".parse().expect("v4")]);
    }

    #[test]
    fn a_v6_only_destination_is_refused_rather_than_sent_around_the_tunnel() {
        // The failure this prevents: a marked AF_INET6 socket matches no v4
        // policy rule, so it leaves by the ordinary route and the destination
        // sees this host rather than the far end. A visible error beats a
        // silent bypass.
        let addr = Address::Domain("example.invalid".to_owned(), 443);
        let targets = vec!["[2001:db8::1]:443".parse().expect("v6")];
        let e = tunnelable(targets, &addr).expect_err("must not be carried");
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            crate::protocol::reply_code_for(&e),
            crate::protocol::reply::ADDRESS_NOT_SUPPORTED,
            "so the client stops asking for an address it cannot reach here"
        );
    }

    #[test]
    fn a_name_that_does_not_resolve_at_all_is_not_reported_as_unsupported() {
        let addr = Address::Domain("example.invalid".to_owned(), 443);
        assert!(
            tunnelable(vec![], &addr)
                .expect("empty is not an error here")
                .is_empty(),
            "no addresses is a resolution failure, which the caller already reports"
        );
    }

    use super::*;

    #[test]
    fn a_literal_address_resolves_to_itself() {
        let a = Address::Socket("192.0.2.1:443".parse().expect("addr"));
        assert_eq!(
            resolve(&a).expect("resolve"),
            vec!["192.0.2.1:443".parse::<SocketAddr>().expect("addr")]
        );
    }

    #[test]
    fn localhost_resolves() {
        // Uses the resolver but touches no network.
        let a = Address::Domain("localhost".to_owned(), 80);
        let addrs = resolve(&a).expect("resolve");
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn an_unresolvable_name_fails_rather_than_hanging() {
        let a = Address::Domain("this-name-should-not-exist.invalid".to_owned(), 80);
        assert!(resolve(&a).is_err());
    }

    #[test]
    fn an_unmarked_socket_can_be_created() {
        // Mark 0 means "no mark", which needs no privilege at all.
        let fd = marked_socket(libc::AF_INET, libc::SOCK_STREAM, 0).expect("socket");
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn marking_without_privilege_says_what_is_missing() {
        // Skipped when privileged, where it would succeed.
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let fd = marked_socket(libc::AF_INET, libc::SOCK_STREAM, 0).expect("socket");
        match set_mark(fd.as_raw_fd(), 0x51) {
            Err(e) => assert!(
                e.to_string().contains("CAP_NET_ADMIN"),
                "unhelpful error: {e}"
            ),
            Ok(()) => panic!("marking should need privilege"),
        }
    }

    #[test]
    fn connecting_to_a_closed_port_is_refused_promptly() {
        // Loopback only: binds nothing, and the connection is refused because
        // nothing is listening.
        let a = Address::Socket("127.0.0.1:1".parse().expect("addr"));
        let err = connect_tcp(&a, 0).expect_err("nothing listens on port 1");
        assert_eq!(
            crate::protocol::reply_code_for(&err),
            crate::protocol::reply::CONNECTION_REFUSED
        );
    }

    #[test]
    fn a_connection_to_a_listening_socket_succeeds() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let a = Address::Socket(format!("127.0.0.1:{port}").parse().expect("addr"));
        let stream = connect_tcp(&a, 0).expect("connect");
        assert_eq!(stream.peer_addr().expect("peer").port(), port);
    }
}
