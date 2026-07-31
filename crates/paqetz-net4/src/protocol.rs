//! SOCKS5 wire format: RFC 1928, and RFC 1929 for username/password auth.
//!
//! Pure codec — every function here reads or writes bytes and does no I/O of
//! its own, so the parsing is tested without a socket.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// The only protocol version.
pub const VERSION: u8 = 5;

/// Authentication methods.
pub mod auth {
    /// No authentication required.
    pub const NONE: u8 = 0x00;
    /// Username and password, per RFC 1929.
    pub const USER_PASS: u8 = 0x02;
    /// Sent when nothing offered is acceptable.
    pub const UNACCEPTABLE: u8 = 0xFF;
    /// RFC 1929's own version byte, which is not the SOCKS version.
    pub const USER_PASS_VERSION: u8 = 0x01;
}

/// Request commands.
pub mod cmd {
    /// Open a TCP connection to the target.
    pub const CONNECT: u8 = 0x01;
    /// Accept an inbound connection. Not supported.
    pub const BIND: u8 = 0x02;
    /// Relay UDP datagrams.
    pub const UDP_ASSOCIATE: u8 = 0x03;
}

/// Reply codes.
pub mod reply {
    /// The request succeeded.
    pub const SUCCESS: u8 = 0x00;
    /// Something went wrong that no other code describes.
    pub const GENERAL_FAILURE: u8 = 0x01;
    /// The network is unreachable.
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    /// The host is unreachable.
    pub const HOST_UNREACHABLE: u8 = 0x04;
    /// The target refused the connection.
    pub const CONNECTION_REFUSED: u8 = 0x05;
    /// The command is not supported.
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// The address type is not supported.
    pub const ADDRESS_NOT_SUPPORTED: u8 = 0x08;
}

/// Address types.
pub(crate) mod atyp {
    pub(crate) const IPV4: u8 = 0x01;
    pub(crate) const DOMAIN: u8 = 0x03;
    pub(crate) const IPV6: u8 = 0x04;
}

/// A destination, which SOCKS5 may express as a name rather than an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// A literal address and port.
    Socket(SocketAddr),
    /// A name and port, resolved by whoever connects rather than by the client.
    Domain(String, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(a) => write!(f, "{a}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl Address {
    /// Reads an address from `ATYP ADDR PORT`.
    ///
    /// # Errors
    /// Returns an error on a short read or an unsupported address type.
    pub fn read(r: &mut impl Read) -> io::Result<Self> {
        let mut kind = [0u8; 1];
        r.read_exact(&mut kind)?;
        match kind[0] {
            atyp::IPV4 => {
                let mut buf = [0u8; 6];
                r.read_exact(&mut buf)?;
                let (ip, port) = buf.split_at(4);
                Ok(Self::Socket(SocketAddr::from((
                    Ipv4Addr::new(
                        *ip.first().unwrap_or(&0),
                        *ip.get(1).unwrap_or(&0),
                        *ip.get(2).unwrap_or(&0),
                        *ip.get(3).unwrap_or(&0),
                    ),
                    be16(port),
                ))))
            }
            atyp::IPV6 => {
                let mut buf = [0u8; 18];
                r.read_exact(&mut buf)?;
                let (ip, port) = buf.split_at(16);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip);
                Ok(Self::Socket(SocketAddr::from((
                    Ipv6Addr::from(octets),
                    be16(port),
                ))))
            }
            atyp::DOMAIN => {
                let mut len = [0u8; 1];
                r.read_exact(&mut len)?;
                if len[0] == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socks5: zero-length domain name",
                    ));
                }
                let mut name = vec![0u8; usize::from(len[0])];
                r.read_exact(&mut name)?;
                let mut port = [0u8; 2];
                r.read_exact(&mut port)?;
                let host = String::from_utf8(name).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "socks5: domain is not UTF-8")
                })?;
                Ok(Self::Domain(host, be16(&port)))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("socks5: unsupported address type {other:#04x}"),
            )),
        }
    }

    /// Appends the `ATYP ADDR PORT` encoding to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Socket(SocketAddr::V4(a)) => {
                out.push(atyp::IPV4);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Self::Socket(SocketAddr::V6(a)) => {
                out.push(atyp::IPV6);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Self::Domain(host, port) => {
                out.push(atyp::DOMAIN);
                // A name longer than 255 bytes cannot be expressed; truncating
                // would send the wrong destination, so it is clamped to nothing
                // and the caller's connect fails cleanly instead.
                let bytes = host.as_bytes();
                let len = u8::try_from(bytes.len()).unwrap_or(0);
                out.push(len);
                out.extend_from_slice(bytes.get(..usize::from(len)).unwrap_or(&[]));
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }
}

/// Reads the client greeting and returns the methods it offers.
///
/// # Errors
/// Returns an error on a short read or a wrong version.
pub fn read_greeting(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head)?;
    if head[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5: version {} is not 5", head[0]),
        ));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if !methods.is_empty() {
        r.read_exact(&mut methods)?;
    }
    Ok(methods)
}

/// Writes the chosen authentication method.
///
/// # Errors
/// Returns the underlying write error.
pub fn write_method(w: &mut impl Write, method: u8) -> io::Result<()> {
    w.write_all(&[VERSION, method])
}

/// Reads a username/password submission.
///
/// # Errors
/// Returns an error on a short read or a wrong sub-negotiation version.
pub fn read_user_pass(r: &mut impl Read) -> io::Result<(String, String)> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head)?;
    if head[0] != auth::USER_PASS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks5: wrong username/password version",
        ));
    }
    let mut user = vec![0u8; usize::from(head[1])];
    r.read_exact(&mut user)?;
    let mut plen = [0u8; 1];
    r.read_exact(&mut plen)?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    r.read_exact(&mut pass)?;
    Ok((lossy(user), lossy(pass)))
}

/// Writes the username/password result. Zero means success.
///
/// # Errors
/// Returns the underlying write error.
pub fn write_user_pass_result(w: &mut impl Write, ok: bool) -> io::Result<()> {
    w.write_all(&[auth::USER_PASS_VERSION, u8::from(!ok)])
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// What the client wants done.
    pub command: u8,
    /// Where it wants it done.
    pub address: Address,
}

/// Reads a request.
///
/// # Errors
/// Returns an error on a short read or a wrong version.
pub fn read_request(r: &mut impl Read) -> io::Result<Request> {
    let mut head = [0u8; 3];
    r.read_exact(&mut head)?;
    if head[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socks5: version {} is not 5", head[0]),
        ));
    }
    // head[2] is a reserved byte, ignored by the RFC.
    Ok(Request {
        command: head[1],
        address: Address::read(r)?,
    })
}

/// Writes a reply.
///
/// # Errors
/// Returns the underlying write error.
pub fn write_reply(w: &mut impl Write, code: u8, bound: &Address) -> io::Result<()> {
    let mut out = vec![VERSION, code, 0];
    bound.write_to(&mut out);
    w.write_all(&out)
}

/// Maps a connection failure to the reply code that describes it.
///
/// Clients show these to users, so a refused connection reading as "refused"
/// rather than "general failure" is the difference between a useful message and
/// a shrug.
#[must_use]
pub fn reply_code_for(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => reply::CONNECTION_REFUSED,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => reply::HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => reply::NETWORK_UNREACHABLE,
        // Raised for a destination that is IPv6-only. Saying so lets a client
        // stop asking, rather than read a general failure and retry the same
        // address it will never reach through here.
        io::ErrorKind::Unsupported => reply::ADDRESS_NOT_SUPPORTED,
        _ => reply::GENERAL_FAILURE,
    }
}

/// A UDP relay datagram: `RSV(2) FRAG ATYP ADDR PORT DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Where the payload is going, or where it came from.
    pub address: Address,
    /// The payload itself.
    pub payload: &'a [u8],
}

/// Parses a UDP relay datagram.
///
/// # Errors
/// Returns an error if the datagram is truncated, fragmented, or carries an
/// unsupported address type.
pub fn parse_udp(buf: &[u8]) -> io::Result<UdpDatagram<'_>> {
    let (head, mut rest) = buf.split_at_checked(3).ok_or_else(short)?;
    // Fragmentation is optional in the RFC and universally unimplemented;
    // reassembling it would be real work for no demand.
    if head.get(2) != Some(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks5: fragmented UDP datagrams are not supported",
        ));
    }
    let before = rest.len();
    let address = Address::read(&mut rest)?;
    let consumed = before - rest.len();
    let payload = buf.get(3 + consumed..).ok_or_else(short)?;
    Ok(UdpDatagram { address, payload })
}

/// Builds a UDP relay datagram.
#[must_use]
pub fn build_udp(address: &Address, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    address.write_to(&mut out);
    out.extend_from_slice(payload);
    out
}

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "socks5: truncated datagram")
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([*b.first().unwrap_or(&0), *b.get(1).unwrap_or(&0)])
}

fn lossy(v: Vec<u8>) -> String {
    String::from_utf8_lossy(&v).into_owned()
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn addr(s: &str) -> Address {
        Address::Socket(s.parse().expect("address"))
    }

    #[test]
    fn an_ipv4_address_round_trips() {
        let a = addr("192.0.2.1:443");
        let mut out = Vec::new();
        a.write_to(&mut out);
        assert_eq!(out, vec![1, 192, 0, 2, 1, 0x01, 0xBB]);
        assert_eq!(Address::read(&mut out.as_slice()).expect("read"), a);
    }

    #[test]
    fn an_ipv6_address_round_trips() {
        let a = addr("[2001:db8::1]:8080");
        let mut out = Vec::new();
        a.write_to(&mut out);
        assert_eq!(out.len(), 1 + 16 + 2);
        assert_eq!(Address::read(&mut out.as_slice()).expect("read"), a);
    }

    #[test]
    fn a_domain_round_trips() {
        let a = Address::Domain("example.com".to_owned(), 443);
        let mut out = Vec::new();
        a.write_to(&mut out);
        assert_eq!(out[0], 3);
        assert_eq!(out[1], 11);
        assert_eq!(Address::read(&mut out.as_slice()).expect("read"), a);
    }

    #[test]
    fn a_zero_length_domain_is_refused() {
        let bytes = [3u8, 0, 0, 80];
        assert!(Address::read(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn an_unsupported_address_type_is_refused() {
        for kind in [0u8, 2, 5, 0xFF] {
            let bytes = [kind, 1, 2, 3, 4, 0, 80];
            assert!(Address::read(&mut bytes.as_slice()).is_err(), "{kind}");
        }
    }

    #[test]
    fn a_truncated_address_is_refused_rather_than_guessed() {
        let full = {
            let mut v = Vec::new();
            addr("192.0.2.1:443").write_to(&mut v);
            v
        };
        for len in 0..full.len() {
            assert!(Address::read(&mut &full[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn a_greeting_is_read() {
        let bytes = [5u8, 2, auth::NONE, auth::USER_PASS];
        let methods = read_greeting(&mut bytes.as_slice()).expect("greeting");
        assert_eq!(methods, vec![auth::NONE, auth::USER_PASS]);
    }

    #[test]
    fn a_greeting_offering_nothing_is_read_as_empty() {
        // Legal on the wire, and the caller then finds nothing acceptable.
        let bytes = [5u8, 0];
        assert!(
            read_greeting(&mut bytes.as_slice())
                .expect("greeting")
                .is_empty()
        );
    }

    #[test]
    fn a_wrong_version_is_refused() {
        for version in [0u8, 4, 6] {
            let bytes = [version, 1, 0];
            assert!(read_greeting(&mut bytes.as_slice()).is_err(), "{version}");
            let bytes = [version, cmd::CONNECT, 0, 1, 1, 2, 3, 4, 0, 80];
            assert!(read_request(&mut bytes.as_slice()).is_err(), "{version}");
        }
    }

    #[test]
    fn a_request_is_read() {
        let bytes = [5u8, cmd::CONNECT, 0, 1, 192, 0, 2, 1, 0x01, 0xBB];
        let req = read_request(&mut bytes.as_slice()).expect("request");
        assert_eq!(req.command, cmd::CONNECT);
        assert_eq!(req.address, addr("192.0.2.1:443"));
    }

    #[test]
    fn a_reply_is_written_in_the_documented_shape() {
        let mut out = Vec::new();
        write_reply(&mut out, reply::SUCCESS, &addr("127.0.0.1:1080")).expect("write");
        assert_eq!(out, vec![5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn credentials_round_trip() {
        let mut bytes = vec![auth::USER_PASS_VERSION, 4];
        bytes.extend_from_slice(b"user");
        bytes.push(6);
        bytes.extend_from_slice(b"secret");
        let (u, p) = read_user_pass(&mut bytes.as_slice()).expect("credentials");
        assert_eq!(u, "user");
        assert_eq!(p, "secret");
    }

    #[test]
    fn empty_credentials_are_read_rather_than_rejected() {
        // The server decides whether empty is acceptable; the codec does not.
        let bytes = [auth::USER_PASS_VERSION, 0, 0];
        let (u, p) = read_user_pass(&mut bytes.as_slice()).expect("credentials");
        assert!(u.is_empty() && p.is_empty());
    }

    #[test]
    fn the_credential_result_uses_zero_for_success() {
        let mut ok = Vec::new();
        write_user_pass_result(&mut ok, true).expect("write");
        assert_eq!(ok, vec![1, 0]);
        let mut bad = Vec::new();
        write_user_pass_result(&mut bad, false).expect("write");
        assert_eq!(bad, vec![1, 1]);
    }

    #[test]
    fn a_udp_datagram_round_trips() {
        let a = addr("192.0.2.1:53");
        let built = build_udp(&a, b"query");
        let parsed = parse_udp(&built).expect("parse");
        assert_eq!(parsed.address, a);
        assert_eq!(parsed.payload, b"query");
    }

    #[test]
    fn a_udp_datagram_to_a_domain_round_trips() {
        let a = Address::Domain("dns.example".to_owned(), 53);
        let built = build_udp(&a, b"query");
        let parsed = parse_udp(&built).expect("parse");
        assert_eq!(parsed.address, a);
        assert_eq!(parsed.payload, b"query");
    }

    #[test]
    fn a_fragmented_udp_datagram_is_refused() {
        let mut built = build_udp(&addr("192.0.2.1:53"), b"x");
        built[2] = 1;
        assert!(parse_udp(&built).is_err());
    }

    #[test]
    fn an_empty_udp_payload_is_allowed() {
        let built = build_udp(&addr("192.0.2.1:53"), b"");
        assert!(parse_udp(&built).expect("parse").payload.is_empty());
    }

    #[test]
    fn truncated_udp_datagrams_are_refused_without_panicking() {
        let full = build_udp(&addr("192.0.2.1:53"), b"payload");
        for len in 0..full.len() - 7 {
            assert!(parse_udp(&full[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn arbitrary_bytes_do_not_panic_the_parsers() {
        let mut state = 0x243F_6A88u32;
        for len in 0..64usize {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    u8::try_from((state >> 24) & 0xFF).unwrap_or(0)
                })
                .collect();
            let _ = parse_udp(&junk);
            let _ = read_greeting(&mut junk.as_slice());
            let _ = read_request(&mut junk.as_slice());
            let _ = read_user_pass(&mut junk.as_slice());
            let _ = Address::read(&mut junk.as_slice());
        }
    }

    #[test]
    fn failures_map_to_the_code_a_client_can_explain() {
        assert_eq!(
            reply_code_for(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            reply::CONNECTION_REFUSED
        );
        assert_eq!(
            reply_code_for(&io::Error::from(io::ErrorKind::NetworkUnreachable)),
            reply::NETWORK_UNREACHABLE
        );
        assert_eq!(
            reply_code_for(&io::Error::from(io::ErrorKind::TimedOut)),
            reply::GENERAL_FAILURE
        );
    }
}
