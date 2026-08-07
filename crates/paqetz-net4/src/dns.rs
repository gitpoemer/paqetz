//! Name resolution that happens on the far side of the tunnel.
//!
//! The SOCKS5 listener runs on the client, which is the host inside whatever
//! network the tunnel exists to get out of. Resolving a name with the system
//! resolver there asks that network's DNS server — so the one part of the path
//! that decides *where the connection goes* never enters the tunnel at all.
//!
//! Two things follow, and both were observed before this existed. A resolver
//! that answers with a sinkhole address for names it does not like sends the
//! connection somewhere that never answers, and it fails ten seconds later at
//! the connect timeout with nothing to suggest DNS was involved. And every name
//! looked up is handed to that network in plaintext, which tells it exactly what
//! is being reached — on a tool whose whole purpose is that this is not visible.
//!
//! So queries go out over a marked socket, the same way a proxied connection
//! does, and are answered by a resolver reached through the tunnel. The local
//! network sees an ordinary TCP conversation and no names.
//!
//! This is a deliberately small resolver: one question, `A` records, no cache,
//! no search domains, no `/etc/hosts`. That is the whole of what a SOCKS5
//! CONNECT to a name needs, and every part of a larger one is another parser
//! reading hostile bytes.

use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::dial;

/// How long to wait for a reply before trying again.
const TIMEOUT: Duration = Duration::from_secs(4);

/// How many times to ask over UDP before giving up on it.
const ATTEMPTS: u32 = 2;

/// The largest reply worth reading. Bigger answers arrive over TCP.
const MAX_REPLY: usize = 1232;

/// A pointer chain longer than this is malformed or malicious.
const MAX_JUMPS: usize = 16;

/// Records we ask for and understand.
const TYPE_A: u16 = 1;
/// The internet class.
const CLASS_IN: u16 = 1;

/// Where to send queries, and how to mark them so they take the tunnel.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// The DNS server, reached through the tunnel rather than beside it.
    pub server: SocketAddrV4,
    /// The firewall mark that steers a socket into the tunnel.
    pub mark: u32,
    /// The tunnel device to pin queries to, which needs no routing state.
    pub device: Option<String>,
}

impl Resolver {
    /// Looks up the `A` records for `host`, pairing each with `port`.
    ///
    /// # Errors
    /// Returns an error if the query cannot be sent, no reply arrives, the
    /// reply is malformed, or the name has no `A` record.
    pub fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let id = query_id()?;
        let query = encode_query(id, host)?;

        let reply = match self.ask_udp(&query)? {
            // Truncated: the answer did not fit, and the rest is only available
            // over TCP. Rare for a single A record, but a name behind many
            // addresses reaches it.
            Reply::Truncated => self.ask_tcp(&query)?,
            Reply::Whole(bytes) => bytes,
        };

        let addresses = parse_answers(&reply, id)?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} has no IPv4 address"),
            ));
        }
        Ok(addresses
            .into_iter()
            .map(|a| SocketAddr::V4(SocketAddrV4::new(a, port)))
            .collect())
    }

    /// Asks over UDP, retrying once before giving up.
    fn ask_udp(&self, query: &[u8]) -> io::Result<Reply> {
        let sock = dial::bind_udp(self.mark, self.device.as_deref())?;
        sock.set_read_timeout(Some(TIMEOUT))?;
        let mut buf = vec![0u8; MAX_REPLY];

        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no reply from the resolver");
        for _ in 0..ATTEMPTS {
            sock.send_to(query, self.server)?;
            match sock.recv_from(&mut buf) {
                // Only the resolver's own answers count. Anything else on this
                // socket is someone else's, and taking it would be taking a
                // stranger's word for where a connection should go.
                Ok((n, from)) if from == SocketAddr::V4(self.server) => {
                    let Some(bytes) = buf.get(..n) else { continue };
                    if truncated(bytes) {
                        return Ok(Reply::Truncated);
                    }
                    return Ok(Reply::Whole(bytes.to_vec()));
                }
                Ok(_) => continue,
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Asks over TCP, which prefixes the message with its length.
    fn ask_tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut sock = TcpStream::connect_timeout(&SocketAddr::V4(self.server), TIMEOUT)?;
        sock.set_read_timeout(Some(TIMEOUT))?;
        sock.set_write_timeout(Some(TIMEOUT))?;

        let len = u16::try_from(query.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        sock.write_all(&framed)?;

        let mut prefix = [0u8; 2];
        sock.read_exact(&mut prefix)?;
        let n = usize::from(u16::from_be_bytes(prefix));
        if n == 0 || n > MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolver replied with an implausible length",
            ));
        }
        let mut reply = vec![0u8; n];
        sock.read_exact(&mut reply)?;
        Ok(reply)
    }
}

/// A UDP reply, which may be a note that the answer is elsewhere.
enum Reply {
    /// The whole message.
    Whole(Vec<u8>),
    /// Too big for UDP; ask again over TCP.
    Truncated,
}

/// A query identifier, from the kernel's random source.
///
/// Random rather than sequential because it is what stops an off-path party
/// answering before the real resolver does. The reply also has to arrive from
/// the server's address on the socket the query left by, but the identifier is
/// the part that is not merely address-based.
fn query_id() -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    let mut filled = 0;
    while filled < bytes.len() {
        let rest = bytes
            .get_mut(filled..)
            .ok_or_else(|| io::Error::other("short buffer"))?;
        // The syscall rather than glibc's wrapper, which only exists from 2.25.
        // The oldest cross-compilation image predates that, and a build that
        // links against a newer symbol would also refuse to start on the older
        // systems this is meant to drop onto.
        //
        // SAFETY: writes at most `len` bytes into a buffer of that length.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                rest.as_mut_ptr().cast::<libc::c_void>(),
                rest.len(),
                0,
            )
        };
        match usize::try_from(n) {
            Ok(0) | Err(_) => {
                let e = io::Error::last_os_error();
                // A signal arriving mid-call is not a failure to produce
                // randomness; it is a reason to ask again.
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            Ok(got) => filled += got,
        }
    }
    Ok(u16::from_be_bytes(bytes))
}

/// Whether the reply says the answer did not fit.
fn truncated(msg: &[u8]) -> bool {
    msg.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

/// Builds a query for the `A` records of `host`.
///
/// # Errors
/// Returns an error if the name is empty, over-long, or has an empty label.
fn encode_query(id: u16, host: &str) -> io::Result<Vec<u8>> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a usable host name: {host:?}"),
        ));
    }

    let mut msg = Vec::with_capacity(host.len() + 18);
    msg.extend_from_slice(&id.to_be_bytes());
    // Recursion desired. We are asking a resolver to do the work, not walking
    // the delegation chain ourselves.
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // one question
    msg.extend_from_slice(&0u16.to_be_bytes()); // no answers
    msg.extend_from_slice(&0u16.to_be_bytes()); // no authority
    msg.extend_from_slice(&0u16.to_be_bytes()); // no additional

    for label in host.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not a usable label in {host:?}: {label:?}"),
                )
            })?;
        msg.push(len);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root

    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

/// Steps over a name, following compression pointers, and returns the offset
/// just past it.
///
/// The pointer chain is bounded: a message that points back at itself would
/// otherwise loop for ever, and the message is written by whoever answered.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    let mut end = None;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            // A pointer, which ends this name wherever it was read from.
            0xC0 => {
                let lo = *msg.get(pos + 1)?;
                let target = usize::from(u16::from_be_bytes([len & 0x3F, lo]));
                jumps += 1;
                if jumps > MAX_JUMPS || target >= msg.len() {
                    return None;
                }
                end = end.or(Some(pos + 2));
                pos = target;
            }
            0x00 => {
                if len == 0 {
                    return Some(end.unwrap_or(pos + 1));
                }
                pos = pos.checked_add(usize::from(len) + 1)?;
                if pos > msg.len() {
                    return None;
                }
            }
            // 0x40 and 0x80 are reserved and have never meant anything.
            _ => return None,
        }
    }
}

/// Reads the `A` records out of a reply.
///
/// # Errors
/// Returns an error if the reply is not an answer to `id`, reports a failure,
/// or is malformed.
fn parse_answers(msg: &[u8], id: u16) -> io::Result<Vec<Ipv4Addr>> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("resolver: {what}"));

    let header = msg.get(..12).ok_or_else(|| bad("reply is too short"))?;
    let (Some(hi), Some(lo)) = (header.first(), header.get(1)) else {
        return Err(bad("reply is too short"));
    };
    if u16::from_be_bytes([*hi, *lo]) != id {
        return Err(bad("reply does not answer the question that was asked"));
    }
    let flags = u16::from_be_bytes([
        *header.get(2).ok_or_else(|| bad("truncated header"))?,
        *header.get(3).ok_or_else(|| bad("truncated header"))?,
    ]);
    if flags & 0x8000 == 0 {
        return Err(bad("reply is not a response"));
    }
    match flags & 0x000F {
        0 => {}
        3 => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "resolver: no such name",
            ));
        }
        code => return Err(bad(&format!("refused the query, code {code}"))),
    }

    let questions = u16::from_be_bytes([
        *header.get(4).ok_or_else(|| bad("truncated header"))?,
        *header.get(5).ok_or_else(|| bad("truncated header"))?,
    ]);
    let answers = u16::from_be_bytes([
        *header.get(6).ok_or_else(|| bad("truncated header"))?,
        *header.get(7).ok_or_else(|| bad("truncated header"))?,
    ]);

    // Past the question section, which is echoed back.
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(msg, pos).ok_or_else(|| bad("malformed question name"))?;
        pos = pos
            .checked_add(4)
            .filter(|p| *p <= msg.len())
            .ok_or_else(|| bad("question runs past the end"))?;
    }

    let mut found = Vec::new();
    for _ in 0..answers {
        pos = skip_name(msg, pos).ok_or_else(|| bad("malformed record name"))?;
        let rtype = u16::from_be_bytes([
            *msg.get(pos)
                .ok_or_else(|| bad("record runs past the end"))?,
            *msg.get(pos + 1)
                .ok_or_else(|| bad("record runs past the end"))?,
        ]);
        let class = u16::from_be_bytes([
            *msg.get(pos + 2)
                .ok_or_else(|| bad("record runs past the end"))?,
            *msg.get(pos + 3)
                .ok_or_else(|| bad("record runs past the end"))?,
        ]);
        let rdlen = usize::from(u16::from_be_bytes([
            *msg.get(pos + 8)
                .ok_or_else(|| bad("record runs past the end"))?,
            *msg.get(pos + 9)
                .ok_or_else(|| bad("record runs past the end"))?,
        ]));
        let rdata = pos
            .checked_add(10)
            .ok_or_else(|| bad("record runs past the end"))?;
        let next = rdata
            .checked_add(rdlen)
            .filter(|p| *p <= msg.len())
            .ok_or_else(|| bad("record runs past the end"))?;

        // Anything else in here is a CNAME or a record we did not ask about.
        // The resolver has already followed the chain; the addresses at the end
        // of it are what we came for.
        if rtype == TYPE_A && class == CLASS_IN && rdlen == 4 {
            let octets = msg.get(rdata..next).ok_or_else(|| bad("short A record"))?;
            if let [a, b, c, d] = *octets {
                found.push(Ipv4Addr::new(a, b, c, d));
            }
        }
        pos = next;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a reply: header, echoed question, then the given answer records.
    fn reply(id: u16, flags: u16, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        let count = u16::try_from(answers.len()).expect("few answers");
        m.extend_from_slice(&count.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        // Question: example.invalid A IN
        for label in ["example", "invalid"] {
            m.push(u8::try_from(label.len()).expect("short label"));
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, rdata) in answers {
            m.extend_from_slice(&[0xC0, 12]); // pointer back to the question
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            let len = u16::try_from(rdata.len()).expect("short rdata");
            m.extend_from_slice(&len.to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn a_query_asks_one_question_about_the_name() {
        let q = encode_query(0xBEEF, "example.invalid").expect("encode");
        assert_eq!(q.get(..2), Some(&[0xBE, 0xEF][..]), "the identifier leads");
        assert_eq!(q.get(4..6), Some(&[0, 1][..]), "exactly one question");
        assert!(
            q.windows(8).any(|w| w == b"\x07example"),
            "the name is written as length-prefixed labels"
        );
        assert_eq!(q.get(q.len() - 4..), Some(&[0, 1, 0, 1][..]), "A, IN");
    }

    #[test]
    fn a_trailing_root_dot_is_accepted() {
        assert_eq!(
            encode_query(1, "example.invalid.").expect("encode"),
            encode_query(1, "example.invalid").expect("encode")
        );
    }

    #[test]
    fn names_that_cannot_be_encoded_are_refused() {
        for host in ["", ".", "a..b", &"x".repeat(64), &"y".repeat(254)] {
            assert!(encode_query(1, host).is_err(), "{host:?} should not encode");
        }
    }

    #[test]
    fn addresses_are_read_from_the_answers() {
        let msg = reply(0x1234, 0x8180, &[(TYPE_A, &[203, 0, 113, 5])]);
        assert_eq!(
            parse_answers(&msg, 0x1234).expect("parse"),
            vec![Ipv4Addr::new(203, 0, 113, 5)]
        );
    }

    #[test]
    fn a_cname_before_the_address_is_stepped_over() {
        // What a real reply for a name behind a CDN looks like: the resolver
        // has followed the chain and returns both records.
        let msg = reply(7, 0x8180, &[(5, &[0xC0, 12]), (TYPE_A, &[203, 0, 113, 9])]);
        assert_eq!(
            parse_answers(&msg, 7).expect("parse"),
            vec![Ipv4Addr::new(203, 0, 113, 9)]
        );
    }

    #[test]
    fn a_reply_to_a_different_question_is_refused() {
        // The identifier is what stops an off-path answer being taken as the
        // real one, so a mismatch has to be fatal rather than ignored.
        let msg = reply(0x1234, 0x8180, &[(TYPE_A, &[203, 0, 113, 5])]);
        assert!(parse_answers(&msg, 0x9999).is_err());
    }

    #[test]
    fn a_query_echoed_back_is_not_an_answer() {
        let msg = reply(1, 0x0100, &[]);
        assert!(parse_answers(&msg, 1).is_err(), "QR is not set");
    }

    #[test]
    fn nxdomain_reads_as_not_found_rather_than_malformed() {
        let msg = reply(1, 0x8183, &[]);
        let e = parse_answers(&msg, 1).expect_err("nxdomain");
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_pointer_loop_does_not_hang() {
        // 0xC00C at offset 12 points at itself. Without the jump bound this
        // walks for ever on a message an attacker controls.
        let mut msg = reply(1, 0x8180, &[]);
        msg.truncate(12);
        msg.extend_from_slice(&[0xC0, 12]);
        assert!(skip_name(&msg, 12).is_none());
    }

    #[test]
    fn a_pointer_past_the_end_is_refused() {
        let mut msg = reply(1, 0x8180, &[]);
        msg.truncate(12);
        msg.extend_from_slice(&[0xC0, 200]);
        assert!(skip_name(&msg, 12).is_none());
    }

    #[test]
    fn a_record_claiming_more_data_than_it_has_is_refused() {
        let mut msg = reply(1, 0x8180, &[(TYPE_A, &[203, 0, 113, 5])]);
        let n = msg.len();
        // Overwrite the rdlength with something far past the end.
        if let Some(b) = msg.get_mut(n - 6) {
            *b = 0xFF;
        }
        if let Some(b) = msg.get_mut(n - 5) {
            *b = 0xFF;
        }
        assert!(parse_answers(&msg, 1).is_err());
    }

    #[test]
    fn every_truncation_of_a_valid_reply_is_handled() {
        // Not a correctness check so much as a promise that nothing here
        // panics on a short read, since every byte comes off the network.
        let full = reply(1, 0x8180, &[(TYPE_A, &[203, 0, 113, 5])]);
        for n in 0..full.len() {
            let _ = full.get(..n).map(|part| parse_answers(part, 1));
        }
    }

    #[test]
    fn the_truncated_flag_is_read_from_the_header() {
        assert!(truncated(&reply(1, 0x8380, &[])));
        assert!(!truncated(&reply(1, 0x8180, &[])));
        assert!(!truncated(&[]));
    }

    /// Whether an error means there was nowhere to send a query, rather than
    /// that sending one went wrong.
    ///
    /// `scripts/test-privileged.sh` runs the ignored tests inside a throwaway
    /// network namespace with no path off the host, where a resolver test
    /// measures the sandbox rather than the resolver. Anything else — refused,
    /// timed out, malformed, not permitted — is a real result and must fail.
    fn no_route(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable
        )
    }

    #[test]
    fn only_having_nowhere_to_ask_is_a_reason_to_skip() {
        assert!(no_route(&io::Error::from(
            io::ErrorKind::NetworkUnreachable
        )));
        assert!(no_route(&io::Error::from(io::ErrorKind::HostUnreachable)));
        // Everything else is a result the test below exists to catch, and
        // skipping on it would turn a broken resolver into a green run.
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData,
        ] {
            assert!(!no_route(&io::Error::from(kind)), "{kind:?} was skipped");
        }
    }

    /// Everything above is synthetic. This one talks to a real resolver, so it
    /// is ignored by default: `cargo test -- --ignored --nocapture dns::tests::real`.
    #[test]
    #[ignore = "needs a resolver on the network"]
    fn real_lookups_answer() {
        let r = Resolver {
            server: SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53),
            mark: 0,
            device: None,
        };

        let addrs = match r.lookup("one.one.one.one", 443) {
            Ok(addrs) => addrs,
            Err(e) if no_route(&e) => {
                eprintln!("skipped: no route to a resolver ({e})");
                return;
            }
            Err(e) => panic!("a name that resolves: {e}"),
        };
        assert!(
            addrs.iter().any(|a| a.ip() == Ipv4Addr::new(1, 1, 1, 1)),
            "got {addrs:?}"
        );
        assert!(addrs.iter().all(|a| a.port() == 443));

        let e = r
            .lookup("no-such-host.invalid", 443)
            .expect_err("`.invalid` never resolves");
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
    }

    #[test]
    fn identifiers_are_not_predictable() {
        let ids: std::collections::HashSet<u16> = (0..32).filter_map(|_| query_id().ok()).collect();
        assert!(
            ids.len() > 24,
            "32 draws collapsed to {} distinct values",
            ids.len()
        );
    }
}
