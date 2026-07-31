//! Per-endpoint connection state: the synthetic TCP conversation.
//!
//! paqet invented its sequence numbers — `seq = base + (counter << 7)`, and an
//! acknowledgement derived from the same counter — so the numbers bore no
//! relation to the bytes actually sent. Any middlebox modelling TCP state sees
//! that immediately. This type keeps them honest instead: `seq` is the initial
//! sequence number plus the payload bytes genuinely sent, and `ack` is the
//! peer's initial sequence number plus the payload bytes genuinely received.
//!
//! # The one place this cannot be perfectly faithful
//!
//! The carrier never retransmits — nothing owns these segments, which is the
//! whole premise (decision D2). So when a packet is lost in the network, the
//! gap in our sequence space is never filled, and our acknowledgement stops
//! advancing past what we actually received.
//!
//! An observer therefore sees a flow whose retransmissions are all missing.
//! That is a real thing that happens to real TCP connections on bad paths, and
//! it is the closest self-consistent behaviour available without a
//! retransmission queue. The alternative — acknowledging bytes we never
//! received, so the numbers stay contiguous — would mean acknowledging data
//! that was never sent, which is *less* like real TCP, not more.
//!
//! # Windows
//!
//! Sequence and acknowledgement numbers are `u32` and wrap. All arithmetic here
//! is wrapping, which is what TCP specifies.

use core::net::Ipv4Addr;

use crate::profile::OsProfile;
use crate::segment::{self, Fields, Kind, Segment};
use crate::{Error, Result};

/// How the synthetic conversation begins.
///
/// This is a real trade-off, and which way it should go depends on the network,
/// not on first principles. See `docs/decisions/D14-carrier-mode.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Carrier {
    /// Never emit a SYN. Both ends derive each other's initial sequence number
    /// from the tunnel handshake, so sequencing is exact from the first packet
    /// without any segment being exchanged to establish it.
    ///
    /// This is paqet's behaviour and the default, for two reasons. A middlebox
    /// that builds flow state on SYN never creates any, so the flow is never
    /// inspected; and the responder never answers an unauthenticated segment,
    /// so the port stays indistinguishable from filtered.
    #[default]
    Midstream,

    /// Emit a real SYN / SYN+ACK / ACK exchange before any data.
    ///
    /// Preferable against a middlebox that *drops* mid-stream flows rather than
    /// ignoring them. Costs a round trip at startup, and means the responder
    /// answers a segment it cannot authenticate — see the decision record.
    Handshake,
}

/// Which side of the synthetic connection this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the opening SYN.
    Initiator,
    /// Replies with SYN+ACK.
    Responder,
}

/// How far the synthetic handshake has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing sent or received yet.
    Idle,
    /// Our SYN is out; waiting for the peer's SYN+ACK.
    SynSent,
    /// We answered a SYN; waiting for the completing ACK.
    SynReceived,
    /// Handshake complete; data may flow.
    Established,
    /// A FIN has been sent or received.
    Closed,
}

/// Everything needed to construct an [`Endpoint`].
///
/// `isn`, `peer_isn`, and `ts_base` are supplied by the caller rather than
/// generated here, so this crate needs no RNG and stays deterministic under
/// test. In [`Carrier::Midstream`] they are derived from the tunnel handshake,
/// which is what lets both ends agree on sequence numbers without exchanging a
/// SYN.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Our address and port.
    pub local: (Ipv4Addr, u16),
    /// The peer's address and port.
    pub remote: (Ipv4Addr, u16),
    /// Fingerprint to present.
    pub profile: OsProfile,
    /// Which side of the conversation we are.
    pub role: Role,
    /// Whether to perform a synthetic handshake.
    pub carrier: Carrier,
    /// Our initial sequence number.
    pub isn: u32,
    /// The peer's initial sequence number.
    ///
    /// Required under [`Carrier::Midstream`]. Ignored under
    /// [`Carrier::Handshake`], where it is learned from the peer's SYN.
    pub peer_isn: u32,
    /// Offset added to the clock to form the TCP timestamp, so the timestamp
    /// clock does not start near zero and reveal process start.
    pub ts_base: u32,
}

/// One end of a synthetic TCP conversation with one peer.
///
/// This is per-peer state, and there is no per-flow state anywhere (D4): a
/// single endpoint carries every inner packet exchanged with that peer.
#[derive(Debug)]
pub struct Endpoint {
    local: (Ipv4Addr, u16),
    remote: (Ipv4Addr, u16),
    profile: OsProfile,
    role: Role,
    carrier: Carrier,
    phase: Phase,

    local_isn: u32,
    remote_isn: Option<u32>,
    /// Payload bytes sent, plus one for each SYN or FIN we have sent.
    sent: u32,
    /// Payload bytes received, plus one for each SYN or FIN the peer sent.
    received: u32,

    /// Milliseconds added to the caller's clock to form `ts_val`, so the
    /// timestamp clock does not start at zero and reveal process start.
    ts_base: u32,
    /// Most recent timestamp seen from the peer, echoed back as `ts_ecr`.
    peer_ts_val: u32,

    /// Drives IP Identification and window jitter.
    counter: u32,
    /// Whether our SYN's one byte of sequence space has been counted.
    ///
    /// A retransmitted SYN carries the same sequence number as the original, so
    /// it must be counted once however many times it goes out.
    syn_counted: bool,
}

impl Endpoint {
    /// Creates an endpoint.
    #[must_use]
    pub const fn new(cfg: Config) -> Self {
        // Under Midstream there is no SYN to send, none to wait for, and none
        // to account for in the sequence space: both ends already know where
        // the other's numbering starts.
        let midstream = matches!(cfg.carrier, Carrier::Midstream);
        Self {
            local: cfg.local,
            remote: cfg.remote,
            profile: cfg.profile,
            role: cfg.role,
            carrier: cfg.carrier,
            phase: if midstream {
                Phase::Established
            } else {
                Phase::Idle
            },
            local_isn: cfg.isn,
            remote_isn: if midstream { Some(cfg.peer_isn) } else { None },
            sent: 0,
            received: 0,
            ts_base: cfg.ts_base,
            peer_ts_val: 0,
            counter: 0,
            syn_counted: midstream,
        }
    }

    /// The current handshake phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether data may be sent.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established)
    }

    /// The peer's address and port.
    #[must_use]
    pub const fn remote(&self) -> (Ipv4Addr, u16) {
        self.remote
    }

    /// Updates the peer's address and port, for roaming (D5).
    ///
    /// Called only once a packet from the new address has authenticated. The
    /// sequence state is deliberately preserved: from TCP's point of view this
    /// is the same conversation seen from a new vantage point, and resetting it
    /// would produce exactly the mid-stream jump the design is avoiding.
    pub const fn set_remote(&mut self, remote: (Ipv4Addr, u16)) {
        self.remote = remote;
    }

    /// The carrier mode in force.
    #[must_use]
    pub const fn carrier(&self) -> Carrier {
        self.carrier
    }

    /// The profile in force.
    #[must_use]
    pub const fn profile(&self) -> &OsProfile {
        &self.profile
    }

    /// The next sequence number this endpoint will place on the wire.
    #[must_use]
    pub const fn next_seq(&self) -> u32 {
        self.local_isn.wrapping_add(self.sent)
    }

    /// The acknowledgement this endpoint will place on the wire, if the peer's
    /// initial sequence number is known.
    #[must_use]
    pub const fn next_ack(&self) -> Option<u32> {
        match self.remote_isn {
            Some(isn) => Some(isn.wrapping_add(self.received)),
            None => None,
        }
    }

    /// Writes the segment that should be sent next for the handshake, if any.
    ///
    /// Always `Ok(None)` under [`Carrier::Midstream`], which is the point of
    /// that mode. Otherwise returns `Ok(None)` when the handshake needs nothing
    /// from this side right now. The caller drives retransmission: a lost SYN simply means calling
    /// this again, which is why the phase does not advance on a repeat.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold the segment.
    pub fn handshake(&mut self, out: &mut [u8], now: u64) -> Result<Option<usize>> {
        if matches!(self.carrier, Carrier::Midstream) {
            return Ok(None);
        }
        let kind = match (self.role, self.phase) {
            (Role::Initiator, Phase::Idle | Phase::SynSent) => Kind::Syn,
            (Role::Responder, Phase::SynReceived) => Kind::SynAck,
            _ => return Ok(None),
        };
        let n = self.emit_raw(kind, &[], out, now)?;
        // The SYN's own sequence byte is not counted here. Every retransmission
        // must carry the ISN itself; the byte is accounted for when the
        // handshake completes, in `establish`.
        if self.phase == Phase::Idle {
            self.phase = Phase::SynSent;
        }
        Ok(Some(n))
    }

    /// Writes one data segment carrying `payload`.
    ///
    /// # Errors
    /// - [`Error::Short`] if `out` cannot hold the segment.
    /// - [`Error::NotEstablished`] if the handshake has not completed.
    pub fn data(&mut self, payload: &[u8], out: &mut [u8], now: u64) -> Result<usize> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        let n = self.emit_raw(Kind::Data, payload, out, now)?;
        let len =
            u32::try_from(payload.len()).map_err(|_| Error::TooLong { len: payload.len() })?;
        self.sent = self.sent.wrapping_add(len);
        Ok(n)
    }

    /// Writes a FIN, closing the conversation.
    ///
    /// paqet's sessions simply stopped, leaving flows half-open from the
    /// network's point of view forever.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold the segment.
    pub fn close(&mut self, out: &mut [u8], now: u64) -> Result<usize> {
        let n = self.emit_raw(Kind::Fin, &[], out, now)?;
        // A FIN occupies one sequence number.
        self.sent = self.sent.wrapping_add(1);
        self.phase = Phase::Closed;
        Ok(n)
    }

    /// Moves to [`Phase::Established`], counting our SYN's sequence byte once.
    fn establish(&mut self) {
        self.phase = Phase::Established;
        if !self.syn_counted {
            self.syn_counted = true;
            self.sent = self.sent.wrapping_add(1);
        }
    }

    /// Writes a segment without touching the sequence counter.
    ///
    /// Callers advance `sent` themselves, because how much sequence space a
    /// segment occupies depends on whether it is a first transmission: a
    /// retransmitted SYN repeats its predecessor's number rather than taking a
    /// new one.
    fn emit_raw(&mut self, kind: Kind, payload: &[u8], out: &mut [u8], now: u64) -> Result<usize> {
        let fields = self.fields(kind, now);
        let n = segment::emit(kind, &self.profile, &fields, payload, out)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(n)
    }

    /// Assembles the volatile fields for one outbound segment.
    fn fields(&self, kind: Kind, now: u64) -> Fields {
        Fields {
            src: self.local,
            dst: self.remote,
            seq: self.next_seq(),
            ack: self.next_ack().unwrap_or(0),
            window: self.window(kind),
            ip_id: self.ip_id(),
            ts_val: self.ts_val(now),
            ts_ecr: self.peer_ts_val,
        }
    }

    /// The window to advertise.
    ///
    /// A SYN carries the profile's unscaled SYN window, since window scaling is
    /// only in force once both sides have agreed it. Afterwards the window is
    /// the profile's, shifted down by the negotiated scale, with a small
    /// deterministic variation so it is not a constant. It does not reflect a
    /// real receive buffer — there isn't one — but a window that never moves is
    /// itself a signature.
    fn window(&self, kind: Kind) -> u16 {
        if kind.is_syn() {
            return self.profile.syn_window;
        }
        let scaled = self.profile.window >> self.profile.window_scale;
        // Vary within about ±6% using a cheap hash of the packet counter.
        let spread = (scaled / 16).max(1);
        let jitter = u64::from(self.counter.wrapping_mul(0x9E37_79B9)) >> 24;
        let offset = jitter % u64::from(spread.saturating_mul(2) + 1);
        let varied = u64::from(scaled) + offset - u64::from(spread);
        u16::try_from(varied.clamp(1, u64::from(u16::MAX))).unwrap_or(u16::MAX)
    }

    /// A varying IPv4 Identification.
    ///
    /// Knuth's multiplicative hash of the packet counter: uniform-looking to an
    /// observer and one multiply to compute. Carried over from paqet, which got
    /// this part right.
    fn ip_id(&self) -> u16 {
        // The shift leaves 16 significant bits, so the narrowing is exact.
        u16::try_from(self.counter.wrapping_mul(0x9E37_79B9) >> 16).unwrap_or(0)
    }

    /// The RFC 7323 timestamp to send.
    fn ts_val(&self, now: u64) -> u32 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the TCP timestamp clock is defined to wrap at 32 bits"
        )]
        let ms = now as u32;
        self.ts_base.wrapping_add(ms)
    }

    /// Folds an inbound segment into the connection state.
    ///
    /// Returns the segment's payload when it is data that should be handed
    /// upward, or `None` for pure handshake and control segments.
    ///
    /// This does **not** authenticate anything. The caller must treat the
    /// payload as untrusted until the tunnel layer has verified it, and should
    /// only call this for segments that arrived on the expected five-tuple.
    pub fn on_receive<'a>(&mut self, seg: &Segment<'a>) -> Option<&'a [u8]> {
        if let Some(ts) = seg.ts_val {
            // Recorded even for segments carrying no payload: a pure ACK has
            // the freshest timestamp, and echoing a stale one is exactly the
            // kind of incoherence a timestamp-checking middlebox looks for.
            self.peer_ts_val = ts;
        }

        if seg.has(segment::flags::RST) {
            self.phase = Phase::Closed;
            return None;
        }

        // The peer's initial sequence number is learned from its SYN.
        if seg.has(segment::flags::SYN) {
            if self.remote_isn.is_none() {
                self.remote_isn = Some(seg.seq);
                // The SYN itself occupies one sequence number.
                self.received = 1;
            }
            match self.role {
                Role::Initiator => self.establish(),
                Role::Responder => self.phase = Phase::SynReceived,
            }
            return None;
        }

        // Data before any SYN. The peer is out of step with us; there is nothing
        // coherent to say about its sequence space.
        self.remote_isn?;

        if self.phase == Phase::SynReceived && seg.has(segment::flags::ACK) {
            self.establish();
        }

        if seg.has(segment::flags::FIN) {
            self.received = self.received.wrapping_add(1);
            self.phase = Phase::Closed;
            return None;
        }

        if seg.payload.is_empty() {
            return None;
        }

        let len = u32::try_from(seg.payload.len()).unwrap_or(u32::MAX);
        self.received = self.received.wrapping_add(len);
        Some(seg.payload)
    }
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::profile::{LINUX_6, WINDOWS_11};
    use crate::segment::{MAX_OVERHEAD, parse_ipv4};

    const CLIENT: (Ipv4Addr, u16) = (Ipv4Addr::new(192, 168, 1, 10), 41000);
    const SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 5), 9999);

    const CLIENT_ISN: u32 = 1_000_000;
    const SERVER_ISN: u32 = 9_000_000;

    fn cfg(role: Role, carrier: Carrier, profile: OsProfile) -> Config {
        let initiator = matches!(role, Role::Initiator);
        Config {
            local: if initiator { CLIENT } else { SERVER },
            remote: if initiator { SERVER } else { CLIENT },
            profile,
            role,
            carrier,
            isn: if initiator { CLIENT_ISN } else { SERVER_ISN },
            peer_isn: if initiator { SERVER_ISN } else { CLIENT_ISN },
            ts_base: if initiator { 5_000 } else { 7_000 },
        }
    }

    /// A handshaking client, since most tests here exercise the handshake path.
    fn client() -> Endpoint {
        Endpoint::new(cfg(Role::Initiator, Carrier::Handshake, LINUX_6))
    }

    fn server() -> Endpoint {
        Endpoint::new(cfg(Role::Responder, Carrier::Handshake, LINUX_6))
    }

    fn midstream_pair() -> (Endpoint, Endpoint) {
        (
            Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, LINUX_6)),
            Endpoint::new(cfg(Role::Responder, Carrier::Midstream, LINUX_6)),
        )
    }

    /// Emits into a scratch buffer and parses the result back.
    fn emitted<F>(f: F) -> Vec<u8>
    where
        F: FnOnce(&mut [u8]) -> Result<usize>,
    {
        let mut buf = vec![0u8; MAX_OVERHEAD + 2048];
        let n = f(&mut buf).expect("emit");
        buf.truncate(n);
        buf
    }

    /// Drives the full three-way handshake between two endpoints.
    fn connect(c: &mut Endpoint, s: &mut Endpoint) {
        let mut buf = vec![0u8; MAX_OVERHEAD + 64];

        let n = c.handshake(&mut buf, 0).expect("syn").expect("some");
        let syn = parse_ipv4(&buf[..n]).expect("parse syn");
        s.on_receive(&syn);

        let n = s.handshake(&mut buf, 1).expect("synack").expect("some");
        let synack = parse_ipv4(&buf[..n]).expect("parse synack");
        c.on_receive(&synack);

        // The initiator's first data segment carries the completing ACK, but an
        // explicit empty ACK is what a real stack sends first.
        let n = c.data(b"", &mut buf, 2).expect("ack");
        let ack = parse_ipv4(&buf[..n]).expect("parse ack");
        s.on_receive(&ack);
    }

    #[test]
    fn a_handshake_establishes_both_ends() {
        let (mut c, mut s) = (client(), server());
        assert_eq!(c.phase(), Phase::Idle);
        connect(&mut c, &mut s);
        assert!(c.is_established());
        assert!(s.is_established());
    }

    #[test]
    fn the_handshake_numbers_are_exactly_right() {
        let (mut c, mut s) = (client(), server());
        let mut buf = vec![0u8; MAX_OVERHEAD + 64];

        let n = c.handshake(&mut buf, 0).expect("syn").expect("some");
        let syn = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(syn.seq, 1_000_000, "SYN carries the ISN");
        s.on_receive(&syn);

        let n = s.handshake(&mut buf, 1).expect("synack").expect("some");
        let synack = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(synack.seq, 9_000_000, "SYN+ACK carries the responder ISN");
        assert_eq!(synack.ack, 1_000_001, "and acknowledges the SYN's one byte");
        c.on_receive(&synack);

        let n = c.data(b"", &mut buf, 2).expect("ack");
        let ack = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(ack.seq, 1_000_001, "past the SYN");
        assert_eq!(ack.ack, 9_000_001, "acknowledging the responder's SYN");
    }

    #[test]
    fn sequence_numbers_track_bytes_sent_exactly() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let mut expected_seq = 1_000_001u32;
        for len in [1usize, 100, 1400, 7, 0, 512] {
            let payload = vec![0xAA; len];
            let packet = emitted(|b| c.data(&payload, b, 10));
            let seg = parse_ipv4(&packet).expect("parse");
            assert_eq!(seg.seq, expected_seq, "payload of {len} bytes");
            expected_seq = expected_seq.wrapping_add(u32::try_from(len).expect("fits"));
            s.on_receive(&seg);
        }
    }

    #[test]
    fn acknowledgements_track_bytes_received_exactly() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let mut expected_ack = 1_000_001u32;
        for len in [10usize, 250, 1400] {
            let payload = vec![0xBB; len];
            let packet = emitted(|b| c.data(&payload, b, 10));
            let seg = parse_ipv4(&packet).expect("parse");
            s.on_receive(&seg);
            expected_ack = expected_ack.wrapping_add(u32::try_from(len).expect("fits"));

            let reply = emitted(|b| s.data(b"", b, 11));
            let reply_seg = parse_ipv4(&reply).expect("parse");
            assert_eq!(reply_seg.ack, expected_ack);
        }
    }

    #[test]
    fn a_long_bidirectional_exchange_stays_consistent() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        for i in 0..500u32 {
            let payload = i.to_be_bytes();

            let packet = emitted(|b| c.data(&payload, b, u64::from(i)));
            let seg = parse_ipv4(&packet).expect("parse");
            assert_eq!(seg.seq, c.next_seq().wrapping_sub(4));
            s.on_receive(&seg);

            let packet = emitted(|b| s.data(&payload, b, u64::from(i)));
            let seg = parse_ipv4(&packet).expect("parse");
            c.on_receive(&seg);
        }

        // Each side's view of the other must agree exactly.
        assert_eq!(c.next_ack(), Some(s.next_seq()));
        assert_eq!(s.next_ack(), Some(c.next_seq()));
    }

    #[test]
    fn sequence_numbers_wrap_like_real_tcp() {
        let mut c = Endpoint::new(Config {
            isn: u32::MAX - 5,
            ts_base: 0,
            ..cfg(Role::Initiator, Carrier::Handshake, LINUX_6)
        });
        let mut s = server();
        connect(&mut c, &mut s);

        // The ISN plus the SYN's byte has already wrapped past zero.
        let packet = emitted(|b| c.data(&[0u8; 100], b, 0));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.seq, u32::MAX.wrapping_add(1).wrapping_sub(5));
        s.on_receive(&seg);
        assert_eq!(s.next_ack(), Some(seg.seq.wrapping_add(100)));
    }

    #[test]
    fn data_before_the_handshake_is_refused() {
        let mut c = client();
        let mut buf = vec![0u8; 2048];
        assert!(matches!(
            c.data(b"too early", &mut buf, 0),
            Err(Error::NotEstablished)
        ));
    }

    #[test]
    fn a_lost_syn_can_be_repeated_without_advancing_the_sequence() {
        let mut c = client();
        let mut buf = vec![0u8; 2048];

        let n = c.handshake(&mut buf, 0).expect("syn").expect("some");
        let first = parse_ipv4(&buf[..n]).expect("parse").seq;
        let n = c.handshake(&mut buf, 1).expect("syn").expect("some");
        let second = parse_ipv4(&buf[..n]).expect("parse").seq;

        assert_eq!(first, second, "a retried SYN must carry the same sequence");
    }

    #[test]
    fn the_responder_offers_nothing_until_it_has_seen_a_syn() {
        let mut s = server();
        let mut buf = vec![0u8; 2048];
        assert_eq!(s.handshake(&mut buf, 0).expect("handshake"), None);
    }

    #[test]
    fn the_peer_timestamp_is_echoed() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let packet = emitted(|b| c.data(b"hello", b, 12_345));
        let seg = parse_ipv4(&packet).expect("parse");
        let client_ts = seg.ts_val.expect("linux profile sends timestamps");
        s.on_receive(&seg);

        let reply = emitted(|b| s.data(b"hi", b, 12_400));
        let reply_seg = parse_ipv4(&reply).expect("parse");
        let opts_ecr = {
            // The echo is the second word of the timestamp option.
            let tcp = &reply[segment::IPV4_LEN..];
            let opts = &tcp[segment::TCP_LEN..];
            u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]])
        };
        assert_eq!(opts_ecr, client_ts);
        assert!(reply_seg.ts_val.is_some());
    }

    #[test]
    fn a_pure_ack_still_refreshes_the_echoed_timestamp() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let packet = emitted(|b| c.data(b"", b, 50_000));
        let seg = parse_ipv4(&packet).expect("parse");
        let fresh = seg.ts_val.expect("timestamp");
        assert!(s.on_receive(&seg).is_none(), "empty payload yields nothing");

        let reply = emitted(|b| s.data(b"x", b, 50_001));
        let tcp = &reply[segment::IPV4_LEN..];
        let opts = &tcp[segment::TCP_LEN..];
        assert_eq!(
            u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]),
            fresh
        );
    }

    #[test]
    fn the_timestamp_clock_does_not_start_at_zero() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);
        let packet = emitted(|b| c.data(b"x", b, 0));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.ts_val, Some(5_000), "ts_base offsets the clock");
    }

    #[test]
    fn the_advertised_window_varies_but_stays_plausible() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let base = LINUX_6.window >> LINUX_6.window_scale;
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u64 {
            let packet = emitted(|b| c.data(b"x", b, i));
            let seg = parse_ipv4(&packet).expect("parse");
            seen.insert(seg.window);
            let w = u32::from(seg.window);
            assert!(
                w.abs_diff(base) <= base / 8 + 1,
                "window {w} strayed too far from {base}"
            );
        }
        assert!(seen.len() > 1, "a constant window is itself a signature");
    }

    #[test]
    fn the_ip_identification_varies() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u64 {
            let packet = emitted(|b| c.data(b"x", b, i));
            seen.insert(u16::from_be_bytes([packet[4], packet[5]]));
        }
        assert!(
            seen.len() > 32,
            "IP ID should look uniform, saw {}",
            seen.len()
        );
    }

    #[test]
    fn a_syn_advertises_the_unscaled_window() {
        let mut c = client();
        let packet = emitted(|b| c.handshake(b, 0).map(|o| o.expect("some")));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.window, LINUX_6.syn_window);
    }

    #[test]
    fn a_fin_consumes_one_sequence_number_and_closes() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let before = c.next_seq();
        let packet = emitted(|b| c.close(b, 100));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.seq, before);
        assert_eq!(c.next_seq(), before.wrapping_add(1));
        assert_eq!(c.phase(), Phase::Closed);

        let ack_before = s.next_ack().expect("established");
        s.on_receive(&seg);
        assert_eq!(s.next_ack(), Some(ack_before.wrapping_add(1)));
        assert_eq!(s.phase(), Phase::Closed);
    }

    #[test]
    fn a_reset_closes_the_endpoint() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let mut buf = vec![0u8; 2048];
        let n = segment::emit(
            Kind::Rst,
            &LINUX_6,
            &Fields {
                src: SERVER,
                dst: CLIENT,
                seq: s.next_seq(),
                ack: 0,
                window: 0,
                ip_id: 1,
                ts_val: 0,
                ts_ecr: 0,
            },
            &[],
            &mut buf,
        )
        .expect("emit rst");
        let rst = parse_ipv4(&buf[..n]).expect("parse");

        assert!(c.on_receive(&rst).is_none());
        assert_eq!(c.phase(), Phase::Closed);
    }

    #[test]
    fn roaming_preserves_the_sequence_space() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let packet = emitted(|b| c.data(b"before roaming", b, 0));
        s.on_receive(&parse_ipv4(&packet).expect("parse"));

        let seq_before = s.next_seq();
        let ack_before = s.next_ack();

        // The client reappears from a new address and port.
        let roamed = (Ipv4Addr::new(198, 51, 100, 77), 55555);
        s.set_remote(roamed);

        assert_eq!(
            s.next_seq(),
            seq_before,
            "roaming must not jump the sequence"
        );
        assert_eq!(s.next_ack(), ack_before);
        assert_eq!(s.remote(), roamed);

        let reply = emitted(|b| s.data(b"after roaming", b, 1));
        let seg = parse_ipv4(&reply).expect("parse");
        assert_eq!(seg.dst, roamed, "and packets follow the peer");
        assert_eq!(seg.seq, seq_before);
    }

    #[test]
    fn data_arriving_before_any_syn_is_ignored() {
        let mut s = server();
        let mut c = client();
        connect(&mut c, &mut s);

        // A fresh responder that never saw a SYN has no sequence space to
        // reason about, so it must not fold the payload in.
        let mut fresh = server();
        let packet = emitted(|b| c.data(b"orphan", b, 0));
        let seg = parse_ipv4(&packet).expect("parse");
        assert!(fresh.on_receive(&seg).is_none());
        assert_eq!(fresh.next_ack(), None);
    }

    #[test]
    fn on_receive_returns_the_payload_of_data_segments() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let payload = b"the inner packet";
        let packet = emitted(|b| c.data(payload, b, 0));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(s.on_receive(&seg), Some(&payload[..]));
    }

    #[test]
    fn a_profile_without_timestamps_omits_and_ignores_them() {
        let mut c = Endpoint::new(cfg(Role::Initiator, Carrier::Handshake, WINDOWS_11));
        let mut s = Endpoint::new(cfg(Role::Responder, Carrier::Handshake, WINDOWS_11));
        connect(&mut c, &mut s);

        let packet = emitted(|b| c.data(b"x", b, 1234));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.ts_val, None);
        assert!(s.on_receive(&seg).is_some());
    }

    #[test]
    fn midstream_is_the_default_and_emits_no_syn() {
        assert_eq!(Carrier::default(), Carrier::Midstream);

        let (mut c, _s) = midstream_pair();
        let mut buf = vec![0u8; 2048];
        assert_eq!(
            c.handshake(&mut buf, 0).expect("handshake"),
            None,
            "midstream must never put a SYN on the wire"
        );
        assert!(c.is_established(), "and data may flow immediately");
    }

    #[test]
    fn midstream_sequencing_is_exact_from_the_very_first_packet() {
        // The property that makes a handshake unnecessary: both ends already
        // know where the other's numbering starts, so the first data segment is
        // already consistent.
        let (mut c, mut s) = midstream_pair();

        let packet = emitted(|b| c.data(b"first ever packet", b, 0));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.seq, CLIENT_ISN);
        assert_eq!(
            seg.ack, SERVER_ISN,
            "acknowledging the peer from packet one"
        );

        s.on_receive(&seg);
        let reply = emitted(|b| s.data(b"reply", b, 1));
        let reply_seg = parse_ipv4(&reply).expect("parse");
        assert_eq!(reply_seg.seq, SERVER_ISN);
        assert_eq!(reply_seg.ack, CLIENT_ISN.wrapping_add(17));
    }

    #[test]
    fn midstream_stays_consistent_over_a_long_exchange() {
        let (mut c, mut s) = midstream_pair();
        for i in 0..500u32 {
            let payload = i.to_be_bytes();
            let packet = emitted(|b| c.data(&payload, b, u64::from(i)));
            s.on_receive(&parse_ipv4(&packet).expect("parse"));
            let reply = emitted(|b| s.data(&payload, b, u64::from(i)));
            c.on_receive(&parse_ipv4(&reply).expect("parse"));
        }
        assert_eq!(c.next_ack(), Some(s.next_seq()));
        assert_eq!(s.next_ack(), Some(c.next_seq()));
    }

    #[test]
    fn midstream_never_answers_an_unauthenticated_segment() {
        // The probe-resistance property. A stranger's SYN must produce nothing:
        // replying would confirm to a prober that something is listening, which
        // is exactly what the tunnel handshake's silence is designed to avoid.
        let (_c, mut s) = midstream_pair();
        let mut buf = vec![0u8; 2048];

        let n = segment::emit(
            Kind::Syn,
            &LINUX_6,
            &Fields {
                src: (Ipv4Addr::new(198, 51, 100, 9), 1234),
                dst: SERVER,
                seq: 42,
                ack: 0,
                window: 64240,
                ip_id: 7,
                ts_val: 1,
                ts_ecr: 0,
            },
            &[],
            &mut buf,
        )
        .expect("emit probe");
        let probe = parse_ipv4(&buf[..n]).expect("parse");

        assert!(s.on_receive(&probe).is_none());
        assert_eq!(
            s.handshake(&mut buf, 0).expect("handshake"),
            None,
            "a probe must not draw a SYN+ACK"
        );
    }

    #[test]
    fn a_lost_packet_leaves_a_gap_rather_than_a_false_acknowledgement() {
        // The documented limitation, pinned so it cannot change silently: with
        // no retransmission, a dropped packet means our acknowledgement falls
        // permanently behind the peer's sequence. It must never run ahead.
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let first = emitted(|b| c.data(&[1u8; 200], b, 0));
        s.on_receive(&parse_ipv4(&first).expect("parse"));

        // This one never arrives.
        let _lost = emitted(|b| c.data(&[2u8; 300], b, 1));

        let third = emitted(|b| c.data(&[3u8; 100], b, 2));
        let third_seg = parse_ipv4(&third).expect("parse");
        s.on_receive(&third_seg);

        let peer_next_seq = c.next_seq();
        let our_ack = s.next_ack().expect("established");
        assert!(
            our_ack != peer_next_seq,
            "the gap should still be visible, not papered over"
        );
        assert_eq!(
            peer_next_seq.wrapping_sub(our_ack),
            300,
            "and it should be exactly the lost segment"
        );
    }
}
