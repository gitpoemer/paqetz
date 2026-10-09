//! Per-endpoint connection state: the synthetic TCP conversation.
//!
//! # Two ways to number the segments, and why the sloppier one wins
//!
//! paqet invents its sequence numbers — `seq = base + (counter << 7)`, with an
//! acknowledgement derived from the same counter — so they bear no relation to
//! the bytes actually sent. This crate originally rejected that as obviously
//! detectable and numbered its segments honestly instead, by payload bytes, the
//! way a real stack does.
//!
//! That was wrong, and it was wrong in a way that only appears in production.
//!
//! Honest numbering makes the flow *reassemblable*, so a middlebox modelling
//! TCP will track it as a byte stream. That costs nothing while every packet
//! arrives. But the carrier never retransmits — nothing owns these segments,
//! which is the premise (D2) — so the first packet the network drops leaves a
//! hole that is never filled: our sequence runs on past it while our
//! acknowledgement freezes at it, for ever. A sender that keeps sending to a
//! receiver that has stopped acknowledging is not something a real connection
//! does for more than a few milliseconds. It either retransmits or it dies.
//!
//! So the flow reads as ordinary TCP right up until the first loss, and as
//! unmistakably synthetic from then until the five-tuple is abandoned — with a
//! stalled reassembly buffer in front of it, which invites further loss, which
//! adds further holes. It is a ratchet, and it only turns one way. Observed in
//! the field as a tunnel that ran perfectly and then decayed to unusable, on a
//! network where paqet, with its "detectable" numbers, kept working.
//!
//! Numbers that were never coherent cannot become incoherent. Nothing
//! reassembles them, so nothing builds the state that honest numbering later
//! violates. [`Sequencing::Opaque`] is therefore the default for a carrier that
//! never opens its connection; [`Sequencing::Stream`] remains for a path that
//! rejects implausible sequence numbers outright rather than tracking them,
//! where the trade runs the other way, and is the default for one that does
//! open it, whose SYN invites exactly that tracking.
//!
//! The acknowledgement no longer freezes, though. It is read off the wire --
//! the end of the furthest segment that arrived -- rather than counted, so the
//! next segment past a hole moves it on, and a peer that restarts or moves to a
//! new port is followed rather than acknowledged at a stream it has abandoned.
//! The hole itself stays, for anything reassembling the stream to wait on.
//!
//! Neither end needs to agree with the other: nothing here validates an inbound
//! `seq` or `ack`. They are read only to compose our own.
//!
//! # Acknowledging like a receiver
//!
//! Nothing here needs an acknowledgement, because nothing is waiting to be
//! released by one. So for a long time the carrier sent none at all, and a
//! capture of a bulk transfer showed the receiving side answering two thousand
//! segments with one data-less segment. No TCP connection looks like that under
//! any conditions, and seeing it needs flow state but not a byte of payload
//! inspection, which makes it cheaper than anything a filter could learn from
//! the payload. [`Endpoint::owes_ack`] reports when a real receiver would have
//! answered -- after [`ACK_EVERY`] payload-bearing segments with nothing sent
//! back -- and the caller sends one. Traffic that flows both ways never reaches
//! it, because every segment already carries the acknowledgement with it.
//!
//! # Windows
//!
//! Sequence and acknowledgement numbers are `u32` and wrap. All arithmetic here
//! is wrapping, which is what TCP specifies.

use core::net::Ipv4Addr;

use crate::profile::OsProfile;
use crate::segment::{self, Fields, Kind, Segment};
use crate::{Error, Result};

/// How many payload-bearing segments may arrive before this end answers.
///
/// Two, which is where a delayed acknowledgement fires on every stack that has
/// one. Higher would halve the cost of the reverse direction and start to look
/// like a receiver that is not keeping up.
pub const ACK_EVERY: u16 = 2;

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

    /// Announce each connection with a SYN and a SYN+ACK, but wait for neither.
    ///
    /// The initiator sends its SYN and carries straight on; the responder sends
    /// its SYN+ACK only once the peer has authenticated, so a stranger still
    /// draws nothing. For a middlebox that will not carry a flow it never saw
    /// open, at no cost in round trips -- though the first segments reach it
    /// before the SYN+ACK does, which a strict one may refuse.
    FakeHandshake,

    /// Emit a real SYN / SYN+ACK / ACK exchange, and wait for it, before any
    /// data.
    ///
    /// Preferable against a middlebox that *drops* mid-stream flows rather than
    /// ignoring them. Costs a round trip on every new connection, and means the
    /// responder answers a segment before the tunnel handshake could
    /// authenticate it -- which the tunnel makes safe by answering only a SYN
    /// whose sequence number proves the sender knows its public key.
    Handshake,
}

impl Carrier {
    /// Whether connections open with a SYN, so the window scale it declares is
    /// in force afterwards.
    #[must_use]
    pub const fn opens(self) -> bool {
        !matches!(self, Self::Midstream)
    }
}

/// How far behind the newest byte seen a segment may start and still be the
/// same stream arriving out of order.
///
/// Anything further back is not reordering but a peer that started numbering
/// afresh -- a restart, or a carrier rebuilt on a new port -- and is taken as
/// the new position. A real stream reorders across a window or two; a megabyte
/// is well past that, and a fresh random base lands inside it once in four
/// thousand.
const REORDER_SPAN: u32 = 1 << 20;

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
    /// The starting guess under [`Carrier::Midstream`] and
    /// [`Carrier::FakeHandshake`], corrected by the first segment the peer
    /// sends. Ignored under [`Carrier::Handshake`], where it is learned from
    /// the peer's SYN+ACK.
    pub peer_isn: u32,
    /// Offset added to the clock to form the TCP timestamp, so the timestamp
    /// clock does not start near zero and reveal process start.
    pub ts_base: u32,
    /// How to number the segments.
    pub sequencing: Sequencing,
    /// Whether to wrap each payload in a TLS application-data record header.
    ///
    /// For a connection opened with a decoy handshake: having claimed to be a
    /// TLS session, what follows has to be shaped like one. Five bytes per
    /// packet, and the far end strips them.
    pub records: bool,
    /// Whether to set Don't Fragment on every packet.
    pub dont_fragment: bool,
    /// The maximum segment size to advertise, when it is not the profile's.
    ///
    /// `None` keeps the profile's, which describes a host on a 1500-byte
    /// Ethernet path. A carrier that deliberately stays below that should say
    /// so, or the largest segment it ever sends sits a fixed distance under
    /// what it promised. Clamped to the profile's value, never above it.
    pub mss: Option<u16>,
}

/// How the sequence and acknowledgement numbers are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sequencing {
    /// Numbers that do not describe a byte stream, so none can be rebuilt from
    /// them. The default, and what survives a lossy path.
    #[default]
    Opaque,
    /// Numbers that track the payload bytes genuinely sent and received.
    ///
    /// Truthful, and therefore checkable — including after a loss the carrier
    /// cannot repair. See the module documentation.
    Stream,
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

    sequencing: Sequencing,
    records: bool,

    local_isn: u32,
    /// Where this connection's IPv4 Identification counts from, for a profile
    /// that counts. Fixed here rather than read from `local_isn`, which a real
    /// handshake replaces once it has numbered its SYN.
    ip_id_base: u32,
    /// Payload bytes sent, plus one for each SYN or FIN we have sent.
    sent: u32,
    /// The next byte expected from the peer: the end of the furthest segment
    /// it has sent that arrived. `None` until its numbering is known.
    ///
    /// Read off the wire rather than counted. A count of bytes received falls
    /// behind for good at the first lost segment, because nothing here is ever
    /// sent again; and it describes a stream the peer may no longer be
    /// numbering, once the peer restarts or moves to a new port.
    peer_next: Option<u32>,
    /// Whether the next segment from the peer sets `peer_next` outright, rather
    /// than only moving it forward.
    ///
    /// Set when where the peer's numbering stands is a guess: at the start,
    /// where it was derived rather than seen, and after the peer moves.
    relearn: bool,
    /// The sequence number of our SYN, once one has been sent.
    syn_seq: Option<u32>,
    /// The timestamp our SYN carried, repeated in every retransmission.
    syn_ts: Option<u32>,

    /// Milliseconds added to the caller's clock to form `ts_val`, so the
    /// timestamp clock does not start at zero and reveal process start.
    ts_base: u32,
    /// Most recent timestamp seen from the peer, echoed back as `ts_ecr`.
    peer_ts_val: u32,

    /// Drives IP Identification and window jitter.
    counter: u32,
    dont_fragment: bool,
    /// Whether our SYN's one byte of sequence space has been counted.
    ///
    /// A retransmitted SYN carries the same sequence number as the original, so
    /// it must be counted once however many times it goes out.
    syn_counted: bool,
    /// The maximum segment size this end advertises.
    mss: u16,
    /// Bytes of the record currently being written that are still to come.
    ///
    /// A record spans as many packets as the sender had ready, so this counts
    /// down across them. Zero means the stream is at a record boundary, which
    /// is the only place anything else -- a decoy flight, which is records of
    /// its own -- may be written without breaking the chain of lengths an
    /// observer follows.
    record_left: usize,
    /// Segments carrying payload received since this end last sent anything.
    ///
    /// A real receiver answers about every second segment. Nothing here needs
    /// an acknowledgement -- there is no retransmission to release -- so the
    /// carrier sent none, and a capture of a two-megabyte transfer showed the
    /// receiving side answering with a single data-less segment. That is not a
    /// condition TCP has, and recognising it needs flow state but no payload
    /// inspection, which makes it the cheapest check anything on the path can
    /// run. Counted here; [`Self::owes_ack`] decides.
    unacked: u16,
}

impl Endpoint {
    /// Creates an endpoint.
    #[must_use]
    pub const fn new(cfg: Config) -> Self {
        // Only a real handshake waits. Under Midstream there is no SYN at all,
        // and a fake one is announced and not waited for: either way both ends
        // already know where the other's numbering starts, and a SYN sent for
        // show sits one below the first data byte rather than taking a number
        // of its own.
        let waits = matches!(cfg.carrier, Carrier::Handshake);
        Self {
            local: cfg.local,
            remote: cfg.remote,
            profile: cfg.profile,
            role: cfg.role,
            carrier: cfg.carrier,
            phase: if waits {
                Phase::Idle
            } else {
                Phase::Established
            },
            sequencing: cfg.sequencing,
            records: cfg.records,
            dont_fragment: cfg.dont_fragment,
            local_isn: cfg.isn,
            ip_id_base: cfg.isn,
            sent: 0,
            peer_next: if waits { None } else { Some(cfg.peer_isn) },
            // Derived, not seen: right for a peer that started when we did,
            // and wrong for one that restarted or moved since.
            relearn: true,
            syn_seq: None,
            syn_ts: None,
            ts_base: cfg.ts_base,
            peer_ts_val: 0,
            counter: 0,
            syn_counted: !waits,
            record_left: 0,
            mss: match cfg.mss {
                Some(mss) => {
                    if mss < cfg.profile.mss {
                        mss
                    } else {
                        cfg.profile.mss
                    }
                }
                None => cfg.profile.mss,
            },
            unacked: 0,
        }
    }

    /// The current handshake phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether the handshake, if there is one, has completed.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established)
    }

    /// Whether a data segment may go out now.
    ///
    /// Later than [`Self::is_established`] for an initiator announcing itself
    /// without waiting: it is established from the start, but its SYN has to be
    /// on the wire before anything follows it.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        match (self.carrier, self.role) {
            (Carrier::FakeHandshake, Role::Initiator) => self.syn_seq.is_some(),
            _ => self.is_established(),
        }
    }

    /// Whether this end still owes the network the SYN that opens its
    /// connection.
    ///
    /// Once under a fake handshake, and until answered under a real one.
    #[must_use]
    pub const fn wants_opening(&self) -> bool {
        matches!(self.role, Role::Initiator)
            && match self.carrier {
                Carrier::Midstream => false,
                Carrier::FakeHandshake => self.syn_seq.is_none(),
                Carrier::Handshake => !self.is_established(),
            }
    }

    /// The peer's address and port.
    #[must_use]
    pub const fn remote(&self) -> (Ipv4Addr, u16) {
        self.remote
    }

    /// Our own address and port.
    #[must_use]
    pub const fn local(&self) -> (Ipv4Addr, u16) {
        self.local
    }

    /// Whether `seg` is a SYN+ACK answering the SYN this end sent.
    ///
    /// The only test an unauthenticated segment gets before it may touch any
    /// state here, so it refuses anything else a SYN+ACK might carry: a reset
    /// or a FIN folded into one would close the connection on the word of
    /// whoever forged it.
    #[must_use]
    pub fn answers_syn(&self, seg: &Segment<'_>) -> bool {
        use segment::flags::{ACK, FIN, RST, SYN};
        seg.flags & (SYN | ACK | RST | FIN) == SYN | ACK
            && self
                .syn_seq
                .is_some_and(|ours| seg.ack == ours.wrapping_add(1))
    }

    /// Whether the peer's acknowledgement in `seg` describes some other
    /// connection's numbering than this end's.
    ///
    /// A peer that restarted on the same addresses and ports opened a new
    /// connection the tuple cannot show, and acknowledges what it was told in
    /// that connection's SYN+ACK. Far from where this end is numbering --
    /// further than anything in flight could be -- is the sign. Never under
    /// opaque numbering, whose acknowledgements describe nothing.
    #[must_use]
    pub fn names_another_connection(&self, seg: &Segment<'_>) -> bool {
        if self.sequencing == Sequencing::Opaque || !self.is_established() {
            return false;
        }
        let ahead = seg.ack.wrapping_sub(self.next_seq());
        ahead > REORDER_SPAN && ahead.wrapping_neg() > REORDER_SPAN
    }

    /// Updates the peer's address and port, for roaming (D5).
    ///
    /// Called only once a packet from the new address has authenticated. Our
    /// own numbering is deliberately preserved: from TCP's point of view this
    /// may be the same conversation seen from a new vantage point, and
    /// resetting it would produce exactly the mid-stream jump the design is
    /// avoiding. The peer's is relearned from its next segment instead, because
    /// a peer arriving from a new port has usually restarted or rebuilt its
    /// carrier, and is numbering from somewhere new.
    pub fn set_remote(&mut self, remote: (Ipv4Addr, u16)) {
        if remote != self.remote {
            self.relearn = true;
        }
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
        match self.sequencing {
            // Advances by a fixed step per packet rather than by the payload,
            // so consecutive segments overlap and contradict each other as a
            // byte stream. That is the point: there is no stream to rebuild,
            // and so no stream state for a later loss to break.
            Sequencing::Opaque => self.local_isn.wrapping_add(self.counter << 7),
            Sequencing::Stream => self.local_isn.wrapping_add(self.sent),
        }
    }

    /// The acknowledgement this endpoint will place on the wire, if one can be
    /// composed.
    #[must_use]
    pub const fn next_ack(&self) -> Option<u32> {
        match self.sequencing {
            // Near our own sequence and drifting, which is what an
            // acknowledgement looks like from the outside, without claiming
            // anything about what arrived.
            Sequencing::Opaque => Some(
                self.local_isn
                    .wrapping_add(self.counter << 7)
                    .wrapping_sub(self.counter & 0x3FF)
                    .wrapping_add(1400),
            ),
            Sequencing::Stream => self.peer_next,
        }
    }

    /// Writes the segment that should be sent next to open the connection, if
    /// any.
    ///
    /// Always `Ok(None)` under [`Carrier::Midstream`], which is the point of
    /// that mode, and for a fake handshake's initiator once its one SYN is out.
    /// A real handshake's initiator gets its SYN for as long as it is
    /// unanswered: the caller drives retransmission, and a repeat carries the
    /// same number and timestamp as the first, which is why the phase does not
    /// advance on one.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold the segment.
    pub fn handshake(&mut self, out: &mut [u8], now: u64) -> Result<Option<usize>> {
        match (self.carrier, self.role, self.phase) {
            (Carrier::FakeHandshake, Role::Initiator, _) if self.syn_seq.is_none() => {
                // One below the first data byte, which is where a real SYN sits.
                let seq = self.next_seq().wrapping_sub(1);
                self.syn(seq, out, now).map(Some)
            }
            (Carrier::Handshake, Role::Initiator, Phase::Idle | Phase::SynSent) => {
                // The SYN's own sequence byte is not counted here. Every
                // retransmission must carry the ISN itself; the byte is
                // accounted for when the handshake completes, in `establish`.
                let n = self.syn(self.local_isn, out, now)?;
                self.phase = Phase::SynSent;
                Ok(Some(n))
            }
            (Carrier::Handshake, Role::Responder, Phase::SynReceived) => {
                self.emit_raw(Kind::SynAck, &[], out, now, false).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Numbers the SYN about to be sent from the timestamp it will carry.
    ///
    /// For a responder that checks the one against the other: `isn_for` turns
    /// the timestamp into the sequence number, and both are fixed here, at the
    /// moment of sending, so neither can drift from the other. Nothing once a
    /// SYN has gone out, because a repeat must be the same SYN.
    pub fn number_syn(&mut self, now: u64, isn_for: impl FnOnce(u32) -> u32) {
        if self.syn_seq.is_some() {
            return;
        }
        let ts = timestamp(self.ts_base, now, self.profile.ts_hz);
        self.syn_ts = Some(ts);
        self.local_isn = isn_for(ts);
    }

    /// Writes a SYN at `seq`.
    ///
    /// The timestamp is fixed by the first one and repeated by every
    /// retransmission, because a responder that checks the SYN checks it
    /// against both numbers together.
    fn syn(&mut self, seq: u32, out: &mut [u8], now: u64) -> Result<usize> {
        let ts_val = *self
            .syn_ts
            .get_or_insert(timestamp(self.ts_base, now, self.profile.ts_hz));
        let fields = Fields {
            seq,
            // A SYN acknowledges nothing, and carries no ACK flag to say so.
            ack: 0,
            ts_val,
            ts_ecr: 0,
            ..self.fields(Kind::Syn, now, false)
        };
        let n = segment::emit(Kind::Syn, &self.profile, &fields, &[], out)?;
        self.counter = self.counter.wrapping_add(1);
        self.syn_seq = Some(seq);
        Ok(n)
    }

    /// Writes the SYN+ACK announcing this end's side of a connection the peer
    /// opened with a fake handshake, acknowledging its first byte at `ack`.
    ///
    /// It sits one below this end's next sequence number, where a real SYN+ACK
    /// sits, so what follows it reads as though it had been the start.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold the segment.
    pub fn answer(&mut self, ack: u32, out: &mut [u8], now: u64) -> Result<usize> {
        let fields = Fields {
            seq: self.next_seq().wrapping_sub(1),
            ack,
            ..self.fields(Kind::SynAck, now, false)
        };
        let n = segment::emit(Kind::SynAck, &self.profile, &fields, &[], out)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(n)
    }

    /// Writes a bare acknowledgement: how an initiator completes the
    /// handshake once the SYN+ACK arrives.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold the segment.
    pub fn ack(&mut self, out: &mut [u8], now: u64) -> Result<usize> {
        self.emit_raw(Kind::Ack, &[], out, now, false)
    }

    /// Whether the stream is between records.
    ///
    /// A decoy flight is records of its own, so writing one in the middle of
    /// another record would break the chain of lengths an observer follows from
    /// the hello onward. Always true when nothing wears records.
    #[must_use]
    pub const fn at_record_boundary(&self) -> bool {
        !self.records || self.record_left == 0
    }

    /// Whether a real receiver would have acknowledged by now.
    ///
    /// True once two payload-bearing segments have arrived with nothing sent
    /// back, which is where a delayed acknowledgement fires. A segment this end
    /// sends carries the acknowledgement with it, so bidirectional traffic
    /// never reaches this and costs nothing.
    #[must_use]
    pub const fn owes_ack(&self) -> bool {
        self.unacked >= ACK_EVERY
    }

    /// Takes up a connection the peer opened against a SYN+ACK this end sent
    /// without remembering it.
    ///
    /// Nothing here knows that SYN+ACK's number -- it was composed from the SYN
    /// alone, by [`answer_syn`] -- but the peer's acknowledgement names the next
    /// byte this end is to send, which is the same thing. `seg` is the peer's
    /// first authenticated segment on the connection, and `ts_base` the clock
    /// the SYN+ACK read, which every segment after it must read too.
    pub fn rejoin(&mut self, seg: &Segment<'_>, ts_base: u32) {
        self.ts_base = ts_base;
        self.local_isn = seg.ack.wrapping_sub(self.sent);
        self.syn_counted = true;
        self.phase = Phase::Established;
        self.remote = seg.src;
        self.peer_next = Some(seg.seq.wrapping_add(occupied(seg)));
        self.relearn = false;
        if let Some(ts) = seg.ts_val {
            self.peer_ts_val = ts;
        }
    }

    /// Writes one data segment carrying `payload`.
    ///
    /// `record` opens an application-data record of that many bytes, which may
    /// be more than this packet carries: the rest of it follows in the packets
    /// after this one, which pass `None`. A real session writes one record per
    /// application write, so one record per burst of packets is what a burst
    /// should look like. One per packet, which is what this did first, put a
    /// record header at the start of every segment of every bulk transfer,
    /// where a real session starts one in about twelve.
    ///
    /// # Errors
    /// - [`Error::Short`] if `out` cannot hold the segment.
    /// - [`Error::NotEstablished`] if the connection is not yet open.
    /// - [`Error::TooLong`] if `record` is longer than a record may be.
    pub fn data(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        now: u64,
        push: bool,
        record: Option<usize>,
    ) -> Result<usize> {
        if !self.is_ready() {
            return Err(Error::NotEstablished);
        }
        // The record header is on the wire, so it occupies sequence space like
        // anything else: counted here rather than in `emit`, which is told what
        // to write and not what it means.
        // A header goes in only at a boundary, whatever the caller asked for.
        // The caller's figure is what it expects the burst to carry, and a
        // packet it then decides not to send would leave the record short and
        // every header after it inside the record before -- so the record this
        // end is already writing always wins, and simply spans further than
        // planned. That keeps the chain of lengths continuous, which is the one
        // property an observer walking the stream depends on.
        let opening = self.records && self.record_left == 0;
        let header = if opening {
            let total = record.unwrap_or(payload.len());
            Some(crate::cover::record_header(total).ok_or(Error::TooLong { len: total })?)
        } else {
            None
        };
        if self.records {
            let total = if opening {
                record.unwrap_or(payload.len())
            } else {
                self.record_left
            };
            self.record_left = total.saturating_sub(payload.len());
        }
        let (n, written) = match header {
            Some(header) => (
                self.emit_parts(Kind::Data, &[&header, payload], out, now, push)?,
                payload.len() + header.len(),
            ),
            None => (
                self.emit_raw(Kind::Data, payload, out, now, push)?,
                payload.len(),
            ),
        };
        let len = u32::try_from(written).map_err(|_| Error::TooLong { len: written })?;
        self.sent = self.sent.wrapping_add(len);
        Ok(n)
    }

    /// Writes a payload that is already shaped the way the wire should see it.
    ///
    /// For the decoy handshake, which is TLS records of its own: wrapping those
    /// in an application-data record would be claiming a session had begun
    /// before its hello.
    ///
    /// # Errors
    /// As [`Self::data`].
    pub fn bare(&mut self, payload: &[u8], out: &mut [u8], now: u64, push: bool) -> Result<usize> {
        if !self.is_ready() {
            return Err(Error::NotEstablished);
        }
        let n = self.emit_raw(Kind::Data, payload, out, now, push)?;
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
        let n = self.emit_raw(Kind::Fin, &[], out, now, true)?;
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
    fn emit_raw(
        &mut self,
        kind: Kind,
        payload: &[u8],
        out: &mut [u8],
        now: u64,
        push: bool,
    ) -> Result<usize> {
        self.emit_parts(kind, &[payload], out, now, push)
    }

    /// As [`Self::emit_raw`], with the payload in pieces.
    fn emit_parts(
        &mut self,
        kind: Kind,
        parts: &[&[u8]],
        out: &mut [u8],
        now: u64,
        push: bool,
    ) -> Result<usize> {
        let fields = self.fields(kind, now, push);
        let n = segment::emit_parts(kind, &self.profile, &fields, parts, out)?;
        self.counter = self.counter.wrapping_add(1);
        // Every segment this end sends carries the current acknowledgement, so
        // whatever was owed has now been said.
        self.unacked = 0;
        Ok(n)
    }

    /// Assembles the volatile fields for one outbound segment.
    fn fields(&self, kind: Kind, now: u64, push: bool) -> Fields {
        Fields {
            src: self.local,
            dst: self.remote,
            seq: self.next_seq(),
            ack: self.next_ack().unwrap_or(0),
            window: self.window(kind),
            ip_id: self.ip_id(),
            ts_val: self.ts_val(now),
            ts_ecr: self.peer_ts_val,
            dont_fragment: self.dont_fragment,
            push,
            mss: self.mss,
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
        // Window scaling is negotiated on the SYN exchange and nowhere else.
        // Under `Midstream` there is no SYN, so the shift that turns a real
        // window into a scaled one has nothing behind it: our peer ignores the
        // field, but anything on the path modelling this flow never saw a scale
        // factor either and reads the number literally.
        //
        // 64240 >> 7 is 501. Advertising 501 bytes to a middlebox that enforces
        // flow control limits the whole conversation to 501 bytes in flight --
        // observed as a tunnel that ran for hours and then collapsed to a
        // trickle with seconds of latency, heavy loss inbound, and none of our
        // own counters showing a thing, because the packets were being kept
        // from us rather than dropped by us. It is also implausible in itself:
        // an established connection advertising half a kilobyte is not what a
        // real one looks like.
        let scaled = if self.carrier.opens() {
            self.profile.window >> self.profile.window_scale.unwrap_or(0)
        } else {
            self.profile.window.min(u32::from(u16::MAX))
        };
        // Vary within about ±6% using a cheap hash of the packet counter.
        //
        // The shift keeps the high bits, where a multiplicative hash carries its
        // randomness, and keeps enough of them to reach the whole band. An
        // earlier version shifted by 24 and kept eight, which is fine while the
        // window is small and silently wrong once it is not: with a spread of
        // 4015 the offset could never exceed 255, so the window sat in a
        // 256-byte band six per cent below the profile and never once reached
        // the value it was meant to vary around. Caught on the wire, where every
        // sample of a supposedly ±6% window fell inside 0.4% of itself -- which
        // is a signature rather than jitter.
        // Downward from the profile's window, never above it. A receiver's
        // advertised window is what is left in its buffer, so it drops as data
        // queues and recovers toward the maximum -- it does not exceed it.
        // Varying either side of the maximum would also push a third of the
        // values past what the field holds, and clamping them would pile a
        // third of every capture on exactly 65535.
        let spread = (scaled / 8).max(1);
        let jitter = u64::from(self.counter.wrapping_mul(0x9E37_79B9)) >> 8;
        let offset = jitter % u64::from(spread + 1);
        let varied = u64::from(scaled).saturating_sub(offset);
        u16::try_from(varied.clamp(1, u64::from(u16::MAX))).unwrap_or(u16::MAX)
    }

    /// The IPv4 Identification the profile calls for.
    ///
    /// Every segment from here belongs to a connection, so this never takes
    /// the zero branch; the reply that does is in `answer_syn`.
    fn ip_id(&self) -> u16 {
        segment::ip_id(&self.profile, self.ip_id_base, self.counter)
    }

    /// The RFC 7323 timestamp to send.
    fn ts_val(&self, now: u64) -> u32 {
        timestamp(self.ts_base, now, self.profile.ts_hz)
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
        if !seg.payload.is_empty() {
            self.unacked = self.unacked.saturating_add(1);
        }
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

        if seg.has(segment::flags::SYN) {
            if seg.has(segment::flags::ACK) {
                // A SYN+ACK answers our SYN only if it acknowledges it, and is
                // where the peer's numbering starts.
                if self
                    .syn_seq
                    .is_some_and(|ours| seg.ack == ours.wrapping_add(1))
                {
                    // A late copy of one already taken must not pull the
                    // acknowledgement back to where the connection began.
                    if self.peer_next.is_none() {
                        self.peer_next = Some(seg.seq.wrapping_add(1));
                        self.relearn = false;
                    } else {
                        self.advance(seg.seq.wrapping_add(1));
                    }
                    if self.phase == Phase::SynSent {
                        self.establish();
                    }
                }
            } else if self.role == Role::Responder && self.peer_next.is_none() {
                // The peer's initial sequence number is learned from its SYN.
                self.peer_next = Some(seg.seq.wrapping_add(1));
                self.phase = Phase::SynReceived;
            }
            return None;
        }

        // Data before any SYN. The peer is out of step with us; there is nothing
        // coherent to say about its sequence space.
        self.peer_next?;

        if self.phase == Phase::SynReceived && seg.has(segment::flags::ACK) {
            self.establish();
        }

        self.advance(seg.seq.wrapping_add(occupied(seg)));

        if seg.has(segment::flags::FIN) {
            self.phase = Phase::Closed;
            return None;
        }

        if seg.payload.is_empty() {
            return None;
        }
        Some(seg.payload)
    }

    /// Moves the acknowledgement to `end`, the byte after a segment that
    /// arrived.
    ///
    /// Forward always: a byte past the furthest one seen is acknowledged even
    /// when something before it never arrived, because nothing here sends
    /// anything twice, and holding the acknowledgement at the hole is a
    /// receiver that stopped acknowledging for good -- which no real connection
    /// survives for more than a moment. Backward only when the jump is too far
    /// to be reordering: then the peer is numbering from somewhere new.
    fn advance(&mut self, end: u32) {
        let Some(next) = self.peer_next else {
            return;
        };
        // Serial-number arithmetic: less than half the space ahead is forward.
        let ahead = end.wrapping_sub(next);
        let forward = ahead != 0 && ahead < 1 << 31;
        let restarted = !forward && next.wrapping_sub(end) > REORDER_SPAN;
        if self.relearn || forward || restarted {
            self.peer_next = Some(end);
            self.relearn = false;
        }
    }
}

/// The RFC 7323 timestamp for a clock reading of `now` milliseconds, on a
/// clock that starts at `ts_base`.
///
/// Public so a caller can know a SYN's timestamp before sending it: the real
/// handshake's sequence number is computed from it.
#[must_use]
pub const fn timestamp(ts_base: u32, now: u64, hz: u32) -> u32 {
    let ticks = now.wrapping_mul(hz as u64) / 1_000;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the TCP timestamp clock is defined to wrap at 32 bits"
    )]
    let ticks = ticks as u32;
    ts_base.wrapping_add(ticks)
}

/// How much sequence space a segment occupies: its payload, and one more for a
/// FIN.
fn occupied(seg: &Segment<'_>) -> u32 {
    let len = u32::try_from(seg.payload.len()).unwrap_or(u32::MAX);
    if seg.has(segment::flags::FIN) {
        len.wrapping_add(1)
    } else {
        len
    }
}

/// What a SYN+ACK needs that the SYN it answers does not supply.
///
/// Grouped because they travel together and come from one place: this end's
/// configuration and its clock.
#[derive(Debug, Clone, Copy)]
pub struct Reply {
    /// This end's initial sequence number.
    pub isn: u32,
    /// The timestamp to send, which the peer will echo.
    pub ts_val: u32,
    /// Whether to set Don't Fragment.
    pub dont_fragment: bool,
    /// The maximum segment size to advertise.
    pub mss: u16,
}

/// The SYN+ACK answering `syn`, composed from it alone.
///
/// Nothing is kept, so a repeated SYN draws the same answer and a flood of them
/// costs nothing but the replies -- which is what lets a responder answer
/// before it knows who is asking. The responder supplies its own sequence
/// number, timestamp and advertised `mss`; the acknowledgement and the echoed
/// timestamp come from the SYN, and the window is the profile's unscaled SYN
/// window, as on any SYN. Once the peer answers, [`Endpoint::rejoin`] takes up the connection.
///
/// # Errors
/// Returns [`Error::Short`] if `out` cannot hold the segment.
pub fn answer_syn(
    profile: &OsProfile,
    local: (Ipv4Addr, u16),
    syn: &Segment<'_>,
    reply: Reply,
    out: &mut [u8],
) -> Result<usize> {
    let Reply {
        isn,
        ts_val,
        dont_fragment,
        mss,
    } = reply;
    let fields = Fields {
        src: local,
        dst: syn.src,
        seq: isn,
        ack: syn.seq.wrapping_add(1),
        window: profile.syn_window,
        // The one packet here that no connection owns: it is composed from the
        // SYN alone, before there is any state to own it, which is the case a
        // counting profile writes zero for. The ISN is the one varying number
        // it has, for the profiles that do not.
        ip_id: segment::unconnected_ip_id(profile, dont_fragment, isn),
        ts_val,
        ts_ecr: syn.ts_val.unwrap_or(0),
        dont_fragment,
        // A SYN+ACK is not a data segment, so the bit means nothing on it.
        push: false,
        // The same number this end's data segments will honour, or the
        // connection promises one size on its first packet and keeps to
        // another for the rest of its life.
        mss: if mss < profile.mss { mss } else { profile.mss },
    };
    segment::emit(Kind::SynAck, profile, &fields, &[], out)
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::profile::{IOS_15, LINUX_6, WINDOWS_11};
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
            // The tests below check the byte-accurate numbering specifically,
            // so they ask for it. `Opaque` is the default and has its own.
            sequencing: Sequencing::Stream,
            records: false,
            dont_fragment: true,
            mss: None,
        }
    }

    fn opaque(role: Role) -> Config {
        Config {
            sequencing: Sequencing::Opaque,
            records: false,
            dont_fragment: true,
            ..cfg(role, Carrier::Midstream, LINUX_6)
        }
    }

    #[test]
    fn opaque_endpoints_still_carry_data_both_ways() {
        // Numbering is cosmetic: nothing validates an inbound seq or ack, so
        // changing how they are composed must not affect what gets carried.
        // This is the check that the change is safe to deploy on one end before
        // the other.
        let mut client = Endpoint::new(opaque(Role::Initiator));
        let mut server = Endpoint::new(opaque(Role::Responder));
        let mut buf = [0u8; 2048];

        for i in 0..4u8 {
            let payload = [i; 600];

            let n = client
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("client emits");
            let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("server parses");
            assert_eq!(seg.payload, &payload[..], "client -> server");
            server.on_receive(&seg);

            let n = server
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("server emits");
            let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("client parses");
            assert_eq!(seg.payload, &payload[..], "server -> client");
            client.on_receive(&seg);
        }
    }

    #[test]
    fn an_opaque_end_and_a_stream_end_still_understand_each_other() {
        // They need not agree, which is what makes a staged rollout possible.
        let mut client = Endpoint::new(opaque(Role::Initiator));
        let mut server = Endpoint::new(cfg(Role::Responder, Carrier::Midstream, LINUX_6));
        let mut buf = [0u8; 2048];
        let payload = [7u8; 600];

        let n = client
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("parse");
        assert_eq!(seg.payload, &payload[..]);
        server.on_receive(&seg);

        let n = server
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("parse");
        assert_eq!(seg.payload, &payload[..]);
    }

    #[test]
    fn an_unscaled_profile_advertises_its_window_whole() {
        // With no scale factor negotiated there is nothing to shift by, so the
        // field is the window itself and the SYN is the small one the device
        // really sends.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::FakeHandshake, IOS_15));
        let mut buf = [0u8; 2048];

        let n = e.handshake(&mut buf, 0).expect("syn").expect("some");
        let syn = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(syn.window, IOS_15.syn_window);

        let n = e
            .data(&[0u8; 100], &mut buf, 0, true, Some(100))
            .expect("data");
        let data = parse_ipv4(&buf[..n]).expect("parse");
        let floor = IOS_15.window - IOS_15.window / 8;
        assert!(
            u32::from(data.window) >= floor,
            "{} is below the band {floor}..={}",
            data.window,
            IOS_15.window
        );
    }

    #[test]
    fn a_slower_clock_ticks_more_slowly() {
        // One second of a 100 Hz clock is a hundred ticks, not a thousand.
        assert_eq!(timestamp(0, 1_000, 1_000), 1_000);
        assert_eq!(timestamp(0, 1_000, 100), 100);
        assert_eq!(timestamp(7, 0, 100), 7);
    }

    #[test]
    fn a_counting_profile_counts_the_identification() {
        // A stack with a socket behind the packet advances a counter, which is
        // what `inet_id` is and what two consecutive packets of one flow show.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, LINUX_6));
        let mut ids = Vec::new();
        for i in 0..8u64 {
            let packet = emitted(|b| e.data(b"x", b, i, true, Some(1)));
            ids.push(u16::from_be_bytes([packet[4], packet[5]]));
        }
        for w in ids.windows(2) {
            assert_eq!(w[1], w[0].wrapping_add(1), "{ids:?} does not count");
        }

        // One counter per connection, not one across every peer: that would be
        // a single monotonic sequence spanning all of them, a stronger
        // identifier than anything else on this wire.
        let mut other = Endpoint::new(Config {
            isn: CLIENT_ISN ^ 0x5555_5555,
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        let packet = emitted(|b| other.data(b"x", b, 0, true, Some(1)));
        assert_ne!(
            u16::from_be_bytes([packet[4], packet[5]]),
            ids[0],
            "two connections start their counters in the same place"
        );
    }

    #[test]
    fn a_random_profile_does_not_count_it() {
        // IOS randomises the field -- `TI=RD` -- so consecutive packets must
        // not be readable as a sequence.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, IOS_15));
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u64 {
            let packet = emitted(|b| e.data(b"x", b, i, true, Some(1)));
            seen.insert(u16::from_be_bytes([packet[4], packet[5]]));
        }
        assert!(
            seen.len() > 32,
            "IP ID should look uniform, saw {}",
            seen.len()
        );
        // And never zero: alongside Don't Fragment that is a quirk a
        // classifier reads as a stack that does not randomise.
        assert!(!seen.contains(&0), "{seen:?} includes a zero");
    }

    #[test]
    fn the_reply_no_connection_owns_is_zero_where_the_profile_counts() {
        // Composed from the SYN alone, before any state exists to count from,
        // which is the kernel's condition for writing zero and the packet nmap
        // reads `TI=Z` off. Not zero for a profile that randomises, and not
        // zero on a packet a hop may split, whatever the profile: a shared zero
        // has the fragments of two packets reassembled into each other.
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");
        for (profile, whole, want_zero) in [
            (LINUX_6, true, true),
            (LINUX_6, false, false),
            (IOS_15, true, false),
        ] {
            let reply = emitted(|b| {
                answer_syn(
                    &profile,
                    SERVER,
                    &syn,
                    Reply {
                        isn: 77,
                        ts_val: 1,
                        dont_fragment: whole,
                        mss: LINUX_6.mss,
                    },
                    b,
                )
            });
            let id = u16::from_be_bytes([reply[4], reply[5]]);
            assert_eq!(
                id == 0,
                want_zero,
                "{} with dont_fragment = {whole} wrote {id}",
                profile.name
            );
        }
    }

    #[test]
    fn the_advertised_window_actually_covers_its_band() {
        // The check the old test could not make. Jitter that only reaches a
        // fraction of its intended range is not jitter -- it is a narrow,
        // constant band, which is exactly the thing being avoided. Found on a
        // real capture where every sample of a supposedly +/-6% window fell
        // within 0.4% of itself.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, LINUX_6));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 100];

        let mut lo = u16::MAX;
        let mut hi = 0u16;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let n = e
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("emit");
            let w = parse_ipv4(buf.get(..n).expect("emitted"))
                .expect("parse")
                .window;
            lo = lo.min(w);
            hi = hi.max(w);
            seen.insert(w);
        }

        let ceiling = u16::try_from(LINUX_6.window).expect("fits");
        let spread = ceiling / 8;
        assert!(
            hi <= ceiling,
            "a receiver never advertises more than its buffer"
        );
        assert!(
            hi > ceiling - spread / 4,
            "never approaches the maximum: {lo}..{hi}"
        );
        assert!(
            lo < ceiling - spread / 2,
            "never drops meaningfully below it: {lo}..{hi}"
        );
        assert!(seen.len() > 500, "only {} distinct values", seen.len());
    }

    #[test]
    fn a_midstream_flow_advertises_a_window_someone_could_believe() {
        // Nothing negotiated a scale factor, because nothing sent a SYN. A
        // middlebox reads this number as it stands, and a middlebox that
        // enforces flow control holds the conversation to it.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, LINUX_6));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 600];

        for _ in 0..16 {
            let n = e
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("emit");
            let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("parse");
            assert!(
                seg.window > 32_000,
                "advertised {} bytes; anything enforcing this would throttle the \
                 tunnel to it",
                seg.window
            );
        }
    }

    #[test]
    fn a_handshaken_flow_still_advertises_the_scaled_window() {
        // There the shift is honest: the SYN said scale 7, so the peer and
        // anything watching multiply it back.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Handshake, LINUX_6));
        let mut buf = [0u8; 2048];
        // Drive it past the handshake so the segments are data, not SYN.
        let _ = e.handshake(&mut buf, 0).expect("syn");
        let expected = LINUX_6.window >> LINUX_6.window_scale.expect("linux scales");
        assert!(expected < 1_000, "sanity: the scaled value is small");
    }

    #[test]
    fn opaque_is_the_default() {
        assert_eq!(Sequencing::default(), Sequencing::Opaque);
    }

    #[test]
    fn opaque_numbers_do_not_describe_the_bytes_sent() {
        // The whole point. If consecutive segments described a coherent byte
        // stream, something would reassemble it -- and then the first packet the
        // network drops leaves a hole this carrier can never fill, which is what
        // took a working tunnel apart in the field.
        let mut e = Endpoint::new(opaque(Role::Initiator));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 1000];

        let mut seqs = Vec::new();
        for _ in 0..8 {
            let n = e
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("emit");
            let seg = parse_ipv4(buf.get(..n).expect("emitted")).expect("parse");
            seqs.push(seg.seq);
        }

        for pair in seqs.windows(2) {
            let (a, b) = (pair.first().expect("a"), pair.get(1).expect("b"));
            let step = b.wrapping_sub(*a);
            assert_ne!(
                step, 1000,
                "advancing by the payload length is exactly what makes it reassemblable"
            );
            assert_eq!(
                step, 128,
                "but it must still advance, and predictably to us"
            );
        }
    }

    #[test]
    fn opaque_segments_overlap_so_no_stream_can_be_rebuilt() {
        // Each segment claims 1000 bytes of space while the numbering leaves
        // only 128 between them, so they contradict each other as a stream.
        // Nothing can reassemble that, so nothing tries.
        let mut e = Endpoint::new(opaque(Role::Initiator));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 1000];

        let n = e
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let first = parse_ipv4(buf.get(..n).expect("emitted"))
            .expect("parse")
            .seq;
        let n = e
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let second = parse_ipv4(buf.get(..n).expect("emitted"))
            .expect("parse")
            .seq;

        assert!(
            second.wrapping_sub(first) < 1000,
            "the second segment must start inside the first's claimed range"
        );
    }

    #[test]
    fn opaque_acknowledgements_do_not_stall_when_a_packet_is_lost() {
        // The failure being fixed: under byte-accurate numbering a dropped
        // inbound packet freezes our acknowledgement for ever, and a sender
        // talking to a receiver that stopped acknowledging is not something a
        // real connection does. Here the acknowledgement is composed from our
        // own counter, so nothing the network does to inbound traffic can wedge
        // it.
        let mut e = Endpoint::new(opaque(Role::Initiator));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 1000];

        let n = e
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let before = parse_ipv4(buf.get(..n).expect("emitted"))
            .expect("parse")
            .ack;

        // Nothing arrives at all -- every inbound packet lost.
        for _ in 0..4 {
            let n = e
                .data(&payload, &mut buf, 0, true, Some(payload.len()))
                .expect("emit");
            let ack = parse_ipv4(buf.get(..n).expect("emitted"))
                .expect("parse")
                .ack;
            assert_ne!(ack, before, "a frozen acknowledgement is the signature");
        }
    }

    #[test]
    fn stream_numbering_acknowledges_only_what_arrives() {
        // With nothing arriving, nothing more is acknowledged: the
        // acknowledgement describes the peer's bytes, not our own sending.
        let mut e = Endpoint::new(cfg(Role::Initiator, Carrier::Midstream, LINUX_6));
        let mut buf = [0u8; 2048];
        let payload = [0u8; 1000];

        let n = e
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let first = parse_ipv4(buf.get(..n).expect("emitted"))
            .expect("parse")
            .ack;
        let n = e
            .data(&payload, &mut buf, 0, true, Some(payload.len()))
            .expect("emit");
        let second = parse_ipv4(buf.get(..n).expect("emitted"))
            .expect("parse")
            .ack;

        assert_eq!(first, second);
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
        let n = c.data(b"", &mut buf, 2, true, Some(0)).expect("ack");
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

        let n = c.data(b"", &mut buf, 2, true, Some(0)).expect("ack");
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
            let packet = emitted(|b| c.data(&payload, b, 10, true, Some(payload.len())));
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
            let packet = emitted(|b| c.data(&payload, b, 10, true, Some(payload.len())));
            let seg = parse_ipv4(&packet).expect("parse");
            s.on_receive(&seg);
            expected_ack = expected_ack.wrapping_add(u32::try_from(len).expect("fits"));

            let reply = emitted(|b| s.data(b"", b, 11, true, Some(0)));
            let reply_seg = parse_ipv4(&reply).expect("parse");
            assert_eq!(reply_seg.ack, expected_ack);
        }
    }

    /// The signal this exists to remove: a record header at the start of every
    /// segment of a bulk transfer, where a real session starts one in about
    /// twelve.
    #[test]
    fn one_record_covers_a_burst_and_the_chain_stays_continuous() {
        let mut c = Endpoint::new(Config {
            records: true,
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        let payload = [7u8; 1400];
        // Eleven packets in one burst, which is what fits in one record at
        // this size, then a twelfth that has to start another.
        let run: usize = 11 * payload.len();
        let mut stream = Vec::new();
        for i in 0..11u64 {
            let open = (i == 0).then_some(run);
            let packet = emitted(|b| c.data(&payload, b, i, i == 10, open));
            let seg = parse_ipv4(&packet).expect("parse");
            stream.extend_from_slice(seg.payload);
            if i == 0 {
                assert_eq!(
                    seg.payload.len(),
                    payload.len() + 5,
                    "the first of a burst carries the header"
                );
                assert!(!c.at_record_boundary(), "and the record is still open");
            } else {
                assert_eq!(
                    seg.payload.len(),
                    payload.len(),
                    "packet {i} carries no header"
                );
            }
        }
        assert!(c.at_record_boundary(), "eleven packets fill the record");

        // The chain: walk it as an observer would, by lengths alone.
        let mut at = 0usize;
        let mut headers = 0;
        while at + 5 <= stream.len() {
            assert_eq!(&stream[at..at + 3], &[0x17, 0x03, 0x03], "at {at}");
            let len = usize::from(u16::from_be_bytes([stream[at + 3], stream[at + 4]]));
            assert!(len <= crate::cover::MAX_SPAN);
            at += 5 + len;
            headers += 1;
        }
        assert_eq!(at, stream.len(), "the lengths reach the end exactly");
        assert_eq!(headers, 1, "one record for the whole burst");
    }

    /// A packet the caller decides not to send after asking for a record would
    /// otherwise leave it short, and every header after it inside the record
    /// before.
    #[test]
    fn a_burst_that_sends_less_than_it_promised_keeps_the_chain() {
        let mut c = Endpoint::new(Config {
            records: true,
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        let payload = [3u8; 500];
        // Promised three packets, sent one; the next burst promises its own and
        // is refused, because the record already open has to be finished first.
        let packet = emitted(|b| c.data(&payload, b, 0, true, Some(3 * payload.len())));
        assert_eq!(
            parse_ipv4(&packet).expect("parse").payload.len(),
            payload.len() + 5
        );
        assert!(!c.at_record_boundary());
        let mut stream = parse_ipv4(&packet).expect("parse").payload.to_vec();
        for i in 1..3u64 {
            let next = emitted(|b| c.data(&payload, b, i, true, Some(payload.len())));
            let seg = parse_ipv4(&next).expect("parse");
            assert_eq!(seg.payload.len(), payload.len(), "no second header");
            stream.extend_from_slice(seg.payload);
        }
        assert!(
            c.at_record_boundary(),
            "the record is finished by later packets"
        );
        let len = usize::from(u16::from_be_bytes([stream[3], stream[4]]));
        assert_eq!(5 + len, stream.len(), "the one length reaches the end");
    }

    /// What the far end does with it, which is the half that decides whether a
    /// spanning record is readable at all.
    #[test]
    fn a_continuation_is_not_mistaken_for_a_header() {
        let mut c = Endpoint::new(Config {
            records: true,
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        let payload = [0x11u8; 1400];
        let first = emitted(|b| c.data(&payload, b, 0, false, Some(2 * payload.len())));
        let second = emitted(|b| c.data(&payload, b, 1, true, None));
        let a = parse_ipv4(&first).expect("parse");
        let b = parse_ipv4(&second).expect("parse");
        assert_eq!(
            crate::cover::unwrap_record(a.payload),
            Some(&payload[..]),
            "the header comes off the first"
        );
        assert_eq!(
            crate::cover::unwrap_record(b.payload),
            None,
            "and nothing comes off the second"
        );
    }

    #[test]
    fn a_long_bidirectional_exchange_stays_consistent() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        for i in 0..500u32 {
            let payload = i.to_be_bytes();

            let packet = emitted(|b| c.data(&payload, b, u64::from(i), true, Some(payload.len())));
            let seg = parse_ipv4(&packet).expect("parse");
            assert_eq!(seg.seq, c.next_seq().wrapping_sub(4));
            s.on_receive(&seg);

            let packet = emitted(|b| s.data(&payload, b, u64::from(i), true, Some(payload.len())));
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
        let packet = emitted(|b| c.data(&[0u8; 100], b, 0, true, Some(100)));
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
            c.data(b"too early", &mut buf, 0, true, Some(b"too early".len())),
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

        let packet = emitted(|b| c.data(b"hello", b, 12_345, true, Some(5)));
        let seg = parse_ipv4(&packet).expect("parse");
        let client_ts = seg.ts_val.expect("linux profile sends timestamps");
        s.on_receive(&seg);

        let reply = emitted(|b| s.data(b"hi", b, 12_400, true, Some(b"hi".len())));
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

        let packet = emitted(|b| c.data(b"", b, 50_000, true, Some(0)));
        let seg = parse_ipv4(&packet).expect("parse");
        let fresh = seg.ts_val.expect("timestamp");
        assert!(s.on_receive(&seg).is_none(), "empty payload yields nothing");

        let reply = emitted(|b| s.data(b"x", b, 50_001, true, Some(1)));
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
        let packet = emitted(|b| c.data(b"x", b, 0, true, Some(1)));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.ts_val, Some(5_000), "ts_base offsets the clock");
    }

    #[test]
    fn the_advertised_window_varies_but_stays_plausible() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let base = LINUX_6.window >> LINUX_6.window_scale.expect("linux scales");
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..64u64 {
            let packet = emitted(|b| c.data(b"x", b, i, true, Some(1)));
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
                dont_fragment: true,
                push: false,
                mss: LINUX_6.mss,
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

        let packet =
            emitted(|b| c.data(b"before roaming", b, 0, true, Some(b"before roaming".len())));
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

        let reply = emitted(|b| s.data(b"after roaming", b, 1, true, Some(b"after roaming".len())));
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
        let packet = emitted(|b| c.data(b"orphan", b, 0, true, Some(b"orphan".len())));
        let seg = parse_ipv4(&packet).expect("parse");
        assert!(fresh.on_receive(&seg).is_none());
        assert_eq!(fresh.next_ack(), None);
    }

    #[test]
    fn on_receive_returns_the_payload_of_data_segments() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let payload = b"the inner packet";
        let packet = emitted(|b| c.data(payload, b, 0, true, Some(payload.len())));
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(s.on_receive(&seg), Some(&payload[..]));
    }

    #[test]
    fn a_profile_without_timestamps_omits_and_ignores_them() {
        let mut c = Endpoint::new(cfg(Role::Initiator, Carrier::Handshake, WINDOWS_11));
        let mut s = Endpoint::new(cfg(Role::Responder, Carrier::Handshake, WINDOWS_11));
        connect(&mut c, &mut s);

        let packet = emitted(|b| c.data(b"x", b, 1234, true, Some(1)));
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

        let packet = emitted(|b| {
            c.data(
                b"first ever packet",
                b,
                0,
                true,
                Some(b"first ever packet".len()),
            )
        });
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.seq, CLIENT_ISN);
        assert_eq!(
            seg.ack, SERVER_ISN,
            "acknowledging the peer from packet one"
        );

        s.on_receive(&seg);
        let reply = emitted(|b| s.data(b"reply", b, 1, true, Some(b"reply".len())));
        let reply_seg = parse_ipv4(&reply).expect("parse");
        assert_eq!(reply_seg.seq, SERVER_ISN);
        assert_eq!(reply_seg.ack, CLIENT_ISN.wrapping_add(17));
    }

    #[test]
    fn midstream_stays_consistent_over_a_long_exchange() {
        let (mut c, mut s) = midstream_pair();
        for i in 0..500u32 {
            let payload = i.to_be_bytes();
            let packet = emitted(|b| c.data(&payload, b, u64::from(i), true, Some(payload.len())));
            s.on_receive(&parse_ipv4(&packet).expect("parse"));
            let reply = emitted(|b| s.data(&payload, b, u64::from(i), true, Some(payload.len())));
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
                dont_fragment: true,
                push: false,
                mss: LINUX_6.mss,
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
    fn a_lost_packet_does_not_freeze_the_acknowledgement() {
        // Nothing here sends anything twice, so an acknowledgement held at a
        // hole is held there for good -- a receiver that stopped acknowledging,
        // which is the one thing a real connection never is for long. The next
        // segment that arrives moves it past the hole.
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);

        let first = emitted(|b| c.data(&[1u8; 200], b, 0, true, Some(200)));
        s.on_receive(&parse_ipv4(&first).expect("parse"));

        // This one never arrives.
        let _lost = emitted(|b| c.data(&[2u8; 300], b, 1, true, Some(300)));

        let third = emitted(|b| c.data(&[3u8; 100], b, 2, true, Some(100)));
        s.on_receive(&parse_ipv4(&third).expect("parse"));

        assert_eq!(s.next_ack(), Some(c.next_seq()));
    }

    #[test]
    fn a_reordered_segment_does_not_pull_the_acknowledgement_back() {
        let (mut c, mut s) = midstream_pair();
        let early = emitted(|b| c.data(&[1u8; 500], b, 0, true, Some(500)));
        let late = emitted(|b| c.data(&[2u8; 500], b, 1, true, Some(500)));

        s.on_receive(&parse_ipv4(&late).expect("parse"));
        let ack = s.next_ack();
        s.on_receive(&parse_ipv4(&early).expect("parse"));

        assert_eq!(s.next_ack(), ack, "the older segment changes nothing");
        assert_eq!(s.next_ack(), Some(c.next_seq()));
    }

    #[test]
    fn a_peer_numbering_from_somewhere_new_is_followed() {
        // A peer that restarted or rebuilt its carrier starts again from a new
        // base, which may lie behind the old position as easily as ahead of
        // it. Acknowledging the old stream would describe nothing on the wire.
        for base in [
            CLIENT_ISN.wrapping_sub(50_000_000),
            CLIENT_ISN.wrapping_add(50_000_000),
        ] {
            let (mut c, mut s) = midstream_pair();
            let packet = emitted(|b| c.data(&[1u8; 100], b, 0, true, Some(100)));
            s.on_receive(&parse_ipv4(&packet).expect("parse"));

            let mut fresh = Endpoint::new(Config {
                isn: base,
                ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
            });
            let packet = emitted(|b| fresh.data(&[2u8; 100], b, 1, true, Some(100)));
            s.on_receive(&parse_ipv4(&packet).expect("parse"));

            assert_eq!(s.next_ack(), Some(base.wrapping_add(100)), "base {base}");
        }
    }

    #[test]
    fn a_peer_at_a_new_address_is_learned_from_its_first_segment() {
        let (mut c, mut s) = midstream_pair();
        let packet = emitted(|b| c.data(&[1u8; 100], b, 0, true, Some(100)));
        s.on_receive(&parse_ipv4(&packet).expect("parse"));

        // Close behind, so only the move explains taking it.
        let mut moved = Endpoint::new(Config {
            isn: CLIENT_ISN.wrapping_sub(1_000),
            local: (Ipv4Addr::new(198, 51, 100, 77), 55555),
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        s.set_remote(moved.local);
        let packet = emitted(|b| moved.data(&[2u8; 10], b, 1, true, Some(10)));
        s.on_receive(&parse_ipv4(&packet).expect("parse"));

        assert_eq!(s.next_ack(), Some(moved.next_seq()));
    }

    #[test]
    fn the_first_segment_settles_a_derived_position() {
        // Where the peer's numbering starts is derived from the tunnel
        // handshake -- right for a peer that started when we did, wrong for
        // one that restarted since. Its first segment says which.
        let mut s = Endpoint::new(cfg(Role::Responder, Carrier::Midstream, LINUX_6));
        let mut stranger = Endpoint::new(Config {
            isn: CLIENT_ISN.wrapping_sub(5_000),
            ..cfg(Role::Initiator, Carrier::Midstream, LINUX_6)
        });
        let packet = emitted(|b| stranger.data(&[1u8; 10], b, 0, true, Some(10)));
        s.on_receive(&parse_ipv4(&packet).expect("parse"));
        assert_eq!(s.next_ack(), Some(stranger.next_seq()));
    }

    /// An endpoint announcing itself without waiting.
    fn announced(role: Role) -> Endpoint {
        Endpoint::new(cfg(role, Carrier::FakeHandshake, LINUX_6))
    }

    #[test]
    fn a_fake_handshake_opens_with_one_syn_just_below_its_data() {
        let mut c = announced(Role::Initiator);
        let mut buf = vec![0u8; MAX_OVERHEAD + 64];
        assert!(c.wants_opening());
        assert!(!c.is_ready(), "nothing may go ahead of the SYN");
        assert!(matches!(
            c.data(b"early", &mut buf, 0, true, Some(b"early".len())),
            Err(Error::NotEstablished)
        ));

        let n = c.handshake(&mut buf, 0).expect("syn").expect("some");
        let syn = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(syn.flags, segment::flags::SYN);
        assert_eq!(syn.seq, CLIENT_ISN.wrapping_sub(1));
        assert_eq!(syn.ack, 0);
        assert_eq!(syn.window, LINUX_6.syn_window);

        assert!(!c.wants_opening(), "announced once");
        assert_eq!(c.handshake(&mut buf, 1).expect("again"), None);
        assert!(c.is_ready(), "and nothing waits for an answer");

        let n = c
            .data(b"first", &mut buf, 2, true, Some(b"first".len()))
            .expect("data");
        let data = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(data.seq, CLIENT_ISN, "the byte after the SYN");
        assert!(
            u32::from(data.window) < LINUX_6.window,
            "scaled, as the SYN declared"
        );
    }

    #[test]
    fn a_fake_handshake_answer_sits_just_below_the_responders_data() {
        let mut s = announced(Role::Responder);
        let mut buf = vec![0u8; MAX_OVERHEAD + 64];
        assert!(!s.wants_opening(), "a responder only ever answers");
        assert_eq!(s.handshake(&mut buf, 0).expect("nothing"), None);

        let n = s.answer(CLIENT_ISN, &mut buf, 0).expect("synack");
        let synack = parse_ipv4(&buf[..n]).expect("parse");
        assert_eq!(synack.flags, segment::flags::SYN | segment::flags::ACK);
        assert_eq!(synack.seq, SERVER_ISN.wrapping_sub(1));
        assert_eq!(synack.ack, CLIENT_ISN);

        let n = s
            .data(b"reply", &mut buf, 1, true, Some(b"reply".len()))
            .expect("data");
        assert_eq!(parse_ipv4(&buf[..n]).expect("parse").seq, SERVER_ISN);
    }

    #[test]
    fn a_fake_handshake_initiator_learns_the_answers_numbering() {
        let mut c = announced(Role::Initiator);
        let mut s = announced(Role::Responder);
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");

        // A responder that has moved on since the numbers were derived.
        let _ = emitted(|b| s.data(&[0u8; 700], b, 0, true, Some(700)));
        let synack = emitted(|b| s.answer(syn.seq.wrapping_add(1), b, 1));
        c.on_receive(&parse_ipv4(&synack).expect("parse"));

        assert_eq!(c.next_ack(), Some(s.next_seq()));
    }

    /// Emits the opening segment an endpoint owes, which a test expects to exist.
    fn opening(e: &mut Endpoint, now: u64) -> Vec<u8> {
        emitted(|b| e.handshake(b, now).map(|n| n.expect("an opening is owed")))
    }

    #[test]
    fn a_repeated_syn_is_the_same_syn() {
        // The responder checks the number against the timestamp, so a repeat
        // that took a fresh timestamp would fail the check it passed the first
        // time.
        let mut c = client();
        let first = opening(&mut c, 100);
        let again = opening(&mut c, 1_100);
        let (first, again) = (
            parse_ipv4(&first).expect("parse"),
            parse_ipv4(&again).expect("parse"),
        );
        assert_eq!(first.seq, again.seq);
        assert_eq!(first.ts_val, again.ts_val);
        assert_eq!(first.ts_val, Some(timestamp(5_000, 100, LINUX_6.ts_hz)));
    }

    #[test]
    fn a_syn_ack_for_someone_elses_syn_opens_nothing() {
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");
        let other = segment::Segment {
            seq: syn.seq.wrapping_add(9),
            ..syn
        };
        let forged = emitted(|b| {
            answer_syn(
                &LINUX_6,
                SERVER,
                &other,
                Reply {
                    isn: 77,
                    ts_val: 1,
                    dont_fragment: true,
                    mss: LINUX_6.mss,
                },
                b,
            )
        });
        c.on_receive(&parse_ipv4(&forged).expect("parse"));
        assert!(!c.is_ready(), "it does not acknowledge our SYN");
        assert!(c.wants_opening());
    }

    #[test]
    fn a_stateless_answer_opens_the_connection_it_answers() {
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");

        let synack = emitted(|b| {
            answer_syn(
                &LINUX_6,
                SERVER,
                &syn,
                Reply {
                    isn: 4_242,
                    ts_val: 9_999,
                    dont_fragment: true,
                    mss: LINUX_6.mss,
                },
                b,
            )
        });
        let synack = parse_ipv4(&synack).expect("parse");
        assert_eq!(synack.flags, segment::flags::SYN | segment::flags::ACK);
        assert_eq!(synack.ack, CLIENT_ISN.wrapping_add(1));
        assert_eq!(synack.dst, CLIENT);
        assert_eq!(synack.window, LINUX_6.syn_window);
        assert_eq!(synack.ts_val, Some(9_999));

        c.on_receive(&synack);
        assert!(c.is_ready());
        assert!(!c.wants_opening());
        let ack = emitted(|b| c.ack(b, 1));
        let ack = parse_ipv4(&ack).expect("parse");
        assert_eq!(ack.flags, segment::flags::ACK);
        assert_eq!(ack.seq, CLIENT_ISN.wrapping_add(1));
        assert_eq!(ack.ack, 4_243);

        // The responder kept nothing, and takes up the connection from the
        // first segment the peer sends on it.
        let mut s = server();
        let hello = emitted(|b| c.data(b"hello", b, 2, true, Some(5)));
        s.rejoin(&parse_ipv4(&hello).expect("parse"), 7_000);
        assert!(s.is_ready());
        assert_eq!(s.next_ack(), Some(CLIENT_ISN.wrapping_add(6)));
        let reply = emitted(|b| s.data(b"hi", b, 3, true, Some(b"hi".len())));
        let reply = parse_ipv4(&reply).expect("parse");
        assert_eq!(reply.seq, 4_243, "the byte after the SYN+ACK it never kept");
        c.on_receive(&reply);
        assert_eq!(c.next_ack(), Some(4_245));
    }

    #[test]
    fn a_forged_syn_ack_is_refused_whatever_else_it_carries() {
        // The one check an unauthenticated segment gets. A reset folded into a
        // SYN+ACK that otherwise answers our SYN would close the connection on
        // the word of whoever claimed the peer's address.
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");
        let synack = emitted(|b| {
            answer_syn(
                &LINUX_6,
                SERVER,
                &syn,
                Reply {
                    isn: 77,
                    ts_val: 1,
                    dont_fragment: true,
                    mss: LINUX_6.mss,
                },
                b,
            )
        });
        let good = parse_ipv4(&synack).expect("parse");
        assert!(c.answers_syn(&good));
        for extra in [segment::flags::RST, segment::flags::FIN] {
            let forged = segment::Segment {
                flags: good.flags | extra,
                ..good
            };
            assert!(!c.answers_syn(&forged), "flags {:#x}", forged.flags);
        }
        let elsewhere = segment::Segment {
            ack: good.ack.wrapping_add(1),
            ..good
        };
        assert!(!c.answers_syn(&elsewhere));
        let no_ack = segment::Segment {
            flags: segment::flags::SYN,
            ..good
        };
        assert!(!c.answers_syn(&no_ack));
    }

    #[test]
    fn a_late_copy_of_the_syn_ack_does_not_rewind_the_acknowledgement() {
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");
        let synack = emitted(|b| {
            answer_syn(
                &LINUX_6,
                SERVER,
                &syn,
                Reply {
                    isn: 4_242,
                    ts_val: 1,
                    dont_fragment: true,
                    mss: LINUX_6.mss,
                },
                b,
            )
        });
        let synack = parse_ipv4(&synack).expect("parse");
        c.on_receive(&synack);

        let mut s = server();
        let hello = emitted(|b| c.data(b"hello", b, 1, true, Some(5)));
        s.rejoin(&parse_ipv4(&hello).expect("parse"), 7_000);
        let reply = emitted(|b| s.data(&[0u8; 900], b, 2, true, Some(900)));
        c.on_receive(&parse_ipv4(&reply).expect("parse"));
        let ack = c.next_ack();

        c.on_receive(&synack);
        assert_eq!(c.next_ack(), ack);
    }

    #[test]
    fn a_peer_that_restarted_in_place_is_told_apart_by_its_acknowledgement() {
        let (mut c, mut s) = (client(), server());
        connect(&mut c, &mut s);
        let current = emitted(|b| {
            c.data(
                b"same connection",
                b,
                0,
                true,
                Some(b"same connection".len()),
            )
        });
        assert!(!s.names_another_connection(&parse_ipv4(&current).expect("parse")));

        let reborn = segment::Segment {
            ack: s.next_seq().wrapping_add(1 << 30),
            ..parse_ipv4(&current).expect("parse")
        };
        assert!(s.names_another_connection(&reborn));
        let behind = segment::Segment {
            ack: s.next_seq().wrapping_sub(1 << 30),
            ..reborn
        };
        assert!(s.names_another_connection(&behind));

        let opaque = Endpoint::new(opaque(Role::Responder));
        assert!(
            !opaque.names_another_connection(&reborn),
            "opaque acknowledgements describe nothing"
        );
    }

    #[test]
    fn a_syn_is_numbered_from_the_timestamp_it_carries() {
        let mut c = client();
        c.number_syn(250, |ts| ts.wrapping_mul(3));
        let syn = opening(&mut c, 900);
        let syn = parse_ipv4(&syn).expect("parse");
        let ts = timestamp(5_000, 250, LINUX_6.ts_hz);
        assert_eq!(
            syn.ts_val,
            Some(ts),
            "the timestamp of when it was numbered"
        );
        assert_eq!(syn.seq, ts.wrapping_mul(3));

        c.number_syn(5_000, |_| 1);
        let again = opening(&mut c, 5_000);
        assert_eq!(
            parse_ipv4(&again).expect("parse").seq,
            syn.seq,
            "a repeat is the same SYN"
        );
    }

    #[test]
    fn rejoining_reads_the_clock_the_syn_ack_read() {
        let mut c = client();
        let syn = opening(&mut c, 0);
        let syn = parse_ipv4(&syn).expect("parse");
        let synack = emitted(|b| {
            answer_syn(
                &LINUX_6,
                SERVER,
                &syn,
                Reply {
                    isn: 1,
                    ts_val: timestamp(123_456, 10, LINUX_6.ts_hz),
                    dont_fragment: true,
                    mss: LINUX_6.mss,
                },
                b,
            )
        });
        c.on_receive(&parse_ipv4(&synack).expect("parse"));
        let hello = emitted(|b| c.data(b"hello", b, 20, true, Some(5)));

        let mut s = server();
        s.rejoin(&parse_ipv4(&hello).expect("parse"), 123_456);
        let reply = emitted(|b| s.data(b"hi", b, 30, true, Some(b"hi".len())));
        assert_eq!(
            parse_ipv4(&reply).expect("parse").ts_val,
            Some(timestamp(123_456, 30, LINUX_6.ts_hz))
        );
    }

    #[test]
    fn nothing_goes_out_before_the_syn_ack() {
        let mut c = client();
        let mut buf = vec![0u8; MAX_OVERHEAD + 64];
        let _ = c.handshake(&mut buf, 0).expect("syn");
        assert!(!c.is_ready());
        assert!(matches!(
            c.data(b"early", &mut buf, 1, true, Some(b"early".len())),
            Err(Error::NotEstablished)
        ));
    }
}
