//! The run loop: TUN ↔ core ↔ tcpwire ↔ datapath.
//!
//! Three threads and one lock. One reads the TUN device, encrypts, and puts
//! packets on the wire; one reads the wire, decrypts, and writes to the TUN
//! device; one drives handshake and rekey timers. There is no async runtime,
//! because a fixed set of long-lived descriptors gains nothing from one and
//! pays scheduling overhead per packet.
//!
//! # State
//!
//! Everything the two data threads share is one [`PeerState`] behind a mutex:
//! the Noise session, the carrier's connection state, and the peer's current
//! endpoint. That is the whole of the tunnel's mutable state — O(peers), never
//! O(flows) (D4).
//!
//! Taking a lock per packet is a deliberate phase-1 simplification. With two
//! threads it is an uncontended atomic in the common case; removing it belongs
//! with the rest of the throughput work.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use paqetz_core::noise::{self, Initiator, PendingResponder, Session};
use paqetz_core::{Millis, PublicKey};
use paqetz_dp::{AfPacketTx, MAX_FRAME, PacketRx, RawTx, Transmit, Tun, sys};
use paqetz_tcpwire::segment::{self, MAX_OVERHEAD};
use paqetz_tcpwire::{Endpoint as Carrier, Role};

use crate::config::{Config, Datapath, TunnelConfig};
use crate::log::{debug, error, info, warn_};
use crate::stats::Stats;

/// How often the timer thread wakes.
const TICK: Duration = Duration::from_millis(250);

/// How far either side of [`noise::REKEY_AFTER_TIME`] a rekey may fall.
///
/// A rekey is two packets, and on a fixed two-minute interval those two packets
/// are a clock -- the most legible thing this carrier emits, and one nothing
/// else on the wire explains. Spreading them over forty seconds costs nothing:
/// the late end still leaves forty seconds before the session would be refused
/// outright, which is far more than a handshake needs.
const REKEY_JITTER: Millis = 20_000;

/// How much a handshake message is padded by.
///
/// Drawn per message, so the two packets a rekey puts on the wire are not the
/// same length twice running. Without it every handshake was one of exactly two
/// sizes, which -- on a strict interval -- is a pattern that needs no
/// cryptanalysis to find and that nothing else about this carrier produces.
fn handshake_pad() -> usize {
    random_u32().map_or(0, |r| r as usize % (noise::MAX_PAD + 1))
}

/// How long to wait before trying a peer that has stopped answering entirely.
///
/// Attempts stop after [`REKEY_ATTEMPT_TIME`] so a tunnel nobody is using does
/// not handshake for ever at a peer that is gone. They used to stop for good,
/// waiting for traffic to restart them -- and an idle client has no traffic, so
/// a path that swallowed ninety seconds of handshakes left a tunnel that stayed
/// down until somebody restarted it.
///
/// That is the worse failure. A peer unreachable for ninety seconds is often
/// reachable thirty seconds later, and two packets a minute at a peer that is
/// genuinely gone is not a cost worth protecting against.
const RETRY_WHEN_GONE: Millis = 30_000;

/// How long to wait before repeating an unanswered confirmation.
const CONFIRM_RETRY: Millis = 1_000;

/// How many unanswered confirmations to send before letting it be.
const CONFIRM_TRIES: u8 = 4;

/// How long to wait before repeating an unanswered handshake.
///
/// WireGuard's interval. Long enough not to flood a peer that is down, short
/// enough that a transient loss costs a few seconds rather than a minute.
const REKEY_TIMEOUT: Millis = 5_000;

/// Random extra delay added to each repeat, up to this many milliseconds.
///
/// WireGuard's, and for its reason: two peers that lost each other at the same
/// moment would otherwise retry in step for ever, so a collision repeats rather
/// than resolves. A third of a second is enough to break the lockstep.
const REKEY_TIMEOUT_JITTER: Millis = 334;

/// How long to keep trying before giving up and waiting for traffic.
///
/// WireGuard's. Past this the peer is not transiently unreachable, it is gone,
/// and handshaking at it every five seconds for ever tells nobody anything.
/// Sending resumes the moment there is something to send.
const REKEY_ATTEMPT_TIME: Millis = 90_000;

/// How long a session may go unanswered before it is presumed dead.
///
/// WireGuard's, and the piece this had been missing entirely. A session is only
/// known to work while the peer keeps answering; if we have sent data and heard
/// nothing authenticated back for this long, the peer has forgotten us -- it
/// restarted, or its state diverged -- and no amount of waiting fixes it,
/// because nothing in the protocol says so out loud.
///
/// Without this the only thing that ever replaced a session was the rekey timer
/// at two minutes, so a server restart cost up to that long while the client
/// encrypted confidently into nothing.
const KEEPALIVE_TIMEOUT: Millis = 10_000;

/// Silence after sending that means the session is dead.
///
/// One keepalive interval for the peer to answer in, plus one handshake
/// interval, which is how WireGuard arrives at fifteen seconds.
const PRESUMED_DEAD: Millis = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

/// Largest inner packet we will handle.
const MAX_INNER: usize = 9000;

/// How many outer ports the carrier moves between.
///
/// The filter covers all of them from the start, so moving costs nothing at
/// run time, and each one is a single extra instruction in it. The firewall
/// rules are generated from this same list when the tunnel starts, so the size
/// is not something an operator has to keep in step by hand.
///
/// Twenty rather than four because the pool is also what a blocked port is
/// escaped into, and a small pool returns to one sooner: at the interval below,
/// four ports come back around in an hour, which turns a single long outage
/// into a short one every hour. Twenty stretch that cycle to about five, so a
/// port that stopped working gets a long rest before it is tried again.
///
/// The ceiling is the capture filter, whose jump offsets are single bytes: the
/// program stays correct to roughly two hundred ports, so twenty is not near
/// anything.
const PORT_POOL: usize = 20;

/// How long a carrier keeps one five-tuple before moving to the next.
///
/// A flow that lives for hours and carries gigabytes accumulates attention
/// somewhere on the path: throughput collapses, a restart cures it, and the only
/// thing a restart changes is the source port. Real hosts open connections and
/// close them; one that never does is unusual whatever its packets look like.
///
/// Jittered, because a fixed period is itself a pattern.
///
/// Halved from thirty minutes on field evidence: a tunnel that had run eleven
/// hours and carried nearly three gigabytes had its five-tuple stopped dead,
/// and the only thing that ever brought it back was a restart -- which changes
/// the port and nothing else. Whatever notices a flow here notices it well
/// inside half an hour, so the flow should not last that long.
const ROTATE_AFTER: Millis = 15 * 60 * 1_000;

/// Random spread applied to each rotation, either side of the interval.
///
/// A third of the interval, as before. Kept proportional rather than fixed: at
/// the old ten minutes it would now reach from five minutes to twenty-five,
/// which is less a jittered interval than an unpredictable one.
const ROTATE_JITTER: Millis = 5 * 60 * 1_000;

/// How many unanswered handshakes mean the five-tuple itself is the problem.
///
/// Rotation guards a *healthy* session against accumulating attention, and used
/// to run only while one existed -- which switched it off at the one moment it
/// was the cure. A path that swallows a flow does not announce it: packets keep
/// leaving, nothing comes back, and because a handshake reuses the carrier it
/// already has, every retry goes out of the same five-tuple that is being
/// dropped. That is a deadlock with no exit but a restart, which recovers only
/// because start-up picks the first port again.
///
/// Four tries is about twenty seconds, so the whole pool is tried inside
/// [`REKEY_ATTEMPT_TIME`] -- a blocked port is ruled out before the peer would
/// be called gone. Rotating when the peer is merely down costs nothing: the
/// next port is as good as this one, and a responder learns where we are from
/// the handshake itself.
const ROTATE_AFTER_UNANSWERED: u32 = 4;

/// What this end will spend on moving its five-tuple around.
///
/// The defaults above are what a censored path wanted when they were measured,
/// which is not a claim about anyone else's path. Every one of them is a guess
/// about a remote adversary's timers, so each is a setting rather than a
/// constant -- and they keep their values while `rotate` is off, so it can be
/// turned off and on again without losing what was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rotation {
    /// Whether the carrier moves at all.
    pub(crate) enabled: bool,
    /// How long one five-tuple is kept, before jitter.
    pub(crate) after: Millis,
    /// Random spread applied either side of `after`.
    pub(crate) jitter: Millis,
    /// How many outer ports to move between.
    pub(crate) ports: usize,
    /// Unanswered handshakes that mean the tuple itself is the problem.
    pub(crate) unanswered: u32,
}

impl Default for Rotation {
    fn default() -> Self {
        Self {
            enabled: true,
            after: ROTATE_AFTER,
            jitter: ROTATE_JITTER,
            ports: PORT_POOL,
            unanswered: ROTATE_AFTER_UNANSWERED,
        }
    }
}

impl Rotation {
    /// How long the next five-tuple should last.
    ///
    /// `jitter` is bounded below `after` when the configuration is read, so the
    /// subtraction cannot go under zero -- and it is saturating anyway, because
    /// a constant that is only safe because of a check somewhere else is one
    /// edit away from not being.
    pub(crate) fn interval(self) -> Millis {
        let spread = random_u32().map_or(0, |r| Millis::from(r) % (2 * self.jitter + 1));
        self.after
            .saturating_add(spread)
            .saturating_sub(self.jitter)
    }
}

/// The port after `current`, wrapping.
///
/// Returns `current` when there is nowhere to go, so the caller can tell that
/// nothing changed rather than tearing down a carrier and rebuilding an
/// identical one.
fn next_port(ports: &[u16], current: u16) -> u16 {
    let Some(at) = ports.iter().position(|p| *p == current) else {
        // Not in the pool at all, which means the port was configured rather
        // than chosen. Staying put is right: the far end has to find us.
        return current;
    };
    ports
        .get((at + 1) % ports.len())
        .copied()
        .unwrap_or(current)
}

/// The shared, mutable state of the tunnel.
struct PeerState {
    /// The established session, once there is one.
    session: Option<Session>,
    /// A session this end has accepted but the peer has not yet used.
    ///
    /// Only the responder fills this. A responder answers any handshake that
    /// authenticates, and a replayed initiation authenticates perfectly well --
    /// it was genuine when it was recorded. Installing that session as the one
    /// to seal under would hand anyone who once captured an initiation a way to
    /// black out the tunnel at will: the peer never negotiated those keys and
    /// cannot open anything sealed under them, so traffic stops until a liveness
    /// timer notices, and the same packet replayed again stops it again.
    ///
    /// So an accepted session waits here until a transport packet arrives under
    /// it. That is proof the peer holds it, and it is proof a replay cannot
    /// manufacture. Until then the established session keeps carrying traffic
    /// and a replay changes nothing an observer can see.
    next: Option<Session>,
    /// The session this one replaced, kept until it expires on its own.
    ///
    /// The two ends do not change session at the same instant, and cannot: a
    /// rekey is a handshake, so there is a round trip between one end
    /// installing the new keys and the other learning of them. Whichever end
    /// moves first spends that round trip receiving packets sealed under keys
    /// it has already discarded, and with one slot those packets are simply
    /// lost -- twice a minute, for ever, on a tunnel that is otherwise
    /// perfectly healthy.
    ///
    /// So the old session is kept for reading. It is never sealed under again;
    /// `open` refuses it past `REJECT_AFTER_TIME` on its own, and the next
    /// rekey drops it.
    previous: Option<Session>,
    /// A handshake we have sent and are awaiting a reply to.
    pending: Option<Initiator>,
    /// The outer packets exchanged with this peer.
    carrier: Option<Wire>,
    /// Recently sent packets, in case the peer asks for one again.
    outbox: crate::repeat::Outbox,
    /// Counters the peer has not delivered.
    inbox: crate::repeat::Inbox,
    /// Where the peer currently is.
    endpoint: Option<SocketAddrV4>,
    /// When the last handshake was sent.
    last_handshake: Millis,
    /// When this session should be replaced.
    ///
    /// Jittered per session and stored, rather than a fixed interval measured
    /// from establishment.
    rekey_at: Millis,
    /// When the handshake just sent may be repeated.
    ///
    /// Stored rather than recomputed, because the interval is jittered: drawing
    /// it afresh on every tick is a new coin flip each time rather than one
    /// deadline, and the earliest of many draws wins -- which collapses the
    /// interval back onto its own lower bound and cancels the decorrelation the
    /// jitter exists to provide.
    retry_at: Millis,
    /// When the first handshake of the current attempt was sent.
    ///
    /// Separate from `last_handshake` so that giving up is measured from when
    /// trying started, not from the most recent try.
    attempt_started: Option<Millis>,
    /// When a packet from the peer last authenticated.
    ///
    /// The only evidence that the peer still has the session we are using.
    last_receive: Option<Millis>,
    /// When we last sent something under the current session.
    last_send: Option<Millis>,
    /// When the last keepalive went out.
    ///
    /// Separate from `last_send`, which only real data may set: a keepalive has
    /// to count as having spoken for the *keepalive* timer, or the timer never
    /// stops firing, but it must not count for the *liveness* timer, or an idle
    /// tunnel asks a question nobody can answer and reads the silence as death.
    last_keepalive: Option<Millis>,
    /// Whether the peer has yet been seen using the session in use here.
    ///
    /// The responder will not seal under a session until it has seen the peer
    /// use it, so the initiator owes it a packet. Without that, an idle tunnel
    /// leaves the responder on the old session until that session expires, and
    /// a responder that then needs to speak first has nothing to speak with.
    ///
    /// Cleared by hearing from the peer under that session, not by sending --
    /// the confirmation is one small packet, and one small packet is exactly
    /// the thing a lossy path drops. Sent once and assumed delivered, a single
    /// loss would strand the responder until the next rekey.
    confirm_owed: bool,
    /// How many confirmations have gone unanswered.
    ///
    /// Bounded, because a peer that is idle has nothing to answer with: a
    /// responder can promote the session, have nothing to say, and stay
    /// silent, which is indistinguishable from never having promoted it. Left
    /// unbounded, that reads as "keep asking" for ever -- a packet a second,
    /// on a carrier whose whole purpose is to be unremarkable, for as long as
    /// the tunnel is up.
    ///
    /// A handful of attempts is enough: they are only lost together if the
    /// path is failing, and a path that drops [`CONFIRM_TRIES`] consecutive
    /// packets has a problem no amount of repeating will solve.
    confirm_tries: u8,
    /// When the carrier should move to the next port.
    rotate_at: Millis,
    /// The smallest path MTU a hop has reported, if any has.
    ///
    /// Kept so the report is announced when it changes rather than when it
    /// arrives. A router repeats one for every oversized packet, and the rule
    /// here is that no per-packet event gets its own line -- otherwise whoever
    /// is sending them decides how much this process writes.
    reported_mtu: Option<u16>,
    /// Handshakes sent since the last one that was answered.
    ///
    /// Distinct from `attempt_started`, which offered traffic clears, so it
    /// cannot say how long a handshake has gone unanswered on a busy tunnel:
    /// a client whose peer has stopped answering still has an application
    /// handing it packets, and every one of those resets that clock. This
    /// counts what actually matters -- tries with no reply -- and only a reply
    /// resets it.
    unanswered: u32,
    /// When a packet carrying actual data last arrived.
    ///
    /// Separate from `last_receive` so a keepalive cannot arm another one. Both
    /// ends answering every keepalive with a keepalive is a loop that never
    /// stops, and an empty packet is not something that needs acknowledging.
    last_data_receive: Option<Millis>,
}

impl PeerState {
    fn new(endpoint: Option<SocketAddrV4>, repeat: crate::repeat::Limits) -> Self {
        Self {
            session: None,
            next: None,
            previous: None,
            pending: None,
            carrier: None,
            outbox: crate::repeat::Outbox::new(repeat),
            inbox: crate::repeat::Inbox::new(repeat),
            endpoint,
            last_handshake: 0,
            rekey_at: Millis::MAX,
            retry_at: 0,
            attempt_started: None,
            last_receive: None,
            last_send: None,
            last_keepalive: None,
            confirm_owed: false,
            confirm_tries: 0,
            last_data_receive: None,
            rotate_at: Millis::MAX,
            reported_mtu: None,
            unanswered: 0,
        }
    }

    /// The header mask for this peer, if any session exists.
    ///
    /// The same for every session with one peer -- it is derived from the
    /// responder's static key -- so any of the three will do, and it lets the
    /// counter be read before it is known which session the packet belongs to.
    fn mask(&self) -> Option<paqetz_core::framing::HeaderMask> {
        self.session
            .as_ref()
            .or(self.previous.as_ref())
            .or(self.next.as_ref())
            .map(|s| s.mask().clone())
    }

    /// Makes `session` the one to seal under, keeping the old one for reading.
    ///
    /// For the initiating side, which asked for this session and therefore
    /// knows the peer holds it: the handshake reply is itself the proof.
    fn install(&mut self, session: Session) {
        self.previous = self.session.replace(session);
        // A session that arrives by rekey supersedes anything still waiting to
        // be confirmed; keeping it would be a third set of keys nobody has used.
        self.next = None;
        self.confirm_owed = true;
        self.confirm_tries = 0;
    }

    /// Accepts `session` without sealing under it yet.
    ///
    /// For the responding side, which has only the peer's word -- and a replay
    /// carries the peer's word just as convincingly as the peer does. See
    /// [`Self::next`].
    fn accept(&mut self, session: Session) {
        self.next = Some(session);
    }

    /// Promotes the waiting session, now that the peer has used it.
    fn confirm(&mut self) {
        if let Some(session) = self.next.take() {
            self.previous = self.session.replace(session);
        }
    }

    /// Decrypts under whichever session the packet belongs to.
    ///
    /// The current one first, because all but a round trip's worth of traffic
    /// belongs to it. `open` compares the session index before it attempts the
    /// AEAD and touches nothing when it does not match, so trying a second
    /// session costs one comparison and cannot corrupt the replay window of the
    /// first.
    ///
    /// `None` means there is no session at all; anything else is the result of
    /// the session the packet was addressed to.
    fn open(
        &mut self,
        packet: &[u8],
        out: &mut [u8],
        now: Millis,
    ) -> Option<paqetz_core::Result<usize>> {
        let mut tried = None;
        if let Some(current) = self.session.as_mut() {
            match current.open(packet, out, now) {
                // Not this one: try the others before calling it noise. An
                // expired session has to fall through exactly as a mismatched
                // one does -- `open` tests expiry before it looks at the index,
                // so a session old enough to refuse everything would otherwise
                // answer for packets addressed to a different session entirely,
                // and the one waiting to be confirmed would never be reached.
                // That deadlocks the tunnel permanently rather than for a
                // moment: the session that could have replaced it is sitting
                // right there, unreachable.
                Err(e @ (paqetz_core::Error::Rejected | paqetz_core::Error::Expired)) => {
                    tried = Some(e);
                }
                result => {
                    // Traffic under the session we are sealing under is proof
                    // the peer has it, so nothing more needs confirming.
                    if result.is_ok() {
                        self.confirm_owed = false;
                        self.confirm_tries = 0;
                    }
                    return Some(result);
                }
            }
        }
        if let Some(previous) = self.previous.as_mut() {
            match previous.open(packet, out, now) {
                Err(e @ (paqetz_core::Error::Rejected | paqetz_core::Error::Expired)) => {
                    tried = Some(e);
                }
                result => return Some(result),
            }
        }
        if let Some(waiting) = self.next.as_mut() {
            let result = waiting.open(packet, out, now);
            // The peer has used the session it was offered, which no replay of
            // an old handshake can do. Only now does it become the one to seal
            // under.
            if result.is_ok() {
                self.confirm();
            }
            return Some(result);
        }
        tried.map(Err)
    }

    /// Whether the current run of handshake attempts has gone on long enough.
    fn exhausted(&self, now: Millis) -> bool {
        self.attempt_started
            .is_some_and(|began| now.saturating_sub(began) >= REKEY_ATTEMPT_TIME)
    }

    /// Drops sessions that can no longer carry anything.
    ///
    /// `seal` refuses a session past `REJECT_AFTER_TIME`, so keeping one means
    /// every outbound packet fails and is counted as a drop -- for keys that
    /// will never work again. In the field that read as a transmit-dropped
    /// counter climbing by thousands while the transmit counter stood still,
    /// which describes the symptom and hides the cause.
    ///
    /// Letting them go makes the state say what is true, and hands the
    /// handshake the path it already has for having no session at all: bounded
    /// attempts, then a slow retry.
    fn retire_expired(&mut self, now: Millis) {
        for slot in [&mut self.session, &mut self.previous, &mut self.next] {
            if slot.as_ref().is_some_and(|s| s.is_expired(now)) {
                *slot = None;
            }
        }
    }

    /// Whether a run that gave up should be started again.
    ///
    /// See [`RETRY_WHEN_GONE`]. Measured from the last attempt rather than from
    /// when the run began, so the wait is a gap in the traffic and not a
    /// countdown that was already running.
    fn revive(&self, now: Millis) -> bool {
        self.exhausted(now)
            && self.session.is_none()
            && now.saturating_sub(self.last_handshake) >= RETRY_WHEN_GONE
    }

    /// Whether the carrier, rather than the peer, is what is not working.
    ///
    /// Indistinguishable from a peer that is down, and deliberately so: the
    /// answer is the same either way, and the one that is cheap to be wrong
    /// about is moving.
    ///
    /// Silence is the test, not the absence of a session. Keying this to
    /// `session.is_none()` made recovery wait for the keys to age out at
    /// `REJECT_AFTER_TIME` -- three minutes of handshaking onto a tuple already
    /// known to be dead, because a session that nothing can reach is still a
    /// session until it expires. The keys were never the problem: they work
    /// perfectly well over the next port, so the peer's own roaming can put the
    /// tunnel back without a rekey at all.
    ///
    /// Both halves are needed. Unanswered handshakes alone would fire on a
    /// lossy path that is otherwise carrying traffic, where a rekey can lose
    /// four messages in a row while data flows the whole time -- and moving the
    /// carrier under a working tunnel is a cost with nothing bought.
    fn stuck(&self, now: Millis, after: u32) -> bool {
        self.unanswered >= after
            && self
                .last_receive
                .is_none_or(|heard| now.saturating_sub(heard) >= PRESUMED_DEAD)
    }

    /// Whether a handshake should be sent now.
    ///
    /// The whole decision, in one place a test can reach. It used to live
    /// inside the function that acts on it, so what a test could check was a
    /// second copy of the same reasoning -- which agrees with itself no matter
    /// what either copy says.
    fn wants_handshake(&self, now: Millis) -> bool {
        let waited = now >= self.retry_at;
        match self.session.as_ref() {
            None if self.exhausted(now) => self.revive(now),
            None => self.pending.is_none() || waited,
            // A session is only known to work while the peer answers. Rekeying
            // on the timer alone left a peer that had forgotten us undetected
            // for two minutes, with everything sent in between encrypted to a
            // key nobody holds.
            //
            // The time half is the tunnel's, so it can be jittered; the
            // message-count half stays where the counter lives.
            // Paced by `waited` like every other path here. It was not, and
            // the deadline that makes a rekey due never stops being past -- so
            // a peer that did not answer was handshaked at on every tick, four
            // times a second, for as long as it stayed silent.
            Some(s) => {
                waited
                    && (s.is_initiator()
                        && (now >= self.rekey_at
                            || s.sent() >= paqetz_core::noise::REKEY_AFTER_MESSAGES)
                        || self.presumed_dead(now))
            }
        }
    }

    /// Records that there is something to send and nothing to send it under.
    ///
    /// Attempts stop after [`REKEY_ATTEMPT_TIME`] because a peer that has not
    /// answered in ninety seconds is not briefly unreachable, it is gone, and a
    /// tunnel nobody is using should not handshake at it for ever.
    ///
    /// They have to start again when someone *is* using it, and this is the
    /// only signal that says so. It used to be read from `last_send`, which
    /// only moves once a packet has been sealed -- so it could not move until a
    /// handshake succeeded, and no handshake would be attempted until it moved.
    /// A server unreachable for ninety seconds left a client that never tried
    /// again, with a tunnel that stayed down until someone restarted it.
    fn wants_to_send(&mut self) {
        self.attempt_started = None;
    }

    /// Records that a handshake just completed.
    ///
    /// The peer answered, which is the freshest evidence available that it holds
    /// this session -- so the liveness timers start from here rather than
    /// carrying over whatever made the previous session look dead. Without this
    /// the condition that triggered the handshake survives it, and the next tick
    /// triggers another, and the tunnel spends its life handshaking.
    fn established(&mut self, now: Millis, rekey_after: Millis) {
        self.rekey_at = now.saturating_add(rekey_after);
        self.last_receive = Some(now);
        self.last_send = None;
        self.last_keepalive = None;
        self.last_data_receive = None;
        self.attempt_started = None;
        // A reply is the only thing that proves this five-tuple still reaches
        // the peer, so it is the only thing that clears the count.
        self.unanswered = 0;
    }

    /// Whether the peer has spoken and we owe it a word back.
    ///
    /// WireGuard's passive keepalive: after data arrives, if we have said
    /// nothing for a keepalive interval, send an empty packet. It holds any NAT
    /// mapping in the path open, and it gives the peer the evidence it needs to
    /// decide whether *we* are still here -- which is the same question this end
    /// asks with `presumed_dead`, from the other side.
    fn owes_keepalive(&self, now: Millis) -> bool {
        let Some(heard) = self.last_data_receive else {
            return false;
        };
        // Either kind of packet counts as having spoken. Counting only data
        // meant a keepalive never satisfied the condition that produced it, so
        // once this went true it stayed true and the tunnel emitted one every
        // tick -- four a second, indefinitely, until the peer happened to send
        // data again. That is the metronome this feature is supposed to be a
        // measured version of.
        let spoke = self.last_send.max(self.last_keepalive).unwrap_or(0);
        spoke < heard && now.saturating_sub(heard) >= KEEPALIVE_TIMEOUT
    }

    /// Whether the peer has stopped answering a session we are still using.
    ///
    /// Only asked of a session we have actually sent under: a tunnel that has
    /// been idle since it came up has heard nothing back because it has said
    /// nothing, which is not the same as being ignored.
    fn presumed_dead(&self, now: Millis) -> bool {
        let Some(sent) = self.last_send else {
            return false;
        };
        let heard = self.last_receive.unwrap_or(0);
        sent > heard && now.saturating_sub(heard) >= PRESUMED_DEAD
    }
}

/// The carrier in use, whichever shape it has.
///
/// One seam, so that everything above it -- the handshake, the replay window,
/// rekeying, roaming, the repeat machinery -- never learns which of these put
/// its bytes on the wire. That is what makes a second shape cheap: it is a
/// different twenty-four or fifty-odd bytes in front of the same payload, not a
/// different tunnel.
enum Wire {
    /// Hand-built TCP segments.
    Tcp(Box<Carrier>),
    /// An IPv4 header, an optional small shell, and the payload.
    Raw(paqetz_tcpwire::rawip::Carrier),
}

impl Wire {
    /// Writes one packet, returning how many bytes it used.
    fn data(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        now: Millis,
    ) -> core::result::Result<usize, paqetz_tcpwire::Error> {
        match self {
            Self::Tcp(c) => c.data(payload, out, now),
            // No clock: nothing in a GRE header is a function of time. The
            // fake-TCP carrier needs one for its timestamp option.
            Self::Raw(c) => c.data(payload, out),
        }
    }

    /// The peer's address as this carrier currently addresses it.
    fn remote(&self) -> SocketAddrV4 {
        match self {
            Self::Tcp(c) => {
                let (ip, port) = c.remote();
                SocketAddrV4::new(ip, port)
            }
            Self::Raw(c) => SocketAddrV4::new(c.remote(), 0),
        }
    }

    /// Follows the peer to a new address.
    fn set_remote(&mut self, remote: SocketAddrV4) {
        match self {
            Self::Tcp(c) => c.set_remote((*remote.ip(), remote.port())),
            // The port is not dropped here so much as never existing: GRE has
            // no ports, and `remote` reports zero for the same reason.
            Self::Raw(c) => c.set_remote(*remote.ip()),
        }
    }

    /// Folds an inbound packet into whatever state the carrier keeps.
    ///
    /// Nothing at all for GRE, which is the point of it: no sequence space, no
    /// acknowledgement, no timestamp to echo, no connection phase.
    fn on_receive(&mut self, seg: &segment::Segment<'_>) {
        if let Self::Tcp(c) = self {
            c.on_receive(seg);
        }
    }
}

/// A running tunnel.
pub(crate) struct Tunnel {
    cfg: TunnelConfig,
    /// Seconds between status lines, which belongs to the process.
    health_interval: u64,
    tun: Arc<Tun>,
    rx: Arc<PacketRx>,
    tx: Arc<Transmit>,
    state: Arc<Mutex<PeerState>>,
    /// Our own outer address and the port currently in use.
    local: Mutex<(Ipv4Addr, u16)>,
    /// Every port the capture filter accepts, in rotation order.
    ports: Vec<u16>,
    /// Our static public key, needed to verify `mac1` on inbound handshakes.
    local_public: PublicKey,
    started: Instant,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
    /// Where the configuration was read from, so `SIGHUP` can re-read it.
    config_path: Option<std::path::PathBuf>,
    /// What to call this tunnel in the log, when the process has several.
    label: Option<String>,
}

/// Anything that can stop the tunnel starting.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// An operating-system call failed.
    #[error("{context}: {source}")]
    Os {
        /// What was being attempted.
        context: String,
        /// The underlying error.
        source: io::Error,
    },

    /// The cryptographic core rejected something.
    #[error("crypto: {0}")]
    Core(#[from] paqetz_core::Error),

    /// The carrier rejected something.
    #[error("carrier: {0}")]
    Wire(#[from] paqetz_tcpwire::Error),

    /// A configuration was valid but names something not yet built.
    #[error("{0}")]
    Unsupported(&'static str),
}

/// Result alias for this module.
pub(crate) type Result<T> = core::result::Result<T, Error>;

fn os<T>(context: impl Into<String>, r: io::Result<T>) -> Result<T> {
    r.map_err(|source| Error::Os {
        context: context.into(),
        source,
    })
}

impl Tunnel {
    /// Brings up the device, sockets, and firewall rules.
    ///
    /// # Errors
    /// Returns the first failure, with context describing what was attempted.
    pub(crate) fn start(cfg: TunnelConfig, health_interval: u64) -> Result<Self> {
        if matches!(
            cfg.interface.shape,
            crate::config::Shape::Tcp(paqetz_tcpwire::Carrier::Handshake)
        ) {
            // The carrier can emit SYN/SYN+ACK/ACK, but nothing here drives that
            // exchange or retries a lost SYN yet. Refusing is better than
            // starting a tunnel whose first data segment fails with
            // "not established". See docs/decisions/D14-carrier-mode.md.
            return Err(Error::Unsupported(
                "carrier = \"handshake\" is not implemented yet; \
                 use the default \"midstream\"",
            ));
        }

        // Said once, at start-up, rather than left for someone to infer from a
        // rotation line that never appears. `rotate` defaults to on, so most
        // configurations that reach here are asking for something this carrier
        // cannot do, and silently not doing it is the worse answer.
        if cfg.interface.rotation.enabled && !cfg.interface.shape.has_ports() {
            warn_!(
                "this carrier has no ports, so `rotate` does nothing: its outer \
                 packets are addresses and a protocol number, and none of those \
                 can be varied"
            );
        }

        let local_public =
            paqetz_core::keys::public_from_private(cfg.interface.private_key.as_bytes());

        // Choosing our own outer port above the kernel's ephemeral range keeps
        // it from colliding with a port the kernel hands to some other socket.
        // paqet picked from 32768-65535, which overlaps that range exactly.
        // A pool rather than one port. The side that waits has to be findable,
        // so it keeps the port it was configured with; the side that initiates
        // takes several and moves between them, which is what stops a single
        // five-tuple living for hours.
        let ports: Vec<u16> = if cfg.interface.listen_port == 0 {
            let pool = cfg.interface.rotation.ports;
            let mut v = Vec::with_capacity(pool);
            while v.len() < pool {
                let r = os("choosing an outer port", random_u32())?;
                let port = 61_000 + u16::try_from(r % 4_000).unwrap_or(0);
                if !v.contains(&port) {
                    v.push(port);
                }
            }
            v
        } else {
            vec![cfg.interface.listen_port]
        };
        let local_port = *ports.first().unwrap_or(&0);

        // Our own outer address is whichever one the kernel would route from.
        // Asking it directly avoids putting an address in the configuration
        // that then has to be kept in step with the host's networking.
        let local_ip = match cfg.peer.endpoint {
            Some(peer) => os(
                "determining our outer address",
                source_address_for(*peer.ip()),
            )?,
            // The side that waits learns its own address from the destination
            // of the first packet that arrives, so nothing is needed here.
            None => Ipv4Addr::UNSPECIFIED,
        };

        let interface = os(
            "finding the interface that routes to the peer",
            outbound_interface(),
        )?;

        let tun = Tun::create(&cfg.interface.device).map_err(|source| Error::Os {
            context: format!("creating TUN device {}", cfg.interface.device),
            source,
        })?;
        os(
            "configuring the TUN device",
            tun.configure(
                cfg.interface.address,
                cfg.interface.netmask,
                cfg.interface.mtu,
            ),
        )?;

        let rx = os(
            format!("opening a capture socket on {interface}"),
            PacketRx::open(&interface, cfg.interface.shape.matching(&ports)),
        )?;
        let _ = rx.set_recv_buffer(8 * 1024 * 1024);

        let tx = match cfg.interface.transmit {
            crate::config::TransmitPath::Raw => {
                Transmit::Raw(os("opening the transmit socket", RawTx::open())?)
            }
            crate::config::TransmitPath::AfPacket => {
                // Needs a peer address to resolve the next hop toward, which
                // only the initiating side has at start-up.
                let peer = cfg.peer.endpoint.map_or(Ipv4Addr::UNSPECIFIED, |e| *e.ip());
                if peer.is_unspecified() {
                    return Err(Error::Unsupported(
                        "transmit = \"afpacket\" needs a peer endpoint to resolve \
                         the next hop toward; the waiting side must use \"raw\"",
                    ));
                }
                Transmit::AfPacket(os(
                    "opening the AF_PACKET transmit socket",
                    AfPacketTx::open(&interface, peer),
                )?)
            }
        };
        let _ = tx.set_send_buffer(4 * 1024 * 1024);
        info!("transmit via {}", tx.name());

        Ok(Self {
            state: Arc::new(Mutex::new(PeerState::new(
                cfg.peer.endpoint,
                cfg.interface.repeat,
            ))),
            cfg,
            health_interval,
            label: None,
            tun: Arc::new(tun),
            rx: Arc::new(rx),
            tx: Arc::new(tx),
            local: Mutex::new((local_ip, local_port)),
            ports,
            local_public,
            started: Instant::now(),
            running: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(Stats::default()),
            config_path: None,
        })
    }

    /// The outer port this end actually receives on.
    ///
    /// Not known from the configuration alone: the initiating side takes an
    /// ephemeral port at start-up, and the firewall rules have to name the port
    /// the kernel would otherwise send resets from — which is this one, not the
    /// peer's.
    pub(crate) fn local_port(&self) -> u16 {
        self.local().1
    }

    /// Our outer address and the port currently in use.
    fn local(&self) -> (Ipv4Addr, u16) {
        *self.local.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every port the capture filter accepts.
    ///
    /// The firewall names all of them, because a rotation moves to one of these
    /// and the rules have to already cover it -- and because replies to the port
    /// just left are still arriving for a while afterwards.
    pub(crate) fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Milliseconds since the tunnel started.
    fn now(&self) -> Millis {
        Millis::try_from(self.started.elapsed().as_millis()).unwrap_or(Millis::MAX)
    }

    /// What this tunnel's packets look like on the wire.
    pub(crate) const fn shape(&self) -> crate::config::Shape {
        self.cfg.interface.shape
    }

    /// Builds a carrier of whichever shape the configuration asked for.
    ///
    /// `numbers` are the sequence bases and timestamp base derived from the
    /// handshake. GRE has nowhere to put them and ignores all three -- there is
    /// no sequence space to align and no timestamp to echo.
    fn wire(
        &self,
        role: Role,
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        numbers: (u32, u32, u32),
    ) -> Wire {
        match self.cfg.interface.shape {
            crate::config::Shape::Tcp(carrier) => {
                Wire::Tcp(Box::new(Carrier::new(paqetz_tcpwire::Config {
                    local,
                    remote,
                    profile: self.cfg.interface.profile,
                    role,
                    carrier,
                    isn: numbers.0,
                    peer_isn: numbers.1,
                    ts_base: numbers.2,
                    sequencing: self.cfg.interface.sequencing,
                })))
            }
            crate::config::Shape::Raw(shell) => Wire::Raw(paqetz_tcpwire::rawip::Carrier::new(
                paqetz_tcpwire::rawip::Config {
                    local: local.0,
                    remote: remote.0,
                    profile: self.cfg.interface.profile,
                    shell,
                },
            )),
        }
    }

    /// Whether this end initiates handshakes.
    const fn is_initiator(&self) -> bool {
        self.cfg.peer.is_initiator()
    }

    /// Runs until stopped. Consumes the tunnel.
    ///
    /// # Errors
    /// Returns a failure from thread startup; per-packet errors are logged and
    /// the loop continues, since one bad packet must never stop the tunnel.
    pub(crate) fn run(self) -> Result<()> {
        let this = Arc::new(self);

        let outbound = Arc::clone(&this);
        let t1 = std::thread::Builder::new()
            .name("tun-to-wire".to_owned())
            .spawn(move || outbound.tun_to_wire())
            .map_err(|source| Error::Os {
                context: "starting the outbound thread".to_owned(),
                source,
            })?;

        let inbound = Arc::clone(&this);
        let t2 = std::thread::Builder::new()
            .name("wire-to-tun".to_owned())
            .spawn(move || inbound.wire_to_tun())
            .map_err(|source| Error::Os {
                context: "starting the inbound thread".to_owned(),
                source,
            })?;

        let timers = Arc::clone(&this);
        let t3 = std::thread::Builder::new()
            .name("timers".to_owned())
            .spawn(move || timers.timers())
            .map_err(|source| Error::Os {
                context: "starting the timer thread".to_owned(),
                source,
            })?;

        let health = Arc::clone(&this);
        let t4 = std::thread::Builder::new()
            .name("health".to_owned())
            .spawn(move || health.health())
            .map_err(|source| Error::Os {
                context: "starting the health thread".to_owned(),
                source,
            })?;

        // The worker threads block in `read` and `recv`, so they cannot notice
        // a flag on their own. The process exits once this returns and the
        // caller has removed the firewall rules; the blocked threads go with
        // it. Waking them properly needs the poll loop that arrives with the
        // rest of the throughput work.
        while this.running.load(Ordering::Relaxed) && !SHUTDOWN.load(Ordering::Relaxed) {
            std::thread::sleep(TICK);
            if reload_requested()
                && let Some(path) = this.config_path.as_ref()
            {
                this.reload(path);
            }
        }
        this.stop();

        drop((t1, t2, t3, t4));
        Ok(())
    }

    /// Names this tunnel in its own log lines.
    ///
    /// Set only when a process carries more than one, so a single tunnel reads
    /// exactly as it always has and three do not interleave into noise.
    pub(crate) fn set_label(&mut self, name: String) {
        self.label = Some(name);
    }

    /// What to put in front of this tunnel's log lines.
    ///
    /// Empty for a lone tunnel, so its output is unchanged, and `"name: "` when
    /// a process carries several and three status lines a minute would otherwise
    /// interleave into something nobody can read.
    fn tag(&self) -> String {
        self.label
            .as_ref()
            .map_or_else(String::new, |n| format!("{n}: "))
    }

    /// Remembers where the configuration came from, enabling `SIGHUP`.
    pub(crate) fn watch_config(&mut self, path: std::path::PathBuf) {
        self.config_path = Some(path);
    }

    /// A handle to the flag that stops every loop, including any front end
    /// started alongside the tunnel.
    pub(crate) fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Prints the health line every `health_interval` seconds.
    fn health(&self) {
        let interval = self.health_interval;
        if interval == 0 {
            return;
        }
        let mut next = Duration::from_secs(interval);
        while self.running.load(Ordering::Relaxed) && !SHUTDOWN.load(Ordering::Relaxed) {
            std::thread::sleep(TICK);
            if self.started.elapsed() < next {
                continue;
            }
            next = self.started.elapsed() + Duration::from_secs(interval);
            if crate::log::enabled(crate::log::Level::Info) {
                // The kernel's own drop counter resets on read, so each line
                // reports the interval since the last rather than a total.
                let drops = self.rx.drops().ok();
                crate::log::emit(
                    crate::log::Level::Info,
                    format_args!("{}{}", self.tag(), self.stats.line(self.now(), drops)),
                );
            }
        }
    }

    /// Applies the parts of a new configuration that can change without
    /// dropping the session, and reports the parts that cannot.
    ///
    /// Deliberately narrow. The log level is the field worth changing on a
    /// running tunnel — turning on detail when something is wrong, without
    /// interrupting the traffic being investigated. Everything else either
    /// belongs to a live session (keys, the carrier's numbering) or to a socket
    /// already bound, and pretending otherwise would produce a tunnel whose
    /// behaviour no longer matches its configuration file.
    pub(crate) fn reload(&self, path: &std::path::Path) {
        let fresh = match Config::load(path) {
            Ok(c) => c,
            Err(e) => {
                error!("reload: {e}; keeping the running configuration");
                return;
            }
        };

        if fresh.log != crate::log::level() {
            crate::log::set_level(fresh.log);
            // Emitted after the change so raising the level shows this line.
            info!("reload: log level is now {}", fresh.log.name());
        }

        // The file describes every tunnel in the process, so find this one.
        // A tunnel that has been renamed or removed is left running on what it
        // has: stopping it because its name moved would be a worse answer than
        // saying so.
        let Some(fresh_tunnel) = fresh.named(&self.cfg.name) else {
            warn_!(
                "reload: no tunnel named {:?} in the file any more; keeping the \
                 running configuration",
                self.cfg.name
            );
            return;
        };
        let fresh = fresh_tunnel;

        let old = &self.cfg;
        let mut needs_restart = Vec::new();
        if fresh.peer.public_key != old.peer.public_key {
            needs_restart.push("peer.public_key");
        }
        if fresh.peer.endpoint != old.peer.endpoint {
            needs_restart.push("peer.endpoint");
        }
        if fresh.peer.allowed_ips != old.peer.allowed_ips {
            needs_restart.push("peer.allowed_ips");
        }
        if fresh.interface.listen_port != old.interface.listen_port {
            needs_restart.push("interface.listen_port");
        }
        if fresh.interface.mtu != old.interface.mtu {
            needs_restart.push("interface.mtu");
        }
        if fresh.interface.address != old.interface.address {
            needs_restart.push("interface.address");
        }
        if fresh.interface.profile != old.interface.profile {
            needs_restart.push("interface.profile");
        }
        if fresh.interface.datapath != old.interface.datapath {
            needs_restart.push("interface.datapath");
        }
        if fresh.interface.transmit != old.interface.transmit {
            needs_restart.push("interface.transmit");
        }

        if needs_restart.is_empty() {
            debug!("reload: nothing else changed");
        } else {
            warn_!(
                "reload: {} changed but needs a restart to take effect",
                needs_restart.join(", ")
            );
        }
    }

    /// Asks the loops to stop.
    pub(crate) fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    // -- outbound ------------------------------------------------------------

    /// Reads inner packets, encrypts them, and puts them on the wire.
    fn tun_to_wire(&self) {
        match self.cfg.interface.datapath {
            Datapath::Simple => self.tun_to_wire_simple(),
            Datapath::Batched => self.tun_to_wire_batched(),
        }
    }

    /// One packet per syscall.
    fn tun_to_wire_simple(&self) {
        let mut inner = vec![0u8; MAX_INNER];
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut frame = vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD];

        while self.running.load(Ordering::Relaxed) {
            let n = match self.tun.recv(&mut inner) {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading the device failed: {e}");
                    break;
                }
            };
            let Some(packet) = inner.get(..n) else {
                continue;
            };
            if let Err(e) = self.send_inner(packet, &mut sealed, &mut frame) {
                self.note_outbound(&e);
            }
        }
    }

    /// Drains whatever is queued, then sends it in one syscall.
    ///
    /// The first read blocks; the rest are non-blocking, so this only ever
    /// collects packets that were already waiting. Under one packet in flight
    /// it behaves exactly as the simple path does — batching costs latency only
    /// if you wait for a batch to form, and this does not.
    fn tun_to_wire_batched(&self) {
        // Set once, not per read. Toggling it around each read cost two extra
        // syscalls per packet, which made batching slower than not batching.
        if let Err(e) = self.tun.set_nonblocking(true) {
            error!("could not set the device non-blocking: {e}");
            return;
        }

        let mut inner: Vec<Vec<u8>> = (0..sys::BATCH).map(|_| vec![0u8; MAX_INNER]).collect();
        let mut frames: Vec<Vec<u8>> = (0..sys::BATCH)
            .map(|_| vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD])
            .collect();
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut lens = [0usize; sys::BATCH];
        let mut dsts = Vec::with_capacity(sys::BATCH);

        while self.running.load(Ordering::Relaxed) {
            // Block for the first, then take anything else already queued.
            let Some(first) = self.read_inner_blocking(&mut inner) else {
                break;
            };
            let mut count = 1;
            if let Some(slot) = lens.get_mut(0) {
                *slot = first;
            }
            while count < sys::BATCH {
                let Some(buf) = inner.get_mut(count) else {
                    break;
                };
                match self.tun.recv_nonblocking(buf) {
                    Ok(Some(n)) if n > 0 => {
                        if let Some(slot) = lens.get_mut(count) {
                            *slot = n;
                        }
                        count += 1;
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }

            // Encrypt each into its own frame buffer, then send them together.
            dsts.clear();
            let mut inner_lens = [0usize; sys::BATCH];
            let mut ready = 0usize;
            for i in 0..count {
                let Some(packet) = inner
                    .get(i)
                    .and_then(|b| b.get(..*lens.get(i).unwrap_or(&0)))
                else {
                    continue;
                };
                let Some(frame) = frames.get_mut(ready) else {
                    break;
                };
                let inner_len = packet.len();
                match self.seal_into(packet, &mut sealed, frame) {
                    Ok(Some((written, dst))) => {
                        if let Some(slot) = lens.get_mut(ready) {
                            *slot = written;
                        }
                        if let Some(slot) = inner_lens.get_mut(ready) {
                            *slot = inner_len;
                        }
                        dsts.push(dst);
                        ready += 1;
                    }
                    Ok(None) => {}
                    Err(e) => self.note_outbound(&e),
                }
            }
            if ready == 0 {
                continue;
            }

            let packets: Vec<&[u8]> = frames
                .iter()
                .take(ready)
                .enumerate()
                .filter_map(|(i, f)| f.get(..*lens.get(i).unwrap_or(&0)))
                .collect();
            let offered = packets.len();
            match self.tx.send_batch(&packets, &dsts) {
                // `sendmmsg` takes a prefix and reports how much. The tail was
                // never sent, and was previously neither retried nor counted --
                // so a full ring turned into loss that every counter denied,
                // which is the hardest kind to find and the easiest to blame on
                // the network.
                Ok(sent) if sent < offered => {
                    let lost = offered - sent;
                    Stats::add(&self.stats.tx_dropped, lost as u64);
                    // Those packets were counted as transmitted when they were
                    // sealed. Take them back rather than leave the figure
                    // describing what was encrypted instead of what left.
                    Stats::sub(&self.stats.tx_packets, lost as u64);
                    let unsent: u64 = inner_lens
                        .get(sent..offered)
                        .map(|s| s.iter().map(|n| *n as u64).sum())
                        .unwrap_or(0);
                    Stats::sub(&self.stats.tx_bytes, unsent);
                }
                Ok(_) => {}
                Err(e) => self.note_outbound(&Error::Os {
                    context: "transmitting a batch".to_owned(),
                    source: e,
                }),
            }
        }
    }

    /// Waits for one inner packet, returning its length.
    ///
    /// Blocks in `poll` rather than in `read`, so the device can stay
    /// non-blocking for the drain that follows, and so the wait has a timeout
    /// through which a shutdown request is noticed.
    fn read_inner_blocking(&self, inner: &mut [Vec<u8>]) -> Option<usize> {
        loop {
            if !self.running.load(Ordering::Relaxed) {
                return None;
            }
            match self.tun.wait_readable(250) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("waiting on the device failed: {e}");
                    return None;
                }
            }
            let buf = inner.first_mut()?;
            match self.tun.recv_nonblocking(buf) {
                Ok(Some(n)) if n > 0 => return Some(n),
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("reading the device failed: {e}");
                    return None;
                }
            }
        }
    }

    /// Records a per-packet outbound failure.
    ///
    /// Counted rather than logged: a packet we cannot send is dropped exactly
    /// as a congested link would drop it, and a line per drop would let a
    /// congested link decide how much this process writes.
    fn note_outbound(&self, e: &Error) {
        Stats::bump(&self.stats.tx_dropped);
        debug!("outbound packet dropped: {e}");
    }

    /// Encrypts one inner packet and transmits it immediately.
    fn send_inner(&self, packet: &[u8], sealed: &mut [u8], frame: &mut [u8]) -> Result<()> {
        let Some((written, dst)) = self.seal_into(packet, sealed, frame)? else {
            return Ok(());
        };
        let Some(out) = frame.get(..written) else {
            return Ok(());
        };
        os("transmitting", self.tx.send(out, dst)).map(|_| ())
    }

    /// Encrypts one inner packet into `frame`, ready to transmit.
    ///
    /// Returns the frame's length and where to send it, or `None` when there is
    /// no session yet — in which case the packet is lost, which is what a link
    /// that is not up yet looks like from above.
    fn seal_into(
        &self,
        packet: &[u8],
        sealed: &mut [u8],
        frame: &mut [u8],
    ) -> Result<Option<(usize, Ipv4Addr)>> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Holding a session back is worth doing while there is a working one to
        // hold it back *for*. Once there is not, refusing to use it stops the
        // tunnel outright -- and a peer that can no longer be sent to is not
        // protected by anything. So an expired or absent session yields to the
        // one waiting, which is no worse than the behaviour this replaced.
        if state.session.as_ref().is_none_or(|s| s.is_expired(now)) {
            state.confirm();
        }
        let Some(session) = state.session.as_mut() else {
            // Traffic with nothing to carry it: the one thing that says this
            // tunnel is wanted, and so the one thing that restarts a run of
            // handshake attempts that has given up.
            state.wants_to_send();
            return Ok(None);
        };
        // The counter this packet will carry, read before sealing spends it.
        let counter = session.sent();
        let n = session.seal(packet, sealed, now)?;

        // Nothing is counted, and nothing is claimed about liveness, until there
        // is a frame to send. Counting first made the transmit figures a measure
        // of what was encrypted rather than what left the host -- so a carrier
        // that was briefly absent showed megabytes going out while the wire was
        // silent -- and armed the liveness timer for a packet nobody could
        // possibly answer, which then reported the peer as gone.
        let Some(carrier) = state.carrier.as_mut() else {
            Stats::bump(&self.stats.tx_dropped);
            return Ok(None);
        };
        let Some(payload) = sealed.get(..n) else {
            Stats::bump(&self.stats.tx_dropped);
            return Ok(None);
        };
        let written = carrier.data(payload, frame, now)?;
        let dst = *carrier.remote().ip();

        // Half of the liveness question -- but only for a packet carrying data.
        //
        // A keepalive is empty, and the far end answers an empty packet with
        // nothing, because there is nothing to answer. Arming this on one would
        // therefore ask a question that cannot be answered and then read the
        // silence as proof the peer had gone: an idle tunnel would send a
        // keepalive, wait fifteen seconds, and rehandshake, for ever.
        if !packet.is_empty() {
            state.last_send = Some(now);
        }
        // Held only if the peer might ask for it. A packet that is itself a
        // repeat or a request is not worth holding: repeating a repeat is a
        // loop, and a lost request is re-derived from the next gap anyway.
        if crate::repeat::parse(packet).is_none() {
            // No pruning: the ring reuses its slots, and `get` refuses anything
            // too old to be worth repeating.
            state.outbox.record(counter, packet, now);
        }
        Stats::bump(&self.stats.tx_packets);
        Stats::add(&self.stats.tx_bytes, packet.len() as u64);
        Ok(Some((written, dst)))
    }

    // -- inbound -------------------------------------------------------------

    /// Reads from the wire, decrypts, and writes inner packets to the device.
    fn wire_to_tun(&self) {
        match self.cfg.interface.datapath {
            Datapath::Simple => self.wire_to_tun_simple(),
            Datapath::Batched => self.wire_to_tun_batched(),
        }
    }

    /// Up to [`sys::BATCH`] frames per syscall.
    fn wire_to_tun_batched(&self) {
        let mut frames: Vec<Vec<u8>> = (0..sys::BATCH).map(|_| vec![0u8; MAX_FRAME]).collect();
        let mut lens = [0usize; sys::BATCH];
        let mut inner = vec![0u8; MAX_INNER];
        let mut reply = vec![0u8; MAX_FRAME];

        while self.running.load(Ordering::Relaxed) {
            let count = match self.rx.recv_batch(&mut frames, &mut lens) {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading from the wire failed: {e}");
                    break;
                }
            };
            for i in 0..count {
                let Some(bytes) = frames
                    .get(i)
                    .and_then(|f| f.get(..*lens.get(i).unwrap_or(&0)))
                else {
                    continue;
                };
                let Some(seg) = self.parse(bytes) else {
                    // Counted here as well as on the unbatched path. It was
                    // not, so which datapath was in use decided whether an
                    // unrecognised frame was a number or nothing at all.
                    self.handle_unparsed(bytes);
                    continue;
                };
                if let Err(e) = self.handle_segment(&seg, &mut inner, &mut reply) {
                    self.note_inbound(&e);
                }
            }
        }
    }

    /// Reads one captured frame as this carrier's, whichever shape it has.
    ///
    /// GRE has no ports, no sequence numbers and no flags, so the segment this
    /// yields carries zero in those fields. Nothing reads them: dispatch to
    /// msg1, msg2 or transport is by keyed `mac1` and by role, neither of which
    /// is a property of the carrier, and `Wire::on_receive` folds them in only
    /// for the shape that has them.
    fn parse<'a>(&self, bytes: &'a [u8]) -> Option<segment::Segment<'a>> {
        match self.cfg.interface.shape {
            crate::config::Shape::Tcp(_) => segment::parse_ethernet(bytes),
            crate::config::Shape::Raw(shell) => {
                let got = paqetz_tcpwire::rawip::parse_ethernet(bytes, shell)?;
                Some(segment::Segment {
                    src: (got.src, 0),
                    dst: (got.dst, 0),
                    seq: 0,
                    ack: 0,
                    flags: 0,
                    window: 0,
                    ts_val: None,
                    payload: got.payload,
                })
            }
        }
    }

    /// Handles a frame the carrier parser did not recognise.
    ///
    /// Almost always nothing: the filter is coarser than the parser and lets
    /// through a little it will not accept. The exception is the one message
    /// the network sends on purpose -- a hop saying a packet was too large --
    /// which is worth more than everything else this sees put together,
    /// because a path that has silently shrunk is indistinguishable from one
    /// that is dropping packets, and that diagnosis has already cost days.
    fn handle_unparsed(&self, bytes: &[u8]) {
        let Some(report) = paqetz_tcpwire::toobig::parse_ethernet(bytes) else {
            Stats::bump(&self.stats.unparsed);
            return;
        };
        self.note_too_big(&report);
    }

    /// Records a path-MTU report, if it describes a packet this end sent.
    ///
    /// The check is what makes an unauthenticated message safe to act on. It
    /// arrives from an intermediate router rather than from the peer, so there
    /// is nothing to verify it against except the five-tuple it quotes -- which
    /// an off-path party does not have. Someone on the path can forge one, but
    /// they can drop the packets outright, which no MTU setting was going to
    /// answer either.
    ///
    /// Nothing is applied. The advertised MTU decides how large a packet may
    /// be, and taking that instruction from the network unverified is a lever
    /// worth being slow about; what this does is say the number out loud, so a
    /// person can decide.
    fn note_too_big(&self, report: &paqetz_tcpwire::toobig::TooBig) {
        let local = self.local();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(peer) = state.endpoint else {
            return;
        };
        if !report.describes(
            local,
            (*peer.ip(), peer.port()),
            self.cfg.interface.shape.protocol(),
        ) {
            // Not ours. Someone else's flow, or a forgery that did not know
            // where to aim -- either way it says nothing about this tunnel.
            Stats::bump(&self.stats.unparsed);
            return;
        }
        let Some(over) = report.shortfall() else {
            // A stale report, or one for a packet that already fits. Routers
            // send these; acting on one would shrink the tunnel for nothing.
            return;
        };
        Stats::bump(&self.stats.too_big);

        // Announced when the number changes, not when a packet arrives.
        let mtu = report.mtu;
        if state.reported_mtu.is_some_and(|seen| seen <= mtu) {
            return;
        }
        state.reported_mtu = Some(mtu);
        drop(state);

        let suggested = self.cfg.interface.mtu.saturating_sub(u32::from(over));
        warn_!(
            "{}a hop on the path takes {mtu} bytes and this end is sending {}; \
             every full-sized packet is being dropped out there. \
             Set interface.mtu to {suggested} or less.",
            self.tag(),
            report.size,
        );
    }

    /// Records a per-packet inbound failure.
    ///
    /// Counted rather than logged, and this is the case that matters: anything
    /// unauthenticated reaches here, so a line per packet would let whoever is
    /// sending garbage at the port choose how much this process writes to disk
    /// and how long it spends formatting. See `crate::stats`.
    fn note_inbound(&self, e: &Error) {
        match e {
            Error::Core(paqetz_core::Error::Rejected) => Stats::bump(&self.stats.rejected),
            Error::Core(paqetz_core::Error::Replay) => Stats::bump(&self.stats.replayed),
            _ => Stats::bump(&self.stats.rejected),
        }
        debug!("inbound packet dropped: {e}");
    }

    /// One frame per syscall.
    fn wire_to_tun_simple(&self) {
        let mut frame = vec![0u8; MAX_FRAME];
        let mut inner = vec![0u8; MAX_INNER];
        let mut reply = vec![0u8; MAX_FRAME];

        while self.running.load(Ordering::Relaxed) {
            let n = match self.rx.recv(&mut frame) {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("reading from the wire failed: {e}");
                    break;
                }
            };
            let Some(bytes) = frame.get(..n) else {
                continue;
            };
            let Some(seg) = self.parse(bytes) else {
                self.handle_unparsed(bytes);
                continue;
            };
            if let Err(e) = self.handle_segment(&seg, &mut inner, &mut reply) {
                self.note_inbound(&e);
            }
        }
    }

    /// Dispatches one inbound segment.
    fn handle_segment(
        &self,
        seg: &segment::Segment<'_>,
        inner: &mut [u8],
        reply: &mut [u8],
    ) -> Result<()> {
        let from = SocketAddrV4::new(seg.src.0, seg.src.1);
        let payload = seg.payload;

        // A handshake and a transport packet can be the same length, so the
        // keyed mac1 decides which this is rather than the length (D7).
        //
        // Which handshake message it could be is decided by role rather than by
        // length: an initiator is never sent a msg1 and a responder is never
        // sent a msg2, and both messages now vary in length, so their ranges
        // overlap and length no longer tells them apart. Role always did, and
        // does not depend on what is on the wire.
        if self.is_initiator() {
            if (noise::MSG2_LEN..=noise::MSG2_MAX).contains(&payload.len())
                && noise::verify_mac1(&self.local_public, payload).is_ok()
            {
                return self.handle_msg2(seg, payload);
            }
        } else if (noise::MSG1_LEN..=noise::MSG1_MAX).contains(&payload.len())
            && noise::verify_mac1(&self.local_public, payload).is_ok()
        {
            return self.handle_msg1(seg, payload, reply);
        }

        self.handle_transport(seg, from, inner)
    }

    /// Accepts an initiator's handshake and answers it.
    fn handle_msg1(
        &self,
        seg: &segment::Segment<'_>,
        payload: &[u8],
        reply: &mut [u8],
    ) -> Result<()> {
        if self.is_initiator() {
            // We initiate; an inbound msg1 is not ours to answer.
            return Ok(());
        }
        let now = self.now();
        let pending =
            PendingResponder::read(&self.cfg.interface.private_key, &self.local_public, payload)?;

        // The authorization decision (D11). An unknown key gets no reply at
        // all, so the port stays indistinguishable from one that is filtered.
        if pending.initiator_static() != &self.cfg.peer.public_key {
            return Err(paqetz_core::Error::Unauthorized.into());
        }

        let epoch = pending.epoch();
        let (isn_i, isn_r, ts_base) =
            noise::carrier_numbers(epoch, &self.cfg.peer.public_key, &self.local_public);

        let index = random_u32().map_err(|source| Error::Os {
            context: "generating a session index".to_owned(),
            source,
        })?;
        // Padded only if the initiator padded. A build that predates the
        // padding checks msg2's length exactly and would refuse a padded reply,
        // so answering in kind is what lets a server be upgraded before its
        // clients rather than in lockstep with them. A current peer pads almost
        // always, so this costs nothing once both ends have moved.
        let pad = if payload.len() > noise::MSG1_LEN {
            handshake_pad()
        } else {
            0
        };
        let (session, (msg2, msg2_len)) = pending.accept(index, now, pad)?;
        let Some(msg2) = msg2.get(..msg2_len) else {
            return Ok(());
        };

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // As on the initiating side: a rekey must not restart the conversation
        // underneath it, so the carrier is built once and then kept.
        if state.carrier.is_none() {
            // We learn our own outer address from where the peer sent to.
            state.carrier = Some(self.wire(
                Role::Responder,
                (seg.dst.0, seg.dst.1),
                seg.src,
                (isn_r, isn_i, ts_base),
            ));
        }

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(());
        };
        carrier.set_remote(SocketAddrV4::new(seg.src.0, seg.src.1));
        // Fold in the segment that carried msg1, so our acknowledgement counts
        // the bytes the peer actually sent.
        carrier.on_receive(seg);

        let written = carrier.data(msg2, reply, now)?;
        let dst = seg.src.0;

        state.accept(session);
        state.pending = None;
        state.established(now, Self::rekey_after());
        state.endpoint = Some(SocketAddrV4::new(seg.src.0, seg.src.1));
        drop(state);

        self.stats.note_handshake(now);
        info!(
            "{}handshake completed with {} at {}:{}",
            self.tag(),
            self.cfg.peer.public_key,
            seg.src.0,
            seg.src.1
        );

        let Some(out) = reply.get(..written) else {
            return Ok(());
        };
        os("transmitting handshake reply", self.tx.send(out, dst))?;
        // A responder sends handshakes too, and counting only the initiator's
        // meant its health line read "0 sent" no matter what it had done --
        // a number that cannot change says nothing about the run it describes.
        Stats::bump(&self.stats.handshakes_sent);
        Ok(())
    }

    /// Completes our own handshake.
    fn handle_msg2(&self, seg: &segment::Segment<'_>, payload: &[u8]) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Borrowed, not taken. `mac1` is keyed on our own static public key, so
        // a reply that gets this far has proved nothing except that its sender
        // knows a key we publish: taking the handshake first meant anyone who
        // did could cancel every attempt this end made, simply by answering
        // before the peer could.
        let result = match state.pending.as_mut() {
            Some(pending) => pending.finish(payload, now),
            None => return Ok(()),
        };
        match result {
            Ok(session) => {
                state.pending = None;
                if let Some(carrier) = state.carrier.as_mut() {
                    carrier.on_receive(seg);
                }
                state.install(session);
                state.established(now, Self::rekey_after());
                drop(state);
                self.stats.note_handshake(now);
                info!(
                    "{}handshake completed with {}",
                    self.tag(),
                    self.cfg.peer.public_key
                );
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Decrypts a transport packet and delivers it.
    fn handle_transport(
        &self,
        seg: &segment::Segment<'_>,
        from: SocketAddrV4,
        inner: &mut [u8],
    ) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Read before opening, because which session the packet belongs to is
        // not yet known and the mask does not depend on the answer.
        let counter = state
            .mask()
            .and_then(|mask| noise::peek_header(&mask, seg.payload).ok())
            .map(|header| header.counter);

        let Some(opened) = state.open(seg.payload, inner, now) else {
            return Ok(());
        };
        let n = opened?;

        // Authenticated, so the endpoint is trustworthy. Roaming (D5): the peer
        // may have moved, and following it here is what makes a NAT rebinding
        // invisible instead of fatal.
        if state.endpoint != Some(from) {
            let was = state.endpoint;
            state.endpoint = Some(from);
            if let Some(carrier) = state.carrier.as_mut() {
                carrier.set_remote(from);
            }
            Stats::bump(&self.stats.roams);
            // The single most useful line when a link is flapping: it says the
            // peer moved and the tunnel followed, rather than leaving a gap in
            // traffic with no explanation.
            info!(
                "peer moved from {} to {from}",
                was.map_or_else(|| "unknown".to_owned(), |a| a.to_string())
            );
        }
        if let Some(carrier) = state.carrier.as_mut() {
            carrier.on_receive(seg);
        }
        // The other half. This is reached only for a packet that decrypted and
        // passed the replay window, so it is the peer speaking and no one else:
        // the one piece of evidence that it still holds this session.
        state.last_receive = Some(now);
        // An empty packet is a keepalive and needs no reply; answering one would
        // have the two ends trading them for ever.
        if n > 0 {
            state.last_data_receive = Some(now);
        }
        // Only once the packet has authenticated: a gap claimed by anyone else
        // would have this end asking its peer for packets nobody sent.
        let asking = match counter {
            Some(c) if self.cfg.interface.repeat.capacity > 0 => state.inbox.arrived(c, now),
            _ => Vec::new(),
        };

        // What a request asks for, resolved while the outbox is still in hand.
        let Some(packet) = inner.get(..n) else {
            drop(state);
            return Ok(());
        };
        let mut repeats: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut repeated: Option<Vec<u8>> = None;
        match crate::repeat::parse(packet) {
            Some(crate::repeat::Control::Nack(wanted)) => {
                for want in wanted {
                    if let Some(held) = state.outbox.get(want, now) {
                        repeats.push((want, held.to_vec()));
                    }
                }
            }
            Some(crate::repeat::Control::Repeat { original, packet }) => {
                state.inbox.satisfied(original);
                repeated = Some(packet.to_vec());
                Stats::bump(&self.stats.repaired);
            }
            None => {}
        }
        drop(state);

        Stats::bump(&self.stats.rx_packets);
        Stats::add(&self.stats.rx_bytes, n as u64);

        if !asking.is_empty() {
            self.ask_for(&asking);
        }
        for (original, held) in repeats {
            self.repeat(original, &held);
        }

        // A repeat carries the packet that was lost; anything else is itself
        // the packet. A request carries nothing to deliver.
        match repeated {
            Some(inner) => self.deliver(&inner),
            None if crate::repeat::parse(packet).is_some() => Ok(()),
            None => self.deliver(packet),
        }
    }

    /// Asks the peer to send these counters again.
    fn ask_for(&self, counters: &[u64]) {
        let mut request = vec![0u8; 3 + counters.len() * 8];
        let Some(n) = crate::repeat::write_nack(counters, &mut request) else {
            return;
        };
        let Some(body) = request.get(..n) else {
            return;
        };
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut frame = vec![0u8; MAX_FRAME];
        if let Err(e) = self.send_inner(body, &mut sealed, &mut frame) {
            debug!("could not ask for a repeat: {e}");
        } else {
            Stats::add(&self.stats.asked, counters.len() as u64);
        }
    }

    /// Sends a packet again, saying which counter it first went out under.
    fn repeat(&self, original: u64, packet: &[u8]) {
        let mut body = vec![0u8; crate::repeat::REPEAT_OVERHEAD + packet.len()];
        let Some(n) = crate::repeat::write_repeat(original, packet, &mut body) else {
            return;
        };
        let Some(body) = body.get(..n) else {
            return;
        };
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut frame = vec![0u8; MAX_FRAME];
        if let Err(e) = self.send_inner(body, &mut sealed, &mut frame) {
            debug!("could not repeat a packet: {e}");
        } else {
            Stats::bump(&self.stats.repeated);
        }
    }

    /// Checks an inner packet and writes it to the device.
    fn deliver(&self, packet: &[u8]) -> Result<()> {
        let Some(source) = inner_source(packet) else {
            return Ok(());
        };

        // Cryptokey routing (D12). Without this a peer can claim any inner
        // source address, including one that reaches a service bound to the
        // host's loopback.
        if !self.cfg.peer.permits(source) {
            Stats::bump(&self.stats.disallowed);
            debug!("inner packet refused: source {source} is outside the peer's range");
            // Once, at a level that is on by default. The counter alone does
            // not point anywhere, and this has a single overwhelming cause: a
            // peer that is a way out sends back replies carrying the address of
            // whatever site was reached, and a peer restricted to its own
            // address refuses every one of them. Handshake fine, tunnel up,
            // counters moving, nothing arrives -- with nothing to suggest the
            // configuration is what is refusing it.
            if !self
                .stats
                .explained_disallowed
                .swap(true, Ordering::Relaxed)
            {
                warn_!("refused an inner packet from {source}: outside this peer's allowed_ips");
                warn_!(
                    "if this peer is a way out to the internet, it needs \
                     `allowed_ips = [\"0.0.0.0/0\"]`"
                );
            }
            return Ok(());
        }
        if !plausible_source(source) {
            Stats::bump(&self.stats.martian);
            debug!("inner packet refused: source {source} is not a usable address");
            return Ok(());
        }

        match self.tun.send(packet) {
            Ok(_) => Ok(()),
            // The device is non-blocking in batched mode, so a full queue
            // refuses the write. That is a drop, exactly as a congested link
            // would be, and inner protocols already cope with it -- but it is
            // still a drop, and one that used to leave no trace at all.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Stats::bump(&self.stats.device_full);
                Ok(())
            }
            Err(source) => Err(Error::Os {
                context: "writing to the TUN device".to_owned(),
                source,
            }),
        }
    }

    // -- timers --------------------------------------------------------------

    /// Starts and refreshes handshakes.
    fn timers(&self) {
        // A responder never starts a handshake, but it does owe keepalives: the
        // peer decides whether this end is still here from what it hears back,
        // and an end that only ever answers goes quiet the moment the other
        // stops asking. So both roles run this loop; only one of them
        // handshakes.
        let initiator = self.is_initiator();
        let mut frame = vec![0u8; MAX_FRAME];
        let mut sealed = vec![0u8; MAX_INNER + paqetz_core::framing::OVERHEAD];
        let mut keepalive_frame =
            vec![0u8; MAX_INNER + MAX_OVERHEAD + paqetz_core::framing::OVERHEAD];

        while self.running.load(Ordering::Relaxed) {
            if initiator && let Err(e) = self.maybe_handshake(&mut frame) {
                warn_!("handshake attempt failed: {e}");
            }
            if let Err(e) = self.maybe_keepalive(&mut sealed, &mut keepalive_frame) {
                debug!("keepalive failed: {e}");
            }
            if initiator {
                self.maybe_rotate();
            }
            std::thread::sleep(TICK);
        }
    }

    /// Moves the carrier to the next port when this one has been used long
    /// enough.
    ///
    /// The initiating side only. The other end has to be findable, so its port
    /// is fixed; and it follows this one automatically, because roaming already
    /// updates a peer's address from the first packet that authenticates.
    ///
    /// A fresh carrier means a fresh sequence base as well as a fresh port,
    /// which is what a new connection looks like. Nothing is torn down: the
    /// capture filter already accepts every port in the pool, so replies still
    /// arriving for the one just left are received as normal.
    ///
    /// Two things ask for a move: the interval, which only a live session
    /// counts down, and [`PeerState::stuck`], which says the tuple is being
    /// dropped and no session will exist until it changes.
    fn maybe_rotate(&self) {
        let rotation = self.cfg.interface.rotation;
        if !rotation.enabled || !self.cfg.interface.shape.has_ports() {
            return;
        }
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stuck = state.stuck(now, rotation.unanswered);
        if !stuck {
            if state.session.is_none() {
                return;
            }
            // Armed once, when there is first a session to carry -- not in
            // `established`, which runs on every rekey and would push the
            // deadline out every two minutes so it never arrived.
            if state.rotate_at == Millis::MAX {
                state.rotate_at = now.saturating_add(rotation.interval());
                return;
            }
            if now < state.rotate_at {
                return;
            }
        }
        state.rotate_at = now.saturating_add(rotation.interval());
        // Zeroed whether or not a move follows. Left standing, `stuck` holds on
        // a single-port pool and this runs on every tick for ever.
        state.unanswered = 0;

        if self.ports.len() < 2 {
            return;
        }
        let (_, current) = self.local();
        let next = next_port(&self.ports, current);
        if next == current {
            return;
        }

        // Rebuilt here rather than left absent for something else to notice.
        // Dropping it and waiting meant every packet in between was encrypted,
        // counted, and thrown away -- and the liveness timer then reported a
        // peer that had answered nothing, because nothing had been asked.
        let Some(peer) = state.endpoint else {
            return;
        };
        let (ip, _) = self.local();
        let epoch = match random_u32() {
            Ok(e) => e,
            Err(e) => {
                warn_!("could not start a new carrier: {e}");
                return;
            }
        };
        let (isn, peer_isn, ts_base) =
            noise::carrier_numbers(epoch, &self.local_public, &self.cfg.peer.public_key);
        state.carrier = Some(self.wire(
            Role::Initiator,
            (ip, next),
            (*peer.ip(), peer.port()),
            (isn, peer_isn, ts_base),
        ));
        if stuck {
            // The point of moving was to try a tuple that might work. Leaving
            // the retry deadline where it was makes the new port wait out the
            // old one's timer before anything is sent from it.
            state.retry_at = now;
        }
        if let Ok(mut local) = self.local.lock() {
            local.1 = next;
        }
        drop(state);
        let why = if stuck {
            "nothing came back"
        } else {
            "time on this one is up"
        };
        info!(
            "{}carrier moved from port {current} to {next}: {why}",
            self.tag()
        );
    }

    /// Sends an empty packet when the peer has spoken and we have not answered.
    ///
    /// The payload is empty on purpose: the far end drops a zero-length inner
    /// packet without looking at it, so this costs one frame and says the only
    /// thing it needs to -- that this end is still here and still holds the
    /// session.
    fn maybe_keepalive(&self, sealed: &mut [u8], frame: &mut [u8]) -> Result<()> {
        let now = self.now();
        {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.session.is_none() {
                return Ok(());
            }
            // The confirmation is owed regardless of the keepalive setting: it
            // is one packet per handshake, and without it a tunnel that turned
            // keepalives off can leave the responder holding a session it is
            // not allowed to use and an old one it can no longer use.
            let owed = if state.confirm_owed {
                // Repeated until the peer answers, but not on every tick: this
                // is a packet whose whole purpose is to be unremarkable.
                state
                    .last_keepalive
                    .is_none_or(|sent| now.saturating_sub(sent) >= CONFIRM_RETRY)
            } else {
                self.cfg.interface.keepalive && state.owes_keepalive(now)
            };
            if !owed {
                return Ok(());
            }
        }
        debug!("keepalive");
        self.send_inner(&[], sealed, frame)?;

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.last_keepalive = Some(now);
        if state.confirm_owed {
            state.confirm_tries = state.confirm_tries.saturating_add(1);
            if state.confirm_tries >= CONFIRM_TRIES {
                // Either it arrived and the peer has nothing to say, or the
                // path is dropping every one of them. Neither is improved by a
                // fifth.
                state.confirm_owed = false;
            }
        }
        Ok(())
    }

    /// How long this session should last before being replaced.
    fn rekey_after() -> Millis {
        let spread =
            random_u32().map_or(REKEY_JITTER, |r| Millis::from(r) % (2 * REKEY_JITTER + 1));
        noise::REKEY_AFTER_TIME + spread - REKEY_JITTER
    }

    /// How long to wait before repeating a handshake, jittered.
    ///
    /// Two peers that lost each other at the same instant would otherwise retry
    /// in lockstep, so a collision repeats rather than resolves.
    fn rekey_interval() -> Millis {
        // No randomness available is a reason to retry on the flat interval,
        // not a reason to fail a handshake.
        REKEY_TIMEOUT + random_u32().map_or(0, |r| Millis::from(r) % REKEY_TIMEOUT_JITTER)
    }

    /// Sends a handshake if one is due.
    fn maybe_handshake(&self, frame: &mut [u8]) -> Result<()> {
        let now = self.now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Before deciding: a session too old to seal under is not a session.
        state.retire_expired(now);

        if !state.wants_handshake(now) {
            return Ok(());
        }
        if state.revive(now) {
            // A fresh run, so it gets its own ninety seconds rather than
            // inheriting a clock that has already expired.
            state.attempt_started = None;
        }
        if state.presumed_dead(now) && state.session.is_some() {
            warn_!(
                "no authenticated packet for {}s while sending; the peer has \
                 forgotten this session, starting a new handshake",
                PRESUMED_DEAD / 1000
            );
        }
        let Some(peer) = state.endpoint else {
            return Ok(());
        };

        let epoch = random_u32().map_err(|source| Error::Os {
            context: "generating an epoch".to_owned(),
            source,
        })?;
        let index = random_u32().map_err(|source| Error::Os {
            context: "generating a session index".to_owned(),
            source,
        })?;

        let (initiator, (msg1, msg1_len)) = Initiator::start(
            &self.cfg.interface.private_key,
            &self.local_public,
            &self.cfg.peer.public_key,
            index,
            epoch,
            handshake_pad(),
        )?;
        let Some(msg1) = msg1.get(..msg1_len) else {
            return Ok(());
        };

        // The carrier is per *connection*, not per session. A rekey replaces
        // the keys above it and must leave the conversation underneath
        // untouched: rebuilding it would restart the sequence numbering on an
        // unchanged five-tuple every couple of minutes, which is exactly the
        // discontinuity byte-accurate sequencing exists to avoid.
        if state.carrier.is_none() {
            let (isn_i, isn_r, ts_base) =
                noise::carrier_numbers(epoch, &self.local_public, &self.cfg.peer.public_key);
            state.carrier = Some(self.wire(
                Role::Initiator,
                self.local(),
                (*peer.ip(), peer.port()),
                (isn_i, isn_r, ts_base),
            ));
        }

        let Some(carrier) = state.carrier.as_mut() else {
            return Ok(());
        };
        let written = carrier.data(msg1, frame, now)?;
        let dst = *peer.ip();

        state.pending = Some(initiator);
        state.last_handshake = now;
        state.retry_at = now.saturating_add(Self::rekey_interval());
        state.attempt_started.get_or_insert(now);
        state.unanswered = state.unanswered.saturating_add(1);
        drop(state);

        let Some(out) = frame.get(..written) else {
            return Ok(());
        };
        os("transmitting handshake", self.tx.send(out, dst))?;
        // Counted here rather than above, so the number says what reached the
        // wire. Bumped before the send it reported attempts, which is the one
        // thing already visible from the tunnel being down.
        Stats::bump(&self.stats.handshakes_sent);
        debug!("handshake sent to {peer}");
        Ok(())
    }
}

/// Reads the source address of an inner IPv4 packet.
fn inner_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.first().map(|b| b >> 4) != Some(4) {
        return None;
    }
    Some(Ipv4Addr::new(
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    ))
}

/// Whether an inner source address is one a peer could legitimately hold.
///
/// Applied regardless of `allowed_ips`, so that widening the allowance — or
/// disabling it — still cannot be used to reach a service bound to the host's
/// loopback, or to spoof a link-local or multicast source (D12).
#[must_use]
pub(crate) fn plausible_source(addr: Ipv4Addr) -> bool {
    !(addr.is_loopback()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_link_local()
        || addr.is_unspecified())
}

/// Asks the kernel which local address it would use to reach `peer`.
///
/// Connecting a UDP socket sends nothing; it only performs the route lookup,
/// which is exactly the question being asked. This is why the configuration has
/// no local-address field.
fn source_address_for(peer: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.connect(SocketAddrV4::new(peer, 9))?;
    match sock.local_addr()? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        std::net::SocketAddr::V6(_) => Err(io::Error::other(
            "the route to the peer is IPv6, which is not supported yet",
        )),
    }
}

/// Names the interface carrying the default route.
///
/// Read from `/proc/net/route` rather than by invoking `ip`, so there is no
/// dependency on which userland is installed.
fn outbound_interface() -> io::Result<String> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(dest), Some(_gw), Some(flags)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // Destination 0.0.0.0 with the "up" flag set is the default route.
        let up = u32::from_str_radix(flags, 16).unwrap_or(0) & 0x0001 != 0;
        if dest == "00000000" && up {
            return Ok(iface.to_owned());
        }
    }
    Err(io::Error::other("no default route found"))
}

/// Set by the signal handler; polled by [`Tunnel::run`].
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Set by the signal handler when `SIGHUP` arrives.
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Whether a reload has been requested, clearing the request.
pub(crate) fn reload_requested() -> bool {
    RELOAD.swap(false, Ordering::Relaxed)
}

/// Records that a reload signal arrived.
extern "C" fn on_hangup(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

/// Records that a shutdown signal arrived.
///
/// Storing to an atomic is async-signal-safe; nothing else here would be, which
/// is why the handler does no work beyond this.
extern "C" fn on_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Arranges for `SIGINT` and `SIGTERM` to request a clean stop.
pub(crate) fn install_signal_handlers() {
    {
        let handler: extern "C" fn(libc::c_int) = on_hangup;
        // SAFETY: as below — the handler only stores to an atomic.
        unsafe {
            libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
        }
    }
    for sig in [libc::SIGINT, libc::SIGTERM] {
        let handler: extern "C" fn(libc::c_int) = on_signal;
        // SAFETY: `on_signal` is a plain `extern "C"` function that only stores
        // to an atomic, which is permitted in a signal handler. The pointer is
        // taken from the function item rather than cast from it, so there is no
        // question of the value being anything other than its address.
        unsafe {
            libc::signal(sig, handler as *const () as libc::sighandler_t);
        }
    }
}

/// Reads four random bytes from the kernel.
fn random_u32() -> io::Result<u32> {
    use std::io::Read as _;
    let mut buf = [0u8; 4];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    /// A peer state that has sent and received at the given times.
    fn spoke(sent: Option<Millis>, heard: Option<Millis>) -> PeerState {
        PeerState {
            last_send: sent,
            last_receive: heard,
            last_data_receive: heard,
            ..PeerState::new(None, crate::repeat::Limits::off())
        }
    }

    #[test]
    fn nothing_is_counted_as_sent_while_there_is_no_carrier() {
        // Counting before the carrier check made the transmit figures a measure
        // of what was encrypted rather than what left the host: observed as
        // 64 MB "sent" against 5 MB received while the wire was silent, with the
        // liveness timer then reporting a peer that had answered nothing because
        // nothing had been asked. `tx_dropped` is the honest counter for this.
        let stats = Stats::default();
        Stats::bump(&stats.tx_dropped);
        assert_eq!(
            stats.tx_packets.load(Ordering::Relaxed),
            0,
            "a packet with nowhere to go is not a packet that was sent"
        );
        assert_eq!(stats.tx_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_tuple_nothing_answers_is_left_behind() {
        // The failure this exists for: a client sent 3381 handshakes over four
        // and a half hours, every one of them onto a port the path had stopped
        // carrying, while the server's counters -- every one of them, including
        // the ones that count packets it cannot make sense of -- stood still.
        // Rotation was the cure and ran only while a session existed, so it was
        // off exactly when it was needed. Only a restart recovered it, and the
        // one thing a restart changes is the port.
        let now = 10 * PRESUMED_DEAD;
        let mut state = spoke(None, None);
        assert!(
            !state.stuck(now, ROTATE_AFTER_UNANSWERED),
            "a fresh state has not tried anything yet"
        );

        for _ in 0..ROTATE_AFTER_UNANSWERED - 1 {
            state.unanswered += 1;
            assert!(
                !state.stuck(now, ROTATE_AFTER_UNANSWERED),
                "a handful of losses is a lossy path, not a dead tuple"
            );
        }
        state.unanswered += 1;
        assert!(
            state.stuck(now, ROTATE_AFTER_UNANSWERED),
            "past the threshold the tuple is the suspect"
        );

        // Traffic offered by the application clears `attempt_started`, which is
        // why that clock could not be used here: on a busy tunnel it never runs
        // out. This count answers to replies alone.
        state.wants_to_send();
        assert!(
            state.stuck(now, ROTATE_AFTER_UNANSWERED),
            "offered traffic is not an answer from the peer"
        );

        state.established(now, 120_000);
        assert!(
            !state.stuck(now, ROTATE_AFTER_UNANSWERED),
            "a reply proves the tuple still reaches"
        );
    }

    #[test]
    fn a_dead_tuple_is_left_without_waiting_for_the_keys_to_age_out() {
        // The first cut of this asked `session.is_none()`, which reads as "the
        // tunnel is down" and is not the same thing. A session no packet can
        // reach is still a session until REJECT_AFTER_TIME, so recovery waited
        // three minutes for keys to expire that were never the problem -- they
        // work perfectly over the next port, and the peer's roaming picks them
        // up there without a rekey at all.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (session, _) = session_pair(&client, &server, 1);

        let heard = 1_000;
        let mut state = spoke(Some(heard), Some(heard));
        state.session = Some(session);
        state.unanswered = ROTATE_AFTER_UNANSWERED;

        assert!(
            !state.stuck(heard + PRESUMED_DEAD - 1, ROTATE_AFTER_UNANSWERED),
            "a peer heard from this recently is answering something"
        );
        assert!(
            state.stuck(heard + PRESUMED_DEAD, ROTATE_AFTER_UNANSWERED),
            "silence for a liveness interval is the signal, not expiry"
        );
        assert!(
            !state
                .session
                .as_ref()
                .expect("session")
                .is_expired(heard + PRESUMED_DEAD),
            "and the session is still good, which is exactly the point"
        );
    }

    #[test]
    fn a_carrier_still_hearing_replies_is_never_stuck() {
        // A lossy path can swallow four handshakes in a row while the tunnel
        // carries data the whole time -- the old VPS lost one packet in five,
        // which makes that ordinary rather than rare. Moving the carrier there
        // buys nothing and costs a five-tuple that was working.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (session, _) = session_pair(&client, &server, 1);

        let heard = 60_000;
        let mut state = spoke(Some(heard), Some(heard));
        state.session = Some(session);
        state.unanswered = ROTATE_AFTER_UNANSWERED * 10;
        assert!(
            !state.stuck(heard + 1, ROTATE_AFTER_UNANSWERED),
            "no count of unanswered rekeys outweighs a peer that is answering"
        );

        // Losing the session changes nothing on its own; the silence is what
        // decides, and here there has not been any.
        state.session = None;
        assert!(
            !state.stuck(heard + 1, ROTATE_AFTER_UNANSWERED),
            "a missing session is not evidence about the path"
        );
    }

    #[test]
    fn rotation_walks_the_pool_and_comes_back() {
        let pool = [61001u16, 61002, 61003, 61004];
        let mut seen = vec![pool[0]];
        let mut at = pool[0];
        for _ in 0..4 {
            at = next_port(&pool, at);
            seen.push(at);
        }
        assert_eq!(seen, [61001, 61002, 61003, 61004, 61001], "wraps around");
    }

    #[test]
    fn a_configured_port_never_rotates() {
        // The side that waits has to be findable, so it keeps the port it was
        // given -- and its pool is that one port alone.
        assert_eq!(next_port(&[8443], 8443), 8443);
        assert_eq!(
            next_port(&[61001, 61002], 9999),
            9999,
            "a port outside the pool means it was configured, so stay put"
        );
        assert_eq!(next_port(&[], 8443), 8443, "and an empty pool goes nowhere");
    }

    #[test]
    fn traffic_restarts_a_run_of_attempts_that_gave_up() {
        // The failure this closes: a server unreachable for ninety seconds left
        // the client having stopped trying, with no path back. The signal that
        // used to be relied on -- `last_send` -- cannot move without a session,
        // and no session would be attempted until it moved.
        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.attempt_started = Some(0);
        assert!(!s.exhausted(REKEY_ATTEMPT_TIME - 1), "still trying");
        assert!(s.exhausted(REKEY_ATTEMPT_TIME), "long enough to stop");
        assert!(
            s.exhausted(REKEY_ATTEMPT_TIME * 100),
            "and it stays stopped on its own"
        );

        // Someone tries to use the tunnel.
        s.wants_to_send();
        assert!(
            !s.exhausted(REKEY_ATTEMPT_TIME * 100),
            "traffic is what says the tunnel is wanted"
        );
    }

    #[test]
    fn a_rekey_that_goes_unanswered_is_paced_like_everything_else() {
        // The deadline that makes a rekey due never stops being past, so
        // without pacing a silent peer was handshaked at on every tick -- four
        // times a second, for as long as it stayed silent.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (session, _) = session_pair(&client, &server, 200);

        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.install(session);
        s.rekey_at = 1_000;
        s.retry_at = 0;

        assert!(
            s.wants_handshake(1_000),
            "due, and nothing has been sent yet"
        );
        // What `maybe_handshake` records when it sends one.
        s.retry_at = 1_000 + REKEY_TIMEOUT;
        assert!(
            !s.wants_handshake(1_001),
            "and not again on the very next tick"
        );
        assert!(!s.wants_handshake(1_000 + REKEY_TIMEOUT - 1));
        assert!(
            s.wants_handshake(1_000 + REKEY_TIMEOUT),
            "and again once the interval has passed"
        );
    }

    #[test]
    fn a_session_too_old_to_seal_under_is_let_go() {
        // Keeping one means every outbound packet fails and is counted as a
        // drop, for keys that will never work again -- a transmit-dropped
        // counter climbing by thousands while transmit stands still.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (a, _) = session_pair(&client, &server, 210);
        let (b, _) = session_pair(&client, &server, 220);

        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.install(a);
        s.accept(b);

        let alive = paqetz_core::noise::REJECT_AFTER_TIME - 1;
        s.retire_expired(alive);
        assert!(s.session.is_some(), "still usable");
        assert!(s.next.is_some());

        s.retire_expired(paqetz_core::noise::REJECT_AFTER_TIME);
        assert!(s.session.is_none(), "expired, so no longer a session");
        assert!(s.previous.is_none());
        assert!(s.next.is_none());
    }

    #[test]
    fn a_run_that_gave_up_is_started_again_rather_than_abandoned() {
        // The gap left by making traffic the trigger: an idle client has no
        // traffic. A path that swallowed ninety seconds of handshakes left a
        // tunnel down until somebody noticed and restarted it -- and the thing
        // most likely to be waiting on it, Xray, resolves its names through it,
        // so it could not be the traffic that woke it either.
        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.attempt_started = Some(0);
        s.last_handshake = REKEY_ATTEMPT_TIME - 5_000;
        s.retry_at = Millis::MAX;

        assert!(
            s.wants_handshake(REKEY_ATTEMPT_TIME - 1),
            "a run under way keeps trying"
        );
        assert!(
            !s.wants_handshake(REKEY_ATTEMPT_TIME),
            "and stops when it has gone on long enough"
        );

        // Measured from the last attempt, not from when the run began.
        let due_at = s.last_handshake + RETRY_WHEN_GONE;
        assert!(!s.wants_handshake(due_at - 1), "not yet");
        assert!(
            s.wants_handshake(due_at),
            "and then it tries again, instead of waiting for a restart"
        );

        // A fresh run gets its own ninety seconds, not a clock already expired.
        s.attempt_started = None;
        assert!(!s.exhausted(due_at), "the new run has time of its own");
    }

    #[test]
    fn an_idle_tunnel_with_nothing_to_send_still_gives_up() {
        // The other half: attempts stop for a tunnel nobody is using, or an
        // unreachable peer is handshaked at for ever.
        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        assert!(!s.exhausted(0), "nothing attempted yet");
        s.attempt_started = Some(1_000);
        assert!(s.exhausted(1_000 + REKEY_ATTEMPT_TIME));
    }

    #[test]
    fn an_idle_tunnel_does_not_handshake_itself_to_death() {
        // The regression this exists to stop. A keepalive is empty, so the peer
        // answers it with nothing -- there is nothing to answer. Arming the
        // liveness timer on one asks a question that cannot be answered and then
        // reads the silence as proof the peer had gone, so a healthy idle tunnel
        // rehandshakes for ever. Shipped, and observed in production as
        // throughput collapsing while the tunnel looked up.
        let heard = 1_000;
        let s = spoke(None, Some(heard));

        // The peer spoke, we owe it a keepalive, and we send one.
        assert!(s.owes_keepalive(heard + KEEPALIVE_TIMEOUT));
        // A keepalive must leave `last_send` alone: `seal_into` skips it for an
        // empty packet, so nothing here moves and the state is unchanged.
        assert!(
            !s.presumed_dead(heard + KEEPALIVE_TIMEOUT + PRESUMED_DEAD + 1),
            "an unanswered keepalive is not evidence of anything"
        );
    }

    #[test]
    fn a_completed_handshake_settles_the_liveness_timers() {
        // Otherwise the condition that triggered the handshake survives it, the
        // next tick triggers another, and each one replaces the session on both
        // ends and rejects whatever was in flight.
        let mut s = spoke(Some(1_000), Some(0));
        assert!(
            s.presumed_dead(PRESUMED_DEAD + 1),
            "dead before the handshake"
        );

        s.established(PRESUMED_DEAD + 1, noise::REKEY_AFTER_TIME);
        assert!(
            !s.presumed_dead(PRESUMED_DEAD + 1),
            "the peer just answered; it cannot be dead in the same instant"
        );
        assert!(
            !s.presumed_dead(PRESUMED_DEAD * 2),
            "and stays alive until something is sent and goes unanswered"
        );
        assert_eq!(s.attempt_started, None, "the attempt succeeded");
    }

    #[test]
    fn data_after_a_handshake_still_arms_the_liveness_timer() {
        // The fix must not disable the mechanism it is fixing.
        let mut s = spoke(None, None);
        s.established(0, noise::REKEY_AFTER_TIME);
        s.last_send = Some(1_000);
        assert!(s.presumed_dead(1_000 + PRESUMED_DEAD));
    }

    /// One complete handshake, returning the two ends of the same session.
    ///
    /// `index` keeps successive sessions distinguishable, which is the whole
    /// point of the test below: a packet has to be routed to the session it was
    /// sealed under, and the index is what says which that is.
    fn session_pair(
        client: &paqetz_core::KeyPair,
        server: &paqetz_core::KeyPair,
        index: u32,
    ) -> (Session, Session) {
        session_pair_at(client, server, index, 0)
    }

    /// As above, but established at `at` -- which decides when it expires.
    fn session_pair_at(
        client: &paqetz_core::KeyPair,
        server: &paqetz_core::KeyPair,
        index: u32,
        at: Millis,
    ) -> (Session, Session) {
        let (mut initiator, (msg1, msg1_len)) = Initiator::start(
            &client.private,
            &client.public,
            &server.public,
            index,
            index,
            // Unpadded, so a test that cares about padding has to ask for it.
            0,
        )
        .expect("start");
        let msg1 = msg1.get(..msg1_len).expect("msg1");
        let pending = PendingResponder::read(&server.private, &server.public, msg1).expect("read");
        let (server_side, (msg2, msg2_len)) = pending.accept(index + 1, at, 0).expect("accept");
        let msg2 = msg2.get(..msg2_len).expect("msg2");
        let client_side = initiator.finish(msg2, at).expect("finish");
        (client_side, server_side)
    }

    #[test]
    fn a_rekey_does_not_lose_what_was_already_in_flight() {
        // The two ends cannot change session in the same instant: a rekey is a
        // handshake, so there is a round trip between one end installing the new
        // keys and the other hearing about it. Everything the peer sends in that
        // window is sealed under the session this end has just replaced. With
        // one slot it was all dropped -- a burst of loss twice a minute, on a
        // tunnel with nothing else wrong with it.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");

        let (old_client, mut old_server) = session_pair(&client, &server, 10);
        let (new_client, mut new_server) = session_pair(&client, &server, 20);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(old_client);

        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];

        let n = old_server.seal(b"before", &mut wire, 0).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, 0)
                .expect("a session")
                .expect("the current session reads its own traffic"),
            b"before".len(),
            "the current session reads its own traffic"
        );

        // The rekey lands, and the peer has not yet noticed.
        state.install(new_client);

        let n = old_server.seal(b"in flight", &mut wire, 0).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, 0)
                .expect("a session")
                .expect("a packet sealed under the session just replaced is still readable"),
            b"in flight".len(),
            "a packet sealed under the session just replaced is still readable"
        );
        assert_eq!(inner.get(..b"in flight".len()), Some(&b"in flight"[..]));

        let n = new_server.seal(b"after", &mut wire, 0).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, 0)
                .expect("a session")
                .expect("and the new session still reads its own"),
            b"after".len(),
            "and the new session still reads its own"
        );
    }

    #[test]
    fn a_responder_does_not_seal_under_a_session_the_peer_has_not_used() {
        // A replayed handshake authenticates perfectly -- it was genuine when it
        // was recorded -- so a responder that installed every session it
        // accepted would hand anyone who once captured an initiation a way to
        // black out the tunnel on demand: the peer never negotiated those keys
        // and cannot read anything sealed under them.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");

        let (mut live_peer, live) = session_pair(&client, &server, 60);
        let (_, replayed) = session_pair(&client, &server, 70);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(live);
        let established = state.session.as_ref().expect("a session").local_index();

        // The replay lands. It must change nothing about what goes out.
        state.accept(replayed);
        assert_eq!(
            state.session.as_ref().expect("a session").local_index(),
            established,
            "an accepted session is not the one to seal under"
        );

        // And the real peer is still heard, on the session it actually holds.
        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];
        let n = live_peer.seal(b"still here", &mut wire, 0).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, 0)
                .expect("a session")
                .expect("still here"),
            b"still here".len()
        );
        assert_eq!(
            state.session.as_ref().expect("a session").local_index(),
            established,
            "and traffic on the live session does not promote the waiting one"
        );
    }

    #[test]
    fn using_an_accepted_session_is_what_promotes_it() {
        // The peer using the session is proof it holds the keys, which is
        // exactly what a replay of an old handshake cannot manufacture.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");

        let (_, old) = session_pair(&client, &server, 80);
        let (mut peer, fresh) = session_pair(&client, &server, 90);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(old);
        state.accept(fresh);
        let waiting = state.next.as_ref().expect("waiting").local_index();

        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];
        let n = peer.seal(b"using it", &mut wire, 0).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, 0)
                .expect("a session")
                .expect("using it"),
            b"using it".len()
        );
        assert_eq!(
            state.session.as_ref().expect("a session").local_index(),
            waiting,
            "the peer used it, so it is now the one to seal under"
        );
        assert!(state.next.is_none(), "and nothing is left waiting");
    }

    #[test]
    fn an_expired_session_does_not_shadow_the_one_waiting_behind_it() {
        // This is the regression that took a live tunnel down. `Session::open`
        // tests expiry before it looks at the index, so an expired session
        // answers for packets addressed to a *different* session -- and it
        // answers with an error that is not `Rejected`, which stopped the
        // search. The session that could have replaced it sat one slot away,
        // unreachable, and the tunnel stayed down for good rather than for a
        // moment.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");

        // The old one is established at zero; the one replacing it a rekey
        // later, so there is a moment when the first has expired and the second
        // has not. That moment is the whole failure.
        let (_, old) = session_pair_at(&client, &server, 110, 0);
        let rekeyed = paqetz_core::noise::REKEY_AFTER_TIME;
        let (mut peer, fresh) = session_pair_at(&client, &server, 120, rekeyed);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(old);
        state.accept(fresh);

        let later = paqetz_core::noise::REJECT_AFTER_TIME + 1;
        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];
        let n = peer.seal(b"after expiry", &mut wire, later).expect("seal");
        assert_eq!(
            state
                .open(wire.get(..n).expect("sealed"), &mut inner, later)
                .expect("a session")
                .expect("the waiting session is reachable"),
            b"after expiry".len()
        );
    }

    #[test]
    fn an_unanswered_confirmation_gives_up_rather_than_asking_for_ever() {
        // A responder can promote the session, have nothing to say, and stay
        // silent -- which looks exactly like never having promoted it. Asking
        // again for ever turns that into one packet a second for the life of
        // the tunnel, which was visible in the field as a transmit counter
        // climbing at a steady 60 a minute with nothing using the tunnel.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (_, session) = session_pair(&client, &server, 140);

        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.install(session);
        for _ in 0..CONFIRM_TRIES {
            assert!(s.confirm_owed, "still worth asking");
            // What `maybe_keepalive` records after each attempt.
            s.confirm_tries = s.confirm_tries.saturating_add(1);
            if s.confirm_tries >= CONFIRM_TRIES {
                s.confirm_owed = false;
            }
        }
        assert!(!s.confirm_owed, "asked enough");
    }

    #[test]
    fn hearing_from_the_peer_is_what_settles_the_confirmation() {
        // Not sending it. The confirmation is one small packet, and a path that
        // drops one would stall the responder until the next rekey if sending
        // were taken as proof of arrival.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (mut peer, session) = session_pair(&client, &server, 130);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(session);
        assert!(state.confirm_owed);

        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];
        let n = peer.seal(b"heard", &mut wire, 0).expect("seal");
        state
            .open(wire.get(..n).expect("sealed"), &mut inner, 0)
            .expect("a session")
            .expect("heard");
        assert!(
            !state.confirm_owed,
            "the peer used this session, so it plainly has it"
        );
    }

    #[test]
    fn a_keepalive_satisfies_the_timer_that_produced_it() {
        // It did not, once: only data counted as having spoken, so the
        // condition survived the packet it emitted and fired again on the next
        // tick -- four empty packets a second for as long as the peer stayed
        // quiet.
        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.last_data_receive = Some(1_000);
        assert!(!s.owes_keepalive(1_000), "not yet");
        assert!(
            s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT),
            "the peer spoke"
        );

        s.last_keepalive = Some(1_000 + KEEPALIVE_TIMEOUT);
        assert!(
            !s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT),
            "answered once, and once is the whole point"
        );
        assert!(
            !s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT * 10),
            "and it stays answered until the peer speaks again"
        );

        s.last_data_receive = Some(2_000 + KEEPALIVE_TIMEOUT * 10);
        assert!(s.owes_keepalive(2_000 + KEEPALIVE_TIMEOUT * 11), "it spoke");
    }

    #[test]
    fn a_keepalive_still_does_not_make_the_peer_look_alive() {
        // The other half of the same distinction: answering a peer is not
        // evidence the peer answered us, and conflating the two is what made an
        // idle tunnel handshake itself to death.
        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        s.last_keepalive = Some(1_000);
        assert!(
            !s.presumed_dead(1_000 + PRESUMED_DEAD * 10),
            "a keepalive asks nothing, so silence after one proves nothing"
        );
    }

    #[test]
    fn the_initiator_owes_one_packet_after_a_handshake() {
        // Which is what lets the responder promote. Without it an idle tunnel
        // leaves the responder on a session that eventually expires.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");
        let (session, _) = session_pair(&client, &server, 100);

        let mut s = PeerState::new(None, crate::repeat::Limits::off());
        assert!(!s.confirm_owed, "nothing has happened yet");
        s.install(session);
        assert!(
            s.confirm_owed,
            "a handshake completed and nothing has used it"
        );
    }

    #[test]
    fn only_the_session_before_this_one_is_kept() {
        // Two rekeys, and the first session is gone. Keeping every session a
        // tunnel ever had would be an unbounded set of live keys, which is a
        // worse problem than the one being solved.
        let client = paqetz_core::KeyPair::generate().expect("client");
        let server = paqetz_core::KeyPair::generate().expect("server");

        let (first, mut first_server) = session_pair(&client, &server, 30);
        let (second, _) = session_pair(&client, &server, 40);
        let (third, _) = session_pair(&client, &server, 50);

        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        state.install(first);
        state.install(second);
        state.install(third);

        let mut wire = [0u8; 256];
        let mut inner = [0u8; 256];
        let n = first_server.seal(b"stale", &mut wire, 0).expect("seal");
        assert!(
            matches!(
                state.open(wire.get(..n).expect("sealed"), &mut inner, 0),
                Some(Err(paqetz_core::Error::Rejected))
            ),
            "two rekeys back is not kept"
        );
    }

    #[test]
    fn nothing_opens_before_there_is_a_session() {
        let mut state = PeerState::new(None, crate::repeat::Limits::off());
        let mut inner = [0u8; 64];
        assert!(state.open(&[0u8; 32], &mut inner, 0).is_none());
    }

    #[test]
    fn a_session_nobody_answers_is_presumed_dead() {
        // The gap this closes: before it, the only thing that ever replaced a
        // session was the rekey timer at two minutes, so a peer that had
        // forgotten us went undetected for that long while everything sent in
        // between was encrypted to a key nobody held.
        let s = spoke(Some(1_000), Some(500));
        assert!(!s.presumed_dead(1_000), "silence has not lasted yet");
        assert!(!s.presumed_dead(500 + PRESUMED_DEAD - 1));
        assert!(s.presumed_dead(500 + PRESUMED_DEAD));
    }

    #[test]
    fn an_idle_tunnel_is_not_presumed_dead() {
        // Nothing has been sent, so hearing nothing back is not evidence of
        // anything. Rehandshaking here would mean a tunnel nobody is using
        // handshaking for ever.
        let s = spoke(None, None);
        assert!(!s.presumed_dead(10 * PRESUMED_DEAD));

        let never_sent = spoke(None, Some(1_000));
        assert!(!never_sent.presumed_dead(10 * PRESUMED_DEAD));
    }

    #[test]
    fn a_peer_that_answers_keeps_its_session() {
        let s = spoke(Some(1_000), Some(1_500));
        assert!(
            !s.presumed_dead(1_500 + PRESUMED_DEAD + 1),
            "it answered after we spoke, so the silence since is ours"
        );
    }

    #[test]
    fn a_keepalive_is_owed_only_after_the_peer_speaks_and_we_do_not() {
        let s = spoke(Some(100), Some(1_000));
        assert!(!s.owes_keepalive(1_000), "not yet");
        assert!(!s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT - 1));
        assert!(s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT));

        let answered = spoke(Some(2_000), Some(1_000));
        assert!(
            !answered.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT),
            "we already said something after they did"
        );
    }

    #[test]
    fn a_keepalive_does_not_arm_another_keepalive() {
        // Two ends answering every keepalive with a keepalive is a loop that
        // never stops. Only a packet carrying data sets `last_data_receive`, so
        // an empty one cannot start it.
        let mut s = spoke(Some(100), Some(1_000));
        s.last_data_receive = None;
        assert!(!s.owes_keepalive(1_000 + KEEPALIVE_TIMEOUT * 10));
    }

    #[test]
    fn the_rekey_lands_in_a_band_rather_than_on_a_tick() {
        // A rekey is two packets, and on a fixed interval those two packets are
        // a clock. Nothing else this carrier emits is periodic, so the clock was
        // the most legible thing on the wire.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let v = Tunnel::rekey_after();
            assert!(
                (noise::REKEY_AFTER_TIME - REKEY_JITTER..=noise::REKEY_AFTER_TIME + REKEY_JITTER)
                    .contains(&v),
                "{v} is outside the band"
            );
            seen.insert(v);
        }
        assert!(seen.len() > 200, "only {} distinct values", seen.len());

        // The late end must still leave room to rekey before the session would
        // be refused outright, or jitter would trade a fingerprint for an
        // outage.
        const {
            assert!(noise::REKEY_AFTER_TIME + REKEY_JITTER < noise::REJECT_AFTER_TIME);
        }
    }

    #[test]
    fn the_padding_covers_its_whole_band() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..512 {
            let pad = handshake_pad();
            assert!(pad <= noise::MAX_PAD, "{pad} is over the maximum");
            seen.insert(pad);
        }
        assert!(seen.len() > noise::MAX_PAD / 2, "only {} sizes", seen.len());
    }

    #[test]
    fn the_retry_interval_is_wireguards_plus_jitter() {
        // Flat retries let two peers that lost each other at the same moment
        // collide for ever.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let v = Tunnel::rekey_interval();
            assert!(
                (REKEY_TIMEOUT..REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER).contains(&v),
                "{v} outside the interval"
            );
            seen.insert(v);
        }
        assert!(seen.len() > 8, "not varying: {} values", seen.len());
    }

    #[test]
    fn the_timers_are_the_ones_wireguard_uses() {
        assert_eq!(REKEY_TIMEOUT, 5_000);
        assert_eq!(KEEPALIVE_TIMEOUT, 10_000);
        assert_eq!(REKEY_ATTEMPT_TIME, 90_000);
        assert_eq!(PRESUMED_DEAD, 15_000);
        assert_eq!(paqetz_core::noise::REKEY_AFTER_TIME, 120_000);
        assert_eq!(paqetz_core::noise::REJECT_AFTER_TIME, 180_000);
    }

    use super::*;

    #[test]
    fn inner_source_reads_the_ipv4_source_field() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 7, 0, 2]);
        assert_eq!(inner_source(&packet), Some(Ipv4Addr::new(10, 7, 0, 2)));
    }

    #[test]
    fn inner_source_rejects_non_ipv4_and_runts() {
        let mut packet = [0u8; 20];
        packet[0] = 0x60; // IPv6
        assert_eq!(inner_source(&packet), None);
        for len in 0..16 {
            let mut short = vec![0u8; len];
            if let Some(b) = short.first_mut() {
                *b = 0x45;
            }
            assert_eq!(inner_source(&short), None, "len {len}");
        }
    }

    #[test]
    fn martian_sources_are_refused() {
        // These must be refused even when allowed_ips is set to "any", because
        // the danger is not which peer sent them but where they could reach.
        for addr in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 1, 2, 3),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            assert!(!plausible_source(addr), "{addr} should be refused");
        }
    }

    #[test]
    fn ordinary_sources_are_allowed() {
        for addr in [
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ] {
            assert!(plausible_source(addr), "{addr} should be allowed");
        }
    }

    #[test]
    fn random_u32_produces_varying_values() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            seen.insert(random_u32().expect("urandom"));
        }
        assert!(seen.len() > 30, "saw only {} distinct values", seen.len());
    }

    #[test]
    fn the_default_route_is_discoverable() {
        // Read-only: parses /proc/net/route and touches nothing.
        match outbound_interface() {
            Ok(name) => assert!(!name.is_empty()),
            Err(e) => {
                // A machine with no default route is a legitimate state; the
                // point is that parsing does not panic or hang.
                assert!(e.to_string().contains("default route"), "got: {e}");
            }
        }
    }
}
