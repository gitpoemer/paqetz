//! Selective repeat: asking for the packets a lossy path swallowed.
//!
//! Decision D2 says the tunnel carries no reliability layer, on the grounds
//! that everything inside it already has one. That holds while a link loses a
//! packet in a hundred. It stops holding at a packet in four: inner TCP's
//! recovery is paced by its own retransmission timer, which is at best a
//! couple of hundred milliseconds and grows on every loss, so a quarter-lossy
//! link turns a browser into a slideshow no matter how correct everything else
//! is.
//!
//! # Why not a reliable stream
//!
//! The obvious answer is what paqet does: run a reliable ordered protocol
//! inside the tunnel. That makes one lost packet block every inner flow behind
//! it, because ordering is enforced across traffic that was never one stream —
//! dozens of unrelated connections, all waiting on a retransmission that
//! matters to one of them.
//!
//! What is wanted instead is much smaller: notice a specific packet is missing,
//! ask for that one, and give up quickly if it does not arrive. No ordering, no
//! head-of-line blocking, no window, no congestion control. The transport
//! counter is already a monotonic sequence, already authenticated, and already
//! carried in every packet, so the gap is visible without adding anything to
//! the wire.
//!
//! # Why it gives up
//!
//! A repeat is worth sending while it would arrive sooner than inner TCP's own
//! retransmission. Past that it is duplicated effort on a link that is already
//! struggling, so [`DEADLINE`] bounds how old a packet may be to be worth
//! resending and [`MAX_ASKS`] bounds how many times it may be asked for.
//!
//! # What goes on the wire
//!
//! Nothing new. Control messages travel as ordinary transport packets, sealed
//! under the same session, and are told from tunnelled traffic by their first
//! byte: inner packets are IPv4, whose first nibble is 4, so a leading zero
//! cannot be one. An observer sees packets of the same shape as any other.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use paqetz_core::Millis;

/// Leading byte of a control message. Not a valid IPv4 first byte.
const MARKER: u8 = 0x00;

/// A request for packets that never arrived.
const KIND_NACK: u8 = 1;
/// A packet being sent again, carrying the counter it first went out under.
const KIND_REPEAT: u8 = 2;

/// How many packets beyond a gap must arrive before it is called a loss.
///
/// Reordering is not loss, and a path that delivers out of order would
/// otherwise be asked to repeat packets that are already in flight. Three is
/// TCP's own threshold for the same judgement, for the same reason.
const REORDER_TOLERANCE: usize = 3;

/// How old a packet may be and still be worth repeating.
///
/// Beyond this, inner TCP will have noticed the loss itself, and a repeat is
/// two copies of the same recovery competing on a link that is already losing
/// a quarter of what crosses it.
const DEADLINE: Millis = 400;

/// How many times one packet may be asked for.
///
/// Loss here arrives in bursts, so the request and the repeat can both be
/// swallowed by the same burst that took the original. One retry covers that;
/// more is a link that is not going to deliver this packet.
const MAX_ASKS: u8 = 2;

/// How many counters may be outstanding at once.
///
/// A bound on memory that also bounds the damage from a peer inventing gaps.
const MAX_OUTSTANDING: usize = 512;

/// Control messages carried inside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control<'a> {
    /// These counters never arrived.
    Nack(Vec<u64>),
    /// A packet, sent again, and the counter it first went out under.
    Repeat { original: u64, packet: &'a [u8] },
}

/// Reads a control message, or `None` if this is ordinary tunnelled traffic.
///
/// Every field is bounds-checked against the buffer: this is peer-supplied
/// input, and a peer that has authenticated is still not a reason to trust a
/// length it chose.
pub(crate) fn parse(payload: &[u8]) -> Option<Control<'_>> {
    let (&first, rest) = payload.split_first()?;
    if first != MARKER {
        return None;
    }
    let (&kind, rest) = rest.split_first()?;
    match kind {
        KIND_NACK => {
            let (&count, mut rest) = rest.split_first()?;
            let mut counters = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let (bytes, tail) = rest.split_at_checked(8)?;
                counters.push(u64::from_le_bytes(bytes.try_into().ok()?));
                rest = tail;
            }
            Some(Control::Nack(counters))
        }
        KIND_REPEAT => {
            let (bytes, packet) = rest.split_at_checked(8)?;
            Some(Control::Repeat {
                original: u64::from_le_bytes(bytes.try_into().ok()?),
                packet,
            })
        }
        _ => None,
    }
}

/// Writes a request for the given counters into `out`.
///
/// Returns the length written, or `None` if `out` is too small.
pub(crate) fn write_nack(counters: &[u64], out: &mut [u8]) -> Option<usize> {
    let count = u8::try_from(counters.len()).ok()?;
    let need = 3 + counters.len() * 8;
    let slot = out.get_mut(..need)?;
    let (head, mut rest) = slot.split_at_mut(3);
    head.copy_from_slice(&[MARKER, KIND_NACK, count]);
    for counter in counters {
        let (bytes, tail) = rest.split_at_mut(8);
        bytes.copy_from_slice(&counter.to_le_bytes());
        rest = tail;
    }
    Some(need)
}

/// Writes `packet` as a repeat of `original` into `out`.
pub(crate) fn write_repeat(original: u64, packet: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = 10 + packet.len();
    let slot = out.get_mut(..need)?;
    let (head, body) = slot.split_at_mut(10);
    head.get_mut(..2)?.copy_from_slice(&[MARKER, KIND_REPEAT]);
    head.get_mut(2..)?.copy_from_slice(&original.to_le_bytes());
    body.copy_from_slice(packet);
    Some(need)
}

/// Bytes of overhead a repeat adds to the packet it carries.
pub(crate) const REPEAT_OVERHEAD: usize = 10;

/// The sending side: what was sent recently, in case it is asked for again.
///
/// Holds the *inner* packets rather than the sealed ones. A sealed packet
/// cannot be sent twice — its counter is the AEAD nonce, and repeating a nonce
/// under the same key is the one thing this construction must never do — so a
/// repeat is a fresh sealing of the same contents.
pub(crate) struct Outbox {
    sent: VecDeque<(u64, Vec<u8>, Millis)>,
    capacity: usize,
}

impl Outbox {
    /// An outbox holding at most `capacity` packets.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            sent: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Records a packet that has just gone out under `counter`.
    pub(crate) fn record(&mut self, counter: u64, packet: &[u8], now: Millis) {
        if self.capacity == 0 {
            return;
        }
        while self.sent.len() >= self.capacity {
            self.sent.pop_front();
        }
        self.sent.push_back((counter, packet.to_vec(), now));
    }

    /// Returns the packet sent under `counter`, if it is still worth repeating.
    ///
    /// Kept rather than removed: a burst can swallow a repeat as easily as it
    /// swallowed the original, and the peer is allowed to ask twice.
    pub(crate) fn get(&self, counter: u64, now: Millis) -> Option<&[u8]> {
        self.sent.iter().find_map(|(c, packet, at)| {
            (*c == counter && now.saturating_sub(*at) <= DEADLINE).then_some(packet.as_slice())
        })
    }

    /// Drops everything too old to be worth repeating.
    pub(crate) fn prune(&mut self, now: Millis) {
        while let Some((_, _, at)) = self.sent.front() {
            if now.saturating_sub(*at) > DEADLINE {
                self.sent.pop_front();
            } else {
                break;
            }
        }
    }

    /// How many packets are being held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.sent.len()
    }
}

/// One counter that has not arrived.
#[derive(Debug, Clone, Copy)]
struct Gap {
    /// When the gap was first noticed.
    seen: Millis,
    /// How many packets have arrived with a higher counter since.
    ahead: usize,
    /// How many times it has been asked for.
    asks: u8,
}

/// The receiving side: which counters are missing, and when to ask.
pub(crate) struct Inbox {
    /// Highest counter seen, once anything has been.
    highest: Option<u64>,
    gaps: BTreeMap<u64, Gap>,
}

impl Inbox {
    pub(crate) const fn new() -> Self {
        Self {
            highest: None,
            gaps: BTreeMap::new(),
        }
    }

    /// Records an arrival, and returns the counters now worth asking for.
    ///
    /// A gap is only reported once [`REORDER_TOLERANCE`] later packets have
    /// arrived, so a path that delivers out of order is not asked to repeat
    /// what is already on its way.
    pub(crate) fn arrived(&mut self, counter: u64, now: Millis) -> Vec<u64> {
        self.gaps.remove(&counter);

        match self.highest {
            None => self.highest = Some(counter),
            Some(highest) if counter > highest => {
                // Everything between the old high-water mark and this packet is
                // missing, until it turns up.
                for missing in (highest + 1)..counter {
                    if self.gaps.len() >= MAX_OUTSTANDING {
                        break;
                    }
                    self.gaps.entry(missing).or_insert(Gap {
                        seen: now,
                        ahead: 0,
                        asks: 0,
                    });
                }
                self.highest = Some(counter);
            }
            Some(_) => {}
        }

        // This packet is "ahead" of every gap below it.
        for (at, gap) in &mut self.gaps {
            if *at < counter {
                gap.ahead = gap.ahead.saturating_add(1);
            }
        }

        let mut ask = Vec::new();
        self.gaps.retain(|at, gap| {
            if now.saturating_sub(gap.seen) > DEADLINE || gap.asks >= MAX_ASKS {
                // Too late to be worth repeating, or asked for enough times.
                // Inner protocols own it from here.
                return false;
            }
            if gap.ahead >= REORDER_TOLERANCE {
                ask.push(*at);
                gap.asks = gap.asks.saturating_add(1);
                gap.ahead = 0;
            }
            true
        });
        ask
    }

    /// Records that a repeat satisfied `counter`.
    pub(crate) fn satisfied(&mut self, counter: u64) {
        self.gaps.remove(&counter);
    }

    /// How many counters are outstanding.
    #[cfg(test)]
    fn outstanding(&self) -> usize {
        self.gaps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_message_cannot_be_mistaken_for_a_packet() {
        // Inner packets are IPv4, so their first nibble is 4. Nothing that
        // starts with a zero byte can be one, which is the whole basis for
        // telling them apart without adding a field to the wire.
        let ipv4 = [0x45u8, 0x00, 0x00, 0x28];
        assert_eq!(parse(&ipv4), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn a_nack_survives_the_round_trip() {
        let counters = vec![7u64, 9, 1_000_000];
        let mut buf = [0u8; 64];
        let n = write_nack(&counters, &mut buf).expect("write");
        assert_eq!(
            parse(buf.get(..n).expect("slice")),
            Some(Control::Nack(counters))
        );
    }

    #[test]
    fn a_repeat_carries_its_original_counter_and_its_packet() {
        let packet = [0x45u8, 0x00, 0x11, 0x22, 0x33];
        let mut buf = [0u8; 64];
        let n = write_repeat(42, &packet, &mut buf).expect("write");
        assert_eq!(n, REPEAT_OVERHEAD + packet.len());
        match parse(buf.get(..n).expect("slice")) {
            Some(Control::Repeat {
                original,
                packet: got,
            }) => {
                assert_eq!(original, 42);
                assert_eq!(got, &packet[..]);
            }
            other => panic!("expected a repeat, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_control_message_is_refused_rather_than_guessed_at() {
        // Peer-supplied, and a peer that has authenticated is still not a
        // reason to trust a length it chose.
        assert_eq!(parse(&[MARKER]), None);
        assert_eq!(parse(&[MARKER, KIND_NACK]), None);
        // Claims three counters, carries one.
        assert_eq!(parse(&[MARKER, KIND_NACK, 3, 1, 0, 0, 0, 0, 0, 0, 0]), None);
        // A repeat with a truncated counter.
        assert_eq!(parse(&[MARKER, KIND_REPEAT, 1, 2, 3]), None);
        assert_eq!(parse(&[MARKER, 99]), None);
    }

    #[test]
    fn reordering_is_not_loss() {
        // Two packets swapped in flight must not produce a request. Asking for
        // a packet that is already on its way costs bandwidth on a link that
        // has none to spare, and arrives as a duplicate.
        let mut inbox = Inbox::new();
        assert!(inbox.arrived(1, 0).is_empty());
        assert!(inbox.arrived(3, 0).is_empty());
        assert!(inbox.arrived(2, 0).is_empty(), "2 turned up on its own");
        assert_eq!(inbox.outstanding(), 0);
    }

    #[test]
    fn a_gap_is_asked_for_once_enough_has_gone_past_it() {
        let mut inbox = Inbox::new();
        assert!(inbox.arrived(1, 0).is_empty());
        // 2 is missing. 3, 4 arrive -- still within reordering tolerance.
        assert!(inbox.arrived(3, 0).is_empty());
        assert!(inbox.arrived(4, 0).is_empty());
        // The third packet past it settles the question.
        assert_eq!(inbox.arrived(5, 0), vec![2]);
    }

    #[test]
    fn a_repeat_stops_the_asking() {
        let mut inbox = Inbox::new();
        inbox.arrived(1, 0);
        inbox.arrived(3, 0);
        inbox.arrived(4, 0);
        assert_eq!(inbox.arrived(5, 0), vec![2]);
        inbox.satisfied(2);
        assert_eq!(inbox.outstanding(), 0);
        for c in 6..12 {
            assert!(inbox.arrived(c, 0).is_empty(), "asked again after a repeat");
        }
    }

    #[test]
    fn asking_gives_up_rather_than_going_on_for_ever() {
        // A link that has swallowed a packet twice is not going to produce it,
        // and inner protocols own it from here.
        let mut inbox = Inbox::new();
        inbox.arrived(1, 0);
        let mut asks = 0;
        for c in 3..40 {
            asks += inbox.arrived(c, 0).len();
        }
        assert_eq!(asks, usize::from(MAX_ASKS), "asked {asks} times");
        assert_eq!(inbox.outstanding(), 0, "and then let it go");
    }

    #[test]
    fn a_gap_older_than_the_deadline_is_abandoned() {
        let mut inbox = Inbox::new();
        inbox.arrived(1, 0);
        inbox.arrived(3, 0);
        // Past the deadline, the packet is no longer worth repeating: inner TCP
        // has noticed by now, and two recoveries for one loss is waste on a
        // link that is already losing.
        assert!(inbox.arrived(4, DEADLINE + 1).is_empty());
        assert_eq!(inbox.outstanding(), 0);
    }

    #[test]
    fn a_peer_inventing_gaps_cannot_grow_this_without_bound() {
        let mut inbox = Inbox::new();
        inbox.arrived(0, 0);
        inbox.arrived(u64::from(u32::MAX), 0);
        assert!(inbox.outstanding() <= MAX_OUTSTANDING);
    }

    #[test]
    fn the_outbox_keeps_what_is_worth_repeating_and_drops_the_rest() {
        let mut outbox = Outbox::new(4);
        for c in 0..4u64 {
            let byte = u8::try_from(c).expect("small");
            outbox.record(c, &[byte; 8], 0);
        }
        assert_eq!(outbox.get(2, 0), Some(&[2u8; 8][..]));
        assert_eq!(outbox.get(9, 0), None, "never sent");
        assert_eq!(outbox.get(2, DEADLINE + 1), None, "too old to be worth it");

        // Capacity is a hard bound: the oldest goes to make room.
        outbox.record(4, &[4u8; 8], 0);
        assert_eq!(outbox.len(), 4);
        assert_eq!(outbox.get(0, 0), None, "evicted");
        assert_eq!(outbox.get(4, 0), Some(&[4u8; 8][..]));

        outbox.prune(DEADLINE + 1);
        assert_eq!(outbox.len(), 0);
    }

    #[test]
    fn an_outbox_of_no_capacity_holds_nothing() {
        // What `retransmit = false` gets: the code path stays, and costs a
        // comparison rather than a copy of every packet.
        let mut outbox = Outbox::new(0);
        outbox.record(1, &[0u8; 1400], 0);
        assert_eq!(outbox.len(), 0);
        assert_eq!(outbox.get(1, 0), None);
    }
}
