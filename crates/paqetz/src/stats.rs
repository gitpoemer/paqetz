//! Counters, and the periodic line that reports them.
//!
//! # Why per-packet events are counted rather than logged
//!
//! Anything that fails to authenticate reaches the receive path's error
//! handling. Logging a line there means an attacker sending garbage to the port
//! chooses how much this process writes to disk and how much time it spends
//! formatting — turning a probe into an amplifier. It is the same shape as the
//! replay-window bug avoided in `paqetz-core`: an attacker must never be able
//! to make the defender do unbounded work.
//!
//! So the receive path increments a counter, which is one relaxed atomic add,
//! and a line every interval reports the totals. A flood costs one increment
//! per packet no matter how large it is.
//!
//! Counters are split so that each is written by one thread in the common case:
//! the transmit side touches only `tx_*`, the receive side only `rx_*` and the
//! rejection counters. That keeps the cache line they live on from bouncing
//! between cores.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Everything worth counting.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    /// Inner packets encrypted and put on the wire.
    pub(crate) tx_packets: AtomicU64,
    /// Inner bytes encrypted.
    pub(crate) tx_bytes: AtomicU64,
    /// Outbound packets dropped because there was no session or no room.
    pub(crate) tx_dropped: AtomicU64,

    /// Inner packets decrypted and delivered.
    pub(crate) rx_packets: AtomicU64,
    /// Inner bytes delivered.
    pub(crate) rx_bytes: AtomicU64,

    /// Packets that failed authentication.
    ///
    /// A steady climb here with nothing else moving is the signature of a
    /// scanner, or of a peer whose keys do not match.
    pub(crate) rejected: AtomicU64,
    /// Packets whose counter was stale or already seen.
    pub(crate) replayed: AtomicU64,
    /// Inner packets refused because their source is outside the peer's range.
    pub(crate) disallowed: AtomicU64,
    /// Inner packets refused for having an impossible source address.
    pub(crate) martian: AtomicU64,
    /// Whether the first refused source has already been explained.
    ///
    /// The counter says how many; it cannot say why, and the why is almost
    /// always a peer whose `allowed_ips` is narrower than what it forwards.
    pub(crate) explained_disallowed: AtomicBool,

    /// Handshakes started by this side.
    pub(crate) handshakes_sent: AtomicU64,
    /// Handshakes that completed.
    pub(crate) handshakes_done: AtomicU64,
    /// Times the peer's endpoint changed under an authenticated packet.
    pub(crate) roams: AtomicU64,
    /// Milliseconds of uptime at the last completed handshake.
    pub(crate) last_handshake_ms: AtomicU64,
}

impl Stats {
    /// Adds one to a counter. Relaxed: these are for a human, not for ordering.
    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` to a counter.
    #[inline]
    pub(crate) fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// Records a completed handshake.
    pub(crate) fn note_handshake(&self, now_ms: u64) {
        self.handshakes_done.fetch_add(1, Ordering::Relaxed);
        self.last_handshake_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Renders the health line.
    ///
    /// Deliberately one line: it is meant to be skimmed in a terminal or
    /// grepped out of a journal, not parsed.
    pub(crate) fn line(&self, now_ms: u64, ring_drops: Option<u32>) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);

        let handshake = match get(&self.last_handshake_ms) {
            0 => "never".to_owned(),
            at => format!("{}s ago", (now_ms.saturating_sub(at)) / 1000),
        };

        let mut line = format!(
            "up {} | handshake {handshake} | tx {} pkt/{} | rx {} pkt/{}",
            duration(now_ms),
            get(&self.tx_packets),
            bytes(get(&self.tx_bytes)),
            get(&self.rx_packets),
            bytes(get(&self.rx_bytes)),
        );

        // Only mention the bad counters when they are non-zero, so a healthy
        // line stays short enough to read at a glance and anything appearing in
        // it is worth looking at.
        for (name, value) in [
            ("rejected", get(&self.rejected)),
            ("replayed", get(&self.replayed)),
            ("disallowed", get(&self.disallowed)),
            ("martian", get(&self.martian)),
            ("tx-dropped", get(&self.tx_dropped)),
            ("roams", get(&self.roams)),
        ] {
            if value > 0 {
                line.push_str(&format!(" | {name} {value}"));
            }
        }
        if let Some(drops) = ring_drops
            && drops > 0
        {
            line.push_str(&format!(" | ring-drops {drops}"));
        }
        line
    }
}

/// Renders a byte count in units a person reads.
fn bytes(n: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("kB", 1_000),
        ("B", 1),
    ];
    for (unit, scale) in UNITS {
        if n >= scale {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a display figure, rendered to two decimal places"
            )]
            let scaled = n as f64 / scale as f64;
            return format!("{scaled:.2} {unit}");
        }
    }
    "0 B".to_owned()
}

/// Renders a duration in units a person reads.
fn duration(ms: u64) -> String {
    let secs = ms / 1000;
    let (d, h, m, s) = (
        secs / 86_400,
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_line_mentions_only_what_is_working() {
        let s = Stats::default();
        Stats::add(&s.tx_packets, 1000);
        Stats::add(&s.tx_bytes, 1_400_000);
        Stats::add(&s.rx_packets, 900);
        Stats::add(&s.rx_bytes, 1_200_000);
        s.note_handshake(5_000);

        let line = s.line(65_000, Some(0));
        assert!(line.contains("tx 1000 pkt/1.40 MB"), "got: {line}");
        assert!(line.contains("rx 900 pkt"), "got: {line}");
        assert!(line.contains("handshake 60s ago"), "got: {line}");
        for noise in ["rejected", "replayed", "martian", "ring-drops", "roams"] {
            assert!(!line.contains(noise), "{noise} should be absent: {line}");
        }
    }

    #[test]
    fn a_counter_that_moves_appears() {
        let s = Stats::default();
        Stats::bump(&s.rejected);
        Stats::bump(&s.rejected);
        Stats::bump(&s.martian);
        let line = s.line(1000, Some(7));
        assert!(line.contains("rejected 2"), "got: {line}");
        assert!(line.contains("martian 1"), "got: {line}");
        assert!(line.contains("ring-drops 7"), "got: {line}");
        assert!(!line.contains("replayed"), "got: {line}");
    }

    #[test]
    fn a_tunnel_that_has_never_connected_says_so() {
        let line = Stats::default().line(30_000, None);
        assert!(line.contains("handshake never"), "got: {line}");
    }

    #[test]
    fn byte_counts_read_in_sensible_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512.00 B");
        assert_eq!(bytes(1_500), "1.50 kB");
        assert_eq!(bytes(2_400_000), "2.40 MB");
        assert_eq!(bytes(3_500_000_000), "3.50 GB");
    }

    #[test]
    fn durations_read_in_sensible_units() {
        assert_eq!(duration(5_000), "5s");
        assert_eq!(duration(90_000), "1m30s");
        assert_eq!(duration(3_723_000), "1h2m");
        assert_eq!(duration(90_000_000), "1d1h");
    }

    #[test]
    fn counting_is_the_cheap_operation_the_hot_path_needs() {
        // Not a timing assertion — just a check that the counters are plain
        // atomics with no locking or allocation behind them, since that is the
        // property the receive path depends on under a flood.
        let s = Stats::default();
        for _ in 0..100_000 {
            Stats::bump(&s.rejected);
        }
        assert_eq!(s.rejected.load(Ordering::Relaxed), 100_000);
    }
}
