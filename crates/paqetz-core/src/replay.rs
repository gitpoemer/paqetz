//! Sliding-window anti-replay over the transport counter.
//!
//! The tunnel provides no ordering and no retransmission (decision D2), so the
//! receive path must tolerate reordering and duplication while rejecting
//! replays. This is the bitmap algorithm from RFC 6479, which slides a window
//! of accepted counters without shifting the bitmap on every packet: the window
//! is a ring of 64-bit words, and advancing clears only the words that were
//! skipped.
//!
//! # Check before commit
//!
//! [`ReplayWindow::check`] does not mutate. The receive path must
//! [`check`](ReplayWindow::check), then decrypt, and only
//! [`commit`](ReplayWindow::commit) once authentication has succeeded.
//! Committing first would let an attacker advance the window with forged
//! packets and have legitimate ones fall outside it — a denial of service that
//! costs the attacker nothing.

/// Number of 64-bit words in the bitmap. Must be a power of two.
const WORDS: usize = 32;

/// Bits per bitmap word.
const BITS_PER_WORD: u64 = 64;

/// Total bits tracked by the bitmap.
pub const WINDOW_BITS: u64 = WORDS as u64 * BITS_PER_WORD;

/// How far behind the highest accepted counter a packet may be and still be
/// considered.
///
/// One word narrower than the bitmap: advancing the window clears whole words,
/// so the word containing the new highest counter is only partially in the
/// past. Reserving it keeps the arithmetic exact rather than approximately
/// right.
pub const WINDOW_SIZE: u64 = WINDOW_BITS - BITS_PER_WORD;

/// Mask that folds a word index into the ring.
const WORD_MASK: u64 = WORDS as u64 - 1;

/// Tracks which transport counters have been seen on one receiving session.
#[derive(Clone)]
pub struct ReplayWindow {
    bitmap: [u64; WORDS],
    /// Highest counter accepted so far.
    highest: u64,
    /// Whether any counter has been committed yet.
    ///
    /// Needed because counter 0 is a legitimate first packet and cannot be
    /// distinguished from the initial value of `highest` without it.
    started: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window, having accepted nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bitmap: [0; WORDS],
            highest: 0,
            started: false,
        }
    }

    /// The highest counter committed so far, or `None` if nothing has been.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        if self.started {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Reports whether `counter` would be accepted, without recording it.
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if !self.started || counter > self.highest {
            return true;
        }
        if self.highest - counter > WINDOW_SIZE {
            return false;
        }
        !self.is_set(counter)
    }

    /// Records `counter` as seen, advancing the window if it is a new high.
    ///
    /// Call only after [`check`](Self::check) returned `true` *and* the packet
    /// authenticated. Committing a counter that would not pass `check` is a
    /// no-op for counters already set, and for stale counters it does nothing
    /// harmful — but it indicates a caller bug.
    pub fn commit(&mut self, counter: u64) {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.set(counter);
            return;
        }

        if counter > self.highest {
            // Clear the words we are skipping over, so their stale bits are not
            // mistaken for recently-seen counters. Never clear more than the
            // whole ring.
            let old_word = self.highest / BITS_PER_WORD;
            let new_word = counter / BITS_PER_WORD;
            let skipped = (new_word - old_word).min(WORDS as u64);
            for i in 0..skipped {
                let idx = word_index(old_word + 1 + i);
                if let Some(w) = self.bitmap.get_mut(idx) {
                    *w = 0;
                }
            }
            self.highest = counter;
        }

        self.set(counter);
    }

    fn is_set(&self, counter: u64) -> bool {
        let idx = word_index(counter / BITS_PER_WORD);
        let bit = 1u64 << (counter % BITS_PER_WORD);
        self.bitmap.get(idx).is_some_and(|w| w & bit != 0)
    }

    fn set(&mut self, counter: u64) {
        let idx = word_index(counter / BITS_PER_WORD);
        let bit = 1u64 << (counter % BITS_PER_WORD);
        if let Some(w) = self.bitmap.get_mut(idx) {
            *w |= bit;
        }
    }
}

/// Folds a word number into the bitmap ring.
///
/// The mask bounds the result below `WORDS`, so the narrowing cannot lose
/// information on any target this runs on.
const fn word_index(word: u64) -> usize {
    (word & WORD_MASK) as usize
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// Convenience for tests: check-then-commit, as the receive path does.
    fn accept(w: &mut ReplayWindow, counter: u64) -> bool {
        if w.check(counter) {
            w.commit(counter);
            true
        } else {
            false
        }
    }

    #[test]
    fn accepts_counter_zero_first() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.highest(), None);
        assert!(accept(&mut w, 0));
        assert_eq!(w.highest(), Some(0));
    }

    #[test]
    fn rejects_replay_of_counter_zero() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, 0));
        assert!(!accept(&mut w, 0));
    }

    #[test]
    fn accepts_a_long_ascending_run_and_rejects_every_replay() {
        let mut w = ReplayWindow::new();
        for c in 0..10_000 {
            assert!(accept(&mut w, c), "counter {c} should be accepted");
        }
        for c in (10_000 - WINDOW_SIZE)..10_000 {
            assert!(!accept(&mut w, c), "counter {c} should be a replay");
        }
    }

    #[test]
    fn accepts_reordering_inside_the_window() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, 100));
        // Everything below the high-water mark but inside the window is still
        // acceptable exactly once.
        for c in 0..100 {
            assert!(accept(&mut w, c), "counter {c} should be accepted");
        }
        for c in 0..100 {
            assert!(!accept(&mut w, c), "counter {c} should be a replay");
        }
    }

    #[test]
    fn rejects_counters_older_than_the_window() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, WINDOW_SIZE + 500));
        assert!(!accept(&mut w, 0));
        assert!(!accept(&mut w, 499));
        // The oldest still-acceptable counter is exactly WINDOW_SIZE behind.
        assert!(accept(&mut w, 500));
    }

    #[test]
    fn a_jump_beyond_the_bitmap_clears_all_history() {
        let mut w = ReplayWindow::new();
        for c in 0..200 {
            assert!(accept(&mut w, c));
        }
        let far = 1_000_000;
        assert!(accept(&mut w, far));
        // Old counters are now out of window, not merely unset.
        assert!(!accept(&mut w, 150));
        // Counters just below the new high are fresh and acceptable.
        assert!(accept(&mut w, far - 1));
        assert!(!accept(&mut w, far - 1));
    }

    #[test]
    fn a_jump_of_exactly_one_word_clears_only_that_word() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, 0));
        assert!(accept(&mut w, 5));
        // Advance one word. Counter 0 and 5 live in word 0 and must survive.
        assert!(accept(&mut w, BITS_PER_WORD));
        assert!(!accept(&mut w, 0), "word 0 must not have been cleared");
        assert!(!accept(&mut w, 5), "word 0 must not have been cleared");
    }

    #[test]
    fn wraps_around_the_ring_without_false_replays() {
        let mut w = ReplayWindow::new();
        // Walk well past a full trip around the ring, one word at a time.
        for step in 0..(WORDS as u64 * 4) {
            let c = step * BITS_PER_WORD;
            assert!(accept(&mut w, c), "counter {c} should be accepted");
        }
    }

    #[test]
    fn check_does_not_mutate() {
        let mut w = ReplayWindow::new();
        assert!(w.check(7));
        assert!(w.check(7), "check must be idempotent");
        assert_eq!(w.highest(), None, "check must not advance the window");
        w.commit(7);
        assert!(!w.check(7));
    }

    #[test]
    fn a_forged_high_counter_cannot_shift_the_window_without_commit() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, 10));
        // An attacker's packet claiming a huge counter is checked, fails to
        // authenticate, and is never committed.
        assert!(w.check(u64::MAX / 2));
        // The legitimate next counter is unaffected.
        assert!(accept(&mut w, 11));
        assert_eq!(w.highest(), Some(11));
    }

    #[test]
    fn handles_counters_near_the_top_of_the_range() {
        let mut w = ReplayWindow::new();
        let top = u64::MAX;
        assert!(accept(&mut w, top));
        assert!(!accept(&mut w, top));
        assert!(accept(&mut w, top - 1));
        assert!(!accept(&mut w, top - WINDOW_SIZE - 1));
    }
}
