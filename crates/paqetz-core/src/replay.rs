//! Sliding-window anti-replay over the in-ciphertext counter.
//!
//! The tunnel provides no ordering and no retransmission (decision D2), so the
//! receive path must tolerate reordering and duplication while rejecting
//! replays. A sliding bitmap window over the 64-bit counter does both: counters
//! ahead of the window advance it, counters inside it are accepted once, and
//! counters behind it are dropped.

/// Width of the replay bitmap, in counter positions.
///
/// Sized so that reordering across a high-bandwidth-delay path is tolerated
/// without ever falling outside the window.
pub const WINDOW_BITS: usize = 2048;
