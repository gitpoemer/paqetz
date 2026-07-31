//! Fake-TCP wire format (decision D6).
//!
//! Each transport packet is carried as the payload of one hand-crafted TCP
//! segment. No kernel TCP stack owns these segments, so nothing ever
//! retransmits them — the channel is a lossy datagram channel, which is
//! exactly what the tunnel above expects.
//!
//! This crate is deliberately payload-agnostic: it emits and parses opaque
//! byte slices and does not depend on `paqetz-core`. Keeping the framing and
//! the carrier independent is what lets each be fuzzed on its own.
//!
//! # What was carried over from paqet, and what was fixed
//!
//! Kept, because they were right: varying IP Identification, and echoing the
//! peer's observed TCP timestamp so a middlebox checking timestamp reciprocity
//! sees real semantics.
//!
//! Fixed, because each was a signature:
//!
//! - **A synthetic handshake.** paqet's flows began mid-stream with `PSH,ACK`
//!   and never carried a SYN, so every flow was permanently half-open from the
//!   network's point of view. See [`endpoint`].
//! - **Byte-accurate sequencing.** paqet computed `seq` from a packet counter,
//!   unrelated to the bytes it had sent. Here `seq` and `ack` are exactly the
//!   bytes sent and received.
//! - **No flag cycling.** paqet cycled TCP flags from a configured list because
//!   its sequence numbers were invented and no combination was more coherent
//!   than another. With a real connection underneath, random flags would now
//!   contradict the state they sit alongside, so the flags follow from what the
//!   segment is for. See [`segment::Kind`].
//! - **Profile-driven constants.** TTL, MSS, window scale, and window come from
//!   an [`profile::OsProfile`] rather than being the same four numbers forever.
//! - **DSCP 0.** paqet marked every packet Expedited Forwarding, which is an
//!   odd marking for bulk traffic and is re-marked or policed on many networks.
//! - **A `FIN` on close**, rather than the flow simply stopping.

pub mod checksum;
pub mod endpoint;
pub mod profile;
pub mod segment;

pub use endpoint::{Endpoint, Phase, Role};
pub use profile::OsProfile;
pub use segment::{Kind, Segment};

/// Anything that can go wrong building or reading a segment.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A buffer was too short to hold the segment.
    #[error("buffer too short: need {need} bytes, have {have}")]
    Short {
        /// Minimum acceptable length.
        need: usize,
        /// Length actually supplied.
        have: usize,
    },

    /// The packet would not fit in an IPv4 datagram.
    #[error("packet of {len} bytes exceeds what IPv4 can express")]
    TooLong {
        /// The offending length.
        len: usize,
    },

    /// Data was offered before the synthetic handshake completed.
    #[error("connection is not established")]
    NotEstablished,
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
