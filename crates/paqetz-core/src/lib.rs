//! Tunnel core: Noise IK handshake, transport-packet framing, anti-replay.
//!
//! This crate performs **no I/O** and reads no clock. Everything here is a pure
//! state machine over byte slices, with the current time passed in by the
//! caller, so the handshake, replay window, and framing are testable and
//! fuzzable without sockets or sleeps. That constraint is deliberate — it is
//! the single biggest testability gap in the Go implementation this replaces.
//!
//! See `docs/08-rewrite-plan.md` for the design and `docs/decisions/` for the
//! decisions that constrain it.

pub mod framing;
pub mod keys;
pub mod noise;
pub mod replay;

pub use keys::{KeyPair, PrivateKey, PublicKey};

/// Milliseconds from an arbitrary monotonic origin.
///
/// Time enters this crate only as a parameter. The caller owns the clock, which
/// keeps the crate I/O-free and lets tests drive rekey timing without waiting.
pub type Millis = u64;

/// Anything that can go wrong in the core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A buffer was too short to hold or to contain a complete message.
    #[error("buffer too short: need at least {need} bytes, have {have}")]
    Short {
        /// Minimum acceptable length.
        need: usize,
        /// Length actually supplied.
        have: usize,
    },

    /// AEAD authentication failed, or the handshake was malformed.
    ///
    /// Deliberately carries no detail. This is the error an attacker can
    /// provoke at will, so distinguishing "bad tag" from "unknown peer" here
    /// would hand them an oracle. The caller drops the packet either way.
    #[error("packet failed authentication")]
    Rejected,

    /// The counter was outside the replay window, or has already been seen.
    #[error("replayed or stale counter")]
    Replay,

    /// The session has sent or lived too long to keep using (see
    /// [`noise::REJECT_AFTER_TIME`] and [`noise::REJECT_AFTER_MESSAGES`]).
    #[error("session expired; a new handshake is required")]
    Expired,

    /// The initiator's static key is not in the responder's peer list.
    #[error("peer is not authorized")]
    Unauthorized,

    /// A key was not the expected length, or was not valid base64.
    #[error("malformed key: {0}")]
    MalformedKey(&'static str),

    /// The Noise implementation rejected an operation.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
