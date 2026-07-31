//! Tunnel core: Noise IK handshake, transport-packet framing, anti-replay.
//!
//! This crate performs **no I/O**. Everything here is a pure state machine over
//! byte slices, so the handshake, replay window, and framing are testable and
//! fuzzable without sockets. That constraint is deliberate — it is the single
//! biggest testability gap in the Go implementation this replaces.
//!
//! See `docs/08-rewrite-plan.md` for the design and `docs/decisions/` for the
//! decisions that constrain it.

pub mod framing;
pub mod noise;
pub mod replay;
