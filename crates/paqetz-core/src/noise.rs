//! Noise IK handshake and transport sessions (decisions D1, D11).
//!
//! One cipher suite, no negotiation: X25519 for key agreement,
//! ChaCha20-Poly1305 for transport, BLAKE2s for hashing — WireGuard's
//! instantiation of Noise IK.
//!
//! Peers are named by static public key. The initiator's static key travels
//! encrypted inside the first handshake message; the responder decrypts it,
//! looks it up in its peer list, and drops the handshake **silently** if the
//! key is not authorized. An unauthenticated prober therefore cannot
//! distinguish the port from one that is filtered.
//!
//! Note that the WireGuard *wire format* is deliberately not used — its
//! cleartext `04 00 00 00` prefix would be an instant signature inside a TCP
//! payload. Only the cryptographic construction is shared. See
//! [`crate::framing`].

use core::time::Duration;

/// Rekey after this much time has elapsed on a session.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Refuse to use a session older than this; force a new handshake.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Rekey after this many messages have been sent under one session key.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
