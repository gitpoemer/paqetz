//! Transport-packet framing (decision D7).
//!
//! Every packet on the wire is uniform random bytes end to end:
//!
//! ```text
//! [ 8-byte nonce ][ 4-byte masked index ][ AEAD ciphertext ][ 16-byte tag ]
//! ```
//!
//! There is no message type, no reserved bytes, and no length field — the
//! outer IP total length already delimits the payload. The receiver index is
//! masked with `ChaCha8(K_obf, nonce)` so it carries no cleartext identifier,
//! where `K_obf = BLAKE2s("paqetz-idx-v1" || responder_static_public)`. Both
//! ends can derive `K_obf` from values they already hold.
//!
//! The replay counter lives *inside* the ciphertext and is therefore not
//! observable on the wire.

/// Bytes of random nonce at the head of every transport packet.
pub const NONCE_LEN: usize = 8;

/// Bytes of masked session index following the nonce.
pub const INDEX_LEN: usize = 4;

/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// Total framing overhead added to each inner packet.
pub const OVERHEAD: usize = NONCE_LEN + INDEX_LEN + TAG_LEN;

/// Domain-separation label for the index-masking key (D7).
pub const INDEX_MASK_LABEL: &[u8] = b"paqetz-idx-v1";
