//! Transport-packet framing (decision D7).
//!
//! Every packet on the wire is uniform random bytes end to end:
//!
//! ```text
//! [ masked header: 12 ][ ciphertext ][ Poly1305 tag: 16 ]
//! ```
//!
//! The header is `counter (u64 LE) || index (u32 LE)`, XORed with a ChaCha8
//! keystream. There is no message type, no reserved bytes, and no length field
//! — the outer IP total length already delimits the payload.
//!
//! # Why the counter is masked rather than sent in the clear
//!
//! The counter must be the AEAD nonce: it is monotonic, so it can never repeat,
//! whereas a random 8-byte nonce would collide with non-negligible probability
//! within a single session at the packet rates this is built for. But a
//! monotonically increasing integer at a fixed offset is exactly the kind of
//! structure a classifier looks for. Masking gives both properties at once.
//!
//! # Why the mask is keyed on the tag
//!
//! The mask must be computable by the receiver *before* it knows which session
//! the packet belongs to — the index it is trying to recover is what identifies
//! the session. So the keystream nonce has to come from somewhere already
//! visible and unpredictable. The Poly1305 tag is both: uniformly random,
//! always present, always exactly 16 bytes, and different for every packet.
//!
//! The mask key is `K_obf = BLAKE2s("paqetz-idx-v1" || responder_static_public)`,
//! which both ends can derive from what they already hold and which is the same
//! in both directions. An observer without the responder's public key sees
//! uniform random bytes. An observer who has it learns only an opaque session
//! index and a counter — and could have actively probed the responder anyway.
//! This is the same posture as WireGuard's `mac1`.

use blake2::{Blake2s256, Digest as _};
use chacha20::ChaCha8;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};

use crate::keys::PublicKey;
use crate::{Error, Result};

/// Bytes of masked header at the head of every transport packet.
pub const HEADER_LEN: usize = 12;

/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// Total framing overhead added to each inner packet.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// Domain-separation label for the header-masking key.
pub const HEADER_MASK_LABEL: &[u8] = b"paqetz-idx-v1";

/// ChaCha8 nonce width.
const NONCE_LEN: usize = 12;

/// The cleartext contents of a transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Per-session send counter; doubles as the AEAD nonce.
    pub counter: u64,
    /// The receiving session's index, as chosen by the receiver.
    pub index: u32,
}

/// Derives and applies the header mask.
///
/// Cheap to clone; holds only a 32-byte key.
#[derive(Clone)]
pub struct HeaderMask {
    key: [u8; 32],
}

impl HeaderMask {
    /// Derives the mask key from the responder's static public key.
    ///
    /// Both ends call this with the *same* key — the responder's — so the mask
    /// is symmetric across directions.
    #[must_use]
    pub fn derive(responder_static_public: &PublicKey) -> Self {
        let mut h = Blake2s256::new();
        h.update(HEADER_MASK_LABEL);
        h.update(responder_static_public.as_bytes());
        Self {
            key: h.finalize().into(),
        }
    }

    /// Produces the keystream that masks one header.
    fn keystream(&self, tag: &[u8; TAG_LEN]) -> [u8; HEADER_LEN] {
        let (nonce, _) = tag
            .split_first_chunk::<NONCE_LEN>()
            .unwrap_or((&[0; NONCE_LEN], &[]));
        let mut cipher = ChaCha8::new(&self.key.into(), nonce.into());
        let mut ks = [0u8; HEADER_LEN];
        cipher.apply_keystream(&mut ks);
        ks
    }

    /// Masks a header for transmission.
    #[must_use]
    pub fn mask(&self, tag: &[u8; TAG_LEN], header: Header) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (counter_bytes, index_bytes) = out.split_at_mut(8);
        counter_bytes.copy_from_slice(&header.counter.to_le_bytes());
        index_bytes.copy_from_slice(&header.index.to_le_bytes());

        let ks = self.keystream(tag);
        for (b, k) in out.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
        out
    }

    /// Recovers a header from the wire.
    ///
    /// This is an unauthenticated transformation: any 12 bytes decode to *some*
    /// header. A forged packet simply yields a header that identifies no
    /// session, or one whose AEAD open then fails.
    #[must_use]
    pub fn unmask(&self, tag: &[u8; TAG_LEN], masked: &[u8; HEADER_LEN]) -> Header {
        let ks = self.keystream(tag);
        let mut plain = [0u8; HEADER_LEN];
        for ((p, m), k) in plain.iter_mut().zip(masked.iter()).zip(ks.iter()) {
            *p = *m ^ *k;
        }

        let (counter_bytes, index_bytes) = plain.split_at(8);
        let counter = u64::from_le_bytes(counter_bytes.try_into().unwrap_or([0; 8]));
        let index = u32::from_le_bytes(index_bytes.try_into().unwrap_or([0; 4]));
        Header { counter, index }
    }
}

impl core::fmt::Debug for HeaderMask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The mask key is derived from a public value and is not a secret, but
        // printing it invites confusion with keys that are.
        f.write_str("HeaderMask(..)")
    }
}

/// Splits a received packet into its masked header, body, and tag.
///
/// The body returned is the ciphertext *including* the trailing tag, which is
/// what the AEAD open call expects; `tag` is a copy of those last 16 bytes,
/// needed to derive the header mask before decryption.
///
/// # Errors
/// Returns [`Error::Short`] if the packet cannot hold a header and a tag.
pub fn split(packet: &[u8]) -> Result<(&[u8; HEADER_LEN], &[u8], [u8; TAG_LEN])> {
    let (header, body) = packet
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(Error::Short {
            need: OVERHEAD,
            have: packet.len(),
        })?;
    let (_, tag) = body.split_last_chunk::<TAG_LEN>().ok_or(Error::Short {
        need: OVERHEAD,
        have: packet.len(),
    })?;
    Ok((header, body, *tag))
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::keys::KeyPair;

    fn mask_for_test() -> HeaderMask {
        let kp = KeyPair::generate().expect("generate");
        HeaderMask::derive(&kp.public)
    }

    #[test]
    fn mask_then_unmask_round_trips() {
        let m = mask_for_test();
        let tag = [0xA5; TAG_LEN];
        let header = Header {
            counter: 0x0123_4567_89AB_CDEF,
            index: 0xDEAD_BEEF,
        };
        let wire = m.mask(&tag, header);
        assert_eq!(m.unmask(&tag, &wire), header);
    }

    #[test]
    fn round_trips_at_the_extremes() {
        let m = mask_for_test();
        let tag = [0x00; TAG_LEN];
        for header in [
            Header {
                counter: 0,
                index: 0,
            },
            Header {
                counter: u64::MAX,
                index: u32::MAX,
            },
        ] {
            let wire = m.mask(&tag, header);
            assert_eq!(m.unmask(&tag, &wire), header);
        }
    }

    #[test]
    fn the_masked_header_does_not_equal_the_plaintext() {
        let m = mask_for_test();
        let tag = [0x11; TAG_LEN];
        let header = Header {
            counter: 0,
            index: 0,
        };
        // An all-zero header is the worst case: if masking were a no-op it
        // would show up here as twelve zero bytes on the wire.
        let wire = m.mask(&tag, header);
        assert_ne!(wire, [0u8; HEADER_LEN]);
    }

    #[test]
    fn consecutive_counters_do_not_produce_correlated_wire_bytes() {
        // The point of masking is that a monotonic counter must not appear as a
        // monotonic field. Successive counters share a tag here only because
        // the test forces it; in practice tags differ too, which helps further.
        let m = mask_for_test();
        let tag = [0x22; TAG_LEN];
        let a = m.mask(
            &tag,
            Header {
                counter: 1000,
                index: 7,
            },
        );
        let b = m.mask(
            &tag,
            Header {
                counter: 1001,
                index: 7,
            },
        );
        // With a shared keystream the XOR of the two wire headers is the XOR of
        // the two plaintexts, so they differ only where 1000 ^ 1001 does. That
        // is expected; what must not happen is the wire bytes *being* the
        // counter.
        assert_ne!(&a[..8], &1000u64.to_le_bytes());
        assert_ne!(&b[..8], &1001u64.to_le_bytes());
    }

    #[test]
    fn a_different_tag_gives_a_different_mask() {
        let m = mask_for_test();
        let header = Header {
            counter: 42,
            index: 42,
        };
        let a = m.mask(&[0x01; TAG_LEN], header);
        let b = m.mask(&[0x02; TAG_LEN], header);
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_responder_key_gives_a_different_mask() {
        let one = mask_for_test();
        let two = mask_for_test();
        let tag = [0x33; TAG_LEN];
        let header = Header {
            counter: 42,
            index: 42,
        };
        assert_ne!(one.mask(&tag, header), two.mask(&tag, header));
    }

    #[test]
    fn deriving_twice_from_the_same_key_agrees() {
        let kp = KeyPair::generate().expect("generate");
        let a = HeaderMask::derive(&kp.public);
        let b = HeaderMask::derive(&kp.public);
        let tag = [0x44; TAG_LEN];
        let header = Header {
            counter: 9,
            index: 9,
        };
        assert_eq!(a.mask(&tag, header), b.mask(&tag, header));
    }

    #[test]
    fn split_rejects_undersized_packets() {
        for len in 0..OVERHEAD {
            let packet = vec![0u8; len];
            assert!(
                matches!(split(&packet), Err(Error::Short { .. })),
                "a {len}-byte packet must be rejected"
            );
        }
    }

    #[test]
    fn split_accepts_the_minimum_and_returns_the_trailing_tag() {
        let mut packet = vec![0u8; OVERHEAD];
        // Distinguish the tag bytes from the header bytes.
        for (i, b) in packet.iter_mut().enumerate().skip(HEADER_LEN) {
            *b = u8::try_from(i).unwrap_or(0xFF);
        }
        let (header, body, tag) = split(&packet).expect("split");
        assert_eq!(header.len(), HEADER_LEN);
        assert_eq!(body.len(), TAG_LEN, "an empty ciphertext is just the tag");
        assert_eq!(&tag[..], &packet[HEADER_LEN..]);
    }

    #[test]
    fn header_debug_does_not_render_the_key() {
        let m = mask_for_test();
        assert_eq!(format!("{m:?}"), "HeaderMask(..)");
    }
}
