//! Static keypairs and their textual form (decision D11).
//!
//! Peers are named by X25519 public key. There is no password anywhere in the
//! system: the private key *is* the secret, and the public key is not sensitive
//! and may be exchanged over any channel.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Length of an X25519 key, public or private.
pub const KEY_LEN: usize = 32;

/// A peer's public identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Parses the standard base64 form.
    ///
    /// # Errors
    /// Returns [`Error::MalformedKey`] if the input is not base64 or does not
    /// decode to exactly [`KEY_LEN`] bytes.
    pub fn from_base64(s: &str) -> Result<Self> {
        let raw = B64
            .decode(s.trim())
            .map_err(|_| Error::MalformedKey("not valid base64"))?;
        let bytes: [u8; KEY_LEN] = raw
            .try_into()
            .map_err(|_| Error::MalformedKey("wrong length for an X25519 key"))?;
        Ok(Self(bytes))
    }

    /// Renders the standard base64 form.
    #[must_use]
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public keys are not secret, so showing them aids debugging.
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// A peer's private identity. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; KEY_LEN]);

impl PrivateKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Parses the standard base64 form.
    ///
    /// # Errors
    /// Returns [`Error::MalformedKey`] if the input is not base64 or does not
    /// decode to exactly [`KEY_LEN`] bytes.
    pub fn from_base64(s: &str) -> Result<Self> {
        let mut raw = B64
            .decode(s.trim())
            .map_err(|_| Error::MalformedKey("not valid base64"))?;
        let parsed: core::result::Result<[u8; KEY_LEN], _> = raw.as_slice().try_into();
        // Zeroize the intermediate decode buffer regardless of the outcome:
        // it holds the private key, and `Vec` will not clear itself on drop.
        let bytes = parsed.map_err(|_| Error::MalformedKey("wrong length for an X25519 key"));
        raw.zeroize();
        Ok(Self(bytes?))
    }

    /// Renders the standard base64 form.
    ///
    /// The caller is responsible for the lifetime of the returned `String`;
    /// it is not zeroized. Use only when writing a freshly generated key out.
    #[must_use]
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the key. A private key reaching a log is the failure
        // this impl exists to prevent.
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for PrivateKey {}

/// Recovers the public key belonging to a private one.
///
/// Needed because a configuration file holds only the private key, exactly as
/// WireGuard's does: the public half is derivable, so storing it would be a
/// second copy that could disagree with the first.
#[must_use]
pub fn public_from_private(private: &[u8; KEY_LEN]) -> PublicKey {
    let secret = x25519_dalek::StaticSecret::from(*private);
    PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
}

/// A static keypair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The secret half.
    pub private: PrivateKey,
    /// The half that is published to the other end.
    pub public: PublicKey,
}

impl KeyPair {
    /// Generates a fresh keypair from the operating system's CSPRNG.
    ///
    /// # Errors
    /// Returns [`Error::Noise`] if the underlying generator fails.
    pub fn generate() -> Result<Self> {
        let params = crate::noise::pattern();
        let kp = snow::Builder::new(params).generate_keypair()?;
        let private: [u8; KEY_LEN] =
            kp.private.as_slice().try_into().map_err(|_| {
                Error::MalformedKey("generator produced a wrong-length private key")
            })?;
        let public: [u8; KEY_LEN] = kp
            .public
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedKey("generator produced a wrong-length public key"))?;
        Ok(Self {
            private: PrivateKey(private),
            public: PublicKey(public),
        })
    }
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn generate_produces_distinct_keypairs() {
        let a = KeyPair::generate().expect("generate");
        let b = KeyPair::generate().expect("generate");
        assert_ne!(a.public, b.public);
        assert_ne!(a.private, b.private);
    }

    #[test]
    fn a_public_key_can_be_recovered_from_its_private_half() {
        let kp = KeyPair::generate().expect("generate");
        assert_eq!(public_from_private(kp.private.as_bytes()), kp.public);
    }

    #[test]
    fn distinct_private_keys_give_distinct_public_keys() {
        let a = KeyPair::generate().expect("generate");
        let b = KeyPair::generate().expect("generate");
        assert_ne!(
            public_from_private(a.private.as_bytes()),
            public_from_private(b.private.as_bytes())
        );
    }

    #[test]
    fn base64_round_trips() {
        let kp = KeyPair::generate().expect("generate");

        let pub_text = kp.public.to_base64();
        assert_eq!(PublicKey::from_base64(&pub_text).expect("parse"), kp.public);

        let priv_text = kp.private.to_base64();
        assert_eq!(
            PrivateKey::from_base64(&priv_text).expect("parse"),
            kp.private
        );
    }

    #[test]
    fn base64_tolerates_surrounding_whitespace() {
        let kp = KeyPair::generate().expect("generate");
        let padded = format!("  {}\n", kp.public.to_base64());
        assert_eq!(PublicKey::from_base64(&padded).expect("parse"), kp.public);
    }

    #[test]
    fn wrong_length_is_rejected() {
        // Valid base64, but 31 bytes rather than 32.
        let short = B64.encode([0u8; 31]);
        assert!(matches!(
            PublicKey::from_base64(&short),
            Err(Error::MalformedKey(_))
        ));
        assert!(matches!(
            PrivateKey::from_base64(&short),
            Err(Error::MalformedKey(_))
        ));
    }

    #[test]
    fn non_base64_is_rejected() {
        assert!(matches!(
            PublicKey::from_base64("!!! not base64 !!!"),
            Err(Error::MalformedKey(_))
        ));
    }

    #[test]
    fn private_key_debug_does_not_leak() {
        let kp = KeyPair::generate().expect("generate");
        let rendered = format!("{:?}", kp.private);
        assert_eq!(rendered, "PrivateKey(<redacted>)");
        assert!(!rendered.contains(&kp.private.to_base64()));

        // And the same must hold when nested inside the KeyPair's derived Debug.
        let nested = format!("{:?}", kp);
        assert!(!nested.contains(&kp.private.to_base64()));
    }
}
