//! Noise IK handshake and transport sessions (decisions D1, D11).
//!
//! One cipher suite, no negotiation: X25519 for key agreement,
//! ChaCha20-Poly1305 for transport, BLAKE2s for hashing — WireGuard's
//! instantiation of Noise IK, reached through `snow`.
//!
//! The WireGuard *wire format* is deliberately not used. Its transport packet
//! begins with a cleartext message type and three reserved zero bytes; inside a
//! TCP payload that would be `04 00 00 00` at offset 0 of every data packet, an
//! instant signature. Only the cryptographic construction is shared. Framing is
//! [`crate::framing`].
//!
//! # Handshake
//!
//! ```text
//! initiator                                          responder
//!   msg1 = e, es, s, ss, {local_index} || mac1  ───▶
//!                                             ◀───  msg2 = e, ee, se, {local_index} || mac1
//! ```
//!
//! Each side tells the other which index to stamp on packets sent to it, in the
//! encrypted handshake payload. The initiator's static public key travels
//! encrypted inside msg1; the responder decrypts it, looks it up in its peer
//! list, and drops the handshake **silently** if it is not authorized, so an
//! unauthenticated prober cannot distinguish the port from one that is
//! filtered.
//!
//! # `mac1`
//!
//! Both messages carry a 16-byte keyed MAC over everything preceding it, keyed
//! on the *recipient's* static public key. It does two jobs:
//!
//! 1. **Cheap rejection.** A responder verifies `mac1` before performing any
//!    Diffie-Hellman, so flooding it with junk costs the attacker a packet and
//!    the responder one BLAKE2s rather than an X25519 scalar multiplication.
//! 2. **Keyed demultiplexing.** A handshake message and a transport packet can
//!    be the same length — a 116-byte transport packet carrying an 88-byte
//!    inner packet is entirely ordinary. `mac1` settles which one it is without
//!    a type byte on the wire, at a false-positive rate of 2⁻¹²⁸.
//!
//! Cookie replies (WireGuard's `mac2`) are not implemented. They matter when an
//! attacker can flood a public UDP port; here the carrier is TCP on a
//! non-standard port and the topology is point-to-point, so the exposure does
//! not yet justify the state.

use blake2::digest::consts::U16;
use blake2::digest::{KeyInit, Mac as _};
use blake2::{Blake2s256, Blake2sMac, Digest as _};
use snow::params::NoiseParams;
use subtle::ConstantTimeEq as _;

use crate::framing::{self, Header, HeaderMask, OVERHEAD, TAG_LEN};
use crate::keys::{PrivateKey, PublicKey};
use crate::replay::ReplayWindow;
use crate::{Error, Millis, Result};

/// The one handshake pattern. No negotiation (D1).
pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Rekey once a session has been established for this long.
pub const REKEY_AFTER_TIME: Millis = 120_000;

/// Refuse to use a session established longer ago than this.
pub const REJECT_AFTER_TIME: Millis = 180_000;

/// Rekey after this many messages have been sent under one session key.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Refuse to send more than this many messages under one session key.
///
/// Below the point at which the 64-bit counter could wrap, which would repeat
/// an AEAD nonce.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Length of the `mac1` field.
pub const MAC1_LEN: usize = 16;

/// Domain-separation label for the `mac1` key.
pub const MAC1_LABEL: &[u8] = b"paqetz-mac1-v1";

/// Bytes of handshake payload: the sender's session index.
const INDEX_PAYLOAD_LEN: usize = 4;

/// `e (32) || encrypted static (32+16) || encrypted payload (4+16) || mac1 (16)`.
pub const MSG1_LEN: usize = 32 + 48 + (INDEX_PAYLOAD_LEN + 16) + MAC1_LEN;

/// `e (32) || encrypted payload (4+16) || mac1 (16)`.
pub const MSG2_LEN: usize = 32 + (INDEX_PAYLOAD_LEN + 16) + MAC1_LEN;

/// Parses the fixed Noise pattern.
///
/// # Panics
/// Never in practice: [`PATTERN`] is a compile-time constant known to parse,
/// and a failure here would mean the crate was built against an incompatible
/// `snow`.
#[must_use]
pub fn pattern() -> NoiseParams {
    PATTERN
        .parse()
        .unwrap_or_else(|e| panic!("built-in Noise pattern {PATTERN} failed to parse: {e}"))
}

/// Computes `mac1` over `data`, keyed on the recipient's static public key.
fn mac1(recipient: &PublicKey, data: &[u8]) -> [u8; MAC1_LEN] {
    let mut kh = Blake2s256::new();
    kh.update(MAC1_LABEL);
    kh.update(recipient.as_bytes());
    let key: [u8; 32] = kh.finalize().into();

    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key)
        .unwrap_or_else(|_| unreachable!("BLAKE2s accepts a 32-byte key"));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Appends `mac1` to a message whose final [`MAC1_LEN`] bytes are reserved.
fn seal_mac1(recipient: &PublicKey, message: &mut [u8]) -> Result<()> {
    let split = message.len().checked_sub(MAC1_LEN).ok_or(Error::Short {
        need: MAC1_LEN,
        have: message.len(),
    })?;
    let (body, slot) = message.split_at_mut(split);
    slot.copy_from_slice(&mac1(recipient, body));
    Ok(())
}

/// Verifies the `mac1` trailing `message`, in constant time.
///
/// Returns the message body with `mac1` removed.
///
/// # Errors
/// Returns [`Error::Rejected`] if the MAC does not match, which is also how a
/// transport packet that happens to be handshake-sized is told apart from a
/// real handshake.
pub fn verify_mac1<'a>(recipient: &PublicKey, message: &'a [u8]) -> Result<&'a [u8]> {
    let (body, got) = message
        .split_last_chunk::<MAC1_LEN>()
        .ok_or(Error::Rejected)?;
    let want = mac1(recipient, body);
    if bool::from(want.ct_eq(got)) {
        Ok(body)
    } else {
        Err(Error::Rejected)
    }
}

/// An initiator's handshake, waiting for the responder's reply.
pub struct Initiator {
    state: snow::HandshakeState,
    responder_static: PublicKey,
    local_static: PublicKey,
    local_index: u32,
}

impl Initiator {
    /// Starts a handshake, producing msg1.
    ///
    /// `local_index` is the index the responder will stamp on packets sent back
    /// to us; the caller allocates it.
    ///
    /// # Errors
    /// Returns [`Error::Noise`] if `snow` rejects the keys.
    pub fn start(
        local: &PrivateKey,
        local_public: &PublicKey,
        responder_static: &PublicKey,
        local_index: u32,
    ) -> Result<(Self, [u8; MSG1_LEN])> {
        let mut state = snow::Builder::new(pattern())
            .local_private_key(local.as_bytes())?
            .remote_public_key(responder_static.as_bytes())?
            .build_initiator()?;

        let mut msg = [0u8; MSG1_LEN];
        let body_len = {
            let (body, _) = msg.split_at_mut(MSG1_LEN - MAC1_LEN);
            state.write_message(&local_index.to_le_bytes(), body)?
        };
        debug_assert_eq!(body_len, MSG1_LEN - MAC1_LEN);
        seal_mac1(responder_static, &mut msg)?;

        Ok((
            Self {
                state,
                responder_static: *responder_static,
                local_static: *local_public,
                local_index,
            },
            msg,
        ))
    }

    /// Consumes the responder's msg2 and produces the established session.
    ///
    /// # Errors
    /// Returns [`Error::Rejected`] if `mac1` or the AEAD fails, which is what a
    /// forged or mis-sized reply produces.
    pub fn finish(mut self, msg2: &[u8], now: Millis) -> Result<Session> {
        if msg2.len() != MSG2_LEN {
            return Err(Error::Rejected);
        }
        // msg2's mac1 is keyed on *our* static key: we are its recipient.
        let body = verify_mac1(&self.local_static, msg2)?;

        let mut payload = [0u8; INDEX_PAYLOAD_LEN];
        let n = self
            .state
            .read_message(body, &mut payload)
            .map_err(|_| Error::Rejected)?;
        if n != INDEX_PAYLOAD_LEN {
            return Err(Error::Rejected);
        }
        let remote_index = u32::from_le_bytes(payload);

        Ok(Session {
            transport: self.state.into_stateless_transport_mode()?,
            mask: HeaderMask::derive(&self.responder_static),
            local_index: self.local_index,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::new(),
            established: now,
            is_initiator: true,
        })
    }

    /// The index this side will accept on inbound packets.
    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }
}

/// A responder's handshake, after msg1 has been read but before msg2 is sent.
///
/// It exists as a distinct type so the peer-authorization decision cannot be
/// skipped: the caller must inspect [`initiator_static`](Self::initiator_static)
/// and choose to [`accept`](Self::accept). Dropping this value rejects the
/// handshake, silently and with no reply.
pub struct PendingResponder {
    state: snow::HandshakeState,
    responder_static: PublicKey,
    initiator_static: PublicKey,
    remote_index: u32,
}

impl PendingResponder {
    /// Reads msg1.
    ///
    /// Verifies `mac1` before touching the key exchange, so junk is rejected
    /// for the cost of one BLAKE2s.
    ///
    /// # Errors
    /// Returns [`Error::Rejected`] for a wrong length, a bad `mac1`, or a
    /// handshake that fails to decrypt.
    pub fn read(local: &PrivateKey, local_public: &PublicKey, msg1: &[u8]) -> Result<Self> {
        if msg1.len() != MSG1_LEN {
            return Err(Error::Rejected);
        }
        let body = verify_mac1(local_public, msg1)?;

        let mut state = snow::Builder::new(pattern())
            .local_private_key(local.as_bytes())?
            .build_responder()?;

        let mut payload = [0u8; INDEX_PAYLOAD_LEN];
        let n = state
            .read_message(body, &mut payload)
            .map_err(|_| Error::Rejected)?;
        if n != INDEX_PAYLOAD_LEN {
            return Err(Error::Rejected);
        }

        let raw = state.get_remote_static().ok_or(Error::Rejected)?;
        let initiator_static: [u8; 32] = raw.try_into().map_err(|_| Error::Rejected)?;

        Ok(Self {
            state,
            responder_static: *local_public,
            initiator_static: PublicKey::from_bytes(initiator_static),
            remote_index: u32::from_le_bytes(payload),
        })
    }

    /// The initiator's static public key, for the authorization decision.
    #[must_use]
    pub const fn initiator_static(&self) -> &PublicKey {
        &self.initiator_static
    }

    /// Accepts the handshake, producing msg2 and the established session.
    ///
    /// # Errors
    /// Returns [`Error::Noise`] if `snow` rejects the transition.
    pub fn accept(mut self, local_index: u32, now: Millis) -> Result<(Session, [u8; MSG2_LEN])> {
        let mut msg = [0u8; MSG2_LEN];
        let body_len = {
            let (body, _) = msg.split_at_mut(MSG2_LEN - MAC1_LEN);
            self.state.write_message(&local_index.to_le_bytes(), body)?
        };
        debug_assert_eq!(body_len, MSG2_LEN - MAC1_LEN);
        // msg2's mac1 is keyed on the initiator's static key: it is the recipient.
        seal_mac1(&self.initiator_static, &mut msg)?;

        let session = Session {
            transport: self.state.into_stateless_transport_mode()?,
            mask: HeaderMask::derive(&self.responder_static),
            local_index,
            remote_index: self.remote_index,
            send_counter: 0,
            replay: ReplayWindow::new(),
            established: now,
            is_initiator: false,
        };
        Ok((session, msg))
    }
}

/// An established transport session.
///
/// Holds the only per-peer state in the system (D4): the cipher state, one
/// replay window, two indices, and a send counter.
pub struct Session {
    transport: snow::StatelessTransportState,
    mask: HeaderMask,
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    replay: ReplayWindow,
    established: Millis,
    is_initiator: bool,
}

impl Session {
    /// The index this side accepts on inbound packets.
    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }

    /// The index this side stamps on outbound packets.
    #[must_use]
    pub const fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// Whether this side initiated the handshake.
    #[must_use]
    pub const fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// The header mask for this session's peer, for demultiplexing.
    #[must_use]
    pub const fn mask(&self) -> &HeaderMask {
        &self.mask
    }

    /// Encrypts one inner packet into `out`, returning the bytes written.
    ///
    /// `out` must have room for `plaintext.len() + `[`OVERHEAD`].
    ///
    /// # Errors
    /// - [`Error::Short`] if `out` is too small.
    /// - [`Error::Expired`] if the session is too old or has sent too much; the
    ///   caller must handshake again.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8], now: Millis) -> Result<usize> {
        let need = plaintext.len() + OVERHEAD;
        if out.len() < need {
            return Err(Error::Short {
                need,
                have: out.len(),
            });
        }
        if self.is_expired(now) || self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::Expired);
        }

        let counter = self.send_counter;

        let body_len = {
            let (_, body) = out.split_at_mut(framing::HEADER_LEN);
            self.transport.write_message(counter, plaintext, body)?
        };
        let total = framing::HEADER_LEN + body_len;

        // The tag is the last 16 bytes of what we just wrote, and it seeds the
        // header mask (see `framing`).
        let tag = {
            let written = out.get(..total).ok_or(Error::Short {
                need: total,
                have: out.len(),
            })?;
            let (_, tag) = written.split_last_chunk::<TAG_LEN>().ok_or(Error::Short {
                need: OVERHEAD,
                have: total,
            })?;
            *tag
        };

        let header = self.mask.mask(
            &tag,
            Header {
                counter,
                index: self.remote_index,
            },
        );
        let out_len = out.len();
        out.get_mut(..framing::HEADER_LEN)
            .ok_or(Error::Short {
                need: framing::HEADER_LEN,
                have: out_len,
            })?
            .copy_from_slice(&header);

        self.send_counter += 1;
        Ok(total)
    }

    /// Decrypts one transport packet into `out`, returning the bytes written.
    ///
    /// The replay window is consulted before decryption and only updated after
    /// it succeeds, so forged packets cannot advance it (see
    /// [`crate::replay`]).
    ///
    /// # Errors
    /// - [`Error::Short`] if the packet is too small or `out` too small.
    /// - [`Error::Rejected`] if the index does not match or the AEAD fails.
    /// - [`Error::Replay`] if the counter is stale or already seen.
    /// - [`Error::Expired`] if the session is past [`REJECT_AFTER_TIME`].
    pub fn open(&mut self, packet: &[u8], out: &mut [u8], now: Millis) -> Result<usize> {
        if self.is_expired(now) {
            return Err(Error::Expired);
        }

        let (masked, body, tag) = framing::split(packet)?;
        let header = self.mask.unmask(&tag, masked);

        if header.index != self.local_index {
            return Err(Error::Rejected);
        }
        if !self.replay.check(header.counter) {
            return Err(Error::Replay);
        }

        let n = self
            .transport
            .read_message(header.counter, body, out)
            .map_err(|_| Error::Rejected)?;

        self.replay.commit(header.counter);
        Ok(n)
    }

    /// Whether the initiator should start a fresh handshake.
    ///
    /// Only the initiator rekeys, so that both ends do not race to replace the
    /// same session.
    #[must_use]
    pub const fn needs_rekey(&self, now: Millis) -> bool {
        self.is_initiator
            && (now.saturating_sub(self.established) >= REKEY_AFTER_TIME
                || self.send_counter >= REKEY_AFTER_MESSAGES)
    }

    /// Whether the session may no longer be used at all.
    #[must_use]
    pub const fn is_expired(&self, now: Millis) -> bool {
        now.saturating_sub(self.established) >= REJECT_AFTER_TIME
    }

    /// Messages sent under this session so far.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.send_counter
    }

    /// Highest counter accepted from the peer, if any.
    #[must_use]
    pub const fn highest_received(&self) -> Option<u64> {
        self.replay.highest()
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("is_initiator", &self.is_initiator)
            .field("sent", &self.send_counter)
            .finish_non_exhaustive()
    }
}

/// Recovers the header of an inbound transport packet, for demultiplexing.
///
/// Unauthenticated: any sufficiently long byte string yields *some* header. The
/// caller uses the index to select a session, which then authenticates the
/// packet properly in [`Session::open`].
///
/// # Errors
/// Returns [`Error::Short`] if the packet cannot hold a header and a tag.
pub fn peek_header(mask: &HeaderMask, packet: &[u8]) -> Result<Header> {
    let (masked, _, tag) = framing::split(packet)?;
    Ok(mask.unmask(&tag, masked))
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::keys::KeyPair;

    struct Pair {
        client: Session,
        server: Session,
    }

    /// Runs a full handshake and returns both established sessions.
    fn handshake_at(now: Millis) -> (Pair, KeyPair, KeyPair) {
        let client_kp = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");

        let (initiator, msg1) = Initiator::start(
            &client_kp.private,
            &client_kp.public,
            &server_kp.public,
            0x1111_1111,
        )
        .expect("start");

        let pending =
            PendingResponder::read(&server_kp.private, &server_kp.public, &msg1).expect("read");
        assert_eq!(pending.initiator_static(), &client_kp.public);

        let (server, msg2) = pending.accept(0x2222_2222, now).expect("accept");
        let client = initiator.finish(&msg2, now).expect("finish");

        (Pair { client, server }, client_kp, server_kp)
    }

    fn handshake() -> Pair {
        handshake_at(0).0
    }

    fn round_trip(from: &mut Session, to: &mut Session, plaintext: &[u8], now: Millis) {
        let mut wire = vec![0u8; plaintext.len() + OVERHEAD];
        let n = from.seal(plaintext, &mut wire, now).expect("seal");
        assert_eq!(n, plaintext.len() + OVERHEAD);

        let mut out = vec![0u8; plaintext.len() + OVERHEAD];
        let m = to.open(&wire[..n], &mut out, now).expect("open");
        assert_eq!(&out[..m], plaintext);
    }

    #[test]
    fn handshake_establishes_matching_indices() {
        let p = handshake();
        assert_eq!(p.client.local_index(), 0x1111_1111);
        assert_eq!(p.client.remote_index(), 0x2222_2222);
        assert_eq!(p.server.local_index(), 0x2222_2222);
        assert_eq!(p.server.remote_index(), 0x1111_1111);
        assert!(p.client.is_initiator());
        assert!(!p.server.is_initiator());
    }

    #[test]
    fn handshake_message_lengths_are_fixed() {
        let client_kp = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");
        let (init, msg1) =
            Initiator::start(&client_kp.private, &client_kp.public, &server_kp.public, 1)
                .expect("start");
        assert_eq!(msg1.len(), MSG1_LEN);
        let pending =
            PendingResponder::read(&server_kp.private, &server_kp.public, &msg1).expect("read");
        let (_, msg2) = pending.accept(2, 0).expect("accept");
        assert_eq!(msg2.len(), MSG2_LEN);
        drop(init);
    }

    #[test]
    fn data_flows_in_both_directions() {
        let mut p = handshake();
        round_trip(&mut p.client, &mut p.server, b"client to server", 0);
        round_trip(&mut p.server, &mut p.client, b"server to client", 0);
    }

    #[test]
    fn many_packets_round_trip_in_order() {
        let mut p = handshake();
        for i in 0..1000u32 {
            let payload = i.to_le_bytes();
            round_trip(&mut p.client, &mut p.server, &payload, 0);
        }
        assert_eq!(p.client.sent(), 1000);
        assert_eq!(p.server.highest_received(), Some(999));
    }

    #[test]
    fn an_empty_inner_packet_round_trips() {
        let mut p = handshake();
        round_trip(&mut p.client, &mut p.server, b"", 0);
    }

    #[test]
    fn a_full_size_inner_packet_round_trips() {
        let mut p = handshake();
        let payload = vec![0xAB; 1400];
        round_trip(&mut p.client, &mut p.server, &payload, 0);
    }

    #[test]
    fn a_replayed_packet_is_rejected() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"once", &mut wire, 0).expect("seal");

        let mut out = vec![0u8; 128];
        assert!(p.server.open(&wire[..n], &mut out, 0).is_ok());
        assert!(matches!(
            p.server.open(&wire[..n], &mut out, 0),
            Err(Error::Replay)
        ));
    }

    #[test]
    fn reordered_packets_are_accepted() {
        let mut p = handshake();
        let mut packets = Vec::new();
        for i in 0..8u8 {
            let mut wire = vec![0u8; 16 + OVERHEAD];
            let n = p.client.seal(&[i], &mut wire, 0).expect("seal");
            wire.truncate(n);
            packets.push(wire);
        }
        packets.reverse();

        let mut out = vec![0u8; 128];
        for packet in &packets {
            assert!(p.server.open(packet, &mut out, 0).is_ok());
        }
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"authentic", &mut wire, 0).expect("seal");

        // Flip a bit in the ciphertext body.
        wire[framing::HEADER_LEN] ^= 0x01;

        let mut out = vec![0u8; 128];
        assert!(matches!(
            p.server.open(&wire[..n], &mut out, 0),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn a_tampered_header_is_rejected() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"authentic", &mut wire, 0).expect("seal");

        // Corrupting the masked header changes the recovered index, the
        // counter, or both. Either way the packet must not be accepted.
        wire[0] ^= 0xFF;

        let mut out = vec![0u8; 128];
        assert!(p.server.open(&wire[..n], &mut out, 0).is_err());
    }

    #[test]
    fn a_packet_for_another_session_is_rejected() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"hello", &mut wire, 0).expect("seal");

        // The client stamped the server's index; feeding it back to the client
        // must fail the index check rather than being decrypted.
        let mut out = vec![0u8; 128];
        assert!(matches!(
            p.client.open(&wire[..n], &mut out, 0),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn undersized_packets_are_rejected_without_panicking() {
        let mut p = handshake();
        let mut out = vec![0u8; 128];
        for len in 0..OVERHEAD {
            let packet = vec![0u8; len];
            assert!(matches!(
                p.server.open(&packet, &mut out, 0),
                Err(Error::Short { .. })
            ));
        }
    }

    #[test]
    fn random_bytes_are_rejected_without_panicking() {
        let mut p = handshake();
        let mut out = vec![0u8; 2048];
        // Deterministic pseudo-random junk of assorted lengths.
        let mut state = 0x243F_6A88_85A3_08D3u64;
        for len in OVERHEAD..(OVERHEAD + 200) {
            let packet: Vec<u8> = (0..len)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    u8::try_from((state >> 33) & 0xFF).unwrap_or(0)
                })
                .collect();
            assert!(p.server.open(&packet, &mut out, 0).is_err());
        }
    }

    #[test]
    fn seal_rejects_a_short_output_buffer() {
        let mut p = handshake();
        let mut wire = [0u8; OVERHEAD]; // room for the overhead but not the payload
        assert!(matches!(
            p.client.seal(b"too long for this buffer", &mut wire, 0),
            Err(Error::Short { .. })
        ));
    }

    #[test]
    fn an_unauthorized_initiator_is_visible_before_the_reply_is_written() {
        let stranger = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");

        let (_, msg1) = Initiator::start(
            &stranger.private,
            &stranger.public,
            &server_kp.public,
            0xAAAA,
        )
        .expect("start");

        let pending =
            PendingResponder::read(&server_kp.private, &server_kp.public, &msg1).expect("read");

        // The responder learns who is calling and can simply drop the pending
        // handshake. No msg2 is produced, so nothing goes back on the wire.
        assert_eq!(pending.initiator_static(), &stranger.public);
        drop(pending);
    }

    #[test]
    fn a_handshake_to_the_wrong_responder_key_fails_at_mac1() {
        let client_kp = KeyPair::generate().expect("generate");
        let intended = KeyPair::generate().expect("generate");
        let other_server = KeyPair::generate().expect("generate");

        let (_, msg1) =
            Initiator::start(&client_kp.private, &client_kp.public, &intended.public, 1)
                .expect("start");

        // A server that is not the intended recipient rejects on mac1, before
        // doing any Diffie-Hellman at all.
        assert!(matches!(
            PendingResponder::read(&other_server.private, &other_server.public, &msg1),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn mac1_rejects_a_corrupted_handshake() {
        let client_kp = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");
        let (_, mut msg1) =
            Initiator::start(&client_kp.private, &client_kp.public, &server_kp.public, 1)
                .expect("start");

        msg1[0] ^= 0x01;
        assert!(matches!(
            PendingResponder::read(&server_kp.private, &server_kp.public, &msg1),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn handshake_messages_of_the_wrong_length_are_rejected() {
        let server_kp = KeyPair::generate().expect("generate");
        for len in [0usize, 1, MSG1_LEN - 1, MSG1_LEN + 1, 4096] {
            let junk = vec![0u8; len];
            assert!(matches!(
                PendingResponder::read(&server_kp.private, &server_kp.public, &junk),
                Err(Error::Rejected)
            ));
        }
    }

    #[test]
    fn a_forged_msg2_is_rejected() {
        let client_kp = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");
        let (initiator, _msg1) =
            Initiator::start(&client_kp.private, &client_kp.public, &server_kp.public, 1)
                .expect("start");

        let forged = [0u8; MSG2_LEN];
        assert!(matches!(initiator.finish(&forged, 0), Err(Error::Rejected)));
    }

    #[test]
    fn two_handshakes_with_the_same_keys_produce_different_wire_bytes() {
        let client_kp = KeyPair::generate().expect("generate");
        let server_kp = KeyPair::generate().expect("generate");

        let (_, a) = Initiator::start(&client_kp.private, &client_kp.public, &server_kp.public, 1)
            .expect("start");
        let (_, b) = Initiator::start(&client_kp.private, &client_kp.public, &server_kp.public, 1)
            .expect("start");

        // Fresh ephemerals each time, so a recorded handshake cannot be replayed
        // as-is and identical sessions are not identifiable by their bytes.
        assert_ne!(a, b);
    }

    #[test]
    fn peek_header_recovers_what_seal_wrote() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"peek", &mut wire, 0).expect("seal");

        let header = peek_header(p.server.mask(), &wire[..n]).expect("peek");
        assert_eq!(header.index, p.server.local_index());
        assert_eq!(header.counter, 0);
    }

    #[test]
    fn only_the_initiator_asks_for_a_rekey() {
        let (p, ..) = handshake_at(0);
        assert!(!p.client.needs_rekey(REKEY_AFTER_TIME - 1));
        assert!(p.client.needs_rekey(REKEY_AFTER_TIME));
        // The responder never initiates, so both ends do not race.
        assert!(!p.server.needs_rekey(REKEY_AFTER_TIME));
        assert!(!p.server.needs_rekey(REJECT_AFTER_TIME * 10));
    }

    #[test]
    fn an_expired_session_refuses_to_seal_or_open() {
        let (mut p, ..) = handshake_at(0);
        let mut wire = vec![0u8; 64 + OVERHEAD];
        let n = p.client.seal(b"in time", &mut wire, 0).expect("seal");

        assert!(matches!(
            p.client.seal(b"too late", &mut wire, REJECT_AFTER_TIME),
            Err(Error::Expired)
        ));
        let mut out = vec![0u8; 128];
        assert!(matches!(
            p.server.open(&wire[..n], &mut out, REJECT_AFTER_TIME),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn a_session_established_late_measures_age_from_establishment() {
        let (mut p, ..) = handshake_at(1_000_000);
        let mut wire = vec![0u8; 64 + OVERHEAD];
        // Well past REJECT_AFTER_TIME in absolute terms, but young.
        assert!(p.client.seal(b"fine", &mut wire, 1_000_000).is_ok());
        assert!(
            p.client
                .seal(b"fine", &mut wire, 1_000_000 + REJECT_AFTER_TIME - 1)
                .is_ok()
        );
        assert!(matches!(
            p.client
                .seal(b"stale", &mut wire, 1_000_000 + REJECT_AFTER_TIME),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn the_counter_advances_by_one_per_sealed_packet() {
        let mut p = handshake();
        let mut wire = vec![0u8; 64 + OVERHEAD];
        for expected in 0..10 {
            assert_eq!(p.client.sent(), expected);
            let n = p.client.seal(b"x", &mut wire, 0).expect("seal");
            let header = peek_header(p.server.mask(), &wire[..n]).expect("peek");
            assert_eq!(header.counter, expected);
        }
    }

    #[test]
    fn wire_bytes_carry_no_fixed_prefix() {
        // The property that rules out WireGuard's framing: no byte position may
        // be constant across packets. Checked over a run of packets from a
        // single session, where a type byte or reserved field would show up.
        let mut p = handshake();
        let mut first: Option<Vec<u8>> = None;
        let mut differs = [false; framing::HEADER_LEN];

        for i in 0..64u8 {
            let mut wire = vec![0u8; 32 + OVERHEAD];
            let n = p.client.seal(&[i; 8], &mut wire, 0).expect("seal");
            wire.truncate(n);
            match &first {
                None => first = Some(wire),
                Some(f) => {
                    for (idx, flag) in differs.iter_mut().enumerate() {
                        if f.get(idx) != wire.get(idx) {
                            *flag = true;
                        }
                    }
                }
            }
        }

        assert!(
            differs.iter().all(|d| *d),
            "every header byte must vary across packets; constant positions were {:?}",
            differs
                .iter()
                .enumerate()
                .filter(|(_, d)| !**d)
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        );
    }
}
