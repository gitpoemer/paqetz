//! GRE carrier: RFC 2784, IP protocol 47.
//!
//! An alternative to the fake-TCP carrier for a path that refuses it. Measured
//! on a censored route where a TCP five-tuple stopped being carried after
//! hours while GRE went through untouched in both directions -- and where a
//! *malformed* GRE packet was dropped, so something on that path parses this
//! header even though nothing needs to.
//!
//! Twenty-four bytes of outer header against fake-TCP's fifty-odd, no ports, no
//! sequence numbers, no per-packet state at all. What it costs is reachability:
//! protocol 47 has no ports, so it does not survive NAT, and plenty of networks
//! drop it. That is a property of the path, not a setting, which is why this is
//! a choice rather than a default.
//!
//! Everything above the wire is unchanged. This produces and consumes the same
//! opaque byte slices the fake-TCP carrier does, and the tunnel's handshake,
//! replay window, rekeying and roaming never learn which one carried them.

use core::net::Ipv4Addr;

use crate::checksum;
use crate::profile::OsProfile;
use crate::segment::{self, ETH_LEN, ETHERTYPE_IPV4, IPV4_LEN};
use crate::{Error, Result};

/// IP protocol number for GRE.
pub const PROTO_GRE: u8 = 47;

/// The GRE header we emit, and the shortest one there is: no checksum, no key,
/// no sequence number, version 0.
pub const GRE_LEN: usize = 4;

/// Bytes of outer header a GRE-carried packet pays.
pub const OVERHEAD: usize = IPV4_LEN + GRE_LEN;

/// GRE protocol type for IPv4, matching the EtherType.
const GRE_PROTO_IPV4: u16 = ETHERTYPE_IPV4;

/// Flag bits in the first halfword that add optional words after the header.
///
/// Checksum-present adds four bytes (checksum and reserved); key adds four;
/// sequence-number adds four. Read to find the payload, never to refuse a
/// packet -- see [`payload_offset`].
const FLAG_CHECKSUM: u16 = 0x8000;
const FLAG_KEY: u16 = 0x2000;
const FLAG_SEQUENCE: u16 = 0x1000;

/// How this end carries packets over GRE.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Our own outer address.
    pub local: Ipv4Addr,
    /// The peer's, as far as we currently know.
    pub remote: Ipv4Addr,
    /// Which stack to resemble, for the TTL.
    pub profile: OsProfile,
}

/// A GRE carrier for one peer.
///
/// Holds almost nothing, which is the point: the fake-TCP carrier keeps a
/// sequence space, an acknowledgement, a timestamp base and a connection phase,
/// all of which exist to make a synthetic conversation coherent. GRE has no
/// conversation to be coherent about.
#[derive(Debug, Clone)]
pub struct Carrier {
    local: Ipv4Addr,
    remote: Ipv4Addr,
    profile: OsProfile,
    /// Packets sent, feeding the IP Identification.
    ///
    /// Deliberately `u32`: the hash below multiplies and then shifts down
    /// sixteen, which is exact only when the multiply has already wrapped at
    /// thirty-two bits. Widened to `u64` the shift leaves forty-eight
    /// significant bits, the narrowing fails for all but the first few packets,
    /// and every one of them goes out with Identification zero -- a far
    /// stronger marking than the counter this is meant to hide.
    counter: u32,
}

impl Carrier {
    /// Starts a carrier for this peer.
    #[must_use]
    pub const fn new(cfg: Config) -> Self {
        Self {
            local: cfg.local,
            remote: cfg.remote,
            profile: cfg.profile,
            counter: 0,
        }
    }

    /// The peer's current address.
    #[must_use]
    pub const fn remote(&self) -> Ipv4Addr {
        self.remote
    }

    /// Follows the peer to a new address.
    pub const fn set_remote(&mut self, remote: Ipv4Addr) {
        self.remote = remote;
    }

    /// Writes one packet, returning how many bytes were used.
    ///
    /// # Errors
    /// Returns [`Error::Short`] if `out` cannot hold it, or [`Error::TooLong`]
    /// if the result would not fit an IPv4 length field.
    pub fn data(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let total = OVERHEAD + payload.len();
        if out.len() < total {
            return Err(Error::Short {
                need: total,
                have: out.len(),
            });
        }
        let ip_total = u16::try_from(total).map_err(|_| Error::TooLong { len: total })?;

        // Per carrier rather than per process. One counter shared across every
        // peer is a single monotonic sequence spanning all of them, which is a
        // stronger identifier than anything else on the wire here.
        self.counter = self.counter.wrapping_add(1);
        let ip_id = u16::try_from(self.counter.wrapping_mul(0x9E37_79B9) >> 16).unwrap_or(0);

        {
            let mut c = segment::Cursor::new(out);
            c.u8(0x45)?; // version 4, IHL 5 words
            c.u8(0)?; // DSCP 0, as the fake-TCP carrier emits
            c.u16(ip_total)?;
            c.u16(ip_id)?;
            // Don't Fragment, as the fake-TCP carrier sets. A path too small to
            // carry this then says so, and `toobig` reads the answer; clearing
            // it would fragment silently into a capture socket that sees the
            // pieces before the kernel joins them.
            c.u16(0x4000)?;
            c.u8(self.profile.ttl)?;
            c.u8(PROTO_GRE)?;
            c.u16(0)?; // checksum, filled below
            c.put(&self.local.octets())?;
            c.put(&self.remote.octets())?;

            // The minimal RFC 2784 header, every optional field absent.
            // Emitted in full rather than zeroed and forgotten: the path this
            // was measured on drops GRE it cannot parse, so a well-formed
            // header is load-bearing.
            c.u16(0)?;
            c.u16(GRE_PROTO_IPV4)?;
            debug_assert_eq!(c.pos, OVERHEAD);
            c.put(payload)?;
        }

        let ip_ck = {
            let have = out.len();
            checksum::of(out.get(..IPV4_LEN).ok_or(Error::Short {
                need: IPV4_LEN,
                have,
            })?)
        };
        segment::write_at(out, 10, &ip_ck.to_be_bytes())?;
        Ok(total)
    }
}

/// A GRE packet, as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received<'a> {
    /// Who sent it.
    pub src: Ipv4Addr,
    /// Who it was addressed to.
    pub dst: Ipv4Addr,
    /// What the GRE header said it carries.
    pub protocol: u16,
    /// Everything after the GRE header.
    pub payload: &'a [u8],
}

/// Reads a GRE packet out of a captured Ethernet frame.
#[must_use]
pub fn parse_ethernet(frame: &[u8]) -> Option<Received<'_>> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    parse_ipv4(frame.get(ETH_LEN..)?)
}

/// As above, starting at the IPv4 header.
#[must_use]
pub fn parse_ipv4(packet: &[u8]) -> Option<Received<'_>> {
    let ver_ihl = *packet.first()?;
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl_words = usize::from(ver_ihl & 0x0F);
    if ihl_words < 5 {
        return None;
    }
    let ip_header_len = ihl_words * 4;

    if *packet.get(9)? != PROTO_GRE {
        return None;
    }

    // Fragments, on the same terms as the carrier parser: only Don't Fragment
    // may be set, because anything else means this is not a whole datagram.
    let frag = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    if frag & 0xBFFF != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if total_len < ip_header_len || total_len > packet.len() {
        return None;
    }

    let src = address(packet, 12)?;
    let dst = address(packet, 16)?;

    let gre = packet.get(ip_header_len..total_len)?;
    let flags = u16::from_be_bytes([*gre.first()?, *gre.get(1)?]);
    let protocol = u16::from_be_bytes([*gre.get(2)?, *gre.get(3)?]);
    let payload = gre.get(payload_offset(flags)?..)?;

    Some(Received {
        src,
        dst,
        protocol,
        payload,
    })
}

/// Where the payload starts, given the header's flags.
///
/// The flags say how many optional words follow, and that is the only thing
/// they are read for. Refusing a packet because a bit is set would let anyone
/// on the path break the tunnel by flipping one, and would gain nothing: the
/// header is outside the AEAD, so a tampered packet either shifts this offset
/// and fails to decrypt, or does not and decrypts correctly. Rejecting turns
/// the second case -- which the tunnel survives -- into a loss.
///
/// Version is likewise ignored. Version 1 is PPTP's, whose header is laid out
/// differently, but a middlebox that rewrites our packets into PPTP's shape has
/// already broken the payload; there is nothing to preserve by refusing.
///
/// `None` if the flags describe a header longer than the packet could hold.
#[must_use]
pub fn payload_offset(flags: u16) -> Option<usize> {
    let mut len = GRE_LEN;
    // Checksum-present adds a checksum and a reserved halfword together.
    if flags & FLAG_CHECKSUM != 0 {
        len += 4;
    }
    if flags & FLAG_KEY != 0 {
        len += 4;
    }
    if flags & FLAG_SEQUENCE != 0 {
        len += 4;
    }
    Some(len)
}

/// Reads a four-byte address at `at`.
fn address(packet: &[u8], at: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(
        *packet.get(at)?,
        *packet.get(at + 1)?,
        *packet.get(at + 2)?,
        *packet.get(at + 3)?,
    ))
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn carrier() -> Carrier {
        Carrier::new(Config {
            local: Ipv4Addr::new(10, 0, 0, 1),
            remote: Ipv4Addr::new(203, 0, 113, 5),
            profile: crate::profile::LINUX_6,
        })
    }

    /// Wraps an emitted packet in an Ethernet header, as capture would see it.
    fn captured(packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_LEN];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn what_is_emitted_is_what_rfc_2784_describes() {
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        assert_eq!(n, OVERHEAD + 7);
        assert_eq!(OVERHEAD, 24, "twenty of IPv4 and four of GRE");

        assert_eq!(out[0], 0x45, "version 4, no options");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 31, "total length");
        assert_eq!(
            u16::from_be_bytes([out[6], out[7]]),
            0x4000,
            "Don't Fragment, so a small hop reports itself"
        );
        assert_eq!(out[9], PROTO_GRE);
        assert_eq!(&out[12..16], &[10, 0, 0, 1]);
        assert_eq!(&out[16..20], &[203, 0, 113, 5]);

        // The minimal header: no checksum, no key, no sequence, version 0.
        assert_eq!(&out[20..22], &[0, 0], "every optional field absent");
        assert_eq!(
            u16::from_be_bytes([out[22], out[23]]),
            0x0800,
            "carries IPv4"
        );
        assert_eq!(&out[OVERHEAD..31], b"payload");
    }

    #[test]
    fn the_header_checksum_is_computed_rather_than_left_to_the_kernel() {
        // The AF_PACKET transmit path does not fill it in, and a zero IPv4
        // checksum is not legal anywhere.
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        assert_ne!(u16::from_be_bytes([out[10], out[11]]), 0);
        assert_eq!(
            checksum::of(&out[..IPV4_LEN]),
            0,
            "a correct header sums to zero over itself"
        );
        let _ = n;
    }

    #[test]
    fn a_packet_survives_its_own_round_trip() {
        let mut out = vec![0u8; 2000];
        let n = carrier().data(b"the inner packet", &mut out).expect("emit");
        let frame = captured(&out[..n]);
        let got = parse_ethernet(&frame).expect("parse");
        assert_eq!(got.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(got.dst, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(got.protocol, 0x0800);
        assert_eq!(got.payload, b"the inner packet");
    }

    #[test]
    fn the_identification_varies_between_packets() {
        // One counter for every peer would be a single monotonic sequence
        // spanning all of them -- a stronger identifier than anything else on
        // this wire, and the mistake the scheme this borrows from makes.
        let mut c = carrier();
        let mut out = vec![0u8; 200];
        let mut seen = Vec::new();
        for _ in 0..16 {
            c.data(b"x", &mut out).expect("emit");
            seen.push(u16::from_be_bytes([out[4], out[5]]));
        }
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "identifications repeated");
        assert!(
            seen.windows(2).any(|w| w[1] - w[0] != 1),
            "consecutive identifications are a counter in the open"
        );
    }

    #[test]
    fn optional_fields_move_the_payload_and_never_refuse_it() {
        // The point argued through before writing this: the header is outside
        // the AEAD, so refusing a packet on an unauthenticated bit lets anyone
        // on the path break the tunnel by flipping one -- and gains nothing,
        // because a tampered packet that shifts this offset fails to decrypt
        // anyway. Read the flags to find the payload; never to reject.
        assert_eq!(payload_offset(0x0000), Some(4), "the minimal header");
        assert_eq!(payload_offset(FLAG_CHECKSUM), Some(8));
        assert_eq!(payload_offset(FLAG_KEY), Some(8));
        assert_eq!(payload_offset(FLAG_SEQUENCE), Some(8));
        assert_eq!(
            payload_offset(FLAG_CHECKSUM | FLAG_KEY | FLAG_SEQUENCE),
            Some(16),
            "all three, as a PPTP-shaped middlebox might leave it"
        );
        // Version bits and the reserved field change nothing about the length.
        assert_eq!(payload_offset(0x0001), Some(4), "version 1");
        assert_eq!(payload_offset(0x07FF), Some(4), "reserved bits set");
    }

    #[test]
    fn a_header_with_a_key_is_read_at_the_right_offset() {
        // What the scheme this borrows from gets wrong: it advances four bytes
        // unconditionally, so a packet carrying a key is mis-sliced.
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        let mut packet = out[..n].to_vec();
        // Set the key bit and splice four bytes in after the GRE header.
        packet[20..22].copy_from_slice(&FLAG_KEY.to_be_bytes());
        packet.splice(24..24, [0xDE, 0xAD, 0xBE, 0xEF]);
        let total = u16::try_from(packet.len()).expect("small");
        packet[2..4].copy_from_slice(&total.to_be_bytes());

        let frame = captured(&packet);
        let got = parse_ethernet(&frame).expect("parse");
        assert_eq!(
            got.payload, b"payload",
            "the key must be skipped, not read as payload"
        );
    }

    #[test]
    fn other_protocols_and_other_families_are_not_ours() {
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");

        let mut packet = out[..n].to_vec();
        packet[9] = 6; // TCP
        assert!(parse_ethernet(&captured(&packet)).is_none());

        let mut frame = captured(&out[..n]);
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert!(parse_ethernet(&frame).is_none());
    }

    #[test]
    fn a_fragment_is_refused() {
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        for flags in [0x2000u16, 0x0001, 0x1FFF] {
            let mut packet = out[..n].to_vec();
            packet[6..8].copy_from_slice(&flags.to_be_bytes());
            assert!(
                parse_ethernet(&captured(&packet)).is_none(),
                "flags {flags:#x} should not parse"
            );
        }
    }

    #[test]
    fn a_length_longer_than_the_frame_is_refused() {
        // The declared length is attacker-controlled and decides a slice.
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        let mut packet = out[..n].to_vec();
        packet[2..4].copy_from_slice(&9000u16.to_be_bytes());
        assert!(parse_ethernet(&captured(&packet)).is_none());
    }

    #[test]
    fn every_truncation_is_refused_rather_than_read_past() {
        let mut out = vec![0u8; 200];
        let n = carrier().data(b"payload", &mut out).expect("emit");
        let frame = captured(&out[..n]);
        for i in 0..frame.len() {
            let short = &frame[..i];
            let _ = parse_ethernet(short);
        }
    }

    #[test]
    fn a_buffer_too_small_is_refused_rather_than_truncated() {
        let mut c = carrier();
        for len in 0..OVERHEAD + 7 {
            let mut out = vec![0u8; len];
            assert!(
                c.data(b"payload", &mut out).is_err(),
                "{len} bytes should not hold a 27-byte packet"
            );
        }
        let mut out = vec![0u8; OVERHEAD + 7];
        assert!(c.data(b"payload", &mut out).is_ok());
    }
}
