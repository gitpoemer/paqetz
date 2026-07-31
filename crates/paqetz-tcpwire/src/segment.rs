//! Segment construction and parsing.
//!
//! Emission produces an IPv4 header followed by a TCP header and payload, which
//! is what a raw socket with `IP_HDRINCL` expects. Parsing starts one layer
//! lower, at the Ethernet header, because reception is via `AF_PACKET`.

use core::net::Ipv4Addr;

use crate::checksum;
use crate::profile::OsProfile;
use crate::{Error, Result};

/// Ethernet header length.
pub const ETH_LEN: usize = 14;
/// IPv4 header length, without options. We never emit IPv4 options.
pub const IPV4_LEN: usize = 20;
/// TCP header length, without options.
pub const TCP_LEN: usize = 20;

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;

/// TCP option bytes on a SYN when timestamps are negotiated:
/// MSS(4) + SACK-permitted(2) + timestamps(10) + NOP(1) + window scale(3).
const SYN_OPTS_TS: usize = 20;
/// TCP option bytes on a SYN without timestamps, in the order Windows emits:
/// MSS(4) + NOP(1) + window scale(3) + NOP(1) + NOP(1) + SACK-permitted(2).
const SYN_OPTS_NO_TS: usize = 12;
/// TCP option bytes on a non-SYN segment with timestamps: NOP + NOP + TS(10).
const DATA_OPTS_TS: usize = 12;

/// TCP flag bits, as they sit in byte 13 of the header.
pub mod flags {
    /// No more data from sender.
    pub const FIN: u8 = 0x01;
    /// Synchronise sequence numbers.
    pub const SYN: u8 = 0x02;
    /// Reset the connection.
    pub const RST: u8 = 0x04;
    /// Push buffered data to the application.
    pub const PSH: u8 = 0x08;
    /// Acknowledgement field is significant.
    pub const ACK: u8 = 0x10;
    /// Urgent pointer is significant.
    pub const URG: u8 = 0x20;
}

/// What a segment is for.
///
/// paqet cycled TCP flags at random from a configured list, because its
/// sequence numbers were invented and no flag combination was more coherent
/// than another. With a real synthetic connection underneath (see
/// [`crate::endpoint`]) that is no longer true: random flags would now
/// *contradict* the connection state they sit alongside. The kind determines
/// the flags, exactly as a real stack's connection state would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Opening SYN.
    Syn,
    /// Responder's SYN+ACK.
    SynAck,
    /// Handshake-completing ACK, carrying no payload.
    Ack,
    /// Data segment.
    ///
    /// Carries PSH because every tunnel packet is a complete inner packet, so
    /// each one genuinely is the end of a write — which is precisely when a
    /// real stack sets PSH.
    Data,
    /// Graceful close.
    Fin,
    /// Abortive close.
    Rst,
}

impl Kind {
    /// The flag byte for this kind.
    #[must_use]
    pub const fn flags(self) -> u8 {
        match self {
            Self::Syn => flags::SYN,
            Self::SynAck => flags::SYN | flags::ACK,
            Self::Ack => flags::ACK,
            Self::Data => flags::PSH | flags::ACK,
            Self::Fin => flags::FIN | flags::ACK,
            Self::Rst => flags::RST,
        }
    }

    /// Whether this kind carries the SYN bit, which changes the option layout.
    #[must_use]
    pub const fn is_syn(self) -> bool {
        matches!(self, Self::Syn | Self::SynAck)
    }

    /// Whether this kind consumes one sequence number despite carrying no
    /// payload. SYN and FIN do; everything else does not.
    #[must_use]
    pub const fn consumes_sequence(self) -> bool {
        matches!(self, Self::Syn | Self::SynAck | Self::Fin)
    }
}

/// The volatile per-packet fields, chosen by the caller.
#[derive(Debug, Clone, Copy)]
pub struct Fields {
    /// Source address and port.
    pub src: (Ipv4Addr, u16),
    /// Destination address and port.
    pub dst: (Ipv4Addr, u16),
    /// Sequence number of the first payload byte.
    pub seq: u32,
    /// Cumulative acknowledgement.
    pub ack: u32,
    /// Advertised receive window, already scaled down by the profile shift.
    pub window: u16,
    /// IPv4 Identification.
    pub ip_id: u16,
    /// Timestamp option value, if the profile negotiates timestamps.
    pub ts_val: u32,
    /// Timestamp option echo reply.
    pub ts_ecr: u32,
}

/// Bytes of TCP options a segment of this kind carries under this profile.
#[must_use]
pub const fn option_len(kind: Kind, profile: &OsProfile) -> usize {
    if kind.is_syn() {
        if profile.timestamps {
            SYN_OPTS_TS
        } else {
            SYN_OPTS_NO_TS
        }
    } else if profile.timestamps {
        DATA_OPTS_TS
    } else {
        0
    }
}

/// Total bytes an emitted packet occupies, payload included.
#[must_use]
pub const fn packet_len(kind: Kind, profile: &OsProfile, payload_len: usize) -> usize {
    IPV4_LEN + TCP_LEN + option_len(kind, profile) + payload_len
}

/// The largest header overhead any segment can have, for buffer sizing.
pub const MAX_OVERHEAD: usize = IPV4_LEN + TCP_LEN + SYN_OPTS_TS;

/// A bounds-checked forward writer.
///
/// Exists so header construction never indexes a slice directly: every field
/// write is checked once, at the point it happens, and a short buffer surfaces
/// as an error rather than a panic.
struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.pos + bytes.len();
        let have = self.buf.len();
        let slot = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(Error::Short { need: end, have })?;
        slot.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }

    fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_be_bytes())
    }

    fn u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_be_bytes())
    }
}

/// Writes one IPv4 + TCP packet into `out`, returning its length.
///
/// # Errors
/// Returns [`Error::Short`] if `out` cannot hold the packet.
pub fn emit(
    kind: Kind,
    profile: &OsProfile,
    fields: &Fields,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let opts = option_len(kind, profile);
    let tcp_total = TCP_LEN + opts;
    let total = IPV4_LEN + tcp_total + payload.len();
    if out.len() < total {
        return Err(Error::Short {
            need: total,
            have: out.len(),
        });
    }

    let ip_total = u16::try_from(total).map_err(|_| Error::TooLong { len: total })?;

    // ---- IPv4 ----
    {
        let mut c = Cursor::new(out);
        c.u8(0x45)?; // version 4, IHL 5 words
        c.u8(0)?; // DSCP 0 (D6: paqet marked DSCP 46, which stands out)
        c.u16(ip_total)?;
        c.u16(fields.ip_id)?;
        c.u16(0x4000)?; // Don't Fragment
        c.u8(profile.ttl)?;
        c.u8(PROTO_TCP)?;
        c.u16(0)?; // checksum, filled below
        c.put(&fields.src.0.octets())?;
        c.put(&fields.dst.0.octets())?;
    }

    // ---- TCP ----
    {
        let have = out.len();
        let tcp = out.get_mut(IPV4_LEN..).ok_or(Error::Short {
            need: IPV4_LEN,
            have,
        })?;
        let mut c = Cursor::new(tcp);
        c.u16(fields.src.1)?;
        c.u16(fields.dst.1)?;
        c.u32(fields.seq)?;
        c.u32(fields.ack)?;
        let data_offset_words = u8::try_from(tcp_total / 4).unwrap_or(5);
        c.u8(data_offset_words << 4)?;
        c.u8(kind.flags())?;
        c.u16(fields.window)?;
        c.u16(0)?; // checksum, filled below
        c.u16(0)?; // urgent pointer

        write_options(&mut c, kind, profile, fields)?;
        debug_assert_eq!(c.pos, tcp_total);
        c.put(payload)?;
    }

    // ---- checksums ----
    let ip_ck = {
        let header = out.get(..IPV4_LEN).ok_or(Error::Short {
            need: IPV4_LEN,
            have: out.len(),
        })?;
        checksum::of(header)
    };
    write_at(out, 10, &ip_ck.to_be_bytes())?;

    let tcp_ck = {
        let segment = out.get(IPV4_LEN..total).ok_or(Error::Short {
            need: total,
            have: out.len(),
        })?;
        let tcp_len = u16::try_from(segment.len()).map_err(|_| Error::TooLong { len: total })?;
        let pseudo = checksum::pseudo_header_v4(fields.src.0, fields.dst.0, PROTO_TCP, tcp_len);
        checksum::fold(checksum::sum(segment, pseudo))
    };
    write_at(out, IPV4_LEN + 16, &tcp_ck.to_be_bytes())?;

    Ok(total)
}

/// Writes the TCP option block for this kind and profile.
fn write_options(c: &mut Cursor<'_>, kind: Kind, profile: &OsProfile, f: &Fields) -> Result<()> {
    if kind.is_syn() {
        if profile.timestamps {
            // MSS, SACK-permitted, timestamps, NOP, window scale.
            c.u8(2)?;
            c.u8(4)?;
            c.u16(profile.mss)?;
            c.u8(4)?;
            c.u8(2)?;
            c.u8(8)?;
            c.u8(10)?;
            c.u32(f.ts_val)?;
            // A SYN has nothing to echo; SYN+ACK echoes the peer's SYN.
            c.u32(if kind == Kind::SynAck { f.ts_ecr } else { 0 })?;
            c.u8(1)?;
            c.u8(3)?;
            c.u8(3)?;
            c.u8(profile.window_scale)?;
        } else {
            // MSS, NOP, window scale, NOP, NOP, SACK-permitted.
            c.u8(2)?;
            c.u8(4)?;
            c.u16(profile.mss)?;
            c.u8(1)?;
            c.u8(3)?;
            c.u8(3)?;
            c.u8(profile.window_scale)?;
            c.u8(1)?;
            c.u8(1)?;
            c.u8(4)?;
            c.u8(2)?;
        }
    } else if profile.timestamps {
        c.u8(1)?;
        c.u8(1)?;
        c.u8(8)?;
        c.u8(10)?;
        c.u32(f.ts_val)?;
        c.u32(f.ts_ecr)?;
    }
    Ok(())
}

fn write_at(buf: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    let end = offset + bytes.len();
    let have = buf.len();
    buf.get_mut(offset..end)
        .ok_or(Error::Short { need: end, have })?
        .copy_from_slice(bytes);
    Ok(())
}

/// A parsed inbound segment. Borrows the receive buffer.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    /// Source address and port.
    pub src: (Ipv4Addr, u16),
    /// Destination address and port.
    pub dst: (Ipv4Addr, u16),
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Raw flag byte.
    pub flags: u8,
    /// Advertised window, unscaled.
    pub window: u16,
    /// Peer's timestamp value, if it sent one.
    pub ts_val: Option<u32>,
    /// TCP payload.
    pub payload: &'a [u8],
}

impl Segment<'_> {
    /// Whether a given flag bit is set.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Parses an Ethernet frame containing IPv4 and TCP.
///
/// Returns `None` for anything that is not a well-formed, unfragmented IPv4 TCP
/// segment. A caller reading from a capture ring should skip such frames rather
/// than treat them as errors: the ring carries whatever the filter let through.
#[must_use]
pub fn parse_ethernet(frame: &[u8]) -> Option<Segment<'_>> {
    let (_, rest) = frame.split_at_checked(ETH_LEN)?;
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != ETHERTYPE_IPV4 {
        // 802.1Q-tagged frames and IPv6 both land here. IPv6 is deferred to a
        // later phase; VLAN tags would need the filter to strip them.
        return None;
    }
    parse_ipv4(rest)
}

/// Parses an IPv4 packet containing TCP.
#[must_use]
pub fn parse_ipv4(packet: &[u8]) -> Option<Segment<'_>> {
    let ver_ihl = *packet.first()?;
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl_words = usize::from(ver_ihl & 0x0F);
    if ihl_words < 5 {
        return None;
    }
    let ip_header_len = ihl_words * 4;

    if *packet.get(9)? != PROTO_TCP {
        return None;
    }

    // Reject fragments. Of the flags/offset word only Don't Fragment (0x4000)
    // may be set: More Fragments, a non-zero offset, or the reserved bit all
    // mean this is not a complete, safely parseable datagram.
    let frag = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    if frag & 0xBFFF != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if total_len < ip_header_len || total_len > packet.len() {
        // Either a malformed length, or the frame is shorter than it claims.
        // Note this also drops frames padded up to Ethernet's 64-byte minimum
        // only if the declared length exceeds what arrived, which is correct.
        return None;
    }

    let src = Ipv4Addr::new(
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    );
    let dst = Ipv4Addr::new(
        *packet.get(16)?,
        *packet.get(17)?,
        *packet.get(18)?,
        *packet.get(19)?,
    );

    let tcp = packet.get(ip_header_len..total_len)?;
    parse_tcp(tcp, src, dst)
}

fn parse_tcp(tcp: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<Segment<'_>> {
    if tcp.len() < TCP_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([*tcp.first()?, *tcp.get(1)?]);
    let dst_port = u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]);
    let seq = u32::from_be_bytes([*tcp.get(4)?, *tcp.get(5)?, *tcp.get(6)?, *tcp.get(7)?]);
    let ack = u32::from_be_bytes([*tcp.get(8)?, *tcp.get(9)?, *tcp.get(10)?, *tcp.get(11)?]);

    let data_offset_words = usize::from(*tcp.get(12)? >> 4);
    if data_offset_words < 5 {
        return None;
    }
    let tcp_header_len = data_offset_words * 4;
    if tcp_header_len > tcp.len() {
        return None;
    }

    let flags = *tcp.get(13)?;
    let window = u16::from_be_bytes([*tcp.get(14)?, *tcp.get(15)?]);

    let options = tcp.get(TCP_LEN..tcp_header_len)?;
    let ts_val = find_timestamp(options);
    let payload = tcp.get(tcp_header_len..)?;

    Some(Segment {
        src: (src, src_port),
        dst: (dst, dst_port),
        seq,
        ack,
        flags,
        window,
        ts_val,
        payload,
    })
}

/// Walks the TCP option block looking for the timestamp option (kind 8).
fn find_timestamp(options: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    while i < options.len() {
        let kind = *options.get(i)?;
        match kind {
            0 => return None, // end of options
            1 => i += 1,      // NOP
            _ => {
                let len = usize::from(*options.get(i + 1)?);
                if len < 2 || i + len > options.len() {
                    return None;
                }
                if kind == 8 && len == 10 {
                    let v = options.get(i + 2..i + 6)?;
                    return Some(u32::from_be_bytes([
                        *v.first()?,
                        *v.get(1)?,
                        *v.get(2)?,
                        *v.get(3)?,
                    ]));
                }
                i += len;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::profile::{ANDROID_14, LINUX_6, WINDOWS_11};

    fn fields() -> Fields {
        Fields {
            src: (Ipv4Addr::new(192, 168, 1, 10), 40000),
            dst: (Ipv4Addr::new(203, 0, 113, 5), 9999),
            seq: 0x1000_0000,
            ack: 0x2000_0000,
            window: 502,
            ip_id: 0xABCD,
            ts_val: 0x0011_2233,
            ts_ecr: 0x4455_6677,
        }
    }

    fn emit_vec(kind: Kind, profile: &OsProfile, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; MAX_OVERHEAD + payload.len()];
        let n = emit(kind, profile, &fields(), payload, &mut buf).expect("emit");
        buf.truncate(n);
        buf
    }

    #[test]
    fn emitted_lengths_match_the_predicted_ones() {
        for profile in [LINUX_6, WINDOWS_11, ANDROID_14] {
            for kind in [Kind::Syn, Kind::SynAck, Kind::Ack, Kind::Data, Kind::Fin] {
                for payload_len in [0usize, 1, 100, 1400] {
                    let payload = vec![0x5A; payload_len];
                    let packet = emit_vec(kind, &profile, &payload);
                    assert_eq!(
                        packet.len(),
                        packet_len(kind, &profile, payload_len),
                        "{} {kind:?} with {payload_len} bytes",
                        profile.name
                    );
                }
            }
        }
    }

    #[test]
    fn emit_then_parse_round_trips() {
        for profile in [LINUX_6, WINDOWS_11, ANDROID_14] {
            let payload = b"inner packet bytes";
            let packet = emit_vec(Kind::Data, &profile, payload);
            let seg = parse_ipv4(&packet).expect("parse");

            let f = fields();
            assert_eq!(seg.src, f.src);
            assert_eq!(seg.dst, f.dst);
            assert_eq!(seg.seq, f.seq);
            assert_eq!(seg.ack, f.ack);
            assert_eq!(seg.window, f.window);
            assert_eq!(seg.payload, payload);
            assert!(seg.has(flags::PSH));
            assert!(seg.has(flags::ACK));
            assert_eq!(
                seg.ts_val,
                if profile.timestamps {
                    Some(f.ts_val)
                } else {
                    None
                }
            );
        }
    }

    #[test]
    fn checksums_verify() {
        for profile in [LINUX_6, WINDOWS_11] {
            for kind in [Kind::Syn, Kind::SynAck, Kind::Data, Kind::Fin, Kind::Rst] {
                let packet = emit_vec(kind, &profile, b"payload for checksum");

                // A correct IPv4 header checksums to zero including its own field.
                assert_eq!(
                    checksum::of(&packet[..IPV4_LEN]),
                    0,
                    "{} {kind:?} IP checksum",
                    profile.name
                );

                // Likewise for TCP, with the pseudo-header folded in.
                let f = fields();
                let segment = &packet[IPV4_LEN..];
                let pseudo = checksum::pseudo_header_v4(
                    f.src.0,
                    f.dst.0,
                    PROTO_TCP,
                    u16::try_from(segment.len()).expect("fits"),
                );
                assert_eq!(
                    checksum::fold(checksum::sum(segment, pseudo)),
                    0,
                    "{} {kind:?} TCP checksum",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn checksums_verify_for_odd_length_payloads() {
        // The tail-byte path in the checksum is easy to get wrong.
        for len in [1usize, 3, 15, 1399] {
            let packet = emit_vec(Kind::Data, &LINUX_6, &vec![0xC3; len]);
            let f = fields();
            let segment = &packet[IPV4_LEN..];
            let pseudo = checksum::pseudo_header_v4(
                f.src.0,
                f.dst.0,
                PROTO_TCP,
                u16::try_from(segment.len()).expect("fits"),
            );
            assert_eq!(
                checksum::fold(checksum::sum(segment, pseudo)),
                0,
                "len {len}"
            );
        }
    }

    #[test]
    fn dscp_is_zero() {
        // paqet emitted DSCP 46 (Expedited Forwarding) on every packet, which is
        // a standout marking on a bulk flow.
        let packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        assert_eq!(packet[1], 0, "TOS byte must be zero");
    }

    #[test]
    fn the_dont_fragment_bit_is_set_and_no_fragment_offset() {
        let packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x4000);
    }

    #[test]
    fn ttl_comes_from_the_profile() {
        assert_eq!(emit_vec(Kind::Data, &LINUX_6, b"x")[8], 64);
        assert_eq!(emit_vec(Kind::Data, &WINDOWS_11, b"x")[8], 128);
    }

    #[test]
    fn flags_match_the_kind() {
        for (kind, expected) in [
            (Kind::Syn, flags::SYN),
            (Kind::SynAck, flags::SYN | flags::ACK),
            (Kind::Ack, flags::ACK),
            (Kind::Data, flags::PSH | flags::ACK),
            (Kind::Fin, flags::FIN | flags::ACK),
            (Kind::Rst, flags::RST),
        ] {
            let packet = emit_vec(kind, &LINUX_6, b"");
            assert_eq!(packet[IPV4_LEN + 13], expected, "{kind:?}");
        }
    }

    #[test]
    fn a_syn_advertises_mss_and_window_scale() {
        let packet = emit_vec(Kind::Syn, &LINUX_6, b"");
        let seg_start = IPV4_LEN;
        let opts = &packet[seg_start + TCP_LEN..];
        assert_eq!(opts[0], 2, "first option should be MSS");
        assert_eq!(opts[1], 4);
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), LINUX_6.mss);
        // Window scale is the final option in the timestamps layout.
        assert_eq!(opts[17], 3);
        assert_eq!(opts[18], 3);
        assert_eq!(opts[19], LINUX_6.window_scale);
    }

    #[test]
    fn a_plain_syn_echoes_nothing() {
        // Nothing has been received yet, so ts_ecr must be zero even though the
        // caller supplied one.
        let packet = emit_vec(Kind::Syn, &LINUX_6, b"");
        let opts = &packet[IPV4_LEN + TCP_LEN..];
        assert_eq!(
            u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]),
            0
        );
    }

    #[test]
    fn a_syn_ack_echoes_the_peer_timestamp() {
        let packet = emit_vec(Kind::SynAck, &LINUX_6, b"");
        let opts = &packet[IPV4_LEN + TCP_LEN..];
        assert_eq!(
            u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]),
            fields().ts_ecr
        );
    }

    #[test]
    fn a_profile_without_timestamps_emits_none() {
        let packet = emit_vec(Kind::Data, &WINDOWS_11, b"x");
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.ts_val, None);
        // And a data segment then carries no options at all.
        assert_eq!(packet[IPV4_LEN + 12] >> 4, 5);
    }

    #[test]
    fn emit_rejects_a_short_buffer() {
        let payload = [0u8; 100];
        let need = packet_len(Kind::Data, &LINUX_6, payload.len());
        for len in [0usize, 1, need - 1] {
            let mut buf = vec![0u8; len];
            assert!(
                matches!(
                    emit(Kind::Data, &LINUX_6, &fields(), &payload, &mut buf),
                    Err(Error::Short { .. })
                ),
                "buffer of {len} must be rejected"
            );
        }
    }

    #[test]
    fn parse_rejects_malformed_input_without_panicking() {
        let good = emit_vec(Kind::Data, &LINUX_6, b"payload");

        // Truncation at every length.
        for len in 0..good.len() {
            let _ = parse_ipv4(&good[..len]);
        }

        // Single-bit corruption anywhere in the header.
        for byte in 0..(IPV4_LEN + TCP_LEN) {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[byte] ^= 1 << bit;
                let _ = parse_ipv4(&bad);
            }
        }
    }

    #[test]
    fn parse_rejects_non_ipv4() {
        let mut packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        packet[0] = 0x65; // version 6
        assert!(parse_ipv4(&packet).is_none());
    }

    #[test]
    fn parse_rejects_non_tcp() {
        let mut packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        packet[9] = 17; // UDP
        assert!(parse_ipv4(&packet).is_none());
    }

    #[test]
    fn parse_rejects_fragments() {
        for frag in [0x2000u16, 0x0001, 0x8000, 0x201F] {
            let mut packet = emit_vec(Kind::Data, &LINUX_6, b"x");
            packet[6..8].copy_from_slice(&frag.to_be_bytes());
            assert!(parse_ipv4(&packet).is_none(), "frag word {frag:#06x}");
        }
        // Don't Fragment alone is fine.
        let mut packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        assert!(parse_ipv4(&packet).is_some());
    }

    #[test]
    fn parse_rejects_a_length_longer_than_the_frame() {
        let mut packet = emit_vec(Kind::Data, &LINUX_6, b"x");
        let lie = u16::try_from(packet.len() + 1).expect("fits");
        packet[2..4].copy_from_slice(&lie.to_be_bytes());
        assert!(parse_ipv4(&packet).is_none());
    }

    #[test]
    fn parse_tolerates_trailing_ethernet_padding() {
        // Drivers pad short frames to 64 bytes. The declared IP length is
        // authoritative and the padding must not land in the payload.
        let payload = b"tiny";
        let mut packet = emit_vec(Kind::Data, &LINUX_6, payload);
        let real_len = packet.len();
        packet.resize(64, 0);
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.payload, payload);
        assert_eq!(real_len, packet_len(Kind::Data, &LINUX_6, payload.len()));
    }

    #[test]
    fn parse_ethernet_requires_the_ipv4_ethertype() {
        let ip = emit_vec(Kind::Data, &LINUX_6, b"x");
        let mut frame = vec![0u8; ETH_LEN];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        assert!(parse_ethernet(&frame).is_some());

        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6
        assert!(parse_ethernet(&frame).is_none());

        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q
        assert!(parse_ethernet(&frame).is_none());
    }

    #[test]
    fn parse_ethernet_rejects_runt_frames() {
        for len in 0..ETH_LEN + IPV4_LEN {
            let frame = vec![0u8; len];
            assert!(parse_ethernet(&frame).is_none(), "len {len}");
        }
    }

    #[test]
    fn timestamps_are_found_past_other_options() {
        // Options are walked, not assumed to be at a fixed offset. A SYN puts
        // MSS and SACK-permitted ahead of the timestamp.
        let packet = emit_vec(Kind::Syn, &LINUX_6, b"");
        let seg = parse_ipv4(&packet).expect("parse");
        assert_eq!(seg.ts_val, Some(fields().ts_val));
    }

    #[test]
    fn a_truncated_option_block_does_not_panic() {
        for opts in [
            vec![8u8],               // kind with no length
            vec![8, 10],             // length but no value
            vec![8, 0],              // length below the minimum
            vec![8, 255],            // length past the end
            vec![2, 4, 0x05],        // truncated MSS
            vec![1, 1, 1, 1],        // all NOPs
            vec![0, 8, 10, 1, 2, 3], // EOL before the timestamp
        ] {
            let _ = find_timestamp(&opts);
        }
    }
}
