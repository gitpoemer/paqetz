//! Grouping inner packets into one write for the kernel to split.
//!
//! A TUN write is one packet however many buffers it is gathered from, and
//! there is no `sendmmsg` for a character device, so the only way to hand over
//! more than one packet at a time is to hand over something the kernel will
//! segment itself: one IPv4 header, one L4 header, every payload concatenated,
//! and a `virtio_net_hdr` saying where the boundaries are.
//!
//! `tun_ceiling` measures what that is worth, and it is worth measuring on the
//! host in question rather than taken from here: forty datagrams per write came
//! out about six times cheaper per packet than one per write, on a machine
//! where the write was about a third of everything the datapath spent.
//!
//! # What may be merged
//!
//! The kernel is being told these packets *were* one segment that something
//! split, so they have to look like it. Two adjacent packets join a run when
//! every one of these holds:
//!
//! - both are unfragmented IPv4 with no IP options, over TCP or UDP
//! - the addresses, ports, TOS, TTL and Don't Fragment bit all match, because
//!   the first packet's headers are the ones every segment gets
//! - their L4 headers are byte-identical apart from the sequence number and the
//!   checksum, which covers TCP options: a burst sharing one timestamp value
//!   merges, and one that does not merge is one real GRO would also refuse
//! - for TCP, the sequence numbers are contiguous and no flag is set that ends
//!   a stream
//! - every payload is the same length as the first, except the last, which may
//!   be shorter. This is what `gso_size` means, and a run whose middle segment
//!   is short would be split into the wrong packets
//! - the total still fits what an IPv4 header can describe
//!
//! Nothing here holds state between calls. A run cannot span two reads from the
//! wire, which gives up some of the saving -- a batch of thirty-two holding
//! eight flows yields runs of four -- in exchange for owning no per-flow state
//! at all, which [`D4`](../../../docs/decisions/D4-state-is-per-peer.md) is
//! emphatic about. Modelling put runs of four at four fifths of the full
//! saving, so the trade is cheap.

use crate::tun::VNET_HDR_LEN;

/// Bytes of IPv4 header, without options, which is all this accepts.
const IPV4_LEN: usize = 20;
/// The least an L4 header this understands can be.
const UDP_LEN: usize = 8;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Offsets within the L4 header that may differ across a run.
const TCP_SEQ: core::ops::Range<usize> = 4..8;
const TCP_CSUM: core::ops::Range<usize> = 16..18;
const UDP_CSUM: core::ops::Range<usize> = 6..8;

/// Where each protocol keeps its checksum, for the kernel to be pointed at.
const TCP_CSUM_OFFSET: u16 = 16;
const UDP_CSUM_OFFSET: u16 = 6;

/// `gso_type` values from `virtio_net.h`.
const GSO_TCPV4: u8 = 1;
const GSO_UDP_L4: u8 = 5;
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`: the kernel completes the L4 checksum.
const NEEDS_CSUM: u8 = 1;

/// TCP flags that end a run, because a segment carrying one is not mid-stream.
const TCP_ENDS_RUN: u8 = 0x01 | 0x02 | 0x04 | 0x20; // FIN, SYN, RST, URG

/// What an IPv4 total-length field can describe.
const MAX_IP_TOTAL: usize = 65_535;

/// One inner packet, far enough parsed to decide whether it may be merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Packet<'a> {
    /// The L4 header, options included.
    l4: &'a [u8],
    payload: &'a [u8],
    /// IPv4 header bytes that every segment inherits.
    ip: &'a [u8],
    proto: u8,
    /// TCP sequence number, or zero for UDP.
    seq: u32,
}

/// Parses `bytes` far enough to merge it, or rejects it.
fn parse(bytes: &[u8]) -> Option<Packet<'_>> {
    let ip = bytes.get(..IPV4_LEN)?;
    // Version 4 and exactly five words: an IP option would be copied to every
    // segment, which is more care than this is worth.
    if ip.first()? != &0x45 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    // Fragments carry no usable L4 header after the first, and a run of them
    // is not a stream.
    let frag = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
    if frag & 0x3FFF != 0 {
        return None;
    }
    if total > bytes.len() || total < IPV4_LEN {
        return None;
    }
    let proto = *ip.get(9)?;
    let rest = bytes.get(IPV4_LEN..total)?;
    let (l4_len, seq) = match proto {
        PROTO_TCP => {
            let offset = usize::from(rest.get(12)? >> 4) * 4;
            if offset < 20 || offset > rest.len() {
                return None;
            }
            let seq =
                u32::from_be_bytes([*rest.get(4)?, *rest.get(5)?, *rest.get(6)?, *rest.get(7)?]);
            if rest.get(13)? & TCP_ENDS_RUN != 0 {
                return None;
            }
            (offset, seq)
        }
        PROTO_UDP => {
            if rest.len() < UDP_LEN {
                return None;
            }
            (UDP_LEN, 0)
        }
        _ => return None,
    };
    Some(Packet {
        l4: rest.get(..l4_len)?,
        payload: rest.get(l4_len..)?,
        ip,
        proto,
        seq,
    })
}

/// Whether `b` continues the run that `a` is part of.
fn continues(a: &Packet<'_>, b: &Packet<'_>, gso_size: usize) -> bool {
    // The first packet's headers are the ones every segment gets, so anything
    // an observer would read off them has to match.
    if a.ip.get(..2) != b.ip.get(..2) || a.ip.get(4..) != b.ip.get(4..) {
        return false;
    }
    if a.proto != b.proto || a.l4.len() != b.l4.len() {
        return false;
    }
    // Everything but the sequence number and the checksum, which is what makes
    // TCP options work: a burst sharing a timestamp merges and one that does
    // not is refused.
    let varies = if a.proto == PROTO_TCP {
        [TCP_SEQ, TCP_CSUM]
    } else {
        [UDP_CSUM, UDP_CSUM]
    };
    for (i, (x, y)) in a.l4.iter().zip(b.l4.iter()).enumerate() {
        if varies.iter().any(|r| r.contains(&i)) {
            continue;
        }
        if x != y {
            return false;
        }
    }
    if a.proto == PROTO_TCP && b.seq != a.seq.wrapping_add(size32(a.payload.len())) {
        return false;
    }
    // Every segment but the last carries exactly `gso_size`, which is the whole
    // meaning of the field. A short one in the middle would be re-split at the
    // wrong boundaries.
    a.payload.len() == gso_size && !b.payload.is_empty() && b.payload.len() <= gso_size
}

fn size32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// How many packets from `from` may be written as one, and what each segment
/// carries.
///
/// A count of one means the packet has to go on its own, and `gso_size` is then
/// meaningless. The count never exceeds what an IPv4 header can describe.
#[must_use]
pub fn mergeable(packets: &[&[u8]], from: usize) -> (usize, usize) {
    let Some(first) = packets.get(from).and_then(|p| parse(p)) else {
        return (1, 0);
    };
    let gso_size = first.payload.len();
    if gso_size == 0 {
        return (1, 0);
    }
    let mut count = 1;
    let mut bytes = IPV4_LEN + first.l4.len() + gso_size;
    let mut prev = first;
    while let Some(next) = packets.get(from + count).and_then(|p| parse(p)) {
        if !continues(&prev, &next, gso_size) || bytes + next.payload.len() > MAX_IP_TOTAL {
            break;
        }
        bytes += next.payload.len();
        count += 1;
        prev = next;
    }
    (count, gso_size)
}

/// Builds the one frame that stands for `packets[from..from + count]`.
///
/// Returns the `virtio_net_hdr` to write alongside it. `frame` is cleared
/// first. Returns `None` if the run is a single packet, which has nothing to
/// assemble and should be written as it is.
#[must_use]
pub fn assemble(
    packets: &[&[u8]],
    from: usize,
    count: usize,
    gso_size: usize,
    frame: &mut Vec<u8>,
) -> Option<[u8; VNET_HDR_LEN]> {
    if count < 2 {
        return None;
    }
    let first = packets.get(from).and_then(|p| parse(p))?;
    let payload: usize = (from..from + count)
        .map(|i| {
            packets
                .get(i)
                .and_then(|p| parse(p))
                .map_or(0, |p| p.payload.len())
        })
        .sum();
    let total = IPV4_LEN + first.l4.len() + payload;
    let ip_total = u16::try_from(total).ok()?;

    frame.clear();
    frame.reserve(total);
    frame.extend_from_slice(first.ip);
    // The length is the whole frame's; the checksum has to be right for it,
    // because the kernel validates this header before it splits anything.
    frame
        .get_mut(2..4)?
        .copy_from_slice(&ip_total.to_be_bytes());
    frame.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_ck = !fold(sum16(frame.get(..IPV4_LEN)?));
    frame.get_mut(10..12)?.copy_from_slice(&ip_ck.to_be_bytes());

    frame.extend_from_slice(first.l4);
    if first.proto == PROTO_UDP {
        // UDP states its own length, and for a superpacket it states the whole
        // one, as the kernel's own segmenter expects.
        let udp_total = u16::try_from(UDP_LEN + payload).ok()?;
        frame
            .get_mut(IPV4_LEN + 4..IPV4_LEN + 6)?
            .copy_from_slice(&udp_total.to_be_bytes());
    }
    // The half of the checksum the kernel cannot derive: the pseudo-header for
    // one segment, which is the convention `NEEDS_CSUM` expects to find.
    let partial = pseudo_header(&first, gso_size)?;
    let csum_at = IPV4_LEN + usize::from(csum_offset(first.proto));
    frame
        .get_mut(csum_at..csum_at + 2)?
        .copy_from_slice(&partial.to_be_bytes());

    for i in from..from + count {
        let p = packets.get(i).and_then(|p| parse(p))?;
        frame.extend_from_slice(p.payload);
    }

    Some(header(&first, gso_size))
}

const fn csum_offset(proto: u8) -> u16 {
    if proto == PROTO_TCP {
        TCP_CSUM_OFFSET
    } else {
        UDP_CSUM_OFFSET
    }
}

/// The `virtio_net_hdr` describing how to split a frame.
fn header(first: &Packet<'_>, gso_size: usize) -> [u8; VNET_HDR_LEN] {
    let mut h = [0u8; VNET_HDR_LEN];
    h[0] = NEEDS_CSUM;
    h[1] = if first.proto == PROTO_TCP {
        GSO_TCPV4
    } else {
        GSO_UDP_L4
    };
    let hdr_len = u16::try_from(IPV4_LEN + first.l4.len()).unwrap_or(u16::MAX);
    h[2..4].copy_from_slice(&hdr_len.to_le_bytes());
    h[4..6].copy_from_slice(&u16::try_from(gso_size).unwrap_or(u16::MAX).to_le_bytes());
    h[6..8].copy_from_slice(&u16::try_from(IPV4_LEN).unwrap_or(0).to_le_bytes());
    h[8..10].copy_from_slice(&csum_offset(first.proto).to_le_bytes());
    h
}

/// The ones' complement sum of the pseudo-header for one segment.
fn pseudo_header(first: &Packet<'_>, gso_size: usize) -> Option<u16> {
    let mut head = [0u8; 12];
    head.get_mut(..4)?.copy_from_slice(first.ip.get(12..16)?);
    head.get_mut(4..8)?.copy_from_slice(first.ip.get(16..20)?);
    head[9] = first.proto;
    let len = u16::try_from(first.l4.len() + gso_size).ok()?;
    head.get_mut(10..12)?.copy_from_slice(&len.to_be_bytes());
    Some(fold(sum16(&head)))
}

fn sum16(bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    let mut sum: u32 = pairs
        .iter()
        .map(|p| u32::from(u16::from_be_bytes(*p)))
        .sum();
    if let [last] = *rest {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    u16::try_from(sum & 0xFFFF).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    const SRC: [u8; 4] = [10, 7, 0, 2];
    const DST: [u8; 4] = [10, 7, 0, 1];

    /// One inner packet, built the way a real one arrives.
    struct Build {
        proto: u8,
        seq: u32,
        payload: usize,
        flags: u8,
        options: Vec<u8>,
        sport: u16,
        ttl: u8,
    }

    impl Default for Build {
        fn default() -> Self {
            Self {
                proto: PROTO_TCP,
                seq: 1000,
                payload: 1400,
                flags: 0x10, // ACK, which is what mid-stream data carries
                options: Vec::new(),
                sport: 40000,
                ttl: 64,
            }
        }
    }

    impl Build {
        fn bytes(&self) -> Vec<u8> {
            let l4 = if self.proto == PROTO_TCP {
                20 + self.options.len()
            } else {
                UDP_LEN
            };
            let total = IPV4_LEN + l4 + self.payload;
            let mut p = Vec::with_capacity(total);
            p.push(0x45);
            p.push(0);
            p.extend_from_slice(&u16::try_from(total).expect("fits").to_be_bytes());
            p.extend_from_slice(&0x1234u16.to_be_bytes());
            p.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
            p.push(self.ttl);
            p.push(self.proto);
            p.extend_from_slice(&0u16.to_be_bytes());
            p.extend_from_slice(&SRC);
            p.extend_from_slice(&DST);

            p.extend_from_slice(&self.sport.to_be_bytes());
            p.extend_from_slice(&443u16.to_be_bytes());
            if self.proto == PROTO_TCP {
                p.extend_from_slice(&self.seq.to_be_bytes());
                p.extend_from_slice(&7u32.to_be_bytes()); // acknowledgement
                p.push(u8::try_from(l4 / 4).expect("fits") << 4);
                p.push(self.flags);
                p.extend_from_slice(&65535u16.to_be_bytes());
                p.extend_from_slice(&0u16.to_be_bytes()); // checksum
                p.extend_from_slice(&0u16.to_be_bytes()); // urgent
                p.extend_from_slice(&self.options);
            } else {
                p.extend_from_slice(
                    &u16::try_from(UDP_LEN + self.payload)
                        .expect("fits")
                        .to_be_bytes(),
                );
                p.extend_from_slice(&0u16.to_be_bytes()); // checksum
            }
            p.resize(total, 0x5A);
            p
        }
    }

    /// A contiguous stream of `n` packets, each carrying `payload` bytes.
    fn stream(n: usize, payload: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                Build {
                    seq: 1000 + u32::try_from(i * payload).expect("fits"),
                    payload,
                    ..Build::default()
                }
                .bytes()
            })
            .collect()
    }

    fn refs(packets: &[Vec<u8>]) -> Vec<&[u8]> {
        packets.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn a_contiguous_stream_merges_whole() {
        let owned = stream(8, 1400);
        let (count, gso) = mergeable(&refs(&owned), 0);
        assert_eq!((count, gso), (8, 1400));
    }

    #[test]
    fn a_gap_in_the_sequence_ends_the_run() {
        // The carrier never retransmits, so a gap is permanent and the kernel
        // must not be told these were one segment.
        let mut owned = stream(8, 1400);
        owned.remove(3);
        let (count, _) = mergeable(&refs(&owned), 0);
        assert_eq!(count, 3, "the run has to stop at the hole");
        // And the rest still merges, starting after it.
        let (count, _) = mergeable(&refs(&owned), 3);
        assert_eq!(count, 4);
    }

    #[test]
    fn a_short_segment_ends_the_run_but_is_carried_by_it() {
        let mut owned = stream(4, 1400);
        owned[3] = Build {
            seq: 1000 + 3 * 1400,
            payload: 200,
            ..Build::default()
        }
        .bytes();
        let (count, gso) = mergeable(&refs(&owned), 0);
        assert_eq!((count, gso), (4, 1400), "a short last segment belongs");

        // In the middle it does not: everything but the last carries gso_size,
        // or the kernel re-splits at the wrong boundaries.
        let mut owned = stream(4, 1400);
        owned[1] = Build {
            seq: 1000 + 1400,
            payload: 200,
            ..Build::default()
        }
        .bytes();
        let (count, _) = mergeable(&refs(&owned), 0);
        assert_eq!(count, 2, "the short one ends it");
    }

    #[test]
    fn nothing_that_is_not_mid_stream_data_merges() {
        for flags in [0x02, 0x01, 0x04, 0x20] {
            let owned = vec![
                Build {
                    flags: flags | 0x10,
                    ..Build::default()
                }
                .bytes(),
                Build {
                    seq: 2400,
                    ..Build::default()
                }
                .bytes(),
            ];
            let (count, _) = mergeable(&refs(&owned), 0);
            assert_eq!(count, 1, "flags {flags:#04x} should stand alone");
        }
    }

    #[test]
    fn another_flow_ends_the_run() {
        let owned = vec![
            Build::default().bytes(),
            Build {
                sport: 40001,
                seq: 2400,
                ..Build::default()
            }
            .bytes(),
        ];
        assert_eq!(mergeable(&refs(&owned), 0).0, 1);
    }

    #[test]
    fn a_header_the_segments_would_inherit_has_to_match() {
        // Every segment gets the first packet's TTL, so a differing one would
        // be silently rewritten.
        let owned = vec![
            Build::default().bytes(),
            Build {
                ttl: 63,
                seq: 2400,
                ..Build::default()
            }
            .bytes(),
        ];
        assert_eq!(mergeable(&refs(&owned), 0).0, 1);
    }

    #[test]
    fn tcp_options_merge_when_they_match_and_not_otherwise() {
        // Timestamps are on by default on most connections, and a burst inside
        // one millisecond shares a value. That burst is what merges.
        let stamp = |v: u32| {
            let mut o = vec![0x01, 0x01, 0x08, 0x0A];
            o.extend_from_slice(&v.to_be_bytes());
            o.extend_from_slice(&0u32.to_be_bytes());
            o
        };
        let same = vec![
            Build {
                options: stamp(5),
                ..Build::default()
            }
            .bytes(),
            Build {
                options: stamp(5),
                seq: 2400,
                ..Build::default()
            }
            .bytes(),
        ];
        assert_eq!(mergeable(&refs(&same), 0).0, 2, "one timestamp, one run");

        let differing = vec![
            Build {
                options: stamp(5),
                ..Build::default()
            }
            .bytes(),
            Build {
                options: stamp(6),
                seq: 2400,
                ..Build::default()
            }
            .bytes(),
        ];
        assert_eq!(mergeable(&refs(&differing), 0).0, 1);
    }

    #[test]
    fn what_cannot_be_described_is_refused() {
        // An IP option would be copied to every segment, a fragment has no
        // usable header after the first, and neither is worth the care.
        let mut with_options = Build::default().bytes();
        with_options[0] = 0x46;
        assert_eq!(mergeable(&[&with_options], 0).0, 1);

        let mut fragment = Build::default().bytes();
        fragment[6] = 0x20; // more-fragments
        assert_eq!(mergeable(&[&fragment], 0).0, 1);

        // And a packet with no payload has no segment size to describe.
        let empty = Build {
            payload: 0,
            ..Build::default()
        }
        .bytes();
        assert_eq!(mergeable(&[&empty], 0).0, 1);

        assert_eq!(mergeable(&[&[0u8; 4][..]], 0).0, 1, "a runt");
        assert_eq!(mergeable(&[], 0).0, 1, "nothing at all");
    }

    /// The checksum a correct receiver computes for one segment, from scratch.
    fn from_scratch(l4: &[u8], payload: &[u8], proto: u8) -> u16 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&SRC);
        pseudo.extend_from_slice(&DST);
        pseudo.push(0);
        pseudo.push(proto);
        pseudo.extend_from_slice(
            &u16::try_from(l4.len() + payload.len())
                .expect("fits")
                .to_be_bytes(),
        );
        let mut zeroed = l4.to_vec();
        let at = usize::from(csum_offset(proto));
        zeroed[at..at + 2].copy_from_slice(&[0, 0]);
        pseudo.extend_from_slice(&zeroed);
        pseudo.extend_from_slice(payload);
        !fold(sum16(&pseudo))
    }

    #[test]
    fn the_partial_checksum_is_what_the_kernel_can_finish_from() {
        // The kernel sums from `csum_start` -- the L4 header with our partial
        // still in it, plus the payload -- then folds and complements. For that
        // to come out right, the partial has to be the pseudo-header sum. This
        // does exactly that arithmetic and compares it against a checksum
        // computed from scratch, which is what the receiver will check.
        for proto in [PROTO_TCP, PROTO_UDP] {
            let owned: Vec<Vec<u8>> = (0..4)
                .map(|i| {
                    Build {
                        proto,
                        seq: 1000 + u32::try_from(i * 1400).expect("fits"),
                        payload: 1400,
                        ..Build::default()
                    }
                    .bytes()
                })
                .collect();
            let packets = refs(&owned);
            let (count, gso) = mergeable(&packets, 0);
            assert_eq!(count, 4, "{proto}");
            let mut frame = Vec::new();
            let head = assemble(&packets, 0, count, gso, &mut frame).expect("assembles");
            assert_eq!(head[0], NEEDS_CSUM);

            let l4_len = usize::from(u16::from_le_bytes([head[2], head[3]])) - IPV4_LEN;
            let l4 = &frame[IPV4_LEN..IPV4_LEN + l4_len];
            // Each full-size segment the kernel would make, checked as the
            // receiver will check it.
            for seg in 0..count {
                let at = IPV4_LEN + l4_len + seg * gso;
                let payload = &frame[at..at + gso];
                let finished = !fold(sum16(&[l4, payload].concat()));
                assert_eq!(
                    finished,
                    from_scratch(l4, payload, proto),
                    "{proto} segment {seg} would arrive with a bad checksum"
                );
            }
        }
    }

    #[test]
    fn the_frame_is_one_packet_a_receiver_would_accept() {
        let owned = stream(5, 1400);
        let packets = refs(&owned);
        let (count, gso) = mergeable(&packets, 0);
        let mut frame = Vec::new();
        let head = assemble(&packets, 0, count, gso, &mut frame).expect("assembles");

        // The length covers everything, and the checksum covers the length.
        let total = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(usize::from(total), frame.len());
        assert_eq!(fold(sum16(&frame[..IPV4_LEN])), 0xFFFF, "IP checksum");

        // Payloads in order, nothing lost or repeated.
        let body = &frame[IPV4_LEN + 20..];
        assert_eq!(body.len(), 5 * 1400);
        assert!(body.iter().all(|b| *b == 0x5A));

        // And the header describes the split the way the kernel reads it.
        assert_eq!(head[1], GSO_TCPV4);
        assert_eq!(u16::from_le_bytes([head[2], head[3]]), 40);
        assert_eq!(u16::from_le_bytes([head[4], head[5]]), 1400);
        assert_eq!(u16::from_le_bytes([head[6], head[7]]), 20);
        assert_eq!(u16::from_le_bytes([head[8], head[9]]), TCP_CSUM_OFFSET);
    }

    #[test]
    fn a_udp_superpacket_states_its_whole_length() {
        let owned: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                Build {
                    proto: PROTO_UDP,
                    payload: 1200,
                    ..Build::default()
                }
                .bytes()
            })
            .collect();
        let packets = refs(&owned);
        let (count, gso) = mergeable(&packets, 0);
        assert_eq!((count, gso), (3, 1200));
        let mut frame = Vec::new();
        let head = assemble(&packets, 0, count, gso, &mut frame).expect("assembles");
        assert_eq!(head[1], GSO_UDP_L4);
        assert_eq!(u16::from_le_bytes([head[8], head[9]]), UDP_CSUM_OFFSET);
        let udp_len = u16::from_be_bytes([frame[IPV4_LEN + 4], frame[IPV4_LEN + 5]]);
        assert_eq!(usize::from(udp_len), UDP_LEN + 3 * 1200);
    }

    #[test]
    fn one_packet_assembles_to_nothing() {
        // It has no superpacket to be, and should be written as it arrived.
        let owned = stream(1, 1400);
        let mut frame = vec![0xAA; 99];
        assert!(assemble(&refs(&owned), 0, 1, 1400, &mut frame).is_none());
    }

    #[test]
    fn a_reused_buffer_carries_nothing_from_last_time() {
        let owned = stream(3, 1400);
        let packets = refs(&owned);
        let mut frame = vec![0xAA; 70_000];
        let (count, gso) = mergeable(&packets, 0);
        assert!(assemble(&packets, 0, count, gso, &mut frame).is_some());
        assert_eq!(frame.len(), IPV4_LEN + 20 + 3 * 1400);
        assert!(
            !frame.contains(&0xAA),
            "the previous frame's bytes reached this one"
        );
    }

    #[test]
    fn a_run_stops_at_what_an_ipv4_header_can_describe() {
        // Jumbo inner packets reach the limit inside one batch of thirty-two.
        let owned = stream(32, 9000);
        let (count, _) = mergeable(&refs(&owned), 0);
        let frame = IPV4_LEN + 20 + count * 9000;
        assert!(frame <= MAX_IP_TOTAL, "{count} segments is {frame} bytes");
        assert!(
            IPV4_LEN + 20 + (count + 1) * 9000 > MAX_IP_TOTAL,
            "it stopped early at {count}"
        );
    }
}
