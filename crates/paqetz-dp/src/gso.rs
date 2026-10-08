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
/// A UDP datagram states its own length, and the last of a run may be shorter.
const UDP_LENGTH: core::ops::Range<usize> = 4..6;

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

/// Whether `b` continues a run whose previous packet was `a`, carrying
/// `a_payload` bytes.
///
/// The payload length is passed rather than read from `a`, because what is kept
/// between packets is headers; the bytes are already in the frame.
fn continues_after(a: &Packet<'_>, a_payload: usize, b: &Packet<'_>, gso_size: usize) -> bool {
    // The first packet's headers are the ones every segment gets, so anything
    // an observer would read off them has to match -- but only the fields that
    // are *meant* to be the same. Three are not:
    //
    // - the total length, which differs by definition
    // - the Identification, which a real sender advances on every packet, and
    //   which the kernel assigns afresh to each segment it makes
    // - the header checksum, which follows from the other two
    //
    // Comparing those made every run exactly one packet long, for real traffic
    // and only real traffic: a synthetic stream with a fixed Identification
    // merged perfectly, which is how the tests missed it and the benchmark
    // found it.
    // Version and header length, TOS; the fragment flags, TTL and protocol;
    // and the addresses. Everything between is a field that differs by design.
    const SAME: [core::ops::Range<usize>; 3] = [0..2, 6..10, 12..20];
    if SAME
        .iter()
        .any(|r| a.ip.get(r.clone()) != b.ip.get(r.clone()))
    {
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
        [UDP_LENGTH, UDP_CSUM]
    };
    for (i, (x, y)) in a.l4.iter().zip(b.l4.iter()).enumerate() {
        if varies.iter().any(|r| r.contains(&i)) {
            continue;
        }
        if x != y {
            return false;
        }
    }
    if a.proto == PROTO_TCP && b.seq != a.seq.wrapping_add(size32(a_payload)) {
        return false;
    }
    // Every segment but the last carries exactly `gso_size`, which is the whole
    // meaning of the field. A short one in the middle would be re-split at the
    // wrong boundaries.
    a_payload == gso_size && !b.payload.is_empty() && b.payload.len() <= gso_size
}

fn size32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Holds inner packets until they can be written as one frame.
///
/// One copy per packet, into the frame being built, which is the copy the
/// kernel would have made from each separate write anyway. A run of one pays
/// that copy for nothing, so a batch of entirely unrelated packets is slightly
/// worse off than writing each directly -- roughly a sixth of what one write
/// costs, against three quarters of it saved at a run of four.
#[derive(Debug, Default)]
pub struct Coalescer {
    /// The first packet's headers, then every payload.
    frame: Vec<u8>,
    /// Returned alongside the frame, so the caller writes both in one call.
    header: [u8; VNET_HDR_LEN],
    run: Option<Run>,
    /// Whether the frame is waiting to be written.
    ///
    /// Tracked rather than read off the frame's length, because `take` hands
    /// out a borrow of the frame and so cannot clear it. The next `hold`
    /// overwrites it instead.
    pending: bool,
}

/// The run being built.
#[derive(Debug)]
struct Run {
    proto: u8,
    l4_len: usize,
    gso_size: usize,
    count: usize,
    payload: usize,
    /// The last packet admitted, which the next one is compared against.
    last_ip: [u8; IPV4_LEN],
    last_l4: Vec<u8>,
    last_seq: u32,
    last_payload: usize,
}

impl Coalescer {
    /// Whether `packet` can join what is already held.
    ///
    /// True with nothing held, since anything can start a run. False for
    /// anything this cannot describe, which is then written on its own.
    #[must_use]
    pub fn joins(&self, packet: &[u8]) -> bool {
        let Some(next) = parse(packet) else {
            return false;
        };
        let Some(run) = self.run.as_ref() else {
            // Nothing merges onto something this did not understand, which is
            // held as it arrived and has to go out before anything else.
            return !self.pending && !next.payload.is_empty();
        };
        let last = Packet {
            ip: &run.last_ip,
            l4: &run.last_l4,
            payload: &[],
            proto: run.proto,
            seq: run.last_seq,
        };
        if !continues_after(&last, run.last_payload, &next, run.gso_size) {
            return false;
        }
        IPV4_LEN + run.l4_len + run.payload + next.payload.len() <= MAX_IP_TOTAL
    }

    /// Whether `packet` could ever be part of a run.
    ///
    /// A pure-acknowledgement segment carries no payload and so has no segment
    /// size to describe, and the same goes for anything this cannot parse.
    /// Both are written on their own, and a caller that checks this first
    /// spares them a copy into a frame they would be the only occupant of.
    /// On the reverse path of a bulk transfer that is most of the packets.
    #[must_use]
    pub fn can_hold(packet: &[u8]) -> bool {
        parse(packet).is_some_and(|p| !p.payload.is_empty())
    }

    /// Adds `packet` to the run.
    ///
    /// Call [`Self::joins`] first, or [`Self::take`] if it said no. A packet
    /// added without either is written on its own, which is correct but wastes
    /// the frame it was being accumulated into.
    pub fn hold(&mut self, packet: &[u8]) {
        self.pending = true;
        let Some(next) = parse(packet) else {
            // Not something this understands. Held as it is, so it still goes
            // out, as one packet with no segmentation asked for.
            self.frame.clear();
            self.frame.extend_from_slice(packet);
            self.run = None;
            return;
        };
        match self.run.as_mut() {
            Some(run) => {
                self.frame.extend_from_slice(next.payload);
                run.count += 1;
                run.payload += next.payload.len();
                run.last_l4.clear();
                run.last_l4.extend_from_slice(next.l4);
                run.last_seq = next.seq;
                run.last_payload = next.payload.len();
            }
            None => {
                self.frame.clear();
                self.frame.extend_from_slice(next.ip);
                self.frame.extend_from_slice(next.l4);
                self.frame.extend_from_slice(next.payload);
                let mut last_ip = [0u8; IPV4_LEN];
                if let Some(slot) = next.ip.get(..IPV4_LEN) {
                    last_ip.copy_from_slice(slot);
                }
                self.run = Some(Run {
                    proto: next.proto,
                    l4_len: next.l4.len(),
                    gso_size: next.payload.len(),
                    count: 1,
                    payload: next.payload.len(),
                    last_ip,
                    last_l4: next.l4.to_vec(),
                    last_seq: next.seq,
                    last_payload: next.payload.len(),
                });
            }
        }
    }

    /// The frame to write and the header to write with it, if anything is held.
    ///
    /// A run of one yields a header asking for no segmentation, so the caller
    /// writes every case the same way.
    pub fn take(&mut self) -> Option<(&[u8; VNET_HDR_LEN], &[u8])> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        let Some(run) = self.run.take() else {
            // Something unparsed, going out exactly as it arrived.
            self.header = [0u8; VNET_HDR_LEN];
            return Some((&self.header, &self.frame));
        };
        if run.count == 1 {
            self.header = [0u8; VNET_HDR_LEN];
            return Some((&self.header, &self.frame));
        }
        self.header = finish(&mut self.frame, &run)?;
        Some((&self.header, &self.frame))
    }

    /// Whether anything is waiting to be written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.pending
    }

    /// Forgets whatever is held, for a caller that could not write it.
    pub fn clear(&mut self) {
        self.frame.clear();
        self.run = None;
        self.pending = false;
    }
}

/// Rewrites the frame's headers for the whole run and returns its header.
fn finish(frame: &mut [u8], run: &Run) -> Option<[u8; VNET_HDR_LEN]> {
    let ip_total = u16::try_from(IPV4_LEN + run.l4_len + run.payload).ok()?;
    frame
        .get_mut(2..4)?
        .copy_from_slice(&ip_total.to_be_bytes());
    frame.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_ck = !fold(sum16(frame.get(..IPV4_LEN)?));
    frame.get_mut(10..12)?.copy_from_slice(&ip_ck.to_be_bytes());

    if run.proto == PROTO_UDP {
        // UDP states its own length, and a superpacket states the whole one,
        // which is what the kernel's segmenter expects to find.
        let udp_total = u16::try_from(UDP_LEN + run.payload).ok()?;
        frame
            .get_mut(IPV4_LEN + 4..IPV4_LEN + 6)?
            .copy_from_slice(&udp_total.to_be_bytes());
    }
    // The half of the checksum the kernel cannot derive: the pseudo-header for
    // one segment, which is what `NEEDS_CSUM` expects to find there.
    let partial = pseudo_header(frame, run)?;
    let at = IPV4_LEN + usize::from(csum_offset(run.proto));
    frame
        .get_mut(at..at + 2)?
        .copy_from_slice(&partial.to_be_bytes());
    Some(header(run))
}

const fn csum_offset(proto: u8) -> u16 {
    if proto == PROTO_TCP {
        TCP_CSUM_OFFSET
    } else {
        UDP_CSUM_OFFSET
    }
}

/// The `virtio_net_hdr` describing how to split a frame.
fn header(run: &Run) -> [u8; VNET_HDR_LEN] {
    let mut h = [0u8; VNET_HDR_LEN];
    h[0] = NEEDS_CSUM;
    h[1] = if run.proto == PROTO_TCP {
        GSO_TCPV4
    } else {
        GSO_UDP_L4
    };
    let hdr_len = u16::try_from(IPV4_LEN + run.l4_len).unwrap_or(u16::MAX);
    h[2..4].copy_from_slice(&hdr_len.to_le_bytes());
    h[4..6].copy_from_slice(
        &u16::try_from(run.gso_size)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    h[6..8].copy_from_slice(&u16::try_from(IPV4_LEN).unwrap_or(0).to_le_bytes());
    h[8..10].copy_from_slice(&csum_offset(run.proto).to_le_bytes());
    h
}

/// The ones' complement sum of the pseudo-header for one segment.
fn pseudo_header(frame: &[u8], run: &Run) -> Option<u16> {
    let mut head = [0u8; 12];
    head.get_mut(..4)?.copy_from_slice(frame.get(12..16)?);
    head.get_mut(4..8)?.copy_from_slice(frame.get(16..20)?);
    head[9] = run.proto;
    let len = u16::try_from(run.l4_len + run.gso_size).ok()?;
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
        /// Advanced per packet, as a real sender does. Fixed at one value for
        /// every packet, this fixture hid the defect the benchmark found.
        ip_id: u16,
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
                ip_id: 0x1234,
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
            p.extend_from_slice(&self.ip_id.to_be_bytes());
            p.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
            p.push(self.ttl);
            p.push(self.proto);
            p.extend_from_slice(&0u16.to_be_bytes()); // checksum, below
            p.extend_from_slice(&SRC);
            p.extend_from_slice(&DST);
            // A real header checksum, which therefore differs between packets
            // because the Identification and the length do.
            let ck = !fold(sum16(&p[..IPV4_LEN]));
            p[10..12].copy_from_slice(&ck.to_be_bytes());

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
                    ip_id: 0x1234 + u16::try_from(i).expect("fits"),
                    ..Build::default()
                }
                .bytes()
            })
            .collect()
    }

    /// One write the coalescer would make.
    struct Written {
        count: usize,
        header: [u8; VNET_HDR_LEN],
        frame: Vec<u8>,
    }

    impl Written {
        fn gso(&self) -> usize {
            usize::from(u16::from_le_bytes([self.header[4], self.header[5]]))
        }
    }

    /// Drives the coalescer over `packets` exactly as the datapath will, and
    /// returns the writes it would make.
    fn drive(packets: &[Vec<u8>]) -> Vec<Written> {
        let mut c = Coalescer::default();
        let mut out = Vec::new();
        let mut held = 0usize;
        for p in packets {
            if !c.joins(p) {
                if let Some((header, frame)) = c.take() {
                    out.push(Written {
                        count: held,
                        header: *header,
                        frame: frame.to_vec(),
                    });
                }
                held = 0;
            }
            c.hold(p);
            held += 1;
        }
        if let Some((header, frame)) = c.take() {
            out.push(Written {
                count: held,
                header: *header,
                frame: frame.to_vec(),
            });
        }
        assert!(c.is_empty(), "the coalescer kept something back");
        out
    }

    #[test]
    fn a_contiguous_stream_merges_whole() {
        let owned = stream(8, 1400);
        let w = drive(&owned);
        assert_eq!(w.len(), 1, "one write for one stream");
        assert_eq!((w[0].count, w[0].gso()), (8, 1400));
    }

    #[test]
    fn a_gap_in_the_sequence_ends_the_run() {
        // The carrier never retransmits, so a gap is permanent and the kernel
        // must not be told these were one segment.
        let mut owned = stream(8, 1400);
        owned.remove(3);
        let w = drive(&owned);
        assert_eq!(w.len(), 2, "one write each side of the hole");
        assert_eq!(w[0].count, 3, "the run has to stop at the hole");
        assert_eq!(w[1].count, 4, "and the rest still merges");
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
        let w = drive(&owned);
        assert_eq!(w.len(), 1);
        assert_eq!((w[0].count, w[0].gso()), (4, 1400), "a short last belongs");

        // In the middle it does not: everything but the last carries gso_size,
        // or the kernel re-splits at the wrong boundaries.
        let mut owned = stream(4, 1400);
        owned[1] = Build {
            seq: 1000 + 1400,
            payload: 200,
            ..Build::default()
        }
        .bytes();
        let w = drive(&owned);
        assert_eq!(w[0].count, 2, "the short one ends it");
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
            let w = drive(&owned);
            assert_eq!(w[0].count, 1, "flags {flags:#04x} should stand alone");
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
        assert_eq!(drive(&owned)[0].count, 1);
    }

    #[test]
    fn the_fields_that_differ_by_design_do_not_end_a_run() {
        // The defect this exists for: comparing the whole IP header past the
        // total length meant the Identification and the checksum, which differ
        // on every real packet, made every run exactly one packet long. The
        // benchmark found it because the fixture then used a fixed
        // Identification and a zero checksum, so nothing here could.
        let owned = stream(6, 1400);
        let ids: Vec<u16> = owned
            .iter()
            .map(|p| u16::from_be_bytes([p[4], p[5]]))
            .collect();
        assert_eq!(ids.len(), 6);
        assert!(
            ids.windows(2).all(|w| w[0] != w[1]),
            "the fixture has to advance the Identification: {ids:?}"
        );
        let checksums: Vec<u16> = owned
            .iter()
            .map(|p| u16::from_be_bytes([p[10], p[11]]))
            .collect();
        assert!(
            checksums.windows(2).all(|w| w[0] != w[1]),
            "and carry a real checksum, which then differs: {checksums:?}"
        );
        for p in &owned {
            assert_eq!(fold(sum16(&p[..IPV4_LEN])), 0xFFFF, "a valid checksum");
        }

        let w = drive(&owned);
        assert_eq!(w.len(), 1, "a real stream has to merge whole");
        assert_eq!(w[0].count, 6);
    }

    #[test]
    fn a_short_final_datagram_joins_a_udp_run() {
        // UDP states its own length, so the last datagram's header differs
        // from the rest. The kernel writes each segment's own length, which
        // makes it the same kind of field as TCP's sequence number.
        let mut owned: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                Build {
                    proto: PROTO_UDP,
                    payload: 1200,
                    ip_id: 0x900 + i,
                    ..Build::default()
                }
                .bytes()
            })
            .collect();
        owned.push(
            Build {
                proto: PROTO_UDP,
                payload: 400,
                ip_id: 0x903,
                ..Build::default()
            }
            .bytes(),
        );
        let w = drive(&owned);
        assert_eq!(w.len(), 1, "the short one belongs to the run");
        assert_eq!((w[0].count, w[0].gso()), (4, 1200));
        let udp_len = u16::from_be_bytes([w[0].frame[IPV4_LEN + 4], w[0].frame[IPV4_LEN + 5]]);
        assert_eq!(usize::from(udp_len), UDP_LEN + 3 * 1200 + 400);
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
        assert_eq!(drive(&owned)[0].count, 1);
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
        assert_eq!(drive(&same)[0].count, 2, "one timestamp, one run");

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
        assert_eq!(drive(&differing)[0].count, 1);
    }

    #[test]
    fn what_cannot_be_described_is_refused() {
        // An IP option would be copied to every segment, a fragment has no
        // usable header after the first, and neither is worth the care.
        let mut with_options = Build::default().bytes();
        with_options[0] = 0x46;
        let mut fragment = Build::default().bytes();
        fragment[6] = 0x20; // more-fragments
        let empty = Build {
            payload: 0,
            ..Build::default()
        }
        .bytes();

        for (what, packet) in [
            ("IP options", with_options),
            ("a fragment", fragment),
            ("no payload", empty),
            ("a runt", vec![0u8; 4]),
        ] {
            let w = drive(std::slice::from_ref(&packet));
            assert_eq!(w.len(), 1, "{what} should still be written");
            assert_eq!(w[0].count, 1, "{what} should stand alone");
            assert_eq!(w[0].frame, packet, "{what} should go out unchanged");
            assert_eq!(w[0].header, [0u8; VNET_HDR_LEN], "{what} asks for no split");
        }
        assert!(drive(&[]).is_empty(), "nothing at all");
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
            let w = drive(&owned);
            assert_eq!(w[0].count, 4, "{proto}");
            let (head, frame, gso) = (w[0].header, w[0].frame.clone(), w[0].gso());
            assert_eq!(head[0], NEEDS_CSUM);

            let l4_len = usize::from(u16::from_le_bytes([head[2], head[3]])) - IPV4_LEN;
            let l4 = &frame[IPV4_LEN..IPV4_LEN + l4_len];
            // Each full-size segment the kernel would make, checked as the
            // receiver will check it.
            for seg in 0..w[0].count {
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
        let w = drive(&owned);
        let (head, frame) = (w[0].header, w[0].frame.clone());

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
        let w = drive(&owned);
        assert_eq!((w[0].count, w[0].gso()), (3, 1200));
        let (head, frame) = (w[0].header, w[0].frame.clone());
        assert_eq!(head[1], GSO_UDP_L4);
        assert_eq!(u16::from_le_bytes([head[8], head[9]]), UDP_CSUM_OFFSET);
        let udp_len = u16::from_be_bytes([frame[IPV4_LEN + 4], frame[IPV4_LEN + 5]]);
        assert_eq!(usize::from(udp_len), UDP_LEN + 3 * 1200);
    }

    #[test]
    fn one_packet_asks_for_no_split() {
        // It has no superpacket to be, and goes out as it arrived.
        let owned = stream(1, 1400);
        let w = drive(&owned);
        assert_eq!(w[0].header, [0u8; VNET_HDR_LEN]);
        assert_eq!(w[0].frame, owned[0]);
    }

    #[test]
    fn a_reused_coalescer_carries_nothing_from_last_time() {
        // One instance lives for the life of the thread, so a frame must not
        // be able to leak into the next one.
        let mut c = Coalescer::default();
        for packets in [stream(3, 1400), stream(2, 900), stream(5, 1400)] {
            for p in &packets {
                if !c.joins(p) {
                    let _ = c.take();
                }
                c.hold(p);
            }
            let (_, frame) = c.take().expect("something is held");
            let want: usize = IPV4_LEN + 20 + packets.iter().map(|p| p.len() - 40).sum::<usize>();
            assert_eq!(frame.len(), want);
            assert!(c.is_empty());
        }
    }

    #[test]
    fn what_can_never_be_part_of_a_run_says_so() {
        // The caller writes these directly, so they never pay a copy into a
        // frame they would be alone in. On the reverse path of a bulk transfer
        // the acknowledgements are most of the packets.
        let ack = Build {
            payload: 0,
            ..Build::default()
        }
        .bytes();
        assert!(!Coalescer::can_hold(&ack), "a bare acknowledgement");
        assert!(!Coalescer::can_hold(&[0u8; 4]), "a runt");
        assert!(!Coalescer::can_hold(&[]), "nothing");

        let mut fragment = Build::default().bytes();
        fragment[6] = 0x20;
        assert!(!Coalescer::can_hold(&fragment), "a fragment");

        assert!(Coalescer::can_hold(&Build::default().bytes()), "data");
    }

    #[test]
    fn what_cannot_be_written_can_be_dropped() {
        let owned = stream(3, 1400);
        let mut c = Coalescer::default();
        for p in &owned {
            c.hold(p);
        }
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        assert!(c.take().is_none());
    }

    #[test]
    fn a_run_stops_at_what_an_ipv4_header_can_describe() {
        // Jumbo inner packets reach the limit inside one batch of thirty-two.
        let owned = stream(32, 9000);
        let count = drive(&owned)[0].count;
        let frame = IPV4_LEN + 20 + count * 9000;
        assert!(frame <= MAX_IP_TOTAL, "{count} segments is {frame} bytes");
        assert!(
            IPV4_LEN + 20 + (count + 1) * 9000 > MAX_IP_TOTAL,
            "it stopped early at {count}"
        );
    }
}
