//! Path-MTU reports: ICMP "fragmentation needed", parsed from the wire.
//!
//! The carrier sets Don't Fragment, so a hop whose MTU is smaller than the
//! packet cannot pass it on. What it sends back is an ICMP destination
//! unreachable with code 4, carrying the MTU it *can* take and a quotation of
//! the packet that was too big.
//!
//! Without this the tunnel has no way to learn that: the packets simply stop
//! arriving, and every counter at both ends looks exactly as it does when a
//! path is silently dropping them. The report is the one piece of evidence the
//! network volunteers, and it costs nothing to read.
//!
//! Nothing here decides whether to believe it. The message is unauthenticated
//! and arrives from an intermediate router rather than from the peer, so anyone
//! who can guess a five-tuple can forge one; the quotation is returned to the
//! caller so the tunnel can check it against what it actually sent. Parsing and
//! trusting are separate jobs and this module only does the first.

use core::net::Ipv4Addr;

use crate::segment::{ETH_LEN, ETHERTYPE_IPV4};

/// IP protocol number for ICMP.
pub const PROTO_ICMP: u8 = 1;

/// ICMP type: destination unreachable.
pub const DEST_UNREACHABLE: u8 = 3;

/// ICMP code, under that type: fragmentation needed and DF set.
pub const FRAGMENTATION_NEEDED: u8 = 4;

/// The smallest MTU IPv4 requires every host to accept.
///
/// A report below this is not a router describing a real link; nothing on a
/// conforming path can advertise less. Treated as a floor rather than a
/// rejection, because the useful response to a nonsense number is to ignore it
/// rather than to act on it.
pub const MIN_IPV4_MTU: u16 = 68;

/// A router's report that a packet was too big for the next hop.
///
/// The quoted fields describe the packet that provoked it, as the router
/// echoed them back. They are what a caller compares against its own carrier
/// before believing any of this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooBig {
    /// The next hop's MTU, as advertised.
    pub mtu: u16,
    /// Source address of the quoted packet.
    pub origin: Ipv4Addr,
    /// Destination address of the quoted packet.
    pub destination: Ipv4Addr,
    /// IP protocol the quoted packet carried.
    pub protocol: u8,
    /// Total length of the quoted packet, from its own header.
    ///
    /// The exact size the hop refused, which with `mtu` gives the shortfall
    /// without anyone having to assume what the overhead is or what the path
    /// used to be.
    pub size: u16,
    /// The quoted packet's source and destination ports.
    ///
    /// `None` for a protocol that has no ports, and for a quotation too short
    /// to hold them -- RFC 792 asks only for the header plus eight bytes, and a
    /// router that sends the minimum leaves nothing else to check.
    pub ports: Option<(u16, u16)>,
}

/// Reads a fragmentation-needed report out of a captured Ethernet frame.
///
/// `None` for anything that is not one, which is the overwhelming majority of
/// what the capture socket sees.
#[must_use]
pub fn parse_ethernet(frame: &[u8]) -> Option<TooBig> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    parse_ipv4(frame.get(ETH_LEN..)?)
}

/// As above, starting at the IPv4 header of the ICMP message itself.
#[must_use]
pub fn parse_ipv4(packet: &[u8]) -> Option<TooBig> {
    let header_len = ipv4_header_len(packet)?;
    if *packet.get(9)? != PROTO_ICMP {
        return None;
    }
    // The report itself may not be a fragment: the quotation is in the first
    // fragment, but a parser that accepted one would be reading a datagram it
    // cannot see the whole of.
    let frag = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    if frag & 0xBFFF != 0 {
        return None;
    }

    let icmp = packet.get(header_len..)?;
    if *icmp.first()? != DEST_UNREACHABLE || *icmp.get(1)? != FRAGMENTATION_NEEDED {
        return None;
    }
    // Bytes 4 and 5 are unused in this message; the MTU lives in 6 and 7.
    let mtu = u16::from_be_bytes([*icmp.get(6)?, *icmp.get(7)?]);

    // What follows is the packet that was too big, from its IP header on.
    let quoted = icmp.get(8..)?;
    let quoted_header_len = ipv4_header_len(quoted)?;
    let protocol = *quoted.get(9)?;
    let size = u16::from_be_bytes([*quoted.get(2)?, *quoted.get(3)?]);
    let origin = address(quoted, 12)?;
    let destination = address(quoted, 16)?;

    // Ports are read only where they exist and only when the router quoted far
    // enough to include them. A truncated quotation is normal, not an error.
    let ports = match quoted.get(quoted_header_len..) {
        Some(rest) if has_ports(protocol) && rest.len() >= 4 => Some((
            u16::from_be_bytes([*rest.first()?, *rest.get(1)?]),
            u16::from_be_bytes([*rest.get(2)?, *rest.get(3)?]),
        )),
        _ => None,
    };

    Some(TooBig {
        mtu,
        origin,
        destination,
        protocol,
        size,
        ports,
    })
}

impl TooBig {
    /// Whether this report describes a packet the caller actually sent.
    ///
    /// The check that makes the message safe to act on. Everything in it is
    /// attacker-controlled except what a forger would have to know: the exact
    /// five-tuple in flight. Ports are checked when the router quoted them and
    /// skipped when it did not, which is the most a truncated quotation allows.
    ///
    /// This is not authentication -- an on-path party sees the five-tuple and
    /// can forge a matching report. It bounds the attack to somebody already
    /// positioned to drop the packets outright, which is a threat no MTU
    /// setting was ever going to answer.
    #[must_use]
    pub fn describes(&self, from: (Ipv4Addr, u16), to: (Ipv4Addr, u16), protocol: u8) -> bool {
        if self.origin != from.0 || self.destination != to.0 || self.protocol != protocol {
            return false;
        }
        match self.ports {
            Some(quoted) => quoted == (from.1, to.1),
            None => true,
        }
    }

    /// How many bytes the refused packet was over, or `None` if the report
    /// does not describe one that is.
    ///
    /// The number an operator needs, arrived at from the report alone: the
    /// packet's own length against the MTU the hop offered. Nothing here has
    /// to know what the carrier's overhead is or what the path was before.
    #[must_use]
    pub fn shortfall(&self) -> Option<u16> {
        self.size
            .checked_sub(self.usable()?)
            .filter(|over| *over > 0)
    }

    /// The advertised MTU, or `None` if it is too small to be a real link.
    ///
    /// Some routers report zero, which historically meant "guess"; a floor
    /// turns that into no report at all rather than an MTU nothing can carry.
    #[must_use]
    pub const fn usable(&self) -> Option<u16> {
        if self.mtu < MIN_IPV4_MTU {
            None
        } else {
            Some(self.mtu)
        }
    }
}

/// Length of an IPv4 header, checked for version and a sane IHL.
fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let ver_ihl = *packet.first()?;
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let words = usize::from(ver_ihl & 0x0F);
    if words < 5 {
        return None;
    }
    Some(words * 4)
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

/// Whether a protocol carries a source and destination port in its first four
/// bytes, which is the only place a minimal quotation could hold them.
const fn has_ports(protocol: u8) -> bool {
    matches!(protocol, crate::segment::PROTO_TCP | 17)
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// Builds a fragmentation-needed report quoting a packet with these
    /// properties, with `quote` bytes of the original beyond its IP header.
    fn report(mtu: u16, protocol: u8, sport: u16, dport: u16, quote: usize) -> Vec<u8> {
        let mut quoted = vec![0u8; 20];
        quoted[0] = 0x45;
        // The size the hop refused, as the original header declared it. Not the
        // length of the quotation, which is only its first few bytes.
        quoted[2..4].copy_from_slice(&1500u16.to_be_bytes());
        quoted[9] = protocol;
        quoted[12..16].copy_from_slice(&[10, 7, 0, 2]);
        quoted[16..20].copy_from_slice(&[203, 0, 113, 5]);
        let mut tail = Vec::new();
        tail.extend_from_slice(&sport.to_be_bytes());
        tail.extend_from_slice(&dport.to_be_bytes());
        tail.resize(quote, 0);
        quoted.extend_from_slice(&tail);

        let mut icmp = vec![0u8; 8];
        icmp[0] = DEST_UNREACHABLE;
        icmp[1] = FRAGMENTATION_NEEDED;
        icmp[6..8].copy_from_slice(&mtu.to_be_bytes());
        icmp.extend_from_slice(&quoted);

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = PROTO_ICMP;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[10, 7, 0, 2]);
        ip.extend_from_slice(&icmp);

        let mut frame = vec![0u8; ETH_LEN];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    fn a_report_yields_the_mtu_and_the_packet_it_describes() {
        let frame = report(1400, crate::segment::PROTO_TCP, 61001, 8443, 8);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.mtu, 1400);
        assert_eq!(got.origin, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(got.destination, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(got.protocol, crate::segment::PROTO_TCP);
        assert_eq!(got.ports, Some((61001, 8443)));
        assert_eq!(got.size, 1500, "the size the hop refused");
        assert_eq!(
            got.shortfall(),
            Some(100),
            "1500 offered to a hop taking 1400, which is what to lower the MTU by"
        );
    }

    #[test]
    fn a_report_about_a_packet_that_already_fits_asks_for_nothing() {
        // Routers do send these -- a stale report, or one for a packet from
        // before an MTU was lowered. Acting on it would shrink the tunnel for
        // no reason, and repeatedly.
        let frame = report(1500, crate::segment::PROTO_TCP, 61001, 8443, 8);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.shortfall(), None, "1500 into 1500 is not too big");

        let frame = report(9000, crate::segment::PROTO_TCP, 61001, 8443, 8);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.shortfall(), None, "nor is 1500 into 9000");

        // And a nonsense MTU yields no shortfall rather than an enormous one.
        let frame = report(0, crate::segment::PROTO_TCP, 61001, 8443, 8);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.shortfall(), None);
    }

    #[test]
    fn only_a_packet_we_sent_is_described() {
        // The whole safety of acting on this. An off-path forger has to name
        // the five-tuple in flight, which is what it does not have.
        let frame = report(1400, crate::segment::PROTO_TCP, 61001, 8443, 8);
        let got = parse_ethernet(&frame).expect("a report");
        let ours = (Ipv4Addr::new(10, 7, 0, 2), 61001);
        let theirs = (Ipv4Addr::new(203, 0, 113, 5), 8443);

        assert!(got.describes(ours, theirs, crate::segment::PROTO_TCP));
        for (from, to, proto) in [
            ((Ipv4Addr::new(10, 7, 0, 3), 61001), theirs, 6),
            (ours, (Ipv4Addr::new(203, 0, 113, 6), 8443), 6),
            ((Ipv4Addr::new(10, 7, 0, 2), 61002), theirs, 6),
            (ours, (Ipv4Addr::new(203, 0, 113, 5), 8444), 6),
            (ours, theirs, 47),
        ] {
            assert!(
                !got.describes(from, to, proto),
                "a report for someone else's packet was accepted"
            );
        }
    }

    #[test]
    fn a_quotation_too_short_for_ports_is_still_usable() {
        // RFC 792 asks only for the header plus eight bytes, and some routers
        // send exactly that. Refusing those would discard the reports from the
        // most conservative hops, which are the ones with the small MTUs.
        let frame = report(576, crate::segment::PROTO_TCP, 61001, 8443, 2);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.ports, None, "two bytes cannot hold both ports");
        assert!(
            got.describes(
                (Ipv4Addr::new(10, 7, 0, 2), 61001),
                (Ipv4Addr::new(203, 0, 113, 5), 8443),
                crate::segment::PROTO_TCP
            ),
            "addresses and protocol still match, and are all there is to check"
        );
    }

    #[test]
    fn a_protocol_without_ports_has_none_to_compare() {
        // GRE's first four bytes are flags and protocol type, not ports, and
        // reading them as ports would compare noise against a port number.
        let frame = report(1400, 47, 0x0000, 0x0800, 8);
        let got = parse_ethernet(&frame).expect("a report");
        assert_eq!(got.ports, None);
        assert!(got.describes(
            (Ipv4Addr::new(10, 7, 0, 2), 0),
            (Ipv4Addr::new(203, 0, 113, 5), 0),
            47
        ));
    }

    #[test]
    fn an_mtu_no_link_could_have_is_not_a_report() {
        for mtu in [0, 1, MIN_IPV4_MTU - 1] {
            let frame = report(mtu, crate::segment::PROTO_TCP, 61001, 8443, 8);
            let got = parse_ethernet(&frame).expect("a report");
            assert_eq!(
                got.usable(),
                None,
                "{mtu} is below what IPv4 requires every host to accept"
            );
        }
        let frame = report(MIN_IPV4_MTU, crate::segment::PROTO_TCP, 61001, 8443, 8);
        assert_eq!(
            parse_ethernet(&frame).expect("a report").usable(),
            Some(MIN_IPV4_MTU)
        );
    }

    #[test]
    fn other_icmp_and_other_protocols_are_not_reports() {
        let base = report(1400, crate::segment::PROTO_TCP, 61001, 8443, 8);

        // An echo reply, and a destination-unreachable for another reason.
        for (offset, value) in [(ETH_LEN + 20, 0u8), (ETH_LEN + 21, 3)] {
            let mut frame = base.clone();
            frame[offset] = value;
            assert!(
                parse_ethernet(&frame).is_none(),
                "byte {offset} = {value} should not read as fragmentation needed"
            );
        }

        // Not ICMP at all, and not IPv4 at all.
        let mut frame = base.clone();
        frame[ETH_LEN + 9] = crate::segment::PROTO_TCP;
        assert!(parse_ethernet(&frame).is_none());

        let mut frame = base.clone();
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert!(parse_ethernet(&frame).is_none());
    }

    #[test]
    fn every_truncation_is_refused_rather_than_read_past() {
        // Peer-supplied input reached before anything has authenticated it, so
        // the only acceptable failure is `None`.
        let frame = report(1400, crate::segment::PROTO_TCP, 61001, 8443, 8);
        for n in 0..frame.len() {
            let _ = parse_ethernet(&frame[..n]);
        }
    }

    #[test]
    fn a_fragmented_report_is_refused() {
        // The quotation is in the first fragment, but a parser that read it
        // would be describing a datagram it never saw the whole of.
        let mut frame = report(1400, crate::segment::PROTO_TCP, 61001, 8443, 8);
        frame[ETH_LEN + 6] = 0x20; // More Fragments
        assert!(parse_ethernet(&frame).is_none());
    }
}
