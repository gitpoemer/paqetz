//! The internet checksum (RFC 1071).
//!
//! Needed twice per emitted packet: once over the IPv4 header, and once over
//! the TCP pseudo-header plus segment. The TCP one covers the payload, so it
//! scales with packet size and shows up in profiles — see the note in
//! `docs/08-rewrite-plan.md` §8.11 about why the `AF_PACKET` transmit path may
//! end up preferred, since it can hand this to the NIC.

use core::net::Ipv4Addr;

/// Sums 16-bit big-endian words, folding carries in at the end.
///
/// Accumulating in a `u64` lets many words be added before any fold is needed,
/// which is what makes this cheap enough to run per packet.
#[must_use]
pub fn sum(data: &[u8], initial: u64) -> u64 {
    let mut acc = initial;
    // Fixed-size chunks, so each pair is an array and both bytes are reachable
    // without a fallible index -- which is also what the checksum wants: a word
    // half-read as zero is a checksum that passes over corrupt data.
    let (pairs, remainder) = data.as_chunks::<2>();
    for [hi, lo] in pairs {
        acc += (u64::from(*hi) << 8) | u64::from(*lo);
    }
    // An odd trailing byte is the high half of a word whose low half is zero.
    if let Some(last) = remainder.first() {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds an accumulator to 16 bits and complements it.
#[must_use]
pub fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "folded to 16 bits by the loop above"
    )]
    let folded = acc as u16;
    !folded
}

/// Checksums a buffer outright.
#[must_use]
pub fn of(data: &[u8]) -> u16 {
    fold(sum(data, 0))
}

/// The partial sum of the IPv4 TCP pseudo-header.
///
/// Layout: `src (4) | dst (4) | zero (1) | protocol (1) | tcp length (2)`.
#[must_use]
pub fn pseudo_header_v4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, tcp_len: u16) -> u64 {
    let s = src.octets();
    let d = dst.octets();
    let mut acc = 0u64;
    acc += sum(&s, 0);
    acc += sum(&d, 0);
    acc += u64::from(protocol);
    acc += u64::from(tcp_len);
    acc
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn matches_the_rfc_1071_worked_example() {
        // RFC 1071 §3 walks through this byte sequence and arrives at a folded
        // sum of 0xDDF2; the checksum is its one's complement.
        let data = [0x00u8, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        assert_eq!(fold(sum(&data, 0)), !0xDDF2u16);
        assert_eq!(of(&data), 0x220D);
    }

    #[test]
    fn matches_a_known_ipv4_header() {
        // A textbook IPv4 header with its checksum field zeroed; the expected
        // value 0xB861 is the one every worked example of this header gives.
        let header = [
            0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        assert_eq!(of(&header), 0xB861);
    }

    #[test]
    fn a_header_including_its_own_checksum_sums_to_zero() {
        // The defining property: re-checksumming a correct header yields 0.
        let mut header = [
            0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        let c = of(&header);
        header[10] = (c >> 8) as u8;
        header[11] = (c & 0xFF) as u8;
        assert_eq!(of(&header), 0);
    }

    #[test]
    fn handles_an_odd_length_by_padding_the_tail() {
        // The trailing byte is treated as the high half of a 16-bit word.
        assert_eq!(of(&[0xFFu8]), of(&[0xFF, 0x00]));
    }

    #[test]
    fn is_empty_safe() {
        assert_eq!(of(&[]), 0xFFFF);
    }

    #[test]
    fn accumulating_in_pieces_matches_one_pass() {
        let data: Vec<u8> = (0..=255u8).collect();
        let one_pass = sum(&data, 0);
        let (a, b) = data.split_at(64);
        let piecewise = sum(b, sum(a, 0));
        assert_eq!(one_pass, piecewise);
    }
}
