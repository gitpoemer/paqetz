//! The classic-BPF filter attached to the capture socket.
//!
//! The filter runs in the kernel, so packets that are not ours are dropped
//! before they are ever copied to userspace. On a busy host that is the
//! difference between waking up for every frame on the wire and waking up only
//! for our own traffic.
//!
//! It accepts: IPv4, protocol TCP, not a fragment, destination port equal to
//! ours. That is the same predicate paqet expressed as the tcpdump expression
//! `tcp and dst port N`, assembled here directly so there is no libpcap.

/// One classic-BPF instruction, laid out as the kernel expects.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    /// Opcode.
    pub code: u16,
    /// Offset to jump to when the comparison is true.
    pub jt: u8,
    /// Offset to jump to when it is false.
    pub jf: u8,
    /// Immediate operand.
    pub k: u32,
}

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

// Opcodes, assembled from the BPF class/size/mode constants.
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xB1;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

/// EtherType for IPv4.
const ETHERTYPE_IPV4: u32 = 0x0800;
/// IP protocol number for TCP.
const PROTO_TCP: u32 = 6;
/// IP protocol number for ICMP.
const PROTO_ICMP: u32 = 1;
/// Mask selecting the fragment-offset bits of the flags/offset word.
const FRAGMENT_OFFSET_MASK: u32 = 0x1FFF;

/// ICMP type and code, as one halfword: destination unreachable, fragmentation
/// needed.
const ICMP_FRAGMENTATION_NEEDED: u32 = 0x0304;

/// Snapshot length returned for an accepted packet: the whole frame.
const ACCEPT: u32 = 262_144;

/// Instructions before and after the port comparisons.
///
/// Eight of preamble, then one comparison per port, then accept and drop --
/// and then the eight of the path-MTU tail, which sits after them because
/// classic BPF only jumps forward and so cannot share their `accept`.
const FIXED_LEN: usize = 18;

/// How many instructions the program for `ports` will be.
#[must_use]
pub const fn program_len(ports: usize) -> usize {
    FIXED_LEN + ports
}

/// Builds the filter program for this end's local ports.
///
/// The program is:
///
/// ```text
///   ldh  [12]                 ; EtherType
///   jeq  #0x0800      jf fail ; must be IPv4
///   ldb  [23]                 ; IP protocol
///   jeq  #6           jf icmp ; TCP below, anything else may be a PMTU report
///   ldh  [20]                 ; flags and fragment offset
///   jset #0x1fff      jt fail ; must not be a later fragment
///   ldxb 4*([14]&0xf)         ; X := IP header length
///   ldh  [x + 16]             ; TCP destination port
///   jeq  #port0       jt accept
///   jeq  #port1       jt accept
///   ...                       ; the last one falls through to `fail`
/// accept:
///   ret  #262144              ; accept the whole frame
/// fail:
///   ret  #0                   ; drop
/// icmp:                       ; A still holds the IP protocol
///   jeq  #1           jf drop ; must be ICMP
///   ldh  [20]
///   jset #0x1fff      jt drop ; must not be a later fragment
///   ldxb 4*([14]&0xf)
///   ldh  [x + 14]             ; ICMP type and code, as one halfword
///   jeq  #0x0304      jf drop ; fragmentation needed, and DF was set
///   ret  #262144
/// drop:
///   ret  #0
/// ```
///
/// The tail is duplicated rather than shared because classic BPF jumps only
/// forward: nothing after `fail` can reach the `accept` above it.
///
/// Several ports because the carrier moves between them while it runs: a flow
/// that lives for hours accumulates attention somewhere on the path, and
/// changing the source port is what a restart was doing by accident. Filtering
/// on the whole set means rotation needs no new socket and no new filter, which
/// is what makes it possible at all — the capture thread is blocked in `recv`
/// and cannot be interrupted to be handed a new one.
///
/// The fragment check matters for more than tidiness: a later fragment has no
/// TCP header, so without it the port comparison would read whatever payload
/// bytes happened to sit at that offset.
#[must_use]
pub fn program(ports: &[u16]) -> Vec<Insn> {
    let n = ports.len();
    // Jump offsets are relative to the instruction *after* the jump. `accept`
    // sits at index 8 + n and `fail` at 9 + n, so a jump to `fail` from index i
    // is 9 + n - i - 1.
    let to_fail = |i: usize| u8::try_from(9 + n - i - 1).unwrap_or(u8::MAX);
    // The path-MTU tail begins just past `fail`, at 10 + n.
    let to_icmp = |i: usize| u8::try_from(10 + n - i - 1).unwrap_or(u8::MAX);

    let mut prog = Vec::with_capacity(program_len(n));
    prog.push(insn(LD_H_ABS, 0, 0, 12));
    prog.push(insn(JEQ_K, 0, to_fail(1), ETHERTYPE_IPV4));
    prog.push(insn(LD_B_ABS, 0, 0, 23));
    // Not TCP is not yet a reason to drop: a router reporting that a packet was
    // too big sends ICMP, and that report is the only notice the tunnel gets
    // that the path has shrunk under it.
    prog.push(insn(JEQ_K, 0, to_icmp(3), PROTO_TCP));
    prog.push(insn(LD_H_ABS, 0, 0, 20));
    prog.push(insn(JSET_K, to_fail(5), 0, FRAGMENT_OFFSET_MASK));
    prog.push(insn(LDX_B_MSH, 0, 0, 14));
    prog.push(insn(LD_H_IND, 0, 0, 16));

    for (i, port) in ports.iter().enumerate() {
        // Match: jump forward to `accept`. Miss: try the next port, except the
        // last, which falls to `fail`.
        let jt = u8::try_from(n - 1 - i).unwrap_or(u8::MAX);
        let jf = u8::from(i + 1 == n);
        prog.push(insn(JEQ_K, jt, jf, u32::from(*port)));
    }

    prog.push(insn(RET_K, 0, 0, ACCEPT));
    prog.push(insn(RET_K, 0, 0, 0));

    // A holds the IP protocol still: nothing between the jump here and the
    // comparison above it touched the accumulator.
    //
    // Anything this accepts is checked again in userspace, where the quoted
    // packet is compared against what this end actually sent. The filter's job
    // is only to stop the capture thread from being handed every ICMP message
    // on the interface.
    prog.push(insn(JEQ_K, 0, 6, PROTO_ICMP));
    prog.push(insn(LD_H_ABS, 0, 0, 20));
    prog.push(insn(JSET_K, 4, 0, FRAGMENT_OFFSET_MASK));
    prog.push(insn(LDX_B_MSH, 0, 0, 14));
    prog.push(insn(LD_H_IND, 0, 0, 14));
    prog.push(insn(JEQ_K, 0, 1, ICMP_FRAGMENTATION_NEEDED));
    prog.push(insn(RET_K, 0, 0, ACCEPT));
    prog.push(insn(RET_K, 0, 0, 0));
    prog
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// A minimal classic-BPF interpreter, so the program can be tested against
    /// real frames without a kernel. Supports only the opcodes used above.
    fn run(prog: &[Insn], frame: &[u8]) -> u32 {
        let mut pc = 0usize;
        let mut a = 0u32;
        let mut x = 0u32;
        loop {
            let i = prog[pc];
            pc += 1;
            match i.code {
                LD_H_ABS => {
                    let off = i.k as usize;
                    let Some(b) = frame.get(off..off + 2) else {
                        return 0;
                    };
                    a = u32::from(u16::from_be_bytes([b[0], b[1]]));
                }
                LD_B_ABS => {
                    let Some(b) = frame.get(i.k as usize) else {
                        return 0;
                    };
                    a = u32::from(*b);
                }
                LD_H_IND => {
                    let off = (x + i.k) as usize;
                    let Some(b) = frame.get(off..off + 2) else {
                        return 0;
                    };
                    a = u32::from(u16::from_be_bytes([b[0], b[1]]));
                }
                LDX_B_MSH => {
                    let Some(b) = frame.get(i.k as usize) else {
                        return 0;
                    };
                    x = u32::from(*b & 0x0F) * 4;
                }
                JEQ_K => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                JSET_K => pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf }),
                RET_K => return i.k,
                other => panic!("interpreter does not implement opcode {other:#04x}"),
            }
        }
    }

    /// Builds an Ethernet + IPv4 + TCP frame with the given properties.
    fn frame(ethertype: u16, proto: u8, frag: u16, dst_port: u16, ihl_words: u8) -> Vec<u8> {
        let ip_header_len = usize::from(ihl_words) * 4;
        let mut f = vec![0u8; 14 + ip_header_len + 20];
        f[12..14].copy_from_slice(&ethertype.to_be_bytes());
        f[14] = 0x40 | ihl_words;
        f[14 + 6..14 + 8].copy_from_slice(&frag.to_be_bytes());
        f[14 + 9] = proto;
        let tcp = 14 + ip_header_len;
        f[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    fn good(port: u16) -> Vec<u8> {
        frame(0x0800, 6, 0x4000, port, 5)
    }

    /// An ICMP message of this type and code, with a plausible body.
    fn icmp(kind: u8, code: u8, frag: u16, ihl_words: u8) -> Vec<u8> {
        let ip_header_len = usize::from(ihl_words) * 4;
        let mut f = vec![0u8; 14 + ip_header_len + 8 + 28];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x40 | ihl_words;
        f[14 + 6..14 + 8].copy_from_slice(&frag.to_be_bytes());
        f[14 + 9] = 1;
        let at = 14 + ip_header_len;
        f[at] = kind;
        f[at + 1] = code;
        f
    }

    #[test]
    fn a_path_mtu_report_reaches_userspace() {
        // Without this the tunnel cannot learn that the path shrank: the
        // packets simply stop arriving, and every counter looks the same as it
        // does when something is dropping them for any other reason. The
        // report is the only notice the network gives.
        let prog = program(&[9999]);
        assert_eq!(run(&prog, &icmp(3, 4, 0x4000, 5)), ACCEPT);
        // Options in the way move the ICMP header, and the filter reads its
        // offset from the IHL rather than assuming twenty bytes.
        assert_eq!(run(&prog, &icmp(3, 4, 0x4000, 8)), ACCEPT);
    }

    #[test]
    fn other_icmp_stays_in_the_kernel() {
        // Every ping on the interface would otherwise wake the capture thread
        // for nothing, and a host that is pinged is a host doing normal work.
        let prog = program(&[9999]);
        for (kind, code) in [(8u8, 0u8), (0, 0), (3, 0), (3, 3), (11, 0), (5, 1)] {
            assert_eq!(
                run(&prog, &icmp(kind, code, 0x4000, 5)),
                0,
                "ICMP {kind}/{code} should not be captured"
            );
        }
    }

    #[test]
    fn a_later_fragment_of_a_report_is_dropped_before_it_is_read() {
        // The type and code live in the first fragment; a later one has the
        // payload at that offset instead, and would be read as whichever
        // message those bytes happen to spell.
        let prog = program(&[9999]);
        for offset in [0x0001, 0x0100, 0x1FFF] {
            assert_eq!(run(&prog, &icmp(3, 4, offset, 5)), 0, "offset {offset:#x}");
        }

        // More Fragments with a zero offset is a *first* fragment, and this
        // filter passes it -- exactly as it does on the carrier path, whose
        // mask is the same. The strict check belongs in userspace, which can
        // see the whole flags word rather than the offset bits alone, and
        // `toobig` refuses it there.
        assert_eq!(
            run(&prog, &icmp(3, 4, 0x2000, 5)),
            ACCEPT,
            "the filter is a coarse pre-check, not the whole test"
        );
    }

    #[test]
    fn protocols_that_are_neither_tcp_nor_icmp_are_still_dropped() {
        // The TCP miss now falls through to the ICMP tail rather than straight
        // to `fail`, so everything else has to be refused there instead.
        let prog = program(&[9999]);
        for proto in [17u8, 47, 58, 143, 0] {
            assert_eq!(
                run(&prog, &frame(0x0800, proto, 0x4000, 9999, 5)),
                0,
                "protocol {proto} should not be captured"
            );
        }
    }

    #[test]
    fn accepts_our_traffic() {
        let prog = program(&[9999]);
        assert_eq!(run(&prog, &good(9999)), ACCEPT);
    }

    #[test]
    fn rejects_another_port() {
        let prog = program(&[9999]);
        assert_eq!(run(&prog, &good(9998)), 0);
        assert_eq!(run(&prog, &good(443)), 0);
        assert_eq!(run(&prog, &good(0)), 0);
    }

    #[test]
    fn rejects_non_ipv4() {
        let prog = program(&[9999]);
        assert_eq!(run(&prog, &frame(0x86DD, 6, 0, 9999, 5)), 0, "IPv6");
        assert_eq!(run(&prog, &frame(0x0806, 6, 0, 9999, 5)), 0, "ARP");
        assert_eq!(run(&prog, &frame(0x8100, 6, 0, 9999, 5)), 0, "VLAN");
    }

    #[test]
    fn rejects_non_tcp() {
        let prog = program(&[9999]);
        assert_eq!(run(&prog, &frame(0x0800, 17, 0, 9999, 5)), 0, "UDP");
        assert_eq!(run(&prog, &frame(0x0800, 1, 0, 9999, 5)), 0, "ICMP");
    }

    #[test]
    fn rejects_later_fragments() {
        let prog = program(&[9999]);
        // A non-zero fragment offset means there is no TCP header here at all;
        // without this check the port comparison would read payload bytes.
        for frag in [0x0001u16, 0x00FF, 0x1FFF, 0x2001] {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, frag, 9999, 5)),
                0,
                "{frag:#06x}"
            );
        }
        // Don't Fragment and More Fragments with offset zero are both fine: the
        // first fragment does carry the TCP header.
        assert_eq!(run(&prog, &frame(0x0800, 6, 0x4000, 9999, 5)), ACCEPT);
        assert_eq!(run(&prog, &frame(0x0800, 6, 0x2000, 9999, 5)), ACCEPT);
    }

    #[test]
    fn finds_the_port_past_ipv4_options() {
        // The port offset is computed from IHL rather than assumed, so a header
        // carrying options still parses.
        let prog = program(&[9999]);
        for ihl in [5u8, 6, 8, 15] {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, 0, 9999, ihl)),
                ACCEPT,
                "IHL {ihl}"
            );
        }
    }

    #[test]
    fn truncated_frames_are_dropped_rather_than_misread() {
        // The filter reads no further than the TCP destination port, which for
        // a 20-byte IPv4 header ends at offset 38. Anything shorter must be
        // dropped rather than read past.
        const LAST_BYTE_EXAMINED: usize = 14 + 20 + 4;

        let prog = program(&[9999]);
        let full = good(9999);
        for len in 0..LAST_BYTE_EXAMINED {
            assert_eq!(run(&prog, &full[..len]), 0, "truncated to {len}");
        }

        // At and beyond that point the filter has everything it inspects, so it
        // accepts. A runt frame carrying our port in the right place therefore
        // does reach userspace — where the parser rejects it, because the IP
        // total length exceeds the bytes that actually arrived.
        assert_eq!(run(&prog, &full[..LAST_BYTE_EXAMINED]), ACCEPT);
    }

    #[test]
    fn every_port_in_the_set_is_accepted_and_nothing_else_is() {
        // The carrier rotates between these while it runs, so a frame for any of
        // them has to reach us -- including the one we are about to move to, and
        // the one we have just left, which is still carrying replies.
        let ports = [61001u16, 61002, 61003, 61004];
        let prog = program(&ports);
        for p in ports {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, 0, p, 5)),
                ACCEPT,
                "port {p} should be accepted"
            );
        }
        for p in [61000u16, 61005, 443, 0] {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, 0, p, 5)),
                0,
                "port {p} should be dropped"
            );
        }
    }

    #[test]
    fn a_full_pool_still_matches_every_one_of_its_ports() {
        // Four ports were the pool when the test above was written, and it kept
        // testing four after the pool grew to twenty -- so the widths actually
        // in use went unexercised. Run every port of a full-sized pool through
        // the interpreter, and one either side of it.
        let ports: Vec<u16> = (0..20u16).map(|i| 61_000 + i * 7).collect();
        let prog = program(&ports);
        for p in &ports {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, 0, *p, 5)),
                ACCEPT,
                "port {p} of a full pool should be accepted"
            );
        }
        for p in [60_999u16, 61_001, 61_134, 443] {
            assert_eq!(
                run(&prog, &frame(0x0800, 6, 0, p, 5)),
                0,
                "port {p} is not in the pool and should be dropped"
            );
        }
    }

    #[test]
    fn one_port_still_produces_what_it_always_did() {
        let prog = program(&[9999]);
        assert_eq!(prog.len(), program_len(1));
        assert_eq!(
            prog.len(),
            19,
            "eleven for the carrier, plus eight for the path-MTU tail"
        );
    }

    #[test]
    fn the_program_grows_by_one_instruction_per_port() {
        for n in 1..=64 {
            let ports: Vec<u16> = (0..n)
                .map(|i| 61_000 + u16::try_from(i).expect("small"))
                .collect();
            assert_eq!(program(&ports).len(), program_len(n));
        }
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        // Checked for each width, because the offsets to `fail` are computed
        // from the number of ports and an off-by-one there is a filter that
        // silently drops everything.
        // Well past any pool the tunnel builds, because the offsets are single
        // bytes and `try_from` falls back to `u8::MAX` rather than failing --
        // so growing the pool too far would not break loudly, it would build a
        // filter whose jumps land past the end.
        for n in 1..=64usize {
            let ports: Vec<u16> = (0..n)
                .map(|i| 61_000 + u16::try_from(i).expect("small"))
                .collect();
            let prog = program(&ports);
            for (i, ins) in prog.iter().enumerate() {
                for off in [ins.jt, ins.jf] {
                    let dest = i + 1 + usize::from(off);
                    assert!(dest <= prog.len(), "n={n}: instruction {i} jumps out");
                }
            }
        }

        let prog = program(&[9999]);
        for (i, insn) in prog.iter().enumerate() {
            if insn.code == JEQ_K || insn.code == JSET_K {
                for target in [insn.jt, insn.jf] {
                    let dest = i + 1 + usize::from(target);
                    assert!(dest < prog.len(), "instruction {i} jumps out of bounds");
                }
            }
        }
    }

    #[test]
    fn the_program_terminates_on_every_path() {
        // Both terminal instructions must be returns, or a frame could run off
        // the end of the program.
        let prog = program(&[1]);
        assert_eq!(prog[prog.len() - 1].code, RET_K);
        assert_eq!(prog[prog.len() - 2].code, RET_K);
    }
}
