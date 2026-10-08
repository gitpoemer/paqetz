//! Operating-system fingerprint profiles.
//!
//! paqet emitted a constant TTL of 64, a constant MSS of 1460, a constant
//! window scale of 8, and a constant window of 65535 on every packet regardless
//! of what it claimed to be. Together those are a stable signature.
//!
//! A profile fixes the values a real stack would have chosen at connection
//! setup, so that a flow is at least internally consistent with *some*
//! plausible sender. The profile is chosen in configuration; it should match
//! whatever the host would otherwise look like.
//!
//! Each profile's numbers are taken from the matching entry in nmap's
//! `nmap-os-db`, which is what classifies these flows in practice: the SYN
//! option layout from `OPS`, the advertised window from `WIN`, and the initial
//! TTL from `TG`. Where a profile deviates from its device, the reason is on
//! the field.

/// One TCP option in the order a stack writes it on a SYN.
///
/// The layout is as much of the signature as the values are: every stack here
/// offers an MSS and SACK, and they are told apart by what sits between and
/// after them. Keeping the order as data means a new profile is numbers rather
/// than another branch in the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynOption {
    /// Maximum segment size. Four bytes.
    Mss,
    /// Selective acknowledgement permitted. Two bytes.
    SackPermitted,
    /// RFC 7323 timestamps. Ten bytes.
    Timestamps,
    /// One byte of padding.
    Nop,
    /// End of option list, used as padding by stacks that pad with it.
    EndOfList,
    /// Window scale. Three bytes.
    WindowScale,
}

impl SynOption {
    /// Bytes this option occupies.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Mss => 4,
            Self::SackPermitted => 2,
            Self::Timestamps => 10,
            Self::Nop | Self::EndOfList => 1,
            Self::WindowScale => 3,
        }
    }
}

/// What a stack puts in the IPv4 Identification field.
///
/// The interesting split is not "does it randomise" but "does a connection own
/// the packet", which is how the kernel itself branches. From
/// `include/net/ip.h`:
///
/// ```text
/// if (sk && inet_sk(sk)->inet_daddr) {   /* a connected socket */
///         ... iph->id = htons(val);      /* inet_id, += segs */
///         return;
/// }
/// if ((iph->frag_off & htons(IP_DF)) && !skb->ignore_df) {
///         iph->id = 0;
/// ```
///
/// `inet_sock.h` documents the field as "ID counter for DF pkts". So a Linux
/// TCP segment carries a counter even with Don't Fragment set, and the zero is
/// for packets no connection owns -- a listener's SYN+ACK among them, which is
/// why every Linux-derived entry in nmap's database records `TI=Z`: nmap reads
/// it off exactly that packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpId {
    /// Numbered from the connection, and zero on a reply that has none.
    ///
    /// Linux, and Windows, which keeps the same kind of per-connection counter.
    ///
    /// The zero half is honoured only while Don't Fragment is set, because that
    /// is the kernel's own condition for it and because a zero Identification
    /// shared across a flow that *can* be fragmented would have the fragments
    /// of different packets reassembled into each other.
    PerConnection,
    /// A fresh unpredictable value on every packet, connection or not.
    ///
    /// IOS, whose nmap entry records `TI=RD`.
    Random,
}

/// The SYN-time parameters of one operating system's TCP stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsProfile {
    /// Name used in configuration.
    pub name: &'static str,
    /// Initial IP TTL.
    pub ttl: u8,
    /// Maximum segment size advertised on SYN.
    pub mss: u16,
    /// Window-scale shift advertised on SYN, or `None` for a stack that does
    /// not offer the option at all.
    ///
    /// Absent, the window on the wire is the window an observer reads, so it
    /// can never exceed 65535 however much is in flight.
    pub window_scale: Option<u8>,
    /// Receive window advertised on SYN, before scaling.
    pub syn_window: u16,
    /// Receive window advertised after the handshake, before scaling.
    pub window: u32,
    /// Whether the stack negotiates SACK.
    pub sack_permitted: bool,
    /// Whether the stack negotiates RFC 7323 timestamps.
    ///
    /// When false, no timestamp option is emitted and the peer's timestamps are
    /// not echoed — Windows behaves this way by default, and a profile claiming
    /// to be Windows while echoing timestamps would contradict itself.
    pub timestamps: bool,
    /// Ticks per second of the timestamp clock.
    ///
    /// Reported by nmap as `TS` and by p0f as the timestamp frequency, and it
    /// is one of the few fields that cannot be read from a single packet: it
    /// takes two, which makes it one of the harder parts of a stack to fake and
    /// one of the easier ones to check.
    pub ts_hz: u32,
    /// What the stack writes in the IPv4 Identification field.
    pub ip_id: IpId,
    /// Whether the device sets Don't Fragment on its own traffic.
    ///
    /// What *this* sends is the `fragment` setting's decision, since clearing
    /// the bit also caps the MTU it is safe at. This records what the device
    /// would do, so a mismatch can be pointed out rather than silently
    /// contradicting the rest of the profile.
    pub dont_fragment: bool,
    /// The TCP options a SYN carries, in order.
    pub syn_options: &'static [SynOption],
}

/// The option layout shared by Linux and the stacks derived from it.
const LINUX_OPTS: &[SynOption] = &[
    SynOption::Mss,
    SynOption::SackPermitted,
    SynOption::Timestamps,
    SynOption::Nop,
    SynOption::WindowScale,
];

/// Linux 6.x with default `sysctl` settings.
pub const LINUX_6: OsProfile = OsProfile {
    name: "linux-6",
    ttl: 64,
    mss: 1460,
    window_scale: Some(7),
    syn_window: 64240,
    window: 64240,
    sack_permitted: true,
    timestamps: true,
    ts_hz: 1000,
    ip_id: IpId::PerConnection,
    dont_fragment: true,
    syn_options: LINUX_OPTS,
};

/// Windows 11. Notably does not negotiate timestamps by default.
pub const WINDOWS_11: OsProfile = OsProfile {
    name: "windows-11",
    ttl: 128,
    mss: 1460,
    window_scale: Some(8),
    syn_window: 64240,
    window: 65535,
    sack_permitted: true,
    timestamps: false,
    ts_hz: 1000,
    ip_id: IpId::PerConnection,
    dont_fragment: true,
    syn_options: &[
        SynOption::Mss,
        SynOption::Nop,
        SynOption::WindowScale,
        SynOption::Nop,
        SynOption::Nop,
        SynOption::SackPermitted,
    ],
};

/// Recent Android, which is Linux with a larger initial window scale.
pub const ANDROID_14: OsProfile = OsProfile {
    name: "android-14",
    ttl: 64,
    mss: 1460,
    window_scale: Some(8),
    syn_window: 65535,
    window: 65535,
    sack_permitted: true,
    timestamps: true,
    ts_hz: 1000,
    ip_id: IpId::PerConnection,
    dont_fragment: true,
    syn_options: LINUX_OPTS,
};

/// MikroTik RouterOS 6.x, which is Linux 3.3.5 with a router's buffers.
///
/// Linux's option layout, told apart from a desktop Linux by three things its
/// nmap entries agree on across every 6.x release: a window scale of 4 rather
/// than 7, an initial window of ten segments rather than a buffer-derived one,
/// and a 100 Hz timestamp clock, which is the kernel's `CONFIG_HZ` on the
/// embedded builds RouterOS ships.
pub const ROUTEROS_6: OsProfile = OsProfile {
    name: "routeros-6",
    ttl: 64,
    mss: 1460,
    window_scale: Some(4),
    // Ten times the MSS, which is what every RouterOS entry in nmap's database
    // advertises for its own MSS.
    syn_window: 14_600,
    window: 64_240,
    sack_permitted: true,
    timestamps: true,
    ts_hz: 100,
    ip_id: IpId::PerConnection,
    dont_fragment: true,
    syn_options: LINUX_OPTS,
};

/// Cisco IOS 15.x.
///
/// Three things set it apart from every other profile here: an initial TTL of
/// 255, no window scale at all, and a tiny 4128-byte initial window. It pads
/// its options with end-of-list rather than NOPs and puts SACK before the
/// timestamp, so the layout differs from Linux's at the same total length.
pub const IOS_15: OsProfile = OsProfile {
    name: "ios-15",
    ttl: 255,
    mss: 1460,
    window_scale: None,
    // `ip tcp window-size`, which defaults to 4128 and is what IOS advertises
    // on a SYN whatever it is later raised to.
    syn_window: 4_128,
    // Raised, where the SYN window is not, and this is the one number here
    // chosen against the device rather than from it. Without a scale factor
    // the field is the whole window an observer reads, and a flow that stayed
    // at 4128 bytes in flight would be throttled to a trickle by anything
    // enforcing it -- which has already happened once on the path this exists
    // for, and is written up beside `window()` in `endpoint`.
    //
    // The cost is that the field jumps 4128 to about 65535 at the first data
    // segment, sixteenfold in one step, where every other profile's apparent
    // window moves smoothly because its scale factor absorbs the change. No
    // receiver does that: a window grows as an application drains a buffer,
    // and `ip tcp window-size` is not something a router changes mid
    // connection. So this trades a field that is wrong for one that is
    // throttled, which is the right way round for a tunnel but is not
    // invisible.
    window: 65_535,
    // `S` and `T11` in the `OPS` layout: SACK permitted, and a timestamp with
    // both halves filled in. nmap's file holds a second IOS 15 entry offering
    // no options at all (`O1=M5B4`); this is the one that can carry the real
    // handshake, which needs a timestamp to prove a SYN with.
    sack_permitted: true,
    timestamps: true,
    // `TS=A` in its `SEQ` line, which is nmap's way of writing a clock at
    // about a thousand ticks a second.
    ts_hz: 1000,
    // `TI=RD`: IOS randomises the field rather than counting, so there is no
    // zero case for it to have.
    ip_id: IpId::Random,
    dont_fragment: false,
    syn_options: &[
        SynOption::Mss,
        SynOption::SackPermitted,
        SynOption::Nop,
        SynOption::Nop,
        SynOption::Timestamps,
        SynOption::EndOfList,
        SynOption::EndOfList,
    ],
};

/// Every profile that can be named in configuration.
pub const ALL: &[OsProfile] = &[LINUX_6, WINDOWS_11, ANDROID_14, ROUTEROS_6, IOS_15];

/// Looks a profile up by its configuration name.
#[must_use]
pub fn by_name(name: &str) -> Option<OsProfile> {
    ALL.iter().copied().find(|p| p.name == name)
}

impl Default for OsProfile {
    fn default() -> Self {
        LINUX_6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_reachable_by_name() {
        for p in ALL {
            assert_eq!(by_name(p.name), Some(*p), "{} should resolve", p.name);
        }
    }

    #[test]
    fn unknown_names_do_not_resolve() {
        assert_eq!(by_name("plan9"), None);
        assert_eq!(by_name(""), None);
    }

    #[test]
    fn profile_names_are_unique() {
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(a.name, b.name, "duplicate profile name {}", a.name);
            }
        }
    }

    #[test]
    fn profiles_differ_from_one_another() {
        // If two profiles were identical, offering both would be misleading.
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn option_layouts_are_whole_words() {
        // The TCP data offset counts 32-bit words, so a layout that is not a
        // multiple of four cannot be described by the header at all.
        for p in ALL {
            let len: usize = p.syn_options.iter().map(|o| o.bytes()).sum();
            assert!(len.is_multiple_of(4), "{} options are {len} bytes", p.name);
            assert!(len <= 40, "{} options exceed the option space", p.name);
        }
    }

    #[test]
    fn layouts_agree_with_the_flags_beside_them() {
        // Two ways to say the same thing, so they have to say it the same way:
        // the flags drive the data segments and the layout drives the SYN.
        for p in ALL {
            let has = |o| p.syn_options.contains(&o);
            assert_eq!(
                has(SynOption::Timestamps),
                p.timestamps,
                "{} negotiates timestamps in one place and not the other",
                p.name
            );
            assert_eq!(
                has(SynOption::SackPermitted),
                p.sack_permitted,
                "{} negotiates SACK in one place and not the other",
                p.name
            );
            assert_eq!(
                has(SynOption::WindowScale),
                p.window_scale.is_some(),
                "{} offers a window scale in one place and not the other",
                p.name
            );
            assert!(
                has(SynOption::Mss),
                "{} advertises no MSS, which no stack does",
                p.name
            );
        }
    }

    #[test]
    fn an_unscaled_window_fits_the_field() {
        // With no scale factor the window on the wire is the window itself.
        for p in ALL.iter().filter(|p| p.window_scale.is_none()) {
            assert!(
                p.window <= u32::from(u16::MAX),
                "{} cannot advertise {} without a scale",
                p.name,
                p.window
            );
        }
    }

    #[test]
    fn a_timestamp_clock_runs() {
        for p in ALL.iter().filter(|p| p.timestamps) {
            assert!(p.ts_hz > 0, "{} has a stopped clock", p.name);
        }
    }
}
