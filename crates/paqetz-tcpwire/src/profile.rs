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

/// The SYN-time parameters of one operating system's TCP stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsProfile {
    /// Name used in configuration.
    pub name: &'static str,
    /// Initial IP TTL.
    pub ttl: u8,
    /// Maximum segment size advertised on SYN.
    pub mss: u16,
    /// Window-scale shift advertised on SYN.
    pub window_scale: u8,
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
}

/// Linux 6.x with default `sysctl` settings.
pub const LINUX_6: OsProfile = OsProfile {
    name: "linux-6",
    ttl: 64,
    mss: 1460,
    window_scale: 7,
    syn_window: 64240,
    window: 64240,
    sack_permitted: true,
    timestamps: true,
};

/// Windows 11. Notably does not negotiate timestamps by default.
pub const WINDOWS_11: OsProfile = OsProfile {
    name: "windows-11",
    ttl: 128,
    mss: 1460,
    window_scale: 8,
    syn_window: 64240,
    window: 65535,
    sack_permitted: true,
    timestamps: false,
};

/// Recent Android, which is Linux with a larger initial window scale.
pub const ANDROID_14: OsProfile = OsProfile {
    name: "android-14",
    ttl: 64,
    mss: 1460,
    window_scale: 8,
    syn_window: 65535,
    window: 65535,
    sack_permitted: true,
    timestamps: true,
};

/// Every profile that can be named in configuration.
pub const ALL: &[OsProfile] = &[LINUX_6, WINDOWS_11, ANDROID_14];

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
}
