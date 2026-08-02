//! Kernel settings that matter for a host carrying a tunnel.
//!
//! Every value here has a reason attached, because a list of `sysctl` lines
//! copied from somewhere is how hosts acquire settings nobody can justify. The
//! plan is printed before anything is written, and the file it writes is a
//! single drop-in that can be deleted to undo the lot.

use std::io;

/// Where the settings are written.
pub const PATH: &str = "/etc/sysctl.d/99-paqetz.conf";

/// Which hosts a setting is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    /// Any host carrying a tunnel. These are about the capture and transmit
    /// sockets, which both ends have.
    Anywhere,
    /// Only a host that forwards and translates for its peer.
    ///
    /// Connection tracking, source ports and the timers around closing sockets
    /// are all consequences of doing NAT for someone else. A client does none of
    /// it, so on a client these tune nothing -- and a list of settings that do
    /// nothing is how a host ends up with settings nobody can justify.
    Gateway,
}

/// One setting, and why it is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// The `sysctl` key.
    pub key: &'static str,
    /// The value to set.
    pub value: &'static str,
    /// Why, in one line.
    pub reason: &'static str,
    /// Which hosts it is for.
    pub applies: Applies,
}

/// The settings, in the order they are written.
///
/// Deliberately short. Each one addresses something this program actually does;
/// anything that would merely be generally nice is left out, because a setting
/// nobody can explain is a setting nobody can safely change later.
pub const SETTINGS: &[Setting] = &[
    Setting {
        key: "net.core.rmem_max",
        value: "16777216",
        reason: "the capture socket buffers bursts here; too small and the kernel drops \
                 frames before we read them",
        applies: Applies::Anywhere,
    },
    Setting {
        key: "net.core.wmem_max",
        value: "16777216",
        reason: "the transmit socket queues here when the link is busier than \
                 the sender; too small and sends fail with a full queue",
        applies: Applies::Anywhere,
    },
    Setting {
        key: "net.core.netdev_max_backlog",
        value: "16384",
        reason: "how many frames the kernel queues before the capture socket reads them",
        applies: Applies::Anywhere,
    },
    Setting {
        key: "net.core.default_qdisc",
        value: "fq",
        reason: "fair queueing, which BBR requires to pace correctly",
        applies: Applies::Anywhere,
    },
    Setting {
        key: "net.ipv4.tcp_congestion_control",
        value: "bbr",
        reason: "for whichever host originates the tunnelled connections -- which is \
                 the client when a proxy sits in front, since a gateway forwards them \
                 rather than terminating them; BBR handles a loss-prone path far \
                 better than cubic",
        applies: Applies::Anywhere,
    },
    Setting {
        key: "net.ipv4.tcp_fin_timeout",
        value: "15",
        reason: "a gateway opens many short-lived outbound connections; the default \
                 keeps their state around four times longer than it is useful",
        applies: Applies::Gateway,
    },
    Setting {
        key: "net.ipv4.tcp_tw_reuse",
        value: "1",
        reason: "lets outbound connections reuse recently-closed local ports, which a \
                 gateway exhausts quickly without it",
        applies: Applies::Gateway,
    },
    Setting {
        key: "net.ipv4.ip_local_port_range",
        value: "10000 65535",
        reason: "more source ports for translated connections; the default range runs \
                 out under a few thousand concurrent flows",
        applies: Applies::Gateway,
    },
    Setting {
        key: "net.netfilter.nf_conntrack_max",
        value: "262144",
        reason: "translation keeps one connection-tracking entry per flow, and the \
                 default is sized for a workstation",
        applies: Applies::Gateway,
    },
];

/// Whether a setting is for this host.
#[must_use]
pub const fn wanted(s: &Setting, gateway: bool) -> bool {
    match s.applies {
        Applies::Anywhere => true,
        Applies::Gateway => gateway,
    }
}

/// Renders the drop-in file.
#[must_use]
pub fn file_contents(gateway: bool) -> String {
    let mut out = String::from(
        "# Written by `paqetz tune`. Delete this file and reboot to undo.\n\
         #\n\
         # Every setting here is explained; if one does not apply to this host,\n\
         # removing it is safe.\n\n",
    );
    for s in SETTINGS.iter().filter(|s| wanted(s, gateway)) {
        out.push_str(&format!("# {}\n{} = {}\n\n", s.reason, s.key, s.value));
    }
    out
}

/// Reads a setting's current value, if the key exists on this kernel.
#[must_use]
pub fn current(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(path)
        .ok()
        .map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Which settings would actually change on this host.
#[must_use]
pub fn pending(gateway: bool) -> Vec<(&'static Setting, Option<String>)> {
    SETTINGS
        .iter()
        .filter(|s| wanted(s, gateway))
        .filter_map(|s| {
            let now = current(s.key);
            match now.as_deref() {
                // A key the kernel does not have is skipped rather than
                // reported as a change that never happens.
                None => None,
                Some(v) if v == s.value => None,
                Some(_) => Some((s, now)),
            }
        })
        .collect()
}

/// Writes the drop-in and asks the kernel to load it.
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn apply(gateway: bool) -> io::Result<()> {
    std::fs::write(PATH, file_contents(gateway))?;
    let output = std::process::Command::new("sysctl")
        .arg("--system")
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "sysctl --system failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_client_is_not_offered_the_settings_a_gateway_needs() {
        // Connection tracking, source-port range and the close timers are all
        // consequences of translating for someone else. A client translates
        // nothing, so on a client these tune nothing at all -- and settings that
        // do nothing are how a host ends up carrying values nobody can justify.
        let client = file_contents(false);
        let server = file_contents(true);

        for key in [
            "net.netfilter.nf_conntrack_max",
            "net.ipv4.ip_local_port_range",
            "net.ipv4.tcp_tw_reuse",
            "net.ipv4.tcp_fin_timeout",
        ] {
            assert!(!client.contains(key), "{key} is not a client's business");
            assert!(server.contains(key), "{key} belongs on a gateway");
        }
    }

    #[test]
    fn both_ends_get_what_the_capture_socket_needs() {
        // These are about the sockets this program itself opens, which both ends
        // open identically.
        for key in [
            "net.core.rmem_max",
            "net.core.wmem_max",
            "net.core.netdev_max_backlog",
        ] {
            assert!(file_contents(false).contains(key), "{key} on a client");
            assert!(file_contents(true).contains(key), "{key} on a gateway");
        }
    }

    #[test]
    fn congestion_control_is_offered_to_both() {
        // It governs whichever host originates the tunnelled connections. With a
        // proxy in front that is the client: a gateway forwards them rather than
        // terminating them, so its own choice barely applies to them.
        for gateway in [false, true] {
            assert!(file_contents(gateway).contains("net.ipv4.tcp_congestion_control"));
            assert!(file_contents(gateway).contains("net.core.default_qdisc"));
        }
    }

    #[test]
    fn a_client_is_offered_strictly_fewer_settings() {
        // About the classification, not about this host: `pending` reads the
        // running kernel and would make the answer depend on where it ran.
        let client = SETTINGS.iter().filter(|s| wanted(s, false)).count();
        let gateway = SETTINGS.iter().filter(|s| wanted(s, true)).count();
        assert!(client < gateway, "client {client}, gateway {gateway}");
        assert_eq!(gateway, SETTINGS.len(), "a gateway wants all of them");
    }

    use super::*;

    #[test]
    fn every_setting_explains_itself() {
        for s in SETTINGS {
            assert!(!s.reason.is_empty(), "{} has no reason", s.key);
            assert!(
                s.reason.len() > 30,
                "{} needs a real explanation, not a label",
                s.key
            );
        }
    }

    #[test]
    fn keys_are_unique() {
        for (i, a) in SETTINGS.iter().enumerate() {
            for b in SETTINGS.iter().skip(i + 1) {
                assert_ne!(a.key, b.key, "{} appears twice", a.key);
            }
        }
    }

    #[test]
    fn the_file_carries_every_setting_and_its_reason() {
        let text = file_contents(true);
        for s in SETTINGS {
            assert!(text.contains(s.key), "{} missing", s.key);
            assert!(text.contains(s.value), "{} value missing", s.key);
            // The reason is wrapped across lines in the source, so check a
            // distinctive fragment rather than the whole string.
            let fragment = s
                .reason
                .split_whitespace()
                .take(4)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains(&fragment), "{} reason missing", s.key);
        }
    }

    #[test]
    fn the_file_says_how_to_undo_it() {
        assert!(file_contents(true).contains("Delete this file"));
    }

    #[test]
    fn reading_the_hosts_current_values_does_not_fail() {
        // Read-only. A key this kernel lacks yields None rather than an error.
        assert_eq!(current("net.ipv4.definitely_not_a_real_key"), None);
        assert!(current("net.ipv4.ip_forward").is_some());
    }

    #[test]
    fn settings_already_correct_are_not_listed_as_pending() {
        // Whatever this host has, `pending` must never include a key whose
        // current value already matches, or `tune` would claim work it is not
        // doing.
        for (setting, now) in pending(true) {
            assert_ne!(now.as_deref(), Some(setting.value), "{}", setting.key);
        }
    }
}
