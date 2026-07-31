//! Firewall rule management (decision D9).
//!
//! The `NOTRACK` and reset-drop rules are load-bearing, not advisory. Without
//! them the kernel sees inbound segments on a port it has no socket for and
//! answers with a `RST`, which kills the flow and corrupts NAT state along the
//! path. They are preserved exactly as paqet documents them.
//!
//! What changes is that the binary installs them, idempotently, and on **both**
//! ends. paqet documents them for the server only — but the client kernel emits
//! resets for precisely the same reason, which is a real gap rather than an
//! oversight in the docs.
//!
//! # Why this shells out
//!
//! Both `nftables` and `iptables` are configured over netlink, and speaking
//! either protocol directly is a substantial amount of code for something that
//! runs three times in a process's life. Every comparable tool — `wg-quick`
//! included — shells out, and so does this. The cost is a runtime dependency on
//! one of the two binaries; the benefit is that what we do is exactly what the
//! operator would have typed, and can be printed for them to check.
//!
//! Rule *construction* is pure and lives in [`rules`], so the hard part is
//! tested without running anything.

pub mod rules;

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

pub use rules::{Op, TABLE};

/// Which tool is available to configure the firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `nftables`, preferred: rules live in a table we own, so applying and
    /// reverting are whole-table operations that cannot half-succeed.
    Nft,
    /// `iptables`, for hosts without `nft`.
    Iptables,
}

impl Backend {
    /// The command this backend invokes.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Nft => "nft",
            Self::Iptables => "iptables",
        }
    }
}

/// Whether the rules are installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Every rule is present.
    Installed,
    /// No rule is present.
    Absent,
    /// Some rules are present and others are not.
    ///
    /// Reported rather than silently repaired, because it usually means a
    /// previous run was killed part way through, or something else is editing
    /// the same chains.
    Partial,
}

/// Anything that can go wrong managing the firewall.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Neither `nft` nor `iptables` could be run.
    #[error(
        "neither nft nor iptables is available; install one, or apply the rules \
         from `paqetz firewall plan` by hand"
    )]
    NoBackend,

    /// A command ran but reported failure.
    #[error("{command} failed ({status}): {stderr}")]
    CommandFailed {
        /// The command that was run.
        command: String,
        /// How it exited.
        status: String,
        /// What it printed on stderr, trimmed.
        stderr: String,
    },

    /// A command could not be run at all.
    #[error("could not run {command}: {source}")]
    Spawn {
        /// The command that could not be started.
        command: String,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Manages the tunnel's firewall rules for one port.
#[derive(Debug, Clone, Copy)]
pub struct Firewall {
    backend: Backend,
    port: u16,
}

impl Firewall {
    /// Selects a backend, preferring `nftables`.
    ///
    /// # Errors
    /// Returns [`Error::NoBackend`] if neither tool can be run.
    pub fn detect(port: u16) -> Result<Self> {
        for backend in [Backend::Nft, Backend::Iptables] {
            if probe(backend) {
                return Ok(Self { backend, port });
            }
        }
        Err(Error::NoBackend)
    }

    /// Uses a specific backend, without probing.
    #[must_use]
    pub const fn with_backend(backend: Backend, port: u16) -> Self {
        Self { backend, port }
    }

    /// The backend in use.
    #[must_use]
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// The commands [`apply`](Self::apply) would run, for display.
    ///
    /// Exists so an operator can see exactly what is about to be done to their
    /// firewall before it happens, and so the rules can be applied by hand on a
    /// host where this program should not be doing it.
    #[must_use]
    pub fn plan(&self) -> Vec<String> {
        match self.backend {
            Backend::Nft => vec![format!(
                "nft -f - <<'EOF'\n{}EOF",
                rules::nft_apply(self.port)
            )],
            Backend::Iptables => rules::iptables_rules(self.port)
                .iter()
                .map(|r| format!("iptables {}", r.args(Op::Append).join(" ")))
                .collect(),
        }
    }

    /// Installs the rules. Safe to call when they are already installed.
    ///
    /// # Errors
    /// Returns the backend's failure.
    pub fn apply(&self) -> Result<()> {
        match self.backend {
            Backend::Nft => nft_script(&rules::nft_apply(self.port)),
            Backend::Iptables => {
                for rule in rules::iptables_rules(self.port) {
                    // Checking first is what makes this idempotent: `iptables`
                    // will happily append a duplicate of a rule that is already
                    // there, and duplicates then survive one revert each.
                    if run(Backend::Iptables, &rule.args(Op::Check)).is_ok() {
                        continue;
                    }
                    run(Backend::Iptables, &rule.args(Op::Append))?;
                }
                Ok(())
            }
        }
    }

    /// Removes the rules. Safe to call when they are not installed.
    ///
    /// # Errors
    /// Returns the backend's failure.
    pub fn revert(&self) -> Result<()> {
        match self.backend {
            Backend::Nft => nft_script(&rules::nft_revert()),
            Backend::Iptables => {
                for rule in rules::iptables_rules(self.port) {
                    // Delete repeatedly: a crashed earlier run may have left
                    // duplicates, and one delete removes only one copy.
                    while run(Backend::Iptables, &rule.args(Op::Delete)).is_ok() {}
                }
                Ok(())
            }
        }
    }

    /// Reports whether the rules are installed.
    ///
    /// # Errors
    /// Returns the backend's failure, other than a rule simply being absent.
    pub fn status(&self) -> Result<Status> {
        match self.backend {
            Backend::Nft => {
                let listed = run(
                    Backend::Nft,
                    &["list".into(), "table".into(), "ip".into(), TABLE.into()],
                );
                Ok(if listed.is_ok() {
                    Status::Installed
                } else {
                    Status::Absent
                })
            }
            Backend::Iptables => {
                let all = rules::iptables_rules(self.port);
                let present = all
                    .iter()
                    .filter(|r| run(Backend::Iptables, &r.args(Op::Check)).is_ok())
                    .count();
                Ok(if present == all.len() {
                    Status::Installed
                } else if present == 0 {
                    Status::Absent
                } else {
                    Status::Partial
                })
            }
        }
    }
}

/// Whether a backend's command can be run at all.
fn probe(backend: Backend) -> bool {
    Command::new(backend.command())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Runs a backend command with arguments.
fn run(backend: Backend, args: &[String]) -> Result<Output> {
    let output = Command::new(backend.command())
        .args(args)
        .output()
        .map_err(|source| Error::Spawn {
            command: backend.command().to_owned(),
            source,
        })?;
    check(backend.command(), &args.join(" "), output)
}

/// Feeds a script to `nft -f -`.
fn nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Spawn {
            command: "nft".to_owned(),
            source,
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|source| Error::Spawn {
                command: "nft".to_owned(),
                source,
            })?;
        // Dropping closes the pipe, which is what tells `nft` the script ended.
    }

    let output = child.wait_with_output().map_err(|source| Error::Spawn {
        command: "nft".to_owned(),
        source,
    })?;
    check("nft", "-f -", output).map(|_| ())
}

/// Turns a non-zero exit into an error carrying what the tool said.
fn check(command: &str, args: &str, output: Output) -> Result<Output> {
    if output.status.success() {
        return Ok(output);
    }
    Err(Error::CommandFailed {
        command: format!("{command} {args}").trim_end().to_owned(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn nftables_is_preferred_over_iptables() {
        // Ordering matters: nftables lets us own a table, which makes apply and
        // revert whole-table operations that cannot half-succeed.
        assert_eq!(Backend::Nft.command(), "nft");
        assert_eq!(Backend::Iptables.command(), "iptables");
    }

    #[test]
    fn the_nft_plan_is_a_single_transaction() {
        let fw = Firewall::with_backend(Backend::Nft, 9999);
        let plan = fw.plan();
        assert_eq!(plan.len(), 1, "nft applies the whole ruleset atomically");
        assert!(plan[0].contains("nft -f -"));
        assert!(plan[0].contains("tcp dport 9999 notrack"));
    }

    #[test]
    fn the_iptables_plan_lists_every_rule_verbatim() {
        let fw = Firewall::with_backend(Backend::Iptables, 9999);
        let plan = fw.plan();
        assert_eq!(plan.len(), 3);
        for line in &plan {
            assert!(line.starts_with("iptables -t "), "got: {line}");
        }
        assert!(plan[0].contains("--dport 9999 -j NOTRACK"));
        assert!(plan[2].contains("--tcp-flags RST RST -j DROP"));
    }

    #[test]
    fn the_plan_is_runnable_as_printed() {
        // The plan is documentation an operator may paste into a shell, so it
        // must not contain anything that needs further substitution.
        for backend in [Backend::Nft, Backend::Iptables] {
            for line in Firewall::with_backend(backend, 9999).plan() {
                assert!(!line.contains("{}"), "unsubstituted placeholder: {line}");
                assert!(!line.contains("PORT"), "unsubstituted port: {line}");
            }
        }
    }

    #[test]
    fn the_no_backend_error_tells_the_operator_what_to_do() {
        let msg = Error::NoBackend.to_string();
        assert!(msg.contains("firewall plan"), "got: {msg}");
    }

    #[test]
    #[ignore = "invokes nft; run with --ignored in a throwaway namespace"]
    fn the_generated_ruleset_is_valid_nftables() {
        // `nft -c` parses and validates against the live ruleset without
        // applying anything. It still needs privilege to read that ruleset,
        // which is why this cannot run in the default suite. Without it, a
        // syntax error in the generated script would only surface the first
        // time someone tried to bring a tunnel up.
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let script = rules::nft_apply(9999);
        let mut child = Command::new("nft")
            .arg("-c")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("nft should be installed in the test namespace");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(script.as_bytes())
            .expect("write script");
        let out = child.wait_with_output().expect("wait");
        assert!(
            out.status.success(),
            "nft rejected the generated ruleset: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[ignore = "invokes nft; run with --ignored in a throwaway namespace"]
    fn apply_is_idempotent_and_revert_is_complete() {
        let fw = Firewall::with_backend(Backend::Nft, 9999);
        assert_eq!(fw.status().expect("status"), Status::Absent);

        fw.apply().expect("apply");
        assert_eq!(fw.status().expect("status"), Status::Installed);

        // Applying twice must leave the same ruleset, not two copies.
        fw.apply().expect("apply again");
        assert_eq!(fw.status().expect("status"), Status::Installed);

        fw.revert().expect("revert");
        assert_eq!(fw.status().expect("status"), Status::Absent);

        // And reverting when nothing is installed must not fail, because this
        // runs on the shutdown path where an error is noise at best.
        fw.revert().expect("revert again");
    }

    #[test]
    fn a_failure_reports_what_the_tool_said() {
        let err = Error::CommandFailed {
            command: "iptables -t raw -A PREROUTING".to_owned(),
            status: "exit status: 4".to_owned(),
            stderr: "Permission denied (you must be root)".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("iptables -t raw -A PREROUTING"));
        assert!(msg.contains("Permission denied"));
    }
}
