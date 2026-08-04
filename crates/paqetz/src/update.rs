//! Replacing this binary with the latest published one.
//!
//! The same job `scripts/install.sh` does, from inside the program, for a host
//! that already has it. Both fetch the release, check it against the published
//! digest, and refuse to install anything they cannot verify — an updater that
//! skipped that check would be a remote-code-execution channel with a friendly
//! name.
//!
//! # Replacing a file that is running
//!
//! Writing over the binary being executed fails with `ETXTBSY`, so the new one
//! is renamed into place instead: a rename swaps the directory entry and leaves
//! the running process on the file it already opened. That is also what makes
//! it safe — the old binary keeps working until the moment the new one is
//! complete, and a failure part way through leaves the original untouched.
//!
//! The rename has to be on the destination's own filesystem, so the download is
//! copied next to the binary before being moved over it. `/tmp` is frequently a
//! separate filesystem, where a rename would silently become a copy and hit
//! `ETXTBSY` after all.

use std::path::{Path, PathBuf};

use crate::service;

/// Where releases are published.
const REPO: &str = "gitpoemer/paqetz";

/// The target triple this binary was built for, recorded by `build.rs`.
const TARGET: &str = env!("PAQETZ_TARGET");

/// What this binary reports as its own version.
fn running_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// The tag of the most recent release.
///
/// Read from the redirect `releases/latest` performs rather than from the API,
/// which is rate-limited per address and would fail on a busy host for reasons
/// nobody could see.
fn latest_tag() -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://github.com/{REPO}/releases/latest");
    let headers = capture("curl", &["-fsSI", "--max-time", "20", &url])?;
    headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .and_then(|l| l.rsplit('/').next())
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "could not read the latest version from GitHub".into())
}

/// Runs a command, returning its standard output.
fn capture(program: &str, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new(program).args(args).output()?;
    if !out.status.success() {
        return Err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The digest recorded for `name` in a `SHA256SUMS` body.
fn digest_for(sums: &str, name: &str) -> Option<String> {
    sums.lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .find(|(_, f)| f.trim().trim_start_matches('*') == name)
        .map(|(d, _)| d.trim().to_owned())
}

/// `paqetz update`.
///
/// # Errors
/// Returns an error if the release cannot be fetched, its digest cannot be
/// fetched or does not match, or the binary cannot be replaced.
pub(crate) fn run(assume_yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let running = running_version();
    println!("Running {running} ({TARGET})");

    let latest = latest_tag()?;
    if latest == running {
        println!("Already the latest release. Nothing to do.");
        return Ok(());
    }
    println!("Latest is  {latest}");

    if !assume_yes && !confirm(&format!("Replace {running} with {latest}?")) {
        println!("Left alone.");
        return Ok(());
    }

    let target = std::env::current_exe()?;
    let name = format!("paqetz-{TARGET}");
    let base = format!("https://github.com/{REPO}/releases/download/{latest}");

    let tmp = std::env::temp_dir().join(format!("paqetz-update-{}", std::process::id()));
    let _guard = Cleanup(tmp.clone());
    std::fs::create_dir_all(&tmp)?;
    let downloaded = tmp.join(&name);

    println!("==> downloading {name}");
    capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "300",
            "-o",
            &downloaded.display().to_string(),
            &format!("{base}/{name}"),
        ],
    )?;

    // Not optional, and not a warning. A release whose digest cannot be fetched
    // is a release that cannot be checked, and installing it anyway would make
    // this command the easiest way into every host that runs it.
    println!("==> verifying");
    let sums = capture(
        "curl",
        &["-fsSL", "--max-time", "60", &format!("{base}/SHA256SUMS")],
    )
    .map_err(|e| format!("could not fetch SHA256SUMS ({e}); refusing to install"))?;
    let expected = digest_for(&sums, &name)
        .ok_or_else(|| format!("SHA256SUMS carries no entry for {name}; refusing to install"))?;
    let actual = capture("sha256sum", &[&downloaded.display().to_string()])?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if actual != expected {
        return Err(
            format!("checksum mismatch\n  expected {expected}\n  got      {actual}").into(),
        );
    }
    println!("    ok  {actual}");

    replace(&downloaded, &target)?;
    println!("==> replaced {} with {latest}", target.display());

    restart(assume_yes);
    Ok(())
}

/// Moves the downloaded binary over the running one.
fn replace(downloaded: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let dir = target.parent().unwrap_or(Path::new("."));
    // Beside the destination, so the move that follows is a rename on one
    // filesystem rather than a copy that would fail on a running binary.
    let staged = dir.join(".paqetz.new");

    service::run_elevated(
        "cp",
        &[
            &downloaded.display().to_string(),
            &staged.display().to_string(),
        ],
    )?;
    service::run_elevated("chmod", &["755", &staged.display().to_string()])?;
    service::run_elevated(
        "mv",
        &[&staged.display().to_string(), &target.display().to_string()],
    )?;
    Ok(())
}

/// Offers to restart the service, since a replaced file is not a replaced
/// process.
fn restart(assume_yes: bool) {
    if !service::has_systemd() || !service::unit_exists("paqetz") {
        println!("\nNo service installed, so nothing is running the old binary.");
        return;
    }
    // Said either way. The most common way to be confused by an update is to
    // check `--version`, see the new one, and be looking at a tunnel still
    // carried by the old process.
    println!("\nThe running service is still the old binary.");
    if !assume_yes && !confirm("Restart it now?") {
        println!("Left running. `paqetz restart` when you are ready.");
        return;
    }
    match service::run_elevated("systemctl", &["restart", "paqetz"]) {
        Ok(()) => println!("Restarted."),
        Err(e) => println!("Could not restart it: {e}\nRun `paqetz restart` yourself."),
    }
}

/// Asks a yes-or-no question, defaulting to no.
fn confirm(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};
    print!("{prompt} [y/N] > ");
    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Removes the download directory however this returns.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_recorded_at_build_time() {
        // Guessing it at run time cannot distinguish the musl build from the
        // glibc one, and swapping either for the other produces a binary that
        // will not start or has quietly lost the property it was chosen for.
        assert!(TARGET.contains('-'), "not a target triple: {TARGET}");
        assert_ne!(TARGET, "unknown");
    }

    #[test]
    fn the_running_version_matches_the_tag_format() {
        // Compared directly against the tag, so a mismatch in shape would make
        // every release look like an update, for ever.
        let v = running_version();
        assert!(v.starts_with('v'), "{v}");
        assert!(v[1..].split('.').count() >= 2, "{v}");
    }

    #[test]
    fn a_digest_is_found_by_exact_file_name() {
        let sums = "aaa  paqetz-x86_64-unknown-linux-musl\n\
                    bbb  paqetz-x86_64-unknown-linux-gnu\n\
                    ccc *paqetz-aarch64-unknown-linux-musl\n";
        assert_eq!(
            digest_for(sums, "paqetz-x86_64-unknown-linux-musl").as_deref(),
            Some("aaa")
        );
        assert_eq!(
            digest_for(sums, "paqetz-x86_64-unknown-linux-gnu").as_deref(),
            Some("bbb"),
            "the gnu build must not match the musl line by prefix"
        );
        assert_eq!(
            digest_for(sums, "paqetz-aarch64-unknown-linux-musl").as_deref(),
            Some("ccc"),
            "sha256sum marks binary mode with a star"
        );
    }

    #[test]
    fn a_name_that_is_not_listed_has_no_digest() {
        // Which aborts the update rather than installing something unchecked.
        let sums = "aaa  paqetz-x86_64-unknown-linux-musl\n";
        assert_eq!(digest_for(sums, "paqetz-riscv64gc-unknown-linux-gnu"), None);
        assert_eq!(digest_for("", "paqetz-x86_64-unknown-linux-musl"), None);
    }

    #[test]
    fn the_staged_file_sits_beside_the_binary_it_replaces() {
        // On the destination's own filesystem, so the move is a rename. A copy
        // would fail on a binary that is executing.
        let target = Path::new("/usr/local/bin/paqetz");
        let staged = target.parent().expect("parent").join(".paqetz.new");
        assert_eq!(staged, Path::new("/usr/local/bin/.paqetz.new"));
        assert_eq!(staged.parent(), target.parent());
    }
}
