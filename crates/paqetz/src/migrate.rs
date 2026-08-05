//! Converting a single-tunnel configuration to the form that can hold several.
//!
//! The two forms are the same file at different depths: `[interface]` becomes
//! `[tunnel.interface]`, `[peer]` becomes `[tunnel.peer]`, every key unchanged.
//! So this rewrites section headers and moves the three process-level settings
//! to the top, rather than re-rendering the file from a parsed configuration.
//!
//! That choice is the whole design. A renderer has to know every field, and the
//! day one is added and the renderer is not told, migration quietly drops it —
//! from a file holding a private key and the routing a host depends on. A
//! textual transform cannot drop what it does not understand, and it keeps the
//! comments, which a renderer would also have thrown away.
//!
//! Nothing is written unless the result parses to the same configuration as the
//! original. That check is what makes this safe to run on a host reached
//! through the tunnel it is rewriting.

use std::path::Path;

/// The process-level settings, which move from `[interface]` to the top.
const PROCESS_KEYS: &[&str] = &["log", "health_interval", "manage_firewall"];

/// What a file needs, if anything.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Needed {
    /// Already in the new form.
    Nothing,
    /// The converted text.
    Rewrite(String),
}

/// Converts the original form to the new one.
///
/// # Errors
/// Returns an error if the text does not parse, or if the conversion would not
/// parse to the same configuration.
pub(crate) fn convert(text: &str) -> Result<Needed, Box<dyn std::error::Error>> {
    if has_tunnel_section(text) {
        return Ok(Needed::Nothing);
    }

    let before = crate::config::Config::parse(text)?;
    let converted = rewrite(text);
    let after = crate::config::Config::parse(&converted).map_err(|e| {
        format!("the converted file does not parse ({e}); the original is unchanged")
    })?;

    // Compared as parsed rather than as text, so the check is about meaning.
    // `PrivateKey` redacts itself in `Debug`, so the keys are compared as they
    // appear in the file instead -- a rewrite that lost one would otherwise
    // pass, and losing one is the worst outcome available here.
    if format!("{before:?}") != format!("{after:?}") {
        return Err("the converted file would mean something different; refusing".into());
    }
    for line in secrets(text) {
        if !converted.contains(&line) {
            return Err(format!("the conversion dropped `{line}`; refusing").into());
        }
    }
    Ok(Needed::Rewrite(converted))
}

/// Whether the file already uses `[[tunnel]]`.
fn has_tunnel_section(text: &str) -> bool {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .any(|l| l == "[[tunnel]]")
}

/// The key-carrying lines, which must survive verbatim.
fn secrets(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("private_key") || l.starts_with("public_key"))
        .map(str::to_owned)
        .collect()
}

/// Rewrites the headers and hoists the process settings.
fn rewrite(text: &str) -> String {
    let name = value_of(text, "device").unwrap_or_else(|| "paqetz0".to_owned());

    let mut process = Vec::new();
    for key in PROCESS_KEYS {
        if let Some(line) = whole_line(text, key) {
            process.push(line);
        }
    }

    let mut out = String::new();
    if !process.is_empty() {
        out.push_str("# Settings for the process rather than for any one tunnel.\n");
        for line in &process {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }

    let mut started = false;
    for line in text.lines() {
        let bare = line.split('#').next().unwrap_or("").trim();
        match bare {
            "[interface]" => {
                if !started {
                    out.push_str("[[tunnel]]\n");
                    out.push_str(&format!("name = {name:?}\n\n"));
                    started = true;
                }
                out.push_str("[tunnel.interface]\n");
            }
            "[peer]" => out.push_str("[tunnel.peer]\n"),
            "[socks5]" => out.push_str("[tunnel.socks5]\n"),
            _ => {
                // The hoisted settings are not left behind as well.
                if PROCESS_KEYS.iter().any(|k| is_assignment(bare, k)) {
                    continue;
                }
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Whether a line assigns `key`.
fn is_assignment(line: &str, key: &str) -> bool {
    line.split_once('=').is_some_and(|(k, _)| k.trim() == key)
}

/// The whole line assigning `key`, trimmed.
fn whole_line(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| is_assignment(l.split('#').next().unwrap_or(""), key))
        .map(str::to_owned)
}

/// The string value assigned to `key`.
fn value_of(text: &str, key: &str) -> Option<String> {
    whole_line(text, key)?
        .split_once('=')
        .map(|(_, v)| v.trim().trim_matches('"').to_owned())
        .filter(|v| !v.is_empty())
}

/// `paqetz config migrate`.
///
/// # Errors
/// Returns an error if the file cannot be read, converted, or written.
pub(crate) fn run(path: &Path, assume_yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    match convert(&text)? {
        Needed::Nothing => {
            println!("{} already uses [[tunnel]]. Nothing to do.", path.display());
            Ok(())
        }
        Needed::Rewrite(converted) => {
            println!("{} would become:\n", path.display());
            println!("{converted}");
            println!(
                "It parses to the same configuration, and every key line is \
                 accounted for."
            );
            if !assume_yes && !crate::confirm("Write it?") {
                println!("Left alone.");
                return Ok(());
            }

            let backup = path.with_extension("toml.bak");
            // Direct first, elevating only if the kernel refuses -- the same
            // rule the rest of this program follows, so converting a file in
            // your own directory does not ask for a password it does not need.
            if let Err(e) = std::fs::copy(path, &backup)
                && e.kind() == std::io::ErrorKind::PermissionDenied
            {
                crate::service::run_elevated(
                    "cp",
                    &[
                        "-p",
                        &path.display().to_string(),
                        &backup.display().to_string(),
                    ],
                )?;
            }
            // The file holds a private key, so the copy keeps its mode and the
            // rewrite goes back at 0600 rather than whatever the umask says.
            crate::service::write_file(path, &converted, 0o600)?;
            println!("Written. The original is at {}.", backup.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = r#"# A comment worth keeping.

[interface]
manage_firewall = false
health_interval = 30
private_key = "QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="
address = "10.7.0.2/24"
device = "paqetz9"
route_marked = 81

[peer]
# And this one.
public_key = "Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="
endpoint = "203.0.113.5:8443"
tunnel_address = "10.7.0.1"
"#;

    #[test]
    fn the_converted_file_means_the_same_thing() {
        // The check that makes this safe to run unattended: convert refuses
        // unless the result parses to what the original did.
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        let a = crate::config::Config::parse(OLD).expect("old");
        let b = crate::config::Config::parse(&new).expect("new");
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn the_sections_move_one_level_down() {
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        assert!(new.contains("[[tunnel]]"));
        assert!(new.contains("[tunnel.interface]"));
        assert!(new.contains("[tunnel.peer]"));
        assert!(!new.contains("\n[interface]"), "{new}");
        assert!(!new.contains("\n[peer]"), "{new}");
    }

    #[test]
    fn the_tunnel_is_named_for_its_device() {
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        assert!(new.contains(r#"name = "paqetz9""#), "{new}");
    }

    #[test]
    fn the_process_settings_move_to_the_top() {
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        let top = new.split("[[tunnel]]").next().expect("preamble");
        assert!(top.contains("manage_firewall = false"), "{new}");
        assert!(top.contains("health_interval = 30"), "{new}");
        // ...and are not left behind in the tunnel as well, where they would be
        // an unknown field and stop the file parsing.
        assert_eq!(new.matches("manage_firewall").count(), 1, "{new}");
    }

    #[test]
    fn comments_survive() {
        // A renderer would have thrown these away, which is most of the reason
        // this is a textual transform.
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        assert!(new.contains("# A comment worth keeping."), "{new}");
        assert!(new.contains("# And this one."), "{new}");
    }

    #[test]
    fn a_file_already_converted_is_left_alone() {
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        assert_eq!(convert(&new).expect("idempotent"), Needed::Nothing);
    }

    #[test]
    fn a_file_that_does_not_parse_is_refused_before_anything_is_written() {
        assert!(convert("[interface]\nprivate_key = \"nonsense\"\n").is_err());
    }

    #[test]
    fn keys_are_carried_across_verbatim() {
        // `PrivateKey` redacts itself in `Debug`, so comparing parsed
        // configurations would not notice a key that changed. These are checked
        // as they appear in the file.
        let Needed::Rewrite(new) = convert(OLD).expect("convert") else {
            panic!("should have rewritten");
        };
        assert!(new.contains("QEmpXFn5nJPQxCXi7ZKKlpJVCTMWEQKRJ1DzDDN2P2Y="));
        assert!(new.contains("Nk1lHhVE3SPuLvZ3XDvJZkH8xkCPMlTPvGZ0S2qXeXo="));
    }
}
