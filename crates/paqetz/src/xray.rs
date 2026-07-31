//! Generating an Xray REALITY inbound that points at the tunnel.
//!
//! The arrangement this serves: users connect to Xray on the client host, and
//! Xray forwards what it receives through the tunnel. Xray is the inbound,
//! paqetz is the transport.
//!
//! # What this does
//!
//! Generates the configuration and credentials, and — asked for explicitly —
//! downloads and installs Xray itself.
//!
//! Installing was initially left out on the grounds that a tunnel which also
//! installs proxies has two jobs. That compared against the wrong alternative.
//! Nobody carefully installs it by hand; they pipe a script from the internet
//! into a root shell. Doing it here is only worth it if it is done *better*,
//! which means verification that fails closed — see [`install`].
//!
//! The credentials need no Xray present, because REALITY's keys are X25519, the
//! same primitive this program already uses.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use paqetz_core::KeyPair;

/// Where Xray sends what it receives.
#[derive(Debug, Clone)]
pub(crate) enum Upstream {
    /// Through the SOCKS5 listener. Names resolve at the far end.
    Socks5(String),
    /// Directly, with a firewall mark that a policy route steers into the
    /// tunnel. Names resolve on this host, so Xray needs DNS through the
    /// tunnel.
    Marked(u32),
}

/// What the generated configuration is built from.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// The port users connect to.
    pub(crate) listen_port: u16,
    /// The real site REALITY borrows a certificate from, and impersonates.
    pub(crate) dest: String,
    /// Where Xray forwards to.
    pub(crate) upstream: Upstream,
    /// The address to put in the client's URI.
    pub(crate) public_address: String,
}

/// The generated credentials and the two artefacts they appear in.
#[derive(Debug, Clone)]
pub(crate) struct Generated {
    /// The server-side configuration.
    pub(crate) config: String,
    /// The URI a client imports.
    pub(crate) uri: String,
    /// REALITY's public key, which the client needs.
    pub(crate) public_key: String,
}

/// Generates the inbound configuration and the matching client URI.
///
/// # Errors
/// Returns an error if key generation fails.
pub(crate) fn generate(plan: &Plan) -> Result<Generated, Box<dyn std::error::Error>> {
    let keys = KeyPair::generate()?;
    // REALITY encodes its keys base64url without padding, where paqetz uses
    // standard base64. Same 32 bytes either way.
    let private_key = B64URL.encode(keys.private.as_bytes());
    let public_key = B64URL.encode(keys.public.as_bytes());
    let uuid = uuid_v4()?;
    let short_id = short_id()?;

    let outbound = match &plan.upstream {
        Upstream::Socks5(addr) => {
            let (host, port) = addr
                .rsplit_once(':')
                .ok_or_else(|| format!("expected host:port, got {addr:?}"))?;
            format!(
                r#"    {{
      "tag": "tunnel",
      "protocol": "socks",
      "settings": {{
        "servers": [{{ "address": "{host}", "port": {port} }}]
      }}
    }}"#
            )
        }
        Upstream::Marked(mark) => format!(
            r#"    {{
      "tag": "tunnel",
      "protocol": "freedom",
      "streamSettings": {{
        "sockopt": {{ "mark": {mark} }}
      }}
    }}"#
        ),
    };

    // With SOCKS5, paqetz resolves the name at the far end, so Xray must pass
    // it through untouched. With a marked socket Xray resolves it here, which
    // is why that path needs DNS reached through the tunnel.
    let domain_strategy = match plan.upstream {
        Upstream::Socks5(_) => "AsIs",
        Upstream::Marked(_) => "AsIs",
    };

    let dest = &plan.dest;
    let listen_port = plan.listen_port;
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "reality",
      "listen": "0.0.0.0",
      "port": {listen_port},
      "protocol": "vless",
      "settings": {{
        "clients": [
          {{ "id": "{uuid}", "flow": "xtls-rprx-vision" }}
        ],
        "decryption": "none"
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "show": false,
          "dest": "{dest}:443",
          "xver": 0,
          "serverNames": ["{dest}"],
          "privateKey": "{private_key}",
          "shortIds": ["{short_id}"]
        }}
      }},
      "sniffing": {{
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }}
    }}
  ],
  "outbounds": [
{outbound},
    {{ "tag": "block", "protocol": "blackhole" }}
  ],
  "routing": {{
    "domainStrategy": "{domain_strategy}",
    "rules": [
      {{
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }}
    ]
  }}
}}
"#
    );

    let label = urlencode("paqetz");
    let uri = format!(
        "vless://{uuid}@{}:{listen_port}\
         ?security=reality&encryption=none&pbk={public_key}&sni={dest}\
         &sid={short_id}&type=tcp&flow=xtls-rprx-vision&fp=chrome#{label}",
        plan.public_address
    );

    Ok(Generated {
        config,
        uri,
        public_key,
    })
}

/// A random version-4 UUID.
fn uuid_v4() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    random(&mut b)?;
    // Version 4, variant 1, as the format requires.
    if let Some(v) = b.get_mut(6) {
        *v = (*v & 0x0F) | 0x40;
    }
    if let Some(v) = b.get_mut(8) {
        *v = (*v & 0x3F) | 0x80;
    }
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        write!(out, "{byte:02x}").map_err(std::io::Error::other)?;
    }
    Ok(out)
}

/// A random REALITY short ID: eight hexadecimal characters.
fn short_id() -> std::io::Result<String> {
    let mut b = [0u8; 4];
    random(&mut b)?;
    let mut out = String::with_capacity(8);
    for byte in b {
        write!(out, "{byte:02x}").map_err(std::io::Error::other)?;
    }
    Ok(out)
}

/// Fills a buffer from the kernel's generator.
fn random(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

/// Percent-encodes the few characters a URI fragment must not carry.
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

/// The sites REALITY borrows from most credibly.
///
/// The requirement is a real host that speaks TLS 1.3 with HTTP/2, is served
/// from a large network so its address is unremarkable, and is not itself
/// blocked where this runs — that last one being why the choice is offered
/// rather than fixed.
pub(crate) const SUGGESTED_DESTINATIONS: &[&str] = &[
    "www.microsoft.com",
    "www.cloudflare.com",
    "www.apple.com",
    "dl.google.com",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            listen_port: 443,
            dest: "www.microsoft.com".to_owned(),
            upstream: Upstream::Socks5("127.0.0.1:1080".to_owned()),
            public_address: "203.0.113.5".to_owned(),
        }
    }

    /// Checks a document is well-formed JSON: balanced structure, with quotes
    /// and escapes handled, so a stray brace inside a string is not miscounted.
    fn well_formed_json(text: &str) -> Result<(), String> {
        let mut depth = 0i32;
        let mut stack = Vec::new();
        let mut in_string = false;
        let mut escaped = false;
        for (i, c) in text.chars().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            match c {
                '"' => in_string = true,
                '{' | '[' => {
                    stack.push(c);
                    depth += 1;
                }
                '}' | ']' => {
                    let want = if c == '}' { '{' } else { '[' };
                    match stack.pop() {
                        Some(open) if open == want => depth -= 1,
                        other => {
                            return Err(format!("at {i}: {c} closes {other:?}"));
                        }
                    }
                }
                _ => {}
            }
        }
        if in_string {
            return Err("unterminated string".to_owned());
        }
        if depth != 0 {
            return Err(format!("{depth} unclosed"));
        }
        Ok(())
    }

    #[test]
    fn the_generated_configuration_is_well_formed_json() {
        // A configuration Xray cannot read is worse than none, because the
        // failure appears at start-up on another host.
        for upstream in [
            Upstream::Socks5("127.0.0.1:1080".to_owned()),
            Upstream::Marked(81),
        ] {
            let g = generate(&Plan { upstream, ..plan() }).expect("generate");
            well_formed_json(&g.config).unwrap_or_else(|e| panic!("malformed: {e}\n{}", g.config));
        }
    }

    #[test]
    fn the_json_check_rejects_what_it_should() {
        assert!(well_formed_json(r#"{"a": [1, 2]}"#).is_ok());
        assert!(
            well_formed_json(r#"{"a": "}"}"#).is_ok(),
            "braces in strings"
        );
        assert!(well_formed_json(r#"{"a": "\""}"#).is_ok(), "escaped quotes");
        assert!(well_formed_json("{").is_err());
        assert!(well_formed_json("{]").is_err());
        assert!(well_formed_json(r#"{"a"#).is_err());
    }

    #[test]
    fn the_uri_carries_what_a_client_needs() {
        let g = generate(&plan()).expect("generate");
        for part in [
            "vless://",
            "security=reality",
            "flow=xtls-rprx-vision",
            "sni=www.microsoft.com",
            "203.0.113.5:443",
        ] {
            assert!(g.uri.contains(part), "{part} missing from {}", g.uri);
        }
        assert!(g.uri.contains(&format!("pbk={}", g.public_key)));
    }

    #[test]
    fn the_private_key_is_in_the_config_and_never_in_the_uri() {
        // The URI is shared with users; the private key must not travel in it.
        let g = generate(&plan()).expect("generate");
        let private = g
            .config
            .lines()
            .find(|l| l.contains("privateKey"))
            .expect("config has a private key");
        let value = private.split('"').nth(3).expect("value");
        assert!(!value.is_empty());
        assert!(
            !g.uri.contains(value),
            "the private key must not appear in the shared URI"
        );
    }

    #[test]
    fn reality_keys_are_base64url_without_padding() {
        // Xray's own tooling emits them this way; standard base64 is rejected.
        let g = generate(&plan()).expect("generate");
        assert!(!g.public_key.contains('='), "padding: {}", g.public_key);
        assert!(
            !g.public_key.contains('+'),
            "not url-safe: {}",
            g.public_key
        );
        assert!(
            !g.public_key.contains('/'),
            "not url-safe: {}",
            g.public_key
        );
        assert_eq!(
            B64URL.decode(&g.public_key).expect("decodes").len(),
            32,
            "an X25519 key is 32 bytes"
        );
    }

    #[test]
    fn the_socks5_upstream_is_a_socks_outbound() {
        let g = generate(&plan()).expect("generate");
        assert!(g.config.contains("\"protocol\": \"socks\""), "{}", g.config);
        assert!(g.config.contains("\"port\": 1080"), "{}", g.config);
    }

    #[test]
    fn the_marked_upstream_is_a_freedom_outbound_carrying_the_mark() {
        let g = generate(&Plan {
            upstream: Upstream::Marked(81),
            ..plan()
        })
        .expect("generate");
        assert!(
            g.config.contains("\"protocol\": \"freedom\""),
            "{}",
            g.config
        );
        assert!(g.config.contains("\"mark\": 81"), "{}", g.config);
        assert!(!g.config.contains("socks"), "no proxy is involved");
    }

    #[test]
    fn private_addresses_are_refused_by_the_generated_routing() {
        // Otherwise anyone reaching the inbound can address the host's own LAN
        // through it.
        let g = generate(&plan()).expect("generate");
        assert!(g.config.contains("geoip:private"), "{}", g.config);
        assert!(g.config.contains("blackhole"), "{}", g.config);
    }

    #[test]
    fn every_run_produces_fresh_credentials() {
        let a = generate(&plan()).expect("generate");
        let b = generate(&plan()).expect("generate");
        assert_ne!(a.uri, b.uri);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn uuids_have_the_documented_shape() {
        let u = uuid_v4().expect("uuid");
        assert_eq!(u.len(), 36, "{u}");
        assert_eq!(u.matches('-').count(), 4, "{u}");
        assert_eq!(u.chars().nth(14), Some('4'), "version nibble: {u}");
        assert!(
            matches!(u.chars().nth(19), Some('8' | '9' | 'a' | 'b')),
            "variant nibble: {u}"
        );
    }

    #[test]
    fn short_ids_are_eight_hex_characters() {
        let s = short_id().expect("short id");
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "{s}");
    }

    #[test]
    fn labels_are_percent_encoded_for_a_uri_fragment() {
        assert_eq!(urlencode("paqetz"), "paqetz");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a#b"), "a%23b");
    }
}

// ---------------------------------------------------------------------------
// Installing and updating Xray
// ---------------------------------------------------------------------------

/// Where the binary is placed by default.
pub(crate) const DEFAULT_PREFIX: &str = "/usr/local/bin";

/// Why this installs Xray rather than leaving it to a shell script.
///
/// The first instinct was that a tunnel which installs proxies has two jobs.
/// That was the wrong comparison: the alternative is not "the user carefully
/// installs it themselves", it is "the user pipes a script from the internet
/// into a root shell". Doing it here is worth it only if it is done *better*
/// than that, which means one thing above all — verification that fails closed.
///
/// The reference script this replaces verifies the download, but warns and
/// continues when the checksum file is missing. A verification step that can be
/// skipped by an attacker who withholds one file is not a verification step.
/// Here a missing or mismatched digest aborts.
///
/// Everything is done with `curl`, `sha256sum`, and `unzip`, which are on any
/// host that would run this, so it adds no dependency and every command it runs
/// can be read before it runs.
fn arch_name() -> Result<&'static str, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("uname").arg("-m").output()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "x86_64" | "amd64" => Ok("64"),
        "aarch64" | "arm64" => Ok("arm64-v8a"),
        "armv7l" => Ok("arm32-v7a"),
        other => Err(format!("no Xray build published for this architecture ({other})").into()),
    }
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

/// The latest published version tag.
fn latest_version() -> Result<String, Box<dyn std::error::Error>> {
    let body = capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "20",
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
        ],
    )?;
    body.split('"')
        .skip_while(|s| *s != "tag_name")
        .nth(2)
        .map(str::to_owned)
        .ok_or_else(|| "could not read the latest version from GitHub".into())
}

/// The version already installed, if any.
#[must_use]
pub(crate) fn installed_version(prefix: &str) -> Option<String> {
    let out = std::process::Command::new(format!("{prefix}/xray"))
        .arg("version")
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .map(|v| format!("v{}", v.trim_start_matches('v')))
}

/// Downloads, verifies, and installs Xray.
///
/// # Errors
/// Returns an error if any step fails, including — deliberately — a digest that
/// cannot be fetched.
pub(crate) fn install(
    version: Option<&str>,
    prefix: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let arch = arch_name()?;
    let version = match version {
        Some(v) => format!("v{}", v.trim_start_matches('v')),
        None => latest_version()?,
    };

    let base = format!("https://github.com/XTLS/Xray-core/releases/download/{version}");
    let file = format!("Xray-linux-{arch}.zip");
    let dir = std::env::temp_dir().join(format!("paqetz-xray-{version}"));
    std::fs::create_dir_all(&dir)?;
    let zip = dir.join(&file);
    let zip_path = zip.display().to_string();

    println!("  fetching {base}/{file}");
    capture(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "120",
            "-o",
            &zip_path,
            &format!("{base}/{file}"),
        ],
    )?;

    // The digest is not optional. A release whose checksum cannot be fetched is
    // a release that cannot be verified, and an unverifiable binary about to be
    // run as root is not something to shrug at.
    println!("  fetching {base}/{file}.dgst");
    let dgst = capture(
        "curl",
        &["-fsSL", "--max-time", "60", &format!("{base}/{file}.dgst")],
    )
    .map_err(|e| -> Box<dyn std::error::Error> {
        format!(
            "could not fetch the checksum for {file}: {e}\n\
             Refusing to install an unverified binary."
        )
        .into()
    })?;

    let expected = dgst
        .lines()
        .find_map(|l| l.strip_prefix("SHA2-256="))
        .or_else(|| dgst.lines().find_map(|l| l.strip_prefix("SHA256=")))
        .map(str::trim)
        .ok_or("the checksum file carries no SHA-256 line")?
        .to_ascii_lowercase();

    let actual = capture("sha256sum", &[&zip_path])?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if actual != expected {
        return Err(format!(
            "checksum mismatch for {file}\n  expected {expected}\n  got      {actual}\n\
             Not installing."
        )
        .into());
    }
    println!("  checksum verified");

    let dir_path = dir.display().to_string();
    capture("unzip", &["-o", "-q", &zip_path, "xray", "-d", &dir_path])?;

    let target = format!("{prefix}/xray");
    std::fs::create_dir_all(prefix)?;
    std::fs::copy(dir.join("xray"), &target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_dir_all(&dir);

    println!("  installed {version} to {target}");
    Ok(version)
}

/// A systemd unit that runs Xray with the generated configuration.
#[must_use]
pub(crate) fn service_unit(prefix: &str, config: &str) -> String {
    format!(
        "# Install to /etc/systemd/system/xray.service, then:\n\
         #   systemctl enable --now xray\n\
         \n\
         [Unit]\n\
         Description=Xray\n\
         After=network-online.target paqetz.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={prefix}/xray run -config {config}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         # Binding 443 is all the privilege it needs.\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         DynamicUser=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

#[cfg(test)]
mod install_tests {
    use super::*;

    #[test]
    fn this_architecture_maps_to_a_published_build() {
        // Whatever this host is, the mapping must either name a build or say
        // plainly that there is none -- never guess.
        match arch_name() {
            Ok(name) => assert!(
                ["64", "arm64-v8a", "arm32-v7a"].contains(&name),
                "unexpected build name {name}"
            ),
            Err(e) => assert!(e.to_string().contains("architecture"), "{e}"),
        }
    }

    #[test]
    fn the_service_unit_names_the_binary_and_the_configuration() {
        let unit = service_unit("/usr/local/bin", "/etc/xray/config.json");
        assert!(unit.contains("/usr/local/bin/xray run -config /etc/xray/config.json"));
        assert!(unit.contains("After=network-online.target paqetz.service"));
    }

    #[test]
    fn the_service_unit_asks_for_only_what_binding_a_port_needs() {
        let unit = service_unit("/usr/local/bin", "/etc/xray/config.json");
        assert!(unit.contains("CAP_NET_BIND_SERVICE"));
        assert!(!unit.contains("CAP_NET_ADMIN"), "Xray needs no such thing");
        assert!(!unit.contains("User=root"), "and it is not run as root");
    }

    #[test]
    fn an_absent_installation_reports_no_version() {
        assert_eq!(installed_version("/nonexistent-prefix-xyz"), None);
    }
}
