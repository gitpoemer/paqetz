//! Generating an Xray REALITY inbound that points at the tunnel.
//!
//! The arrangement this serves: users connect to Xray on the client host, and
//! Xray forwards what it receives through the tunnel. Xray is the inbound,
//! paqetz is the transport.
//!
//! # Two legs, not two layers
//!
//! REALITY encrypts the hop from the end user to the client host. The tunnel
//! encrypts the hop from the client host to the server. They are sequential and
//! independent: nothing is encrypted twice for the same hop, and neither
//! protects the other's leg.
//!
//! It follows that Xray terminates REALITY on the client host and re-encrypts
//! into the tunnel, so between the two the traffic is in the clear to that
//! machine. That is inherent to a proxy chain rather than a shortcoming here,
//! but it makes the client host a trust boundary and it is worth knowing which
//! machine is in that position. See `docs/09-deployment.md`.
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

/// Where the routing data files come from.
///
/// Xray resolves `geoip:` and `geosite:` names out of two data files, and
/// refuses to start when a configuration names one it cannot resolve. The
/// upstream files carry the whole world; these carry the same plus rules for
/// Iran specifically, which is what makes "leave domestic traffic alone"
/// expressible at all.
const RULES_REPO: &str = "Chocolate4U/Iran-v2ray-rules";

/// The two files Xray reads `geoip:` and `geosite:` names from.
const RULES_FILES: [&str; 2] = ["geoip.dat", "geosite.dat"];

/// Fetches the routing data files and puts them where Xray looks.
///
/// Beside the binary, which is the first place Xray searches -- the failure that
/// prompted this said `open /usr/local/bin/geoip.dat`, naming that directory
/// outright.
///
/// # Errors
/// Returns an error if a file cannot be fetched or written.
pub(crate) fn install_rules(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    let base = format!("https://github.com/{RULES_REPO}/releases/latest/download");
    std::fs::create_dir_all(prefix)?;

    for file in RULES_FILES {
        let target = format!("{prefix}/{file}");
        println!("  fetching {base}/{file}");
        let tmp = std::env::temp_dir().join(format!("paqetz-{file}"));
        let tmp_path = tmp.display().to_string();
        capture(
            "curl",
            &[
                "-fsSL",
                "--max-time",
                "180",
                "-o",
                &tmp_path,
                &format!("{base}/{file}"),
            ],
        )?;

        // Verified where a digest is published. These are data rather than
        // code, so a bad one misroutes rather than executes -- but misrouting
        // is what this file decides, so it is worth checking when it can be.
        match capture(
            "curl",
            &[
                "-fsSL",
                "--max-time",
                "60",
                &format!("{base}/{file}.sha256sum"),
            ],
        ) {
            Ok(published) => {
                let want = published.split_whitespace().next().unwrap_or_default();
                let got = capture("sha256sum", &[&tmp_path])?
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                if want.is_empty() || want != got {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(format!(
                        "{file} does not match its published digest\n  expected {want}\n  got      {got}"
                    )
                    .into());
                }
                println!("    checksum verified");
            }
            Err(_) => println!("    no published checksum; installed unverified"),
        }

        std::fs::copy(&tmp, &target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
        }
        let _ = std::fs::remove_file(&tmp);
        println!("    installed {target}");
    }
    Ok(())
}

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
    /// Keep domestic destinations out of the tunnel.
    ///
    /// Sends anything Xray recognises as Iranian -- by address or by name -- to
    /// the blackhole rather than through the tunnel. A user's own country is
    /// reachable without one, and routing it abroad and back is slower, more
    /// visible, and occasionally blocked at the far end for arriving from the
    /// wrong place.
    pub(crate) block_domestic: bool,
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
        // `domainStrategy` here is what makes Xray resolve the name with its
        // own DNS -- which routes through this same marked outbound, and so
        // through the tunnel -- rather than handing it to the host's resolver.
        // Without it the connection is tunnelled but the lookup that chose its
        // destination is not, which is the failure this whole path exists to
        // avoid. `UseIPv4` because the tunnel carries IPv4.
        Upstream::Marked(mark) => format!(
            r#"    {{
      "tag": "tunnel",
      "protocol": "freedom",
      "settings": {{ "domainStrategy": "UseIPv4" }},
      "streamSettings": {{
        "sockopt": {{ "mark": {mark} }}
      }}
    }}"#
        ),
    };

    // With SOCKS5 the name goes to paqetz untouched and is resolved at the far
    // end, so Xray must not resolve it first. With a marked socket there is no
    // far end to defer to, so Xray does the lookup -- and needs a resolver it
    // reaches through the tunnel, or the local network sees every name and
    // chooses the answers.
    let (domain_strategy, dns) = match plan.upstream {
        Upstream::Socks5(_) => ("AsIs", String::new()),
        Upstream::Marked(_) => (
            "IPIfNonMatch",
            format!(
                r#"  "dns": {{
    "servers": ["{RESOLVER}"],
    "queryStrategy": "UseIPv4"
  }},
"#
            ),
        ),
    };

    let domestic = if plan.block_domestic {
        // Two rules rather than one: an address may be Iranian without its name
        // saying so, and a name may resolve abroad while still being domestic.
        r#",
      {
        "type": "field",
        "ip": ["geoip:ir"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": ["geosite:ir"],
        "outboundTag": "block"
      }"#
    } else {
        ""
    };
    let dest = &plan.dest;
    let listen_port = plan.listen_port;
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
{dns}  "inbounds": [
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
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
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
      }}{domestic}
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
/// The resolver Xray is pointed at on the marked path.
///
/// Reached through the tunnel, so the network this host sits in neither learns
/// the names nor answers for them. Matches what paqetz's own SOCKS5 resolver
/// defaults to, so the two paths behave the same way.
const RESOLVER: &str = "1.1.1.1";

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
            block_domestic: false,
        }
    }

    #[test]
    fn domestic_destinations_are_blocked_only_when_asked_for() {
        let off = generate(&Plan {
            block_domestic: false,
            ..plan()
        })
        .expect("generate");
        assert!(!off.config.contains("geoip:ir"), "{}", off.config);
        assert!(!off.config.contains("geosite:ir"), "{}", off.config);

        let on = generate(&Plan {
            block_domestic: true,
            ..plan()
        })
        .expect("generate");
        // Both, because an address can be domestic without its name saying so
        // and a name can resolve abroad while still being domestic.
        assert!(on.config.contains("\"geoip:ir\""), "{}", on.config);
        assert!(on.config.contains("\"geosite:ir\""), "{}", on.config);
        assert!(on.config.contains("\"geoip:private\""), "and private stays");
    }

    #[test]
    fn the_generated_configuration_is_valid_json_either_way() {
        // The domestic rules are spliced into a JSON array by hand, and a
        // stray or missing comma there is a file Xray refuses to parse.
        for block_domestic in [true, false] {
            let generated = generate(&Plan {
                block_domestic,
                ..plan()
            })
            .expect("generate");
            well_formed_json(&generated.config)
                .unwrap_or_else(|e| panic!("{e}\n{}", generated.config));
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
    fn what_is_sniffed_decides_routing_and_never_the_destination() {
        // Measured through a live chain: Tor stalled at 10% -- TCP connected,
        // link handshake never finished -- everywhere xray sat in the path,
        // and bootstrapped in a second everywhere it did not.
        //
        // Tor's link handshake sends a *randomised* SNI. Sniffing without this
        // flag replaces the destination with whatever name it read, so xray
        // then tries to resolve a domain nobody registered, and the connection
        // dies with the client's TCP already open and waiting. Anything else
        // presenting an SNI that is not a real host meets the same fate.
        //
        // `routeOnly` keeps the sniffed name for routing -- so the domestic
        // rules below still match on it -- and leaves the destination as the
        // address the client actually asked for.
        let generated = generate(&plan()).expect("generate");
        let config = &generated.config;
        assert!(config.contains("\"routeOnly\": true"), "{config}");
        assert!(config.contains("\"destOverride\""), "{config}");

        // The two belong together: destOverride without routeOnly is the bug,
        // so a future edit that drops one has to drop the other.
        let sniff = config
            .split_once("\"sniffing\"")
            .expect("a sniffing block")
            .1
            .split_once('}')
            .expect("its end")
            .0;
        assert!(sniff.contains("routeOnly"), "{sniff}");
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
    fn the_marked_path_resolves_through_the_tunnel() {
        // Without this the connection is tunnelled while the lookup that chose
        // its destination is not -- so the local network still sees every name
        // and still decides what it means, which is most of what the tunnel was
        // for. There is no far end to defer the name to on this path, so Xray
        // has to do it and has to be pointed somewhere reached through the
        // tunnel.
        let g = generate(&Plan {
            upstream: Upstream::Marked(81),
            ..plan()
        })
        .expect("generate");
        assert!(g.config.contains(RESOLVER), "no resolver: {}", g.config);
        assert!(
            g.config.contains(r#""domainStrategy": "UseIPv4""#),
            "freedom would hand the name to the host's resolver: {}",
            g.config
        );
        assert!(
            g.config.contains(r#""queryStrategy": "UseIPv4""#),
            "the tunnel carries IPv4, so asking for anything else wastes a round trip: {}",
            g.config
        );
    }

    #[test]
    fn the_socks5_path_leaves_the_name_alone() {
        // The opposite requirement: paqetz resolves at the far end, so Xray
        // resolving first would defeat it.
        let g = generate(&Plan {
            upstream: Upstream::Socks5("127.0.0.1:1080".to_owned()),
            ..plan()
        })
        .expect("generate");
        assert!(
            g.config.contains(r#""domainStrategy": "AsIs""#),
            "{}",
            g.config
        );
        assert!(!g.config.contains(r#""dns""#), "{}", g.config);
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

/// Where a running Xray reads its configuration.
pub(crate) const CONFIG_PATH: &str = "/etc/xray/config.json";

/// Puts a generated configuration where Xray reads it, and makes Xray use it.
///
/// Writing the file is not applying it. A configuration that a running Xray has
/// not re-read is a configuration that is not in force, and the gap between
/// those two states is the kind that costs an hour to notice -- everything on
/// disk looks right and the behaviour is the old one.
///
/// # Errors
/// Returns an error if the file cannot be written or the unit cannot be
/// installed.
pub(crate) fn apply(
    config: &str,
    prefix: &str,
    marked: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // The REALITY private key lives in here.
    crate::service::write_file(std::path::Path::new(CONFIG_PATH), config, 0o600)?;
    println!("  wrote {CONFIG_PATH} (mode 0600)");

    if !crate::service::has_systemd() {
        println!("  no systemd here; start Xray however this host does it.");
        return Ok(());
    }
    if crate::service::unit_active("xray") {
        crate::service::run_elevated("systemctl", &["restart", "xray"])?;
        println!("  restarted xray, so the new configuration is the one in force");
    } else {
        crate::service::install_unit(
            "xray",
            &service_unit(
                prefix,
                CONFIG_PATH,
                crate::service::has_credentials(),
                marked,
            ),
            true,
        )?;
    }
    Ok(())
}

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
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| crate::service::spawn_failure(program, &e))?;
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

    // Checked before the download rather than after: finding out that the
    // thing which unpacks the archive is missing, having already fetched
    // twenty megabytes, is a worse way to learn it.
    for tool in ["curl", "unzip"] {
        if std::process::Command::new(tool)
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return Err(format!(
                "`{tool}` is not installed, and is needed to fetch and unpack Xray. \
                 Install it (`apt install {tool}`) and run this again."
            )
            .into());
        }
    }

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

    // Not optional. Every configuration this program generates names
    // `geoip:private`, and Xray refuses to start when it cannot resolve a name
    // a rule uses -- so an Xray installed without these is an Xray that does
    // not run.
    install_rules(prefix)?;

    Ok(version)
}

/// A systemd unit that runs Xray with the generated configuration.
#[must_use]
pub(crate) fn service_unit(prefix: &str, config: &str, credentials: bool, marked: bool) -> String {
    // Stamping a mark on a socket is `SO_MARK`, and `SO_MARK` is privileged:
    // without CAP_NET_ADMIN the call fails and the socket goes out unmarked, so
    // the policy route never sees it and the traffic takes the default path.
    // Nothing reports this as an error -- the tunnel is up, Xray is running,
    // and none of it goes through.
    //
    // Only granted when the configuration actually asks for a mark. Handing a
    // service the ability to rewrite packet marks because it might one day need
    // it is how a capability set stops meaning anything.
    let caps = if marked {
        "CAP_NET_BIND_SERVICE CAP_NET_ADMIN"
    } else {
        "CAP_NET_BIND_SERVICE"
    };
    // The configuration holds a REALITY private key, so it is 0600 and owned by
    // root. A service running under `DynamicUser` gets a transient UID that
    // cannot open such a file -- which is exactly right, and exactly why the
    // file has to be handed to it rather than left for it to find.
    //
    // `LoadCredential` has systemd read the file as root before dropping
    // privileges and place it where only this service can see it. Where that is
    // unavailable the service runs as root instead: an unread configuration is
    // a service that does not start, and loosening a file that holds a private
    // key to work around it would be the worse trade.
    let (isolation, path) = if credentials {
        (
            // Named for the format, because Xray reads the format off the
            // extension: a credential called `config` arrives as a file with no
            // extension, and Xray loads it and then refuses to parse it.
            //
            // No line continuation, for the same reason as below: this lands
            // verbatim in a unit file.
            "DynamicUser=true\nLoadCredential=config.json:{config}\n".replace("{config}", config),
            "%d/config.json".to_owned(),
        )
    } else {
        (
            // No line continuation here: what this string holds lands verbatim
            // in a unit file, and a wrapped source line becomes a wrongly
            // indented one.
            "# This systemd is too old to hand a file to a service, so it runs\n# as root rather than as a user that could not read its own key.\n"
                .to_owned(),
            config.to_owned(),
        )
    };
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
         ExecStart={prefix}/xray run -config {path}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         # What it needs: a low port, and a mark if it steers by one.\n\
         AmbientCapabilities={caps}\n\
         CapabilityBoundingSet={caps}\n\
         NoNewPrivileges=true\n\
         {isolation}\
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
        let unit = service_unit("/usr/local/bin", CONFIG_PATH, false, false);
        assert!(unit.contains("/usr/local/bin/xray run -config /etc/xray/config.json"));
        assert!(unit.contains("After=network-online.target paqetz.service"));
    }

    #[test]
    fn a_socks5_upstream_asks_for_only_what_binding_a_port_needs() {
        let unit = service_unit("/usr/local/bin", CONFIG_PATH, true, false);
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE\n"));
        assert!(
            !unit.contains("CAP_NET_ADMIN"),
            "handing it to a service that does not mark anything is how a \
             capability set stops meaning anything:\n{unit}"
        );
        assert!(!unit.contains("User=root"), "and it is not run as root");
    }

    #[test]
    fn a_marked_upstream_is_given_the_privilege_marking_requires() {
        // The regression this closes: the configuration told Xray to stamp a
        // mark, and the unit did not let it. `SO_MARK` needs CAP_NET_ADMIN, so
        // the call failed, the socket went out unmarked, the policy route never
        // saw it, and every connection took the default path -- with the tunnel
        // up, Xray running, and nothing reporting an error.
        let unit = service_unit("/usr/local/bin", CONFIG_PATH, true, true);
        assert!(
            unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN"),
            "{unit}"
        );
        assert!(
            unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN"),
            "the bounding set has to permit what the ambient set grants:\n{unit}"
        );
    }

    #[test]
    fn a_marked_configuration_and_a_marked_unit_go_together() {
        // The two halves that have to agree: if the configuration asks for a
        // mark, the unit must permit one. Read from the generated pair rather
        // than asserted separately, so they cannot drift apart again.
        let generated = generate(&Plan {
            listen_port: 443,
            dest: "www.microsoft.com".to_owned(),
            upstream: Upstream::Marked(81),
            public_address: "example.com".to_owned(),
            block_domestic: false,
        })
        .expect("generate");
        assert!(
            generated.config.contains("\"mark\": 81"),
            "{}",
            generated.config
        );
        assert!(service_unit("/usr/local/bin", CONFIG_PATH, true, true).contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn a_dynamic_user_is_handed_the_configuration_rather_than_left_to_open_it() {
        // The failure this fixes: the configuration holds a private key, so it
        // is 0600 and owned by root, and a transient user cannot open such a
        // file. Xray restarted every five seconds saying "permission denied".
        let unit = service_unit("/usr/local/bin", CONFIG_PATH, true, false);
        assert!(unit.contains("DynamicUser=true"));
        assert!(
            unit.contains("LoadCredential=config.json:/etc/xray/config.json"),
            "{unit}"
        );
        assert!(
            unit.contains("run -config %d/config.json"),
            "it must read what it was handed, not the path it cannot open:\n{unit}"
        );
        // Xray reads the format off the extension. A credential named `config`
        // arrives without one, and Xray loads the file and then refuses it:
        // "Failed to get format of /run/credentials/xray.service/config".
        assert!(
            !unit.contains("run -config %d/config\n"),
            "the credential needs an extension Xray can read a format from:\n{unit}"
        );
        assert!(
            !unit.contains("run -config /etc/xray/config.json"),
            "{unit}"
        );
    }

    #[test]
    fn no_generated_line_carries_the_indentation_of_the_code_that_wrote_it() {
        // Twice now a wrapped source line has put its own leading whitespace
        // into a unit file. systemd tolerates it and it is still wrong: what is
        // written for a file must be written as that file will read it.
        for credentials in [true, false] {
            for marked in [true, false] {
                let unit = service_unit("/usr/local/bin", CONFIG_PATH, credentials, marked);
                for line in unit.lines() {
                    assert_eq!(
                        line,
                        line.trim_start(),
                        "indented line in a generated unit:\n{unit}"
                    );
                }
            }
        }
    }

    #[test]
    fn without_credentials_it_runs_as_root_rather_than_not_at_all() {
        // Below systemd 247 there is no way to hand a file to a transient user.
        // Running as root is the lesser evil: loosening a file that holds a
        // private key so an unprivileged user could read it is the greater one.
        let unit = service_unit("/usr/local/bin", CONFIG_PATH, false, false);
        assert!(!unit.contains("DynamicUser"), "{unit}");
        assert!(!unit.contains("LoadCredential"), "{unit}");
        assert!(unit.contains("run -config /etc/xray/config.json"), "{unit}");
    }

    #[test]
    fn an_absent_installation_reports_no_version() {
        assert_eq!(installed_version("/nonexistent-prefix-xyz"), None);
    }
}
