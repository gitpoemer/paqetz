//! A decoy TLS handshake, for a path that decides what a flow is by its name.
//!
//! Some filters classify a connection from the server name in its first packet
//! and act on nothing afterwards. This crate's segments carry uniform-random
//! bytes, which such a filter cannot classify at all -- and "cannot classify"
//! is itself a verdict on a path that only carries what it recognises. So the
//! first bytes of each connection are a ClientHello naming somewhere ordinary,
//! answered by a ServerHello, and everything after it is what the tunnel was
//! going to send anyway.
//!
//! # Why this is not an injection
//!
//! The known form of this trick belongs to a program that speaks real TLS
//! through the kernel's own stack: it must smuggle the decoy past that stack,
//! so it intercepts its own packets, rewrites the sequence number to sit
//! *behind* the stream, and relies on the observer reassembling more loosely
//! than the server does. All of that machinery -- a netfilter queue, firewall
//! rules, a second raw socket -- exists to inject alongside a stack it does not
//! own.
//!
//! Nothing here needs any of it. This crate writes every segment itself and
//! owns its sequence space, and the far end is the same program: so the decoy
//! is simply the first bytes of the stream, at the sequence number it belongs
//! at, and the far end knows not to decrypt them. An observer that validates
//! sequence numbers reads it just as one that does not, which the injected form
//! cannot say.
//!
//! # What this is worth
//!
//! It buys a name to be classified by, not a conversation. Where the cover is
//! thin, and what each gap would take to close, is written down in
//! `docs/decoy-handshake.md`, which is not published for the same reason the
//! rest of that directory is not.

/// Content type: handshake.
const HANDSHAKE: u8 = 0x16;

/// Content type: application data, which is what everything after a handshake
/// is.
const APPLICATION_DATA: u8 = 0x17;

/// Bytes of record header: content type, version, length.
pub const RECORD_HEADER: usize = 5;

/// The largest payload one record may carry.
pub const MAX_RECORD: usize = 1 << 14;

/// Content type: change cipher spec.
const CHANGE_CIPHER_SPEC: u8 = 0x14;

/// Handshake type: client hello.
const CLIENT_HELLO: u8 = 0x01;

/// Handshake type: server hello.
const SERVER_HELLO: u8 = 0x02;

/// Bytes of ClientHello, record header included.
///
/// What a current Chrome sends, which is a round number because the padding
/// extension is sized to reach it. A hello that varied in length with the name
/// it carried would say how long that name was.
pub const CLIENT_HELLO_LEN: usize = 517;

/// The longest name a hello may carry: the longest a DNS name can be.
pub const MAX_NAME: usize = 253;

/// The longest name for which the hello still reaches exactly
/// [`CLIENT_HELLO_LEN`].
///
/// Past this there is no room for a padding extension and the hello is as long
/// as its name makes it, which is what Chrome does too: it pads a short hello
/// to a round number and leaves a long one alone.
pub const PADDED_NAME: usize = 215;

/// The random numbers one hello needs.
///
/// Supplied rather than drawn here: this crate has no randomness of its own,
/// and a hello whose numbers were derived from anything would repeat.
#[derive(Debug, Clone, Copy, Default)]
pub struct Secrets {
    /// The 32 random bytes at the head of the hello.
    pub random: [u8; 32],
    /// The legacy session identifier, which TLS 1.3 fills with 32 random bytes
    /// and the server echoes back.
    pub session_id: [u8; 32],
    /// The X25519 key share, 32 bytes that are indistinguishable from random.
    pub key_share: [u8; 32],
    /// Which of the sixteen GREASE values this hello uses.
    pub grease: u8,
}

/// The GREASE value for this hello, as RFC 8701 defines them: both bytes equal
/// and of the form `0x?a`.
const fn grease(seed: u8) -> u16 {
    let b = ((seed & 0x0F) << 4) | 0x0A;
    ((b as u16) << 8) | b as u16
}

/// Writes a two-byte big-endian length at `at`, counting from `after`.
fn fill_len(out: &mut [u8], at: usize, after: usize) {
    let len = u16::try_from(out.len().saturating_sub(after)).unwrap_or(0);
    if let Some(slot) = out.get_mut(at..at + 2) {
        slot.copy_from_slice(&len.to_be_bytes());
    }
}

fn u16_be(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// An extension, as type and body.
fn extension(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 4);
    v.extend_from_slice(&ty.to_be_bytes());
    v.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// A decoy ClientHello naming `server_name`.
///
/// The field order is Chrome's, because a hello that matches no real client is
/// a marking of its own: GREASE first and last, the same cipher suites in the
/// same order, ALPN offering h2 and http/1.1, and the padding extension sized
/// so every one of these is [`CLIENT_HELLO_LEN`] bytes whatever the name is.
/// Chrome has shuffled the extensions between those two since version 110, so
/// they are shuffled here too, from `secrets.random`.
///
/// Every hello naming at most [`PADDED_NAME`] bytes is exactly
/// [`CLIENT_HELLO_LEN`] long, so the length says nothing about the name.
///
/// Returns `None` if the name is empty or longer than [`MAX_NAME`].
#[must_use]
pub fn client_hello(server_name: &str, secrets: &Secrets) -> Option<Vec<u8>> {
    let name = server_name.as_bytes();
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let g = grease(secrets.grease);

    let mut middle = Vec::new();

    let mut sni = Vec::with_capacity(name.len() + 5);
    u16_be(&mut sni, u16::try_from(name.len() + 3).unwrap_or(0));
    sni.push(0); // host_name
    u16_be(&mut sni, u16::try_from(name.len()).unwrap_or(0));
    sni.extend_from_slice(name);
    middle.push(extension(0x0000, &sni));

    middle.push(extension(0x0017, &[])); // extended_master_secret
    middle.push(extension(0xFF01, &[0])); // renegotiation_info

    // One GREASE group and the three a browser actually offers, behind the
    // list's own length.
    let mut groups = vec![0x00, 0x08];
    groups.extend_from_slice(&g.to_be_bytes());
    groups.extend_from_slice(&[0x00, 0x1D, 0x00, 0x17, 0x00, 0x18]);
    middle.push(extension(0x000A, &groups));

    middle.push(extension(0x000B, &[0x01, 0x00])); // ec_point_formats
    middle.push(extension(0x0023, &[])); // session_ticket
    middle.push(extension(
        0x0010, // alpn
        &[
            0x00, 0x0C, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    ));
    middle.push(extension(0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00])); // status_request
    middle.push(extension(
        0x000D, // signature_algorithms
        &[
            0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01,
        ],
    ));
    middle.push(extension(0x0012, &[])); // signed_certificate_timestamp

    let mut shares = Vec::with_capacity(45);
    u16_be(&mut shares, 41);
    shares.extend_from_slice(&g.to_be_bytes());
    shares.extend_from_slice(&[0x00, 0x01, 0x00]);
    shares.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
    shares.extend_from_slice(&secrets.key_share);
    middle.push(extension(0x0033, &shares));

    middle.push(extension(0x002D, &[0x01, 0x01])); // psk_key_exchange_modes

    let mut versions = Vec::with_capacity(7);
    versions.push(6);
    versions.extend_from_slice(&g.to_be_bytes());
    versions.extend_from_slice(&[0x03, 0x04, 0x03, 0x03]);
    middle.push(extension(0x002B, &versions));

    middle.push(extension(0x001B, &[0x02, 0x00, 0x02])); // compress_certificate, brotli
    middle.push(extension(0x4469, &[0x00, 0x03, 0x02, b'h', b'2'])); // application_settings

    shuffle(&mut middle, &secrets.random);

    let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
    out.push(HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x01]); // the record claims TLS 1.0, as every client does
    out.extend_from_slice(&[0, 0]); // record length, filled below
    out.push(CLIENT_HELLO);
    out.extend_from_slice(&[0, 0, 0]); // handshake length, filled below
    out.extend_from_slice(&[0x03, 0x03]); // legacy_version
    out.extend_from_slice(&secrets.random);
    out.push(32);
    out.extend_from_slice(&secrets.session_id);

    // The suites Chrome offers, in its order, behind a GREASE value.
    let suites: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ];
    u16_be(&mut out, u16::try_from((suites.len() + 1) * 2).unwrap_or(0));
    u16_be(&mut out, g);
    for suite in suites {
        u16_be(&mut out, suite);
    }
    out.extend_from_slice(&[0x01, 0x00]); // one compression method: null

    let ext_len_at = out.len();
    out.extend_from_slice(&[0, 0]);
    let ext_start = out.len();
    // GREASE first, as Chrome sends it.
    out.extend_from_slice(&extension(g, &[]));
    for ext in &middle {
        out.extend_from_slice(ext);
    }
    out.extend_from_slice(&extension(grease(secrets.grease.wrapping_add(1)), &[0x00]));

    // Padding to a fixed length, which is what makes every hello the same size
    // whatever it names. A name too long to leave room for the extension's own
    // four bytes gets none, as it would from Chrome: padding a hello that is
    // already past the target would mean making it longer still.
    if let Some(padding) = CLIENT_HELLO_LEN.checked_sub(out.len() + 4) {
        out.extend_from_slice(&extension(0x0015, &vec![0u8; padding]));
    }

    fill_len(&mut out, ext_len_at, ext_start);
    fill_len(&mut out, 3, 5);
    let body = u32::try_from(out.len().saturating_sub(9)).unwrap_or(0);
    if let Some(slot) = out.get_mut(6..9) {
        slot.copy_from_slice(&body.to_be_bytes()[1..]);
    }
    Some(out)
}

/// The answer: a ServerHello echoing `session_id`, then a change-cipher-spec
/// record.
///
/// Both in one segment, as a TLS 1.3 server sends them. After this everything
/// in a real session is encrypted records, which is what the tunnel's own
/// traffic already looks like.
#[must_use]
pub fn server_hello(session_id: &[u8; 32], secrets: &Secrets) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.push(HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&[0, 0]);
    out.push(SERVER_HELLO);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&[0x03, 0x03]); // legacy_version
    out.extend_from_slice(&secrets.random);
    out.push(32);
    out.extend_from_slice(session_id);
    u16_be(&mut out, 0x1301); // TLS_AES_128_GCM_SHA256
    out.push(0); // compression

    let ext_len_at = out.len();
    out.extend_from_slice(&[0, 0]);
    let ext_start = out.len();
    out.extend_from_slice(&extension(0x002B, &[0x03, 0x04])); // supported_versions
    let mut share = Vec::with_capacity(36);
    share.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
    share.extend_from_slice(&secrets.key_share);
    out.extend_from_slice(&extension(0x0033, &share));

    fill_len(&mut out, ext_len_at, ext_start);
    fill_len(&mut out, 3, 5);
    let body = u32::try_from(out.len().saturating_sub(9)).unwrap_or(0);
    if let Some(slot) = out.get_mut(6..9) {
        slot.copy_from_slice(&body.to_be_bytes()[1..]);
    }

    out.extend_from_slice(&[CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out
}

/// The header that turns a payload into one application-data record.
///
/// What a session sends after its handshake, and so what the tunnel's own
/// packets wear once a decoy handshake has claimed to be one: without it the
/// stream is a handshake followed by bytes that are not records at all, which
/// anything parsing past the hello walks straight into.
///
/// `None` for a payload too long to be a record, which nothing here produces:
/// the MTU is a fifth of the limit.
#[must_use]
pub fn record_header(payload_len: usize) -> Option<[u8; RECORD_HEADER]> {
    let len = u16::try_from(payload_len).ok()?;
    if payload_len > MAX_RECORD {
        return None;
    }
    let [hi, lo] = len.to_be_bytes();
    Some([APPLICATION_DATA, 0x03, 0x03, hi, lo])
}

/// The payload inside an application-data record, if that is what this is.
///
/// Length-checked rather than type-checked alone, so a sealed packet that
/// happens to begin with these three bytes is not unwrapped unless it also
/// describes its own length exactly -- about one packet in a thousand billion,
/// against a carrier that already tolerates loss.
#[must_use]
pub fn unwrap_record(payload: &[u8]) -> Option<&[u8]> {
    let (head, rest) = payload.split_at_checked(RECORD_HEADER)?;
    if head.first() != Some(&APPLICATION_DATA)
        || head.get(1) != Some(&0x03)
        || head.get(2) != Some(&0x03)
    {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([
        head.get(3).copied()?,
        head.get(4).copied()?,
    ]));
    (len == rest.len()).then_some(rest)
}

/// Whether this payload is one of these decoys rather than something to
/// decrypt.
///
/// True only when the payload is exactly a run of well-formed TLS records
/// beginning with a handshake, which the tunnel's own sealed packets are not:
/// their first bytes are a masked session index and a counter, and the chance
/// of one accidentally describing its own length to the byte is negligible. It
/// is read before the AEAD, so a wrong answer here is at worst one lost packet
/// on a carrier that already tolerates loss.
#[must_use]
pub fn is_cover(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    if first != HANDSHAKE {
        return false;
    }
    let mut at = 0usize;
    while at < payload.len() {
        let Some(rest) = payload.get(at..) else {
            return false;
        };
        let (Some(&kind), Some(&major)) = (rest.first(), rest.get(1)) else {
            return false;
        };
        if (kind != HANDSHAKE && kind != CHANGE_CIPHER_SPEC) || major != 0x03 {
            return false;
        }
        let (Some(&hi), Some(&lo)) = (rest.get(3), rest.get(4)) else {
            return false;
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        at = at.saturating_add(5).saturating_add(len);
    }
    at == payload.len()
}

/// The session identifier in a ClientHello, for the answer to echo.
///
/// `None` unless this is a hello with the 32-byte identifier TLS 1.3 uses, so
/// a truncated or unexpected record yields nothing rather than a guess.
#[must_use]
pub fn session_id(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.first() != Some(&HANDSHAKE) || payload.get(5) != Some(&CLIENT_HELLO) {
        return None;
    }
    // Record header, handshake header, legacy version, random, then the
    // identifier's own length.
    if payload.get(43) != Some(&32) {
        return None;
    }
    payload.get(44..76)?.try_into().ok()
}

/// Shuffles the extensions between the two GREASE values, as Chrome does.
///
/// Driven by bytes that are already random and already on the wire, so this
/// costs nothing and needs nothing drawn for it.
fn shuffle(items: &mut [Vec<u8>], seed: &[u8; 32]) {
    if items.len() < 2 {
        return;
    }
    let mut i = items.len() - 1;
    while i > 0 {
        let byte = seed.get(i % seed.len()).copied().unwrap_or(0);
        let j = usize::from(byte) % (i + 1);
        items.swap(i, j);
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn secrets(fill: u8) -> Secrets {
        Secrets {
            random: [fill; 32],
            session_id: [fill ^ 0xFF; 32],
            key_share: [fill.wrapping_add(7); 32],
            grease: fill,
        }
    }

    /// Walks the records, handshake messages and extensions, failing on
    /// anything that does not describe its own length exactly.
    fn well_formed(hello: &[u8]) -> bool {
        if hello.len() < 9 {
            return false;
        }
        let record = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
        if record + 5 != hello.len() {
            return false;
        }
        let body =
            usize::from(u16::from_be_bytes([hello[7], hello[8]])) + (usize::from(hello[6]) << 16);
        body + 9 == hello.len()
    }

    #[test]
    fn a_hello_is_the_length_it_says_at_every_level() {
        // The one failure that would be invisible on the wire and fatal to the
        // whole point: a filter that cannot parse the decoy learns no name from
        // it, and the connection is then exactly as unclassifiable as it was.
        for name in ["a", "www.example.com", &"x".repeat(PADDED_NAME)] {
            let hello = client_hello(name, &secrets(3)).expect("builds");
            assert_eq!(hello.len(), CLIENT_HELLO_LEN, "{name}");
            assert!(well_formed(&hello), "{name}");
            assert!(is_cover(&hello), "{name}");

            // The extension vector, too: its length must reach exactly the end.
            let ext_at = 76 + 2 + 32 + 2;
            let ext_len = usize::from(u16::from_be_bytes([hello[ext_at], hello[ext_at + 1]]));
            assert_eq!(ext_at + 2 + ext_len, hello.len(), "{name}");
        }
        assert!(client_hello("", &secrets(1)).is_none());
        assert!(client_hello(&"x".repeat(MAX_NAME + 1), &secrets(1)).is_none());

        // Past the padding point there is no room for the extension and the
        // hello is the length its name makes it. Every one must still describe
        // itself exactly, since a filter that cannot parse it learns nothing.
        for extra in 1..=(MAX_NAME - PADDED_NAME) {
            let name = "x".repeat(PADDED_NAME + extra);
            let hello = client_hello(&name, &secrets(2)).expect("builds");
            assert!(well_formed(&hello), "{extra}");
            assert!(is_cover(&hello), "{extra}");
        }
    }

    #[test]
    fn the_name_is_on_the_wire_where_a_filter_reads_it() {
        let hello = client_hello("www.example.com", &secrets(9)).expect("builds");
        let at = hello
            .windows(15)
            .position(|w| w == b"www.example.com")
            .expect("the name is in the hello");
        // Preceded by its own length, a host_name type, and the list length.
        assert_eq!(hello[at - 2..at], [0x00, 0x0F]);
        assert_eq!(hello[at - 3], 0x00);
        assert_eq!(hello[at - 5..at - 3], [0x00, 0x12]);
    }

    #[test]
    fn every_hello_differs_while_its_length_does_not() {
        // Two connections one second apart must not be byte-identical, or the
        // decoy becomes the marking it exists to avoid.
        let a = client_hello("www.example.com", &secrets(1)).expect("builds");
        let b = client_hello("www.example.com", &secrets(2)).expect("builds");
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn the_answer_echoes_what_it_was_asked() {
        // A server that answered with a different session identifier is one
        // that answered nobody's hello.
        let hello = client_hello("www.example.com", &secrets(5)).expect("builds");
        let id = session_id(&hello).expect("a client hello carries one");
        assert_eq!(id, secrets(5).session_id);

        let answer = server_hello(&id, &secrets(6));
        assert!(is_cover(&answer));
        assert_eq!(answer[0], HANDSHAKE);
        assert_eq!(answer[5], SERVER_HELLO);
        assert!(
            answer.windows(32).any(|w| w == id),
            "the identifier is echoed"
        );
        // And the change-cipher-spec record that follows a real one.
        assert_eq!(
            &answer[answer.len() - 6..],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        );
        assert_eq!(session_id(&answer), None, "only a client hello has one");
    }

    #[test]
    fn what_the_tunnel_actually_sends_is_not_mistaken_for_a_decoy() {
        // Read before the AEAD, so this decides whether a real packet is
        // dropped. A sealed packet is a masked index, a counter and ciphertext.
        let mut false_positives = 0;
        let mut payload = [0u8; 256];
        for seed in 0..5_000u32 {
            let mut x = seed.wrapping_mul(2_654_435_761);
            for b in &mut payload {
                // A cheap spread that is not uniform randomness but is varied
                // enough for this: what matters is the first five bytes.
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (x >> 24).to_le_bytes()[0];
            }
            if is_cover(&payload) {
                false_positives += 1;
            }
        }
        assert_eq!(false_positives, 0);

        // And the shapes that are nearly one: right type, wrong length.
        let mut truncated = client_hello("www.example.com", &secrets(4)).expect("builds");
        truncated.pop();
        assert!(!is_cover(&truncated));
        assert!(!is_cover(&[]));
        assert!(!is_cover(&[0x16]));
        assert!(!is_cover(&[0x17, 0x03, 0x03, 0x00, 0x00]));
    }
}
