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

/// The longest name a hello may carry: the longest a DNS name can be.
pub const MAX_NAME: usize = 253;

/// The smallest hello this program sends, which is one naming a single
/// character.
///
/// A hello below this is not one of ours, and one that fits in a single segment
/// is not a fragment of anything. Checked rather than assumed because the value
/// it guards is taken from an unauthenticated packet.
pub const HELLO_MIN: usize = 1024;

/// The largest, with room above it rather than exactly at it.
///
/// A hello naming the longest possible name is 2048 bytes; this leaves room for
/// one that grows without being a number a spoofed packet can use to discard
/// more than a single segment of real traffic.
pub const HELLO_MAX: usize = 2560;

/// The group every current client offers first: an ML-KEM-768 key and an
/// X25519 key, used together.
const X25519_MLKEM768: u16 = 0x11EC;

/// Coefficients in an ML-KEM-768 encapsulation key.
const MLKEM_COEFFS: usize = 768;

/// Bytes of one: the coefficients packed twelve bits each, then the seed the
/// key carries at its end.
const MLKEM_EK: usize = MLKEM_COEFFS * 3 / 2 + 32;

/// Bytes of randomness one is drawn from: two per coefficient, then that seed.
pub const MLKEM_SEED: usize = MLKEM_COEFFS * 2 + 32;

/// Bytes of the client's share for that group.
const PQ_CLIENT_SHARE: usize = MLKEM_EK + 32;

/// Bytes of the server's: an ML-KEM ciphertext, then an X25519 key.
///
/// The ciphertext packs ten and four bits per coefficient, ranges with nothing
/// excluded, so every byte of this is uniform and it needs no shaping.
pub const PQ_SERVER_SHARE: usize = 1088 + 32;

/// Bytes of session ticket the decoy claims to be resuming.
///
/// Server-chosen and opaque, so any plausible length will do; this one is in
/// the middle of what the large front-ends issue.
pub const TICKET_LEN: usize = 224;

/// Bytes of the client's end-of-early-data and Finished flight.
///
/// Encrypted in a real session, so opaque here. Four bytes of
/// `end_of_early_data`, thirty-six of Finished, a content type and a tag.
pub const FINISHED_LEN: usize = 58;

/// The random numbers one decoy needs.
///
/// Supplied rather than drawn here: this crate has no randomness of its own,
/// and a hello whose numbers were derived from anything would repeat. Each end
/// fills all of it and uses the half its role calls for.
#[derive(Debug, Clone)]
pub struct Secrets {
    /// The 32 random bytes at the head of a hello.
    pub random: [u8; 32],
    /// The legacy session identifier, which TLS 1.3 fills with 32 random bytes
    /// and the server echoes back.
    pub session_id: [u8; 32],
    /// The client's standalone X25519 share.
    pub key_share: [u8; 32],
    /// The X25519 half of its hybrid share.
    ///
    /// A separate key pair, because it is one: the same 32 bytes appearing
    /// twice in one hello is a repetition no real client produces and anyone
    /// can see.
    pub hybrid_x25519: [u8; 32],
    /// Reduced into the ML-KEM half of the hybrid share.
    pub mlkem: [u8; MLKEM_SEED],
    /// The server's key share, which is uniform bytes throughout.
    pub server_share: [u8; PQ_SERVER_SHARE],
    /// The session ticket the client offers.
    pub ticket: [u8; TICKET_LEN],
    /// The binder over it, which only the ticket's holder could check.
    pub binder: [u8; 32],
    /// The client's Finished flight.
    pub finished: [u8; FINISHED_LEN],
    /// Which of the sixteen GREASE values this hello uses.
    pub grease: u8,
}

impl Default for Secrets {
    fn default() -> Self {
        Self {
            random: [0; 32],
            session_id: [0; 32],
            key_share: [0; 32],
            hybrid_x25519: [0; 32],
            mlkem: [0; MLKEM_SEED],
            server_share: [0; PQ_SERVER_SHARE],
            ticket: [0; TICKET_LEN],
            binder: [0; 32],
            finished: [0; FINISHED_LEN],
            grease: 0,
        }
    }
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

/// Fills in the record and handshake lengths, which are only known at the end.
fn fill_handshake_len(out: &mut [u8]) {
    fill_len(out, 3, 5);
    let body = u32::try_from(out.len().saturating_sub(9)).unwrap_or(0);
    if let Some(slot) = out.get_mut(6..9) {
        slot.copy_from_slice(&body.to_be_bytes()[1..]);
    }
}

/// An ML-KEM-768 encapsulation key drawn from `seed`.
///
/// Not a real key -- nothing here does lattice arithmetic -- but one whose
/// every coefficient is in range, which is the part that can be checked without
/// the private key. The twelve-bit encoding holds values up to 4095 while a
/// coefficient may only reach 3328, so four in every five uniform-random
/// twelve-bit groups are invalid: a key of plain random bytes would fail a
/// validity check on essentially every one of its 768 coefficients, which is a
/// marking rather than a key. Reducing each draw into the field costs one
/// modulo and removes that entirely. The reduction is very slightly biased
/// toward the bottom thousand values, which is not something a single key could
/// ever show.
fn encapsulation_key(seed: &[u8; MLKEM_SEED]) -> Vec<u8> {
    /// The ML-KEM modulus.
    const Q: u16 = 3329;
    let coefficient = |i: usize| -> u16 {
        let lo = seed.get(2 * i).copied().unwrap_or(0);
        let hi = seed.get(2 * i + 1).copied().unwrap_or(0);
        u16::from_le_bytes([lo, hi]) % Q
    };
    let mut out = Vec::with_capacity(MLKEM_EK);
    for pair in 0..MLKEM_COEFFS / 2 {
        let a = coefficient(2 * pair);
        let b = coefficient(2 * pair + 1);
        out.push(u8::try_from(a & 0xFF).unwrap_or(0));
        out.push(u8::try_from(((a >> 8) & 0x0F) | ((b & 0x0F) << 4)).unwrap_or(0));
        out.push(u8::try_from(b >> 4).unwrap_or(0));
    }
    out.extend_from_slice(seed.get(MLKEM_COEFFS * 2..).unwrap_or(&[]));
    out
}

/// The `pre_shared_key` extension body: one ticket and one binder over it.
fn offered_psk(secrets: &Secrets) -> Vec<u8> {
    let mut identities = Vec::with_capacity(TICKET_LEN + 6);
    u16_be(&mut identities, u16::try_from(TICKET_LEN).unwrap_or(0));
    identities.extend_from_slice(&secrets.ticket);
    // The age the client believes the ticket to be, obfuscated by an offset the
    // server chose. Any value is plausible; this one is a few seconds.
    identities.extend_from_slice(
        &u32::from_be_bytes([
            secrets.random[0],
            secrets.random[1],
            secrets.random[2],
            secrets.random[3],
        ])
        .to_be_bytes(),
    );

    let mut body = Vec::with_capacity(identities.len() + 40);
    u16_be(&mut body, u16::try_from(identities.len()).unwrap_or(0));
    body.extend_from_slice(&identities);
    u16_be(&mut body, 33);
    body.push(32);
    body.extend_from_slice(&secrets.binder);
    body
}

/// A decoy ClientHello naming `server_name`, offering to resume and to send
/// early data.
///
/// The field order is Chrome's, because a hello that matches no real client is
/// a marking of its own: GREASE first and last, the same cipher suites in the
/// same order, ALPN offering h2 and http/1.1, and the post-quantum group every
/// current build offers first. Chrome has shuffled the extensions between those
/// two GREASE values since version 110, so they are shuffled here too, from
/// `secrets.random`.
///
/// # Why it offers to resume
///
/// The tunnel sends its own first packet immediately after this, without
/// waiting for an answer, because that is what a tunnel does. In TLS that is
/// legal only as early data, and only for a client that offered a
/// `pre_shared_key` and an `early_data` extension. Without them the stream
/// stops being TLS at the first byte after the hello, which is a single check
/// for anything already parsing the record layer to read the name. With them it
/// is an ordinary 0-RTT resumption -- which also has no certificate in it, so
/// the short answer that follows is what it should be rather than a flight gone
/// missing.
///
/// The result is longer than one segment, as every current hello is. The caller
/// splits it the way a real stack does.
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

    // One GREASE group, the post-quantum one, and the three a browser has
    // always offered, behind the list's own length.
    let mut groups = vec![0x00, 0x0A];
    groups.extend_from_slice(&g.to_be_bytes());
    groups.extend_from_slice(&X25519_MLKEM768.to_be_bytes());
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

    let ek = encapsulation_key(&secrets.mlkem);
    let mut shares = Vec::with_capacity(PQ_CLIENT_SHARE + 20);
    let list_len = 5 + 4 + PQ_CLIENT_SHARE + 4 + 32;
    u16_be(&mut shares, u16::try_from(list_len).unwrap_or(0));
    // A GREASE share of one byte, as Chrome sends it.
    shares.extend_from_slice(&g.to_be_bytes());
    shares.extend_from_slice(&[0x00, 0x01, 0x00]);
    shares.extend_from_slice(&X25519_MLKEM768.to_be_bytes());
    u16_be(&mut shares, u16::try_from(PQ_CLIENT_SHARE).unwrap_or(0));
    shares.extend_from_slice(&ek);
    shares.extend_from_slice(&secrets.hybrid_x25519);
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
    middle.push(extension(0x002A, &[])); // early_data

    shuffle(&mut middle, &secrets.random);

    let mut out = Vec::with_capacity(PQ_CLIENT_SHARE + 600);
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
    // Last, where the specification requires it and where the binder it carries
    // has to be: it is computed over everything before it.
    out.extend_from_slice(&extension(0x0029, &offered_psk(secrets)));

    fill_len(&mut out, ext_len_at, ext_start);
    fill_handshake_len(&mut out);
    Some(out)
}

/// The answer: a ServerHello accepting the resumption, then a
/// change-cipher-spec record.
///
/// Both in one segment, as a TLS 1.3 server sends them. Accepting the
/// resumption is what makes the rest of the exchange coherent: a resumed
/// handshake sends no certificate, so the hundred-odd bytes the tunnel's own
/// reply occupies are exactly the encrypted extensions and Finished that
/// should follow, rather than a certificate flight that never came.
#[must_use]
pub fn server_hello(session_id: &[u8; 32], secrets: &Secrets) -> Vec<u8> {
    let mut out = Vec::with_capacity(PQ_SERVER_SHARE + 160);
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
    let mut share = Vec::with_capacity(PQ_SERVER_SHARE + 4);
    share.extend_from_slice(&X25519_MLKEM768.to_be_bytes());
    u16_be(&mut share, u16::try_from(PQ_SERVER_SHARE).unwrap_or(0));
    share.extend_from_slice(&secrets.server_share);
    out.extend_from_slice(&extension(0x0033, &share));
    // The identity accepted: the only one offered.
    out.extend_from_slice(&extension(0x0029, &[0x00, 0x00]));

    fill_len(&mut out, ext_len_at, ext_start);
    fill_handshake_len(&mut out);

    out.extend_from_slice(&[CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out
}

/// What the client owes once the answer arrives: a change-cipher-spec record
/// and its Finished flight.
///
/// A client that offered early data sends `end_of_early_data` and `Finished`
/// after the ServerHello, under the handshake keys, so both are opaque here.
/// Without them the exchange is a handshake nobody ever completed, which is a
/// state a filter tracking the record layer can simply time out.
#[must_use]
pub fn client_finished(secrets: &Secrets) -> Vec<u8> {
    let mut out = Vec::with_capacity(FINISHED_LEN + RECORD_HEADER + 6);
    out.extend_from_slice(&[CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out.extend_from_slice(&[APPLICATION_DATA, 0x03, 0x03]);
    u16_be(&mut out, u16::try_from(FINISHED_LEN).unwrap_or(0));
    out.extend_from_slice(&secrets.finished);
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
/// True only when the payload is exactly a run of well-formed TLS records whose
/// first is a handshake or a change-cipher-spec, which the tunnel's own sealed
/// packets are not: their first bytes are a masked session index and a counter,
/// and the chance of one accidentally describing its own length to the byte is
/// negligible. It is read before the AEAD, so a wrong answer here is at worst
/// one lost packet on a carrier that already tolerates loss.
///
/// A record of application data may follow one of those two -- the client's
/// Finished flight is a change-cipher-spec and then its encrypted handshake --
/// but may never lead, because a sealed packet wearing a record header is
/// exactly one application-data record describing its own length. Accepting
/// that shape here would drop every packet the tunnel sends.
#[must_use]
pub fn is_cover(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    if first != HANDSHAKE && first != CHANGE_CIPHER_SPEC {
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
        if (kind != HANDSHAKE && kind != CHANGE_CIPHER_SPEC && kind != APPLICATION_DATA)
            || major != 0x03
        {
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

/// How many bytes of a hello are still to come, for a payload that is the start
/// of one.
///
/// A current ClientHello does not fit in one segment -- the post-quantum key
/// share alone is over a kilobyte -- so it goes out in two, exactly as a real
/// stack sends it. The first carries everything the answering end needs, and
/// this says how much to expect after it so the remainder is recognised as
/// cover rather than handed to the AEAD and counted as somebody sending
/// garbage.
///
/// Deliberately much stricter than [`is_cover`]: a truncated record is a shape
/// a sealed packet could plausibly stumble into, so this additionally requires
/// the handshake type, the legacy version and the session identifier's length
/// to be exactly where a hello puts them, and the two length fields to agree.
///
/// # Why the length is bounded
///
/// This is read from an unauthenticated packet and decides how much *real*
/// traffic the caller then discards. Left unbounded at the record layer's own
/// limit, one spoofed segment would throw away sixteen kilobytes of the
/// victim's traffic, repeatable, and without the sender needing to see the flow
/// at all. A hello small enough to fit in one segment is not a fragment of
/// anything, and one larger than [`HELLO_MAX`] is not a hello this program
/// sends, so both are refused and the damage any accepted value can do is the
/// one packet a lost continuation already costs.
#[must_use]
pub fn owed_after_opening(payload: &[u8]) -> Option<usize> {
    if payload.first() != Some(&HANDSHAKE)
        || payload.get(1) != Some(&0x03)
        || payload.get(2) != Some(&0x01)
        || payload.get(5) != Some(&CLIENT_HELLO)
        || payload.get(9) != Some(&0x03)
        || payload.get(10) != Some(&0x03)
        || payload.get(43) != Some(&32)
    {
        return None;
    }
    let record = usize::from(u16::from_be_bytes([
        payload.get(3).copied()?,
        payload.get(4).copied()?,
    ]));
    let handshake = usize::from(u16::from_be_bytes([
        payload.get(7).copied()?,
        payload.get(8).copied()?,
    ])) + (usize::from(payload.get(6).copied()?) << 16);
    if !(HELLO_MIN..=HELLO_MAX).contains(&record) || handshake + 4 != record {
        return None;
    }
    // Only a first fragment: a whole one is `is_cover`'s business.
    (record + RECORD_HEADER)
        .checked_sub(payload.len())
        .filter(|owed| *owed > 0)
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
            hybrid_x25519: [fill.wrapping_add(19); 32],
            mlkem: core::array::from_fn(|i| fill.wrapping_add(u8::try_from(i % 251).unwrap_or(0))),
            server_share: core::array::from_fn(|i| fill ^ u8::try_from(i % 253).unwrap_or(0)),
            ticket: core::array::from_fn(|i| {
                fill.wrapping_mul(3)
                    .wrapping_add(u8::try_from(i % 241).unwrap_or(0))
            }),
            binder: [fill.wrapping_add(31); 32],
            finished: [fill.wrapping_add(43); FINISHED_LEN],
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

    /// The extension types a hello offers, in the order it offers them.
    fn extensions(hello: &[u8]) -> Vec<u16> {
        let at = 76 + 2 + 32 + 2;
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        let mut out = Vec::new();
        let mut i = at + 2;
        while i + 4 <= end {
            out.push(u16::from_be_bytes([hello[i], hello[i + 1]]));
            i += 4 + usize::from(u16::from_be_bytes([hello[i + 2], hello[i + 3]]));
        }
        out
    }

    #[test]
    fn a_hello_is_the_length_it_says_at_every_level() {
        // The one failure that would be invisible on the wire and fatal to the
        // whole point: a filter that cannot parse the decoy learns no name from
        // it, and the connection is then exactly as unclassifiable as it was.
        for name in ["a", "www.example.com", &"x".repeat(MAX_NAME)] {
            let hello = client_hello(name, &secrets(3)).expect("builds");
            assert!(well_formed(&hello), "{name}");
            assert!(is_cover(&hello), "{name}");

            // The extension vector, too: its length must reach exactly the end.
            let ext_at = 76 + 2 + 32 + 2;
            let ext_len = usize::from(u16::from_be_bytes([hello[ext_at], hello[ext_at + 1]]));
            assert_eq!(ext_at + 2 + ext_len, hello.len(), "{name}");
        }
        assert!(client_hello("", &secrets(1)).is_none());
        assert!(client_hello(&"x".repeat(MAX_NAME + 1), &secrets(1)).is_none());
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
    fn every_hello_differs() {
        // Two connections one second apart must not be byte-identical, or the
        // decoy becomes the marking it exists to avoid.
        let a = client_hello("www.example.com", &secrets(1)).expect("builds");
        let b = client_hello("www.example.com", &secrets(2)).expect("builds");
        assert_ne!(a, b);
        // The same name is the same length, as it is from any real client: the
        // length follows the name, and the name is in the clear beside it.
        assert_eq!(a.len(), b.len());
    }

    /// What makes the early data the tunnel sends immediately afterwards legal
    /// rather than an impossibility a record-layer parser can see in one step.
    #[test]
    fn the_hello_offers_to_resume_and_to_send_early_data() {
        let hello = client_hello("www.example.com", &secrets(7)).expect("builds");
        let exts = extensions(&hello);
        assert!(exts.contains(&0x002A), "early_data: {exts:04x?}");
        assert!(exts.contains(&0x0029), "pre_shared_key: {exts:04x?}");
        assert!(exts.contains(&0x002D), "psk_key_exchange_modes");
        assert_eq!(
            exts.last(),
            Some(&0x0029),
            "the specification puts pre_shared_key last, and so does the binder \
             it carries: {exts:04x?}"
        );
        assert!(exts.contains(&0x0033), "key_share");
        // The group every current client offers first, which is what makes the
        // hello the length a current one is.
        assert!(
            hello.windows(2).any(|w| w == X25519_MLKEM768.to_be_bytes()),
            "the post-quantum group is offered"
        );
        assert!(
            hello.len() > 1500,
            "a current hello does not fit in one segment: {}",
            hello.len()
        );
    }

    /// Plain random bytes would fail a validity check on nearly every
    /// coefficient, which is a marking rather than a key.
    #[test]
    fn the_post_quantum_key_is_every_coefficient_in_range() {
        for fill in [0u8, 1, 17, 200, 255] {
            let ek = encapsulation_key(&secrets(fill).mlkem);
            assert_eq!(ek.len(), MLKEM_EK);
            for pair in 0..MLKEM_COEFFS / 2 {
                let at = pair * 3;
                let a = u16::from(ek[at]) | (u16::from(ek[at + 1] & 0x0F) << 8);
                let b = u16::from(ek[at + 1] >> 4) | (u16::from(ek[at + 2]) << 4);
                assert!(a < 3329, "fill {fill}, coefficient {}: {a}", 2 * pair);
                assert!(b < 3329, "fill {fill}, coefficient {}: {b}", 2 * pair + 1);
            }
        }
    }

    #[test]
    fn the_two_key_shares_are_different_keys() {
        let hello = client_hello("www.example.com", &secrets(4)).expect("builds");
        let s = secrets(4);
        assert_ne!(s.key_share, s.hybrid_x25519);
        // Neither appears twice: a repeated thirty-two bytes is visible to
        // anyone and is not something a real hello contains.
        for key in [s.key_share, s.hybrid_x25519] {
            let found = hello.windows(32).filter(|w| *w == key).count();
            assert_eq!(found, 1, "each share appears once");
        }
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
        // Accepting the resumption is what makes a short reply the right reply
        // rather than a certificate flight that never arrived.
        assert!(
            answer.windows(4).any(|w| w == [0x00, 0x29, 0x00, 0x02]),
            "the answer accepts the offered identity"
        );
        // And the change-cipher-spec record that follows a real one.
        assert_eq!(
            &answer[answer.len() - 6..],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        );
        assert_eq!(session_id(&answer), None, "only a client hello has one");
        // One segment, as a real one is.
        assert!(answer.len() < 1400, "{}", answer.len());
        assert!(
            answer.len() > 1100,
            "a current answer carries a post-quantum ciphertext: {}",
            answer.len()
        );
    }

    /// The flight that turns the exchange from a handshake nobody completed
    /// into one that did.
    #[test]
    fn the_clients_finished_flight_is_cover() {
        let flight = client_finished(&secrets(8));
        assert!(is_cover(&flight), "{flight:02x?}");
        assert_eq!(flight[0], CHANGE_CIPHER_SPEC);
        assert_eq!(flight[6], APPLICATION_DATA);
        assert_eq!(flight.len(), 6 + RECORD_HEADER + FINISHED_LEN);
    }

    /// A hello spans two segments, and the second has to be recognised or it is
    /// handed to the AEAD and counted as somebody sending garbage.
    #[test]
    fn the_second_segment_of_a_hello_is_accounted_for() {
        let hello = client_hello("www.example.com", &secrets(11)).expect("builds");
        for first in [600usize, 1400, 1428, hello.len() - 1] {
            let owed = owed_after_opening(&hello[..first]).expect("a first fragment");
            assert_eq!(owed, hello.len() - first, "split at {first}");
        }
        // A whole one is not a fragment, and is `is_cover`'s business.
        assert_eq!(owed_after_opening(&hello), None);
        // Nor is a fragment of something far too large to be a hello: the
        // number decides how much real traffic the caller discards, so a
        // spoofed one must not be able to name sixteen kilobytes.
        let mut forged = hello[..600].to_vec();
        let huge = u16::try_from(HELLO_MAX + 1).expect("fits");
        forged[3..5].copy_from_slice(&huge.to_be_bytes());
        let body = u32::from(huge) - 4;
        forged[6..9].copy_from_slice(&body.to_be_bytes()[1..]);
        assert_eq!(owed_after_opening(&forged), None, "too large to be a hello");
        // And one claiming to be small enough to have fitted in one segment.
        let mut small = hello[..200].to_vec();
        let tiny = u16::try_from(HELLO_MIN - 1).expect("fits");
        small[3..5].copy_from_slice(&tiny.to_be_bytes());
        let body = u32::from(tiny) - 4;
        small[6..9].copy_from_slice(&body.to_be_bytes()[1..]);
        assert_eq!(owed_after_opening(&small), None, "not a fragment at all");
        assert!(is_cover(&hello));
        // Nor is the answer, which is not a hello at all.
        assert_eq!(
            owed_after_opening(&server_hello(&[0u8; 32], &secrets(1))),
            None
        );
    }

    #[test]
    fn what_the_tunnel_actually_sends_is_not_mistaken_for_a_decoy() {
        // Read before the AEAD, so this decides whether a real packet is
        // dropped. A sealed packet is a masked index, a counter and ciphertext.
        let mut false_positives = 0;
        let mut fragments = 0;
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
            if owed_after_opening(&payload).is_some() {
                fragments += 1;
            }
        }
        assert_eq!(false_positives, 0);
        assert_eq!(fragments, 0);

        // A sealed packet wearing a record header is one application-data
        // record describing its own length exactly. Reading that as cover would
        // drop every packet the tunnel sends.
        let mut sealed = vec![APPLICATION_DATA, 0x03, 0x03, 0x00, 0x20];
        sealed.extend_from_slice(&[0x5A; 32]);
        assert!(!is_cover(&sealed));

        // And the shapes that are nearly one: right type, wrong length.
        let mut truncated = server_hello(&[3u8; 32], &secrets(4));
        truncated.pop();
        assert!(!is_cover(&truncated));
        assert!(!is_cover(&[]));
        assert!(!is_cover(&[0x16]));
        assert!(!is_cover(&[0x17, 0x03, 0x03, 0x00, 0x00]));
    }
}
