//! Bounds what a virtio-net header could remove from the inbound datapath.
//!
//! Step 2 of the measurement plan in `docs/decisions/D15-tun-offloads.md`. The
//! question it answers is narrow and is the one the offload work turns on:
//! writing an inner packet into a TUN device costs a syscall, a copy, an skb,
//! a route lookup and a netfilter traversal, and `bench.sh` puts the whole
//! inbound path at about five microseconds of CPU per packet. How much of that
//! is the TUN write, and how much of *that* would segmentation offload remove?
//!
//! This measures only the TUN write, with nothing else in the way: no capture
//! socket, no AEAD, no carrier. Two modes, the same bytes delivered either way:
//!
//! - `plain`: one `write` per datagram, which is what paqetz does today.
//! - `uso`: one `write` per superpacket, which the kernel splits into datagrams
//!   itself. This is what `IFF_VNET_HDR` buys.
//!
//! The ratio between the two is the ceiling. It is a ceiling rather than a
//! prediction, because paqetz would also have to *build* those superpackets,
//! and on the inbound side that means coalescing across a channel that loses
//! packets and never retransmits -- which is the open question in D15 and is
//! not what this measures.
//!
//! Needs `CAP_NET_ADMIN`. Creates a TUN device and deletes it on the way out.
//!
//! ```text
//! sudo ./target/release/examples/tun_ceiling plain
//! sudo ./target/release/examples/tun_ceiling uso
//! ```

use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DEVICE: &str = "pqprobe0";
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const PORT: u16 = 9999;
const MTU: u32 = 1500;

/// Payload bytes per datagram, sized so one datagram fills the MTU.
const PAYLOAD: usize = 1400;
/// Datagrams per superpacket in `uso` mode.
const PER_SUPERPACKET: usize = 40;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const TUNSETOFFLOAD: libc::Ioctl = 0x4004_54d0;
const TUN_F_CSUM: libc::c_uint = 0x01;
const TUN_F_USO4: libc::c_uint = 0x20;
const TUN_F_USO6: libc::c_uint = 0x40;

/// `virtio_net_hdr`, which precedes every frame once `IFF_VNET_HDR` is set.
///
/// Ten bytes, not twelve: the twelve-byte form is `virtio_net_hdr_mrg_rxbuf`,
/// and TUN only uses that once `TUNSETVNETHDRSZ` asks for it. Writing twelve
/// would leave the kernel reading two bytes of header as the first two bytes of
/// the IP packet, which is the sort of mistake the delivery count below exists
/// to catch.
const VNET_HDR_LEN: usize = 10;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;

const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const PROTO_UDP: u8 = 17;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: i16,
    _pad: [u8; 22],
}

fn open_tun(vnet: bool) -> io::Result<OwnedFd> {
    let mut name = [0 as libc::c_char; 16];
    for (slot, b) in name.iter_mut().zip(DEVICE.as_bytes()) {
        *slot = *b as libc::c_char;
    }
    let flags = IFF_TUN | IFF_NO_PI | if vnet { IFF_VNET_HDR } else { 0 };
    let mut req = IfReq {
        name,
        flags,
        _pad: [0; 22],
    };

    // SAFETY: a nul-terminated path and ordinary open flags.
    let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a fresh descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: TUNSETIFF takes a pointer to an `ifreq`, which this is laid out
    // as.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if vnet {
        // Both USO bits, not just the IPv4 one. `set_offload` in the kernel
        // reads them as a pair -- "TODO: for now USO4 and USO6 should work
        // simultaneously" -- so with only USO4 the bit is left unconsumed and
        // the ioctl returns EINVAL at the end, which looks exactly like the
        // kernel being too old to know the feature at all.
        let features = TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6;
        // SAFETY: TUNSETOFFLOAD takes the feature bits by value.
        if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, features) } < 0 {
            return Err(io::Error::other(format!(
                "TUNSETOFFLOAD(TUN_F_CSUM|TUN_F_USO4|TUN_F_USO6) failed: {}. UDP \
                 segmentation offload needs Linux 6.2 or later; without it this probe \
                 cannot measure the \"uso\" half and the plain figure is all there is",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(fd)
}

/// Brings the device up with an address, via `ip`.
///
/// Shelling out rather than reimplementing four ioctls: this is a probe, and
/// the thing being measured is the write path rather than the setup.
fn configure() -> io::Result<()> {
    for args in [
        vec!["addr", "add", "10.77.0.1/24", "dev", DEVICE],
        vec!["link", "set", DEVICE, "mtu", &MTU.to_string()],
        vec!["link", "set", DEVICE, "up"],
    ] {
        let out = std::process::Command::new("ip").args(&args).output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u16 {
    !fold(sum16(bytes))
}

/// The ones' complement sum of `bytes`, folded to sixteen bits.
fn sum16(bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    let mut sum: u32 = pairs
        .iter()
        .map(|p| u32::from(u16::from_be_bytes(*p)))
        .sum();
    if let [last] = *rest {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    u16::try_from(sum & 0xFFFF).unwrap_or(0)
}

/// The ones' complement sum of the UDP pseudo-header.
///
/// What `VIRTIO_NET_HDR_F_NEEDS_CSUM` expects to find already in the checksum
/// field: the kernel completes the sum over the payload and writes the result
/// back, so the part it cannot know has to be there first.
fn pseudo_header_sum(payload_len: usize) -> u16 {
    let mut head = Vec::with_capacity(12);
    head.extend_from_slice(&REMOTE.octets());
    head.extend_from_slice(&LOCAL.octets());
    head.push(0);
    head.push(PROTO_UDP);
    head.extend_from_slice(
        &u16::try_from(UDP_LEN + payload_len)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    fold(sum16(&head))
}

/// One IPv4 + UDP frame carrying `payload_len` bytes.
///
/// `segmented` writes the headers a superpacket wants: a total length covering
/// everything, and a partial checksum for the kernel to finish, since it is the
/// one splitting this into datagrams.
fn frame(payload_len: usize, segmented: bool) -> Vec<u8> {
    let udp_total = u16::try_from(UDP_LEN + payload_len).unwrap_or(0);
    let ip_total = u16::try_from(IPV4_LEN + UDP_LEN + payload_len).unwrap_or(u16::MAX);

    let mut out = Vec::with_capacity(IPV4_LEN + UDP_LEN + payload_len);
    out.push(0x45); // version 4, five words of header
    out.push(0); // DSCP 0
    out.extend_from_slice(&ip_total.to_be_bytes());
    out.extend_from_slice(&0x4242u16.to_be_bytes());
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    out.push(64);
    out.push(PROTO_UDP);
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    out.extend_from_slice(&REMOTE.octets());
    out.extend_from_slice(&LOCAL.octets());
    let ip_ck = checksum(out.get(..IPV4_LEN).unwrap_or_default());
    if let Some(slot) = out.get_mut(10..12) {
        slot.copy_from_slice(&ip_ck.to_be_bytes());
    }

    out.extend_from_slice(&PORT.to_be_bytes());
    out.extend_from_slice(&PORT.to_be_bytes());
    out.extend_from_slice(&udp_total.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    out.resize(IPV4_LEN + UDP_LEN + payload_len, 0x5A);

    // Segmented, the kernel finishes the checksum for each datagram it makes,
    // so it wants the pseudo-header for *one* of them. Whole, this computes it.
    let ck = if segmented {
        pseudo_header_sum(PAYLOAD)
    } else {
        let mut pseudo = Vec::with_capacity(12 + UDP_LEN + payload_len);
        pseudo.extend_from_slice(&REMOTE.octets());
        pseudo.extend_from_slice(&LOCAL.octets());
        pseudo.push(0);
        pseudo.push(PROTO_UDP);
        pseudo.extend_from_slice(&udp_total.to_be_bytes());
        pseudo.extend_from_slice(out.get(IPV4_LEN..).unwrap_or_default());
        // Zero means "no checksum" in UDP, so it is sent as all ones instead.
        match checksum(&pseudo) {
            0 => 0xFFFF,
            other => other,
        }
    };
    if let Some(slot) = out.get_mut(IPV4_LEN + 6..IPV4_LEN + 8) {
        slot.copy_from_slice(&ck.to_be_bytes());
    }
    out
}

/// The virtio header for a superpacket of `datagrams` datagrams.
fn vnet_header(gso_size: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(VNET_HDR_LEN);
    h.push(VIRTIO_NET_HDR_F_NEEDS_CSUM);
    h.push(VIRTIO_NET_HDR_GSO_UDP_L4);
    // The headers the kernel repeats on every segment, and the payload each
    // segment carries.
    h.extend_from_slice(&u16::try_from(IPV4_LEN + UDP_LEN).unwrap_or(0).to_le_bytes());
    h.extend_from_slice(&u16::try_from(gso_size).unwrap_or(0).to_le_bytes());
    // Where the checksum it completes starts, and the offset within that at
    // which the result belongs: the UDP header's own checksum field.
    h.extend_from_slice(&u16::try_from(IPV4_LEN).unwrap_or(0).to_le_bytes());
    h.extend_from_slice(&6u16.to_le_bytes());
    h
}

/// This thread's CPU time, in microseconds.
///
/// `RUSAGE_THREAD` rather than `RUSAGE_SELF`, so the drainer's `recv` is not
/// counted against the write. The kernel work the write itself triggers -- the
/// route lookup, the netfilter traversal, the socket enqueue -- happens in the
/// writer's own context and is counted, which is right: the datapath pays that
/// too. What the thing at the far end of the socket spends is Xray's problem,
/// not this one's.
fn cpu_micros() -> u64 {
    // SAFETY: `rusage` is plain integers, for which all-zero is valid, and
    // `getrusage` overwrites it before anything reads it.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: `getrusage` fills the struct it is given.
    if unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut usage) } < 0 {
        return 0;
    }
    [usage.ru_utime, usage.ru_stime]
        .iter()
        .map(|t| {
            u64::try_from(t.tv_sec).unwrap_or(0) * 1_000_000 + u64::try_from(t.tv_usec).unwrap_or(0)
        })
        .sum()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let uso = match mode.as_str() {
        "plain" => false,
        "uso" => true,
        // What it would write, without writing it, so the frames can be
        // checked against a packet parser before anyone trusts a number this
        // produced. Needs no privilege.
        "dump" => {
            for (label, segmented) in [("plain", false), ("uso", true)] {
                let payload = if segmented {
                    PAYLOAD * PER_SUPERPACKET
                } else {
                    PAYLOAD
                };
                let mut buf = Vec::new();
                if segmented {
                    buf.extend_from_slice(&vnet_header(PAYLOAD));
                }
                buf.extend_from_slice(&frame(payload, segmented));
                let hex: String = buf
                    .iter()
                    .take(VNET_HDR_LEN + IPV4_LEN + UDP_LEN)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "{label} vnet_hdr={} total={} {hex}",
                    if segmented { VNET_HDR_LEN } else { 0 },
                    buf.len()
                );
            }
            return;
        }
        _ => {
            eprintln!("usage: tun_ceiling plain|uso|dump   (plain and uso need CAP_NET_ADMIN)");
            std::process::exit(2);
        }
    };
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let fd = match open_tun(uso) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("could not open the device: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = configure() {
        eprintln!("could not configure the device: {e}");
        std::process::exit(1);
    }

    // Bound and drained, so delivery can be counted. A probe that measured a
    // write the kernel discarded would report a number for nothing.
    let socket = match UdpSocket::bind((LOCAL, PORT)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not bind {LOCAL}:{PORT}: {e}");
            std::process::exit(1);
        }
    };
    let delivered = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let drainer = {
        let delivered = Arc::clone(&delivered);
        let stop = Arc::clone(&stop);
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            while !stop.load(Ordering::Relaxed) {
                if socket.recv(&mut buf).is_ok() {
                    delivered.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };

    let payload_len = if uso {
        PAYLOAD * PER_SUPERPACKET
    } else {
        PAYLOAD
    };
    let body = frame(payload_len, uso);
    let mut buf = Vec::with_capacity(VNET_HDR_LEN + body.len());
    if uso {
        buf.extend_from_slice(&vnet_header(PAYLOAD));
    }
    buf.extend_from_slice(&body);

    let per_write = if uso { PER_SUPERPACKET as u64 } else { 1 };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let cpu_before = cpu_micros();
    let started = Instant::now();
    let mut writes = 0u64;
    let mut refused = 0u64;
    while Instant::now() < deadline {
        // 64 at a time, so the clock is read once per batch rather than per
        // write: `Instant::now` is itself a syscall-shaped cost on some hosts
        // and this is measuring writes.
        for _ in 0..64 {
            // SAFETY: writing `buf.len()` bytes from a buffer of that length.
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    buf.as_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                refused += 1;
            } else {
                writes += 1;
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let cpu = cpu_micros() - cpu_before;
    stop.store(true, Ordering::Relaxed);
    let _ = drainer.join();

    let packets = writes * per_write;
    let got = delivered.load(Ordering::Relaxed);
    println!("mode            {mode}");
    println!(
        "writes          {writes} ({:.0}/s)",
        writes as f64 / elapsed
    );
    println!(
        "packets         {packets} ({:.0}k/s, {per_write} per write)",
        packets as f64 / elapsed / 1000.0
    );
    println!(
        "cpu             {:.2} us per packet, {:.2} us per write",
        cpu as f64 / packets as f64,
        cpu as f64 / writes as f64
    );
    if refused > 0 {
        println!("refused         {refused} writes returned an error");
    }
    println!(
        "delivered       {got} datagrams reached the socket ({:.1}% of those written)",
        100.0 * got as f64 / packets as f64
    );
    if got * 100 < packets * 50 {
        println!();
        println!(
            "Most of what was written did not arrive, so the per-packet figure above \
             covers the write and the segmentation but not the delivery. Treat it as a \
             bound on the write side only, and find out why before comparing the two modes."
        );
    }

    let _ = std::process::Command::new("ip")
        .args(["link", "del", DEVICE])
        .output();
}
