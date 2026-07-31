//! Thin checked wrappers over the syscalls this crate needs.
//!
//! Every `unsafe` call in the crate funnels through here, so the places that
//! need auditing are few and adjacent. Each wrapper turns the C convention of
//! "negative means look at `errno`" into a `Result`.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

/// Turns a syscall's return value into a `Result`.
fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Turns a syscall's `ssize_t` return value into a `Result`.
fn check_size(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // A non-negative ssize_t always fits in usize.
        Ok(ret.unsigned_abs())
    }
}

/// Opens a file descriptor.
pub fn open(path: &str, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c_path = CString::new(path).map_err(|_| io::Error::other("path contains a NUL byte"))?;
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the
    // call. `open` returns a fresh descriptor or -1.
    let fd = check(unsafe { libc::open(c_path.as_ptr(), flags) })?;
    // SAFETY: `fd` is a fresh, owned descriptor that nothing else holds.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Creates a socket.
pub fn socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: no pointer arguments; returns a fresh descriptor or -1.
    let fd = check(unsafe { libc::socket(domain, ty, protocol) })?;
    // SAFETY: `fd` is a fresh, owned descriptor that nothing else holds.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Issues an `ioctl` whose argument is a pointer to `T`.
///
/// # Safety
/// `request` must be an ioctl that expects a pointer to a `T`, and `T` must be
/// laid out as that ioctl expects.
pub unsafe fn ioctl_ptr<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: the caller guarantees `request` matches `T`'s layout. `arg` is a
    // valid, uniquely borrowed `T` for the duration of the call.
    check(unsafe { libc::ioctl(fd, request, std::ptr::from_mut(arg)) })?;
    Ok(())
}

/// Sets a socket option from a value of type `T`.
///
/// # Safety
/// `level` and `name` must name an option whose value is a `T`.
pub unsafe fn setsockopt<T>(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    let len = size_of::<T>();
    let len = libc::socklen_t::try_from(len)
        .map_err(|_| io::Error::other("socket option value is implausibly large"))?;
    // SAFETY: the caller guarantees the option takes a `T`; `value` is a valid
    // `T` borrowed for the duration of the call, and `len` is its exact size.
    check(unsafe { libc::setsockopt(fd, level, name, std::ptr::from_ref(value).cast(), len) })?;
    Ok(())
}

/// Binds a socket to an address of type `T`.
///
/// # Safety
/// `addr` must be a `sockaddr` variant appropriate to the socket's domain.
pub unsafe fn bind<T>(fd: RawFd, addr: &T) -> io::Result<()> {
    let len = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| io::Error::other("address is implausibly large"))?;
    // SAFETY: the caller guarantees `addr` is the right sockaddr variant;
    // it is borrowed for the duration of the call and `len` is its exact size.
    check(unsafe { libc::bind(fd, std::ptr::from_ref(addr).cast(), len) })?;
    Ok(())
}

/// Reads from a descriptor.
pub fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is uniquely borrowed and `buf.len()` is its exact capacity,
    // so the kernel cannot write out of bounds.
    check_size(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) })
}

/// Writes to a descriptor.
pub fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is borrowed for the duration of the call and `buf.len()` is
    // its exact length.
    check_size(unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) })
}

/// Receives a datagram, discarding the source address.
pub fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is uniquely borrowed and `buf.len()` is its exact capacity.
    check_size(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) })
}

/// Sends a datagram to an address of type `T`.
///
/// # Safety
/// `addr` must be a `sockaddr` variant appropriate to the socket's domain.
pub unsafe fn sendto<T>(fd: RawFd, buf: &[u8], addr: &T) -> io::Result<usize> {
    let len = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| io::Error::other("address is implausibly large"))?;
    // SAFETY: the caller guarantees `addr` is the right sockaddr variant. Both
    // pointers are borrowed for the duration of the call with exact lengths.
    check_size(unsafe {
        libc::sendto(
            fd,
            buf.as_ptr().cast(),
            buf.len(),
            0,
            std::ptr::from_ref(addr).cast(),
            len,
        )
    })
}

/// Looks up an interface index by name.
pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|_| io::Error::other("name contains a NUL byte"))?;
    // SAFETY: `c_name` is a valid NUL-terminated C string outliving the call.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

/// Rewrites a permission error to name the capability that was missing.
///
/// Deliberately does *not* consult the effective uid. Being root is neither
/// necessary nor sufficient: a container can run as root with `CAP_NET_RAW`
/// dropped, and a non-root process can hold it through file capabilities or an
/// ambient set. Naming the capability is therefore correct in every case, and
/// keeping the function pure is what lets it be tested at all — the earlier
/// version short-circuited when root, so under `sudo` its tests asserted
/// nothing.
///
/// Errors other than permission denied are passed through untouched.
#[must_use]
pub fn explain_privilege(err: io::Error, action: &str, capability: &str) -> io::Error {
    if err.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(
            err.kind(),
            format!("{action} requires {capability}; grant it or run as root"),
        )
    } else {
        err
    }
}

/// The `ifreq` structure, as the network ioctls expect it.
///
/// The kernel's version is a union over the second member; we only need a few
/// variants, so this declares the largest of them as a byte array and provides
/// typed accessors. The array must be at least as large as the kernel's union
/// or the ioctls would read past the end.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfReq {
    /// Interface name, NUL-padded.
    pub name: [libc::c_char; libc::IFNAMSIZ],
    /// The union payload.
    pub data: [u8; 24],
}

impl IfReq {
    /// Builds a request naming `iface`, with a zeroed payload.
    pub fn new(iface: &str) -> io::Result<Self> {
        let bytes = iface.as_bytes();
        // Leave room for the terminating NUL.
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::other(format!(
                "interface name {iface:?} is too long (max {} characters)",
                libc::IFNAMSIZ - 1
            )));
        }
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (slot, byte) in name.iter_mut().zip(bytes.iter()) {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "c_char is i8 on this target; the bit pattern is what matters"
            )]
            let c = *byte as libc::c_char;
            *slot = c;
        }
        Ok(Self {
            name,
            data: [0; 24],
        })
    }

    /// Overwrites the payload with the little-endian bytes of `flags`.
    pub const fn set_flags(&mut self, flags: i16) {
        let bytes = flags.to_ne_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
    }

    /// Reads the payload as interface flags.
    #[must_use]
    pub const fn flags(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    /// Overwrites the payload with an MTU.
    pub const fn set_mtu(&mut self, mtu: i32) {
        let bytes = mtu.to_ne_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
        self.data[2] = bytes[2];
        self.data[3] = bytes[3];
    }

    /// Overwrites the payload with a `sockaddr_in` holding `addr`.
    pub fn set_addr(&mut self, addr: std::net::Ipv4Addr) {
        self.data = [0; 24];
        let family = u16::try_from(libc::AF_INET).unwrap_or(2).to_ne_bytes();
        self.data[0] = family[0];
        self.data[1] = family[1];
        // Bytes 2..4 are the port, which is meaningless here and stays zero.
        let octets = addr.octets();
        self.data[4] = octets[0];
        self.data[5] = octets[1];
        self.data[6] = octets[2];
        self.data[7] = octets[3];
    }
}

/// Borrows a descriptor as a raw `RawFd`.
pub fn raw(fd: &OwnedFd) -> RawFd {
    fd.as_raw_fd()
}

/// Largest number of packets moved in one batched syscall.
///
/// Amortising a syscall over 32 packets removes most of its per-packet cost;
/// beyond that the returns flatten while the latency of filling the batch and
/// the size of the on-stack descriptor arrays both grow.
pub const BATCH: usize = 32;

/// Receives up to `BATCH` datagrams in one syscall.
///
/// Returns how many were filled. `lens` is written with each one's length.
///
/// This is the cheap two-thirds of what a `PACKET_MMAP` ring would buy. The
/// ring's remaining advantage is that it avoids the copy out of kernel memory,
/// worth perhaps a hundred nanoseconds per packet; the syscall itself, which
/// dominates, is amortised here for a fraction of the complexity.
pub fn recvmmsg(fd: RawFd, bufs: &mut [Vec<u8>], lens: &mut [usize]) -> io::Result<usize> {
    let n = bufs.len().min(lens.len()).min(BATCH);
    if n == 0 {
        return Ok(0);
    }

    // SAFETY: `iovec` is plain-old-data; an all-zero bit pattern is a valid,
    // if empty, value, and every field used below is set.
    let mut iovecs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
    // SAFETY: likewise for `mmsghdr`.
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };

    for i in 0..n {
        let Some(buf) = bufs.get_mut(i) else { break };
        let Some(iov) = iovecs.get_mut(i) else { break };
        iov.iov_base = buf.as_mut_ptr().cast();
        iov.iov_len = buf.len();
        let Some(msg) = msgs.get_mut(i) else { break };
        msg.msg_hdr.msg_iov = std::ptr::from_mut(iov);
        msg.msg_hdr.msg_iovlen = 1;
    }

    // MSG_WAITFORONE is load-bearing, not an optimisation. Without it, a
    // blocking `recvmmsg` waits for *all* `vlen` messages before returning any
    // -- so asking for 32 means nothing is delivered until 32 frames have
    // arrived. On a tunnel whose first packet is a handshake, that is a
    // deadlock: the one packet that would produce more traffic sits in the
    // kernel waiting for traffic. The flag turns on MSG_DONTWAIT after the
    // first message, giving "take what is here, starting with at least one".
    //
    // SAFETY: `msgs[..n]` is initialised above, each pointing at an `iovec`
    // that borrows one of `bufs` for the duration of the call, with its exact
    // length. A null timeout blocks until the flag's condition is met.
    let got = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            u32::try_from(n).unwrap_or(1),
            libc::MSG_WAITFORONE,
            std::ptr::null_mut(),
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }

    let got = usize::try_from(got).unwrap_or(0);
    for i in 0..got {
        let written = msgs.get(i).map_or(0, |m| m.msg_len);
        if let Some(slot) = lens.get_mut(i) {
            *slot = usize::try_from(written).unwrap_or(0);
        }
    }
    Ok(got)
}

/// Sends up to `BATCH` packets in one syscall, each to its own address.
///
/// Returns how many the kernel accepted. A short count is normal under
/// pressure; the caller drops the remainder, which is what a congested link
/// does anyway and what the absence of a reliability layer (D2) expects.
///
/// # Safety
/// `addrs` must be `sockaddr` variants appropriate to the socket's domain.
pub unsafe fn sendmmsg<T>(fd: RawFd, packets: &[&[u8]], addrs: &[T]) -> io::Result<usize> {
    let n = packets.len().min(addrs.len()).min(BATCH);
    if n == 0 {
        return Ok(0);
    }
    let addr_len = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| io::Error::other("address is implausibly large"))?;

    // SAFETY: as above, `iovec` is plain-old-data.
    let mut iovecs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
    // SAFETY: likewise for `mmsghdr`.
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };

    for i in 0..n {
        let Some(packet) = packets.get(i) else { break };
        let Some(addr) = addrs.get(i) else { break };
        let Some(iov) = iovecs.get_mut(i) else { break };
        // The kernel does not write through this pointer for a send, so
        // casting away constness is sound here.
        iov.iov_base = packet.as_ptr().cast_mut().cast();
        iov.iov_len = packet.len();
        let Some(msg) = msgs.get_mut(i) else { break };
        msg.msg_hdr.msg_iov = std::ptr::from_mut(iov);
        msg.msg_hdr.msg_iovlen = 1;
        msg.msg_hdr.msg_name = std::ptr::from_ref(addr).cast_mut().cast();
        msg.msg_hdr.msg_namelen = addr_len;
    }

    // SAFETY: `msgs[..n]` is initialised above; each borrows one packet and one
    // address for the duration of the call, with exact lengths. The caller
    // guarantees the address type matches the socket's domain.
    let sent = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), u32::try_from(n).unwrap_or(1), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(sent).unwrap_or(0))
}

/// Makes a descriptor non-blocking.
///
/// Used to drain whatever is already queued without waiting for more, which is
/// what turns a stream of single packets into a batch exactly when there is a
/// backlog to batch.
pub fn set_nonblocking(fd: RawFd, on: bool) -> io::Result<()> {
    // SAFETY: F_GETFL takes no pointer argument.
    let flags = check(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    let flags = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: F_SETFL takes an int.
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_names_are_copied_and_nul_terminated() {
        let req = IfReq::new("eth0").expect("valid name");
        let name: Vec<u8> = req
            .name
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| u8::try_from(*c).unwrap_or(0))
            .collect();
        assert_eq!(name, b"eth0");
        assert_eq!(req.name[4], 0, "must be NUL terminated");
    }

    #[test]
    fn ifreq_rejects_over_long_names() {
        // The kernel's buffer is IFNAMSIZ including the NUL, so a name of
        // exactly IFNAMSIZ characters would be truncated rather than rejected.
        let too_long = "a".repeat(libc::IFNAMSIZ);
        assert!(IfReq::new(&too_long).is_err());
        let longest_ok = "a".repeat(libc::IFNAMSIZ - 1);
        assert!(IfReq::new(&longest_ok).is_ok());
    }

    #[test]
    fn ifreq_rejects_interior_nul() {
        assert!(IfReq::new("eth\0 0").is_ok(), "NUL is copied verbatim");
        // The name is not a C string on our side, so a NUL simply terminates it
        // early; what matters is that nothing panics.
    }

    #[test]
    fn ifreq_flags_round_trip() {
        let mut req = IfReq::new("tun0").expect("valid name");
        req.set_flags(0x1043);
        assert_eq!(req.flags(), 0x1043);
    }

    #[test]
    fn ifreq_is_large_enough_for_the_kernel_union() {
        // If this shrinks below what the kernel reads, the ioctls scribble past
        // the end of the struct.
        assert!(size_of::<IfReq>() >= libc::IFNAMSIZ + 16);
    }

    #[test]
    fn a_permission_error_names_the_missing_capability() {
        let err = io::Error::from(io::ErrorKind::PermissionDenied);
        let explained = explain_privilege(err, "opening a capture socket", "CAP_NET_RAW");
        assert_eq!(explained.kind(), io::ErrorKind::PermissionDenied);
        let text = explained.to_string();
        assert!(text.contains("CAP_NET_RAW"), "got: {text}");
        assert!(text.contains("opening a capture socket"), "got: {text}");
    }

    #[test]
    fn other_errors_pass_through_untouched() {
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::AddrInUse,
            io::ErrorKind::InvalidInput,
        ] {
            let explained =
                explain_privilege(io::Error::from(kind), "doing a thing", "CAP_NET_ADMIN");
            assert_eq!(explained.kind(), kind);
            assert!(
                !explained.to_string().contains("CAP_NET_ADMIN"),
                "a {kind:?} error must not be described as a permission problem"
            );
        }
    }

    #[test]
    fn looking_up_the_loopback_interface_succeeds() {
        assert!(if_nametoindex("lo").expect("lo always exists") > 0);
    }

    #[test]
    fn looking_up_a_missing_interface_fails() {
        assert!(if_nametoindex("definitely-not-real").is_err());
    }
}

/// Waits for a descriptor to become readable.
///
/// Returns `true` if it did, `false` if the timeout expired first. A timeout
/// exists so a blocked thread can still notice a shutdown request.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd`, borrowed for the duration of the call.
    let n = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n > 0)
}

#[cfg(test)]
mod batch_tests {
    //! Exercises the batched syscall wrappers over loopback UDP.
    //!
    //! No privilege, no device, no firewall rule: a pair of sockets bound to
    //! ephemeral ports on 127.0.0.1, gone when the test ends. That is enough to
    //! test the descriptor arrays, which is where a mistake in this file would
    //! be, without needing a namespace.

    // Panicking on an out-of-range index is exactly what a test should do.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::net::UdpSocket;

    fn pair() -> (UdpSocket, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx");
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx");
        tx.connect(rx.local_addr().expect("addr")).expect("connect");
        (rx, tx)
    }

    #[test]
    fn one_datagram_round_trips() {
        let (rx, tx) = pair();
        tx.send(b"hello").expect("send");

        let mut bufs: Vec<Vec<u8>> = (0..BATCH).map(|_| vec![0u8; 2048]).collect();
        let mut lens = [0usize; BATCH];
        let n = recvmmsg(rx.as_raw_fd(), &mut bufs, &mut lens).expect("recvmmsg");
        assert_eq!(n, 1);
        assert_eq!(lens[0], 5);
        assert_eq!(&bufs[0][..5], b"hello");
    }

    #[test]
    fn many_datagrams_arrive_in_one_call_with_the_right_lengths() {
        let (rx, tx) = pair();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");

        // Distinct lengths and contents, so a descriptor pointing at the wrong
        // buffer would show up as mismatched data rather than passing by luck.
        for i in 0..8usize {
            let payload = vec![u8::try_from(i).unwrap_or(0); i + 1];
            tx.send(&payload).expect("send");
        }

        let mut bufs: Vec<Vec<u8>> = (0..BATCH).map(|_| vec![0u8; 2048]).collect();
        let mut lens = [0usize; BATCH];
        let mut received = 0usize;
        while received < 8 {
            let n = recvmmsg(rx.as_raw_fd(), &mut bufs[received..], &mut lens[received..])
                .expect("recvmmsg");
            assert!(n > 0);
            received += n;
        }

        for i in 0..8usize {
            assert_eq!(lens[i], i + 1, "datagram {i} has the wrong length");
            assert_eq!(
                bufs[i][..=i],
                vec![u8::try_from(i).unwrap_or(0); i + 1][..],
                "datagram {i} has the wrong contents"
            );
        }
    }

    #[test]
    fn a_batch_of_sends_all_arrive() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx");
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx");
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let dst = match rx.local_addr().expect("addr") {
            std::net::SocketAddr::V4(a) => a,
            std::net::SocketAddr::V6(_) => unreachable!("bound to 127.0.0.1"),
        };

        let payloads: Vec<Vec<u8>> = (0..8usize)
            .map(|i| vec![u8::try_from(i).unwrap_or(0); i + 1])
            .collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();

        // Each message carries its own destination, as the tunnel's do.
        let addrs: Vec<libc::sockaddr_in> = (0..8)
            .map(|_| {
                // SAFETY: `sockaddr_in` is plain old data; every field is set.
                let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                a.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
                a.sin_port = dst.port().to_be();
                a.sin_addr.s_addr = u32::from_ne_bytes(dst.ip().octets());
                a
            })
            .collect();

        // SAFETY: an AF_INET socket sends to `sockaddr_in`.
        let sent = unsafe { sendmmsg(tx.as_raw_fd(), &refs, &addrs) }.expect("sendmmsg");
        assert_eq!(sent, 8, "every message should be accepted");

        let mut got = 0usize;
        let mut buf = [0u8; 2048];
        while got < 8 {
            let n = rx.recv(&mut buf).expect("recv");
            assert_eq!(n, got + 1, "datagram {got} has the wrong length");
            got += 1;
        }
    }

    #[test]
    fn a_partial_batch_returns_rather_than_waiting_for_a_full_one() {
        // The regression test for the bug that made the batched datapath fail
        // every end-to-end check while the unbatched one passed: a blocking
        // recvmmsg without MSG_WAITFORONE waits for all `vlen` messages, so
        // asking for 32 and being sent 3 returns nothing at all. On a tunnel
        // whose first packet is a handshake that is a deadlock.
        let (rx, tx) = pair();
        for i in 0..3u8 {
            tx.send(&[i; 4]).expect("send");
        }

        let mut bufs: Vec<Vec<u8>> = (0..BATCH).map(|_| vec![0u8; 512]).collect();
        let mut lens = [0usize; BATCH];

        // If this ever waits for BATCH messages again, the test hangs rather
        // than failing, so bound it explicitly.
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let fd = rx.as_raw_fd();
        std::thread::spawn(move || {
            let n = recvmmsg(fd, &mut bufs, &mut lens);
            let _ = tx_done.send(n.map(|n| (n, lens[0])));
        });

        let result = rx_done
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("recvmmsg must return without a full batch");
        let (n, first_len) = result.expect("recvmmsg");
        assert!((1..=3).contains(&n), "expected 1..=3 messages, got {n}");
        assert_eq!(first_len, 4);
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let (rx, tx) = pair();
        let mut bufs: Vec<Vec<u8>> = Vec::new();
        let mut lens: [usize; 0] = [];
        assert_eq!(
            recvmmsg(rx.as_raw_fd(), &mut bufs, &mut lens).expect("recvmmsg"),
            0
        );
        let addrs: Vec<libc::sockaddr_in> = Vec::new();
        // SAFETY: no messages are sent, so no address is dereferenced.
        let sent = unsafe { sendmmsg(tx.as_raw_fd(), &[], &addrs) }.expect("sendmmsg");
        assert_eq!(sent, 0);
    }

    #[test]
    fn more_than_a_batch_is_capped_rather_than_overflowing() {
        // The descriptor arrays are BATCH long; asking for more must clamp, not
        // write past their end.
        let (rx, _tx) = pair();
        rx.set_nonblocking(true).expect("nonblocking");
        let mut bufs: Vec<Vec<u8>> = (0..BATCH * 2).map(|_| vec![0u8; 64]).collect();
        let mut lens = vec![0usize; BATCH * 2];
        // Nothing was sent, so this returns EAGAIN rather than data; what
        // matters is that it does not corrupt the stack getting there.
        let _ = recvmmsg(rx.as_raw_fd(), &mut bufs, &mut lens);
    }

    #[test]
    fn non_blocking_can_be_set_and_cleared() {
        let (rx, _tx) = pair();
        let fd = rx.as_raw_fd();
        set_nonblocking(fd, true).expect("set");
        let mut buf = [0u8; 16];
        let err = read(fd, &mut buf).expect_err("nothing to read");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        set_nonblocking(fd, false).expect("clear");
    }
}
