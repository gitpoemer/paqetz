//! The capture socket: `AF_PACKET` with a kernel-side BPF filter.
//!
//! This is the half of the datapath that bypasses the host's TCP/IP stack on
//! ingress. Frames are taken from the device before `netfilter` sees them, so
//! a local firewall rule on our port has no effect on the tunnel — which is
//! the property paqet was built around and is preserved here.

use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};

use crate::bpf;
use crate::sys;

/// `SO_ATTACH_FILTER`, for installing a classic-BPF program.
const SO_ATTACH_FILTER: libc::c_int = 26;

/// `PACKET_IGNORE_OUTGOING`, Linux 4.20 and later.
///
/// Without it the socket also sees the frames we transmit, so every packet we
/// send comes straight back to be parsed and discarded — wasted work
/// proportional to send rate. paqet achieved the same thing with libpcap's
/// direction setting, which it had to skip on Windows.
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;

/// The IPv4 EtherType in network byte order, which is how both the socket's
/// protocol argument and `sockaddr_ll` want it.
///
/// `libc` types `ETH_P_IP` as an `i32` even though it is a 16-bit EtherType,
/// so it is written out rather than narrowed with a cast.
const ETH_P_IP_BE: u16 = 0x0800_u16.to_be();

// Pin the hand-written value to libc's, so the two cannot drift apart.
const _: () = assert!(libc::ETH_P_IP == 0x0800);

/// A classic-BPF program, as `SO_ATTACH_FILTER` expects it.
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const bpf::Insn,
}

/// The capture socket.
#[derive(Debug)]
pub struct PacketRx {
    fd: OwnedFd,
    /// Kept alive because the kernel copies the program at attach time, but
    /// holding it makes the ownership obvious and costs 88 bytes.
    _program: Box<[bpf::Insn; bpf::PROGRAM_LEN]>,
}

impl PacketRx {
    /// Opens a capture socket bound to one interface, filtered to one port.
    ///
    /// Requires `CAP_NET_RAW`.
    ///
    /// # Errors
    /// Returns the underlying OS error, with a clearer message when the failure
    /// is simply a lack of privilege.
    pub fn open(interface: &str, port: u16) -> io::Result<Self> {
        let ifindex = sys::if_nametoindex(interface)?;

        // ETH_P_ALL would also deliver non-IP frames, which the filter would
        // then have to reject; ETH_P_IP narrows it before the filter runs.
        let proto = i32::from(ETH_P_IP_BE);
        let fd = sys::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto).map_err(
            |e| {
                if e.kind() == io::ErrorKind::PermissionDenied && !sys::is_root() {
                    io::Error::new(
                        e.kind(),
                        "opening a capture socket requires CAP_NET_RAW (try running as root)",
                    )
                } else {
                    e
                }
            },
        )?;
        let raw = fd.as_raw_fd();

        // Attach the filter *before* binding. Between bind and attach a socket
        // is unfiltered, so frames matching nothing can queue up and be
        // delivered later; attaching first closes that window.
        let program = Box::new(bpf::program(port));
        let prog = SockFprog {
            len: libc::c_ushort::try_from(bpf::PROGRAM_LEN)
                .map_err(|_| io::Error::other("filter program is implausibly long"))?,
            filter: program.as_ptr(),
        };
        // SAFETY: SO_ATTACH_FILTER takes a `sock_fprog`, which `SockFprog`
        // matches. `program` outlives the call, and the kernel copies the
        // instructions rather than retaining the pointer.
        unsafe { sys::setsockopt(raw, libc::SOL_SOCKET, SO_ATTACH_FILTER, &prog) }?;

        // Not fatal if unsupported: on a kernel older than 4.20 we simply see
        // our own transmissions and drop them a layer up.
        let on: libc::c_int = 1;
        // SAFETY: PACKET_IGNORE_OUTGOING takes an int.
        let _ = unsafe { sys::setsockopt(raw, libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, &on) };

        let mut addr: libc::sockaddr_ll =
            // SAFETY: `sockaddr_ll` is a plain-old-data struct for which an
            // all-zero bit pattern is a valid, if unbound, value.
            unsafe { std::mem::zeroed() };
        addr.sll_family = u16::try_from(libc::AF_PACKET)
            .map_err(|_| io::Error::other("AF_PACKET does not fit in sa_family_t"))?;
        addr.sll_protocol = ETH_P_IP_BE;
        addr.sll_ifindex = i32::try_from(ifindex)
            .map_err(|_| io::Error::other("interface index is implausibly large"))?;
        // SAFETY: an AF_PACKET socket binds with a `sockaddr_ll`.
        unsafe { sys::bind(raw, &addr) }?;

        Ok(Self {
            fd,
            _program: program,
        })
    }

    /// Receives one frame. Blocks until one arrives.
    ///
    /// The frame starts at the Ethernet header, which is what
    /// `paqetz_tcpwire::segment::parse_ethernet` expects.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        sys::recv(self.fd.as_raw_fd(), buf)
    }

    /// Sets the receive buffer size, in bytes.
    ///
    /// The kernel doubles the value internally for bookkeeping. A larger buffer
    /// absorbs bursts that would otherwise be dropped between our reads; paqet
    /// defaulted the equivalent to 8 MiB on the server.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn set_recv_buffer(&self, bytes: usize) -> io::Result<()> {
        let size = libc::c_int::try_from(bytes)
            .map_err(|_| io::Error::other("receive buffer size is implausibly large"))?;
        // SAFETY: SO_RCVBUF takes an int.
        unsafe {
            sys::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size,
            )
        }
    }

    /// Returns how many packets the kernel has dropped for want of buffer
    /// space, since the previous call.
    ///
    /// The counter resets on read, so each call reports the interval since the
    /// last. paqet's deployment guide told operators to watch this number, but
    /// its binary never exposed it (D10).
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn drops(&self) -> io::Result<u32> {
        #[repr(C)]
        #[derive(Default)]
        struct TpacketStats {
            packets: libc::c_uint,
            drops: libc::c_uint,
        }
        let mut stats = TpacketStats::default();
        let mut len = libc::socklen_t::try_from(size_of::<TpacketStats>())
            .map_err(|_| io::Error::other("stats struct is implausibly large"))?;
        // SAFETY: PACKET_STATISTICS fills a `tpacket_stats`, which
        // `TpacketStats` matches; `len` is its exact size and is updated in
        // place by the kernel.
        let ret = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                std::ptr::from_mut(&mut stats).cast(),
                &raw mut len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stats.drops)
    }
}

impl std::os::fd::AsRawFd for PacketRx {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "opens a raw socket; run with --ignored in a throwaway namespace"]
    fn opening_without_privilege_explains_why() {
        if sys::is_root() {
            return;
        }
        let err = PacketRx::open("lo", 9999).expect_err("must fail unprivileged");
        assert!(
            err.to_string().contains("CAP_NET_RAW"),
            "the message should say what is missing, got: {err}"
        );
    }

    #[test]
    fn a_missing_interface_fails_before_the_socket_is_opened() {
        // The interface lookup runs first, so this fails the same way whether
        // or not we are privileged.
        assert!(PacketRx::open("definitely-not-real", 9999).is_err());
    }

    #[test]
    fn the_filter_program_struct_matches_the_kernel_layout() {
        // `sock_fprog` is a u16 length followed by a pointer, so with alignment
        // padding it is two pointer-sized words. If this changes, the kernel
        // reads a different structure than the one we wrote.
        assert_eq!(size_of::<SockFprog>(), 2 * size_of::<*const u8>());
        assert_eq!(align_of::<SockFprog>(), align_of::<*const u8>());
    }

    #[test]
    #[ignore = "opens a raw socket; run with --ignored in a throwaway namespace"]
    fn a_socket_can_be_opened_on_loopback() {
        let rx = PacketRx::open("lo", 9999).expect("open");
        rx.set_recv_buffer(4 * 1024 * 1024).expect("set buffer");
        assert_eq!(rx.drops().expect("drops"), 0);
    }
}
