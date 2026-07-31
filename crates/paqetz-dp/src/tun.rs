//! The TUN device carrying inner IP packets.
//!
//! In L3 mode the kernel routes traffic into this device, we read raw IP
//! packets out of it, encrypt them, and put them on the wire. Inbound packets
//! travel the same path in reverse. Per-flow state lives in the kernel's own
//! routing and connection tracking, where it already exists and is already
//! optimised — which is the whole reason there is none in this program (D4).

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::sys::{self, IfReq};

/// `ioctl` numbers. These are not in `libc` for every target, so they are
/// spelled out; the values are architecture-independent on Linux.
pub(crate) mod ioctls {
    /// Bind a file descriptor from `/dev/net/tun` to an interface.
    pub(crate) const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
    /// Set interface flags.
    pub(crate) const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    /// Get interface flags.
    pub(crate) const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    /// Set the interface MTU.
    pub(crate) const SIOCSIFMTU: libc::c_ulong = 0x8922;
    /// Set the interface address.
    pub(crate) const SIOCSIFADDR: libc::c_ulong = 0x8916;
    /// Set the interface netmask.
    pub(crate) const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
}

/// TUN interface flags.
pub(crate) mod flags {
    /// Layer 3 device: reads and writes are bare IP packets.
    pub(crate) const IFF_TUN: i16 = 0x0001;
    /// No 4-byte protocol prefix on each packet.
    ///
    /// Without this every read and write carries a header we would have to skip
    /// or synthesise, for no benefit — we already know these are IP packets.
    pub(crate) const IFF_NO_PI: i16 = 0x1000;
}

/// The MTU an inner packet must fit within, given the tunnel's overhead.
///
/// The outer packet is: IPv4 (20) + TCP (20) + TCP options (12) + the tunnel's
/// framing overhead (28, from `paqetz-core`) = 80 bytes. Against a 1500-byte
/// path that leaves 1420, and 1400 is taken as the default for headroom — a
/// path with any additional encapsulation in front of it is common enough that
/// spending 20 bytes to avoid black-holing is worth it.
pub const DEFAULT_MTU: u32 = 1400;

/// A TUN device.
#[derive(Debug)]
pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    /// Creates or attaches to a TUN device.
    ///
    /// Requires `CAP_NET_ADMIN`.
    ///
    /// # Errors
    /// Returns the underlying OS error, with a clearer message when the failure
    /// is simply a lack of privilege.
    pub fn create(name: &str) -> io::Result<Self> {
        // Validate the name before opening anything, so a bad name costs no
        // syscall and cannot leave a descriptor behind.
        let mut req = IfReq::new(name)?;

        let fd = sys::open("/dev/net/tun", libc::O_RDWR | libc::O_CLOEXEC)
            .map_err(|e| sys::explain_privilege(e, "opening /dev/net/tun", "CAP_NET_ADMIN"))?;

        req.set_flags(flags::IFF_TUN | flags::IFF_NO_PI);
        // SAFETY: TUNSETIFF expects a pointer to an `ifreq`, which `IfReq` is
        // laid out as.
        unsafe { sys::ioctl_ptr(fd.as_raw_fd(), ioctls::TUNSETIFF, &mut req) }?;

        Ok(Self {
            fd,
            name: name.to_owned(),
        })
    }

    /// The device's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one inner IP packet. Blocks until one arrives.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        sys::read(self.fd.as_raw_fd(), buf)
    }

    /// Reads one inner IP packet if one is already waiting.
    ///
    /// Returns `Ok(None)` when nothing is queued, rather than blocking. This is
    /// what lets the outbound path collect a batch without ever waiting for one
    /// to form: block for the first packet, then take whatever else has already
    /// arrived.
    ///
    /// The descriptor is switched to non-blocking for the call and back
    /// afterwards, so a blocking read elsewhere is unaffected.
    ///
    /// # Errors
    /// Returns the underlying OS error, other than "would block".
    pub fn recv_nonblocking(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let fd = self.fd.as_raw_fd();
        sys::set_nonblocking(fd, true)?;
        let result = sys::read(fd, buf);
        sys::set_nonblocking(fd, false)?;
        match result {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Writes one inner IP packet into the kernel's stack.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        sys::write(self.fd.as_raw_fd(), packet)
    }

    /// Assigns an address and netmask, sets the MTU, and brings the link up.
    ///
    /// Done through `ioctl` rather than by invoking `ip`, so there is no
    /// dependency on which userland is installed and no output to parse.
    /// Routing is left to the caller: routes need netlink, and which routes to
    /// install is a policy question rather than a device one.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr, mtu: u32) -> io::Result<()> {
        // The address ioctls act on any socket, not on the TUN descriptor.
        let sock = sys::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)?;
        let sfd = sock.as_raw_fd();

        let mut req = IfReq::new(&self.name)?;
        req.set_addr(addr);
        // SAFETY: SIOCSIFADDR expects an `ifreq` whose payload is a sockaddr,
        // which `set_addr` has written.
        unsafe { sys::ioctl_ptr(sfd, ioctls::SIOCSIFADDR, &mut req) }?;

        let mut req = IfReq::new(&self.name)?;
        req.set_addr(netmask);
        // SAFETY: as above.
        unsafe { sys::ioctl_ptr(sfd, ioctls::SIOCSIFNETMASK, &mut req) }?;

        let mut req = IfReq::new(&self.name)?;
        let mtu = i32::try_from(mtu).map_err(|_| io::Error::other("MTU is implausibly large"))?;
        req.set_mtu(mtu);
        // SAFETY: SIOCSIFMTU expects an `ifreq` whose payload is an int.
        unsafe { sys::ioctl_ptr(sfd, ioctls::SIOCSIFMTU, &mut req) }?;

        self.set_up(sfd)?;
        Ok(())
    }

    /// Brings the link up, preserving the flags already set.
    fn set_up(&self, sfd: RawFd) -> io::Result<()> {
        let mut req = IfReq::new(&self.name)?;
        // SAFETY: SIOCGIFFLAGS expects an `ifreq` and fills in its flags.
        unsafe { sys::ioctl_ptr(sfd, ioctls::SIOCGIFFLAGS, &mut req) }?;

        // Read-modify-write rather than assigning outright: the kernel sets
        // flags of its own on the device, and clobbering them would undo them.
        let current = req.flags();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "IFF_UP and IFF_RUNNING are both within i16"
        )]
        let up = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        req.set_flags(current | up);
        // SAFETY: SIOCSIFFLAGS expects an `ifreq` whose payload is short flags.
        unsafe { sys::ioctl_ptr(sfd, ioctls::SIOCSIFFLAGS, &mut req) }?;
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_mtu_leaves_room_for_the_tunnel_overhead() {
        // Outer IPv4 + TCP + options + the core framing overhead.
        let overhead = 20 + 20 + 12 + 28;
        assert!(
            DEFAULT_MTU + overhead <= 1500,
            "an inner packet at the MTU plus overhead must fit a 1500-byte path"
        );
    }

    #[test]
    fn device_names_are_length_checked_before_any_syscall() {
        // This must stay syscall-free: the name is validated before
        // /dev/net/tun is opened, which both gives a better error and keeps
        // the default test run from touching the host's network at all.
        let too_long = "z".repeat(64);
        let err = Tun::create(&too_long).expect_err("must be rejected");
        assert!(err.to_string().contains("too long"), "got: {err}");
    }

    #[test]
    #[ignore = "creates a network device; run with --ignored in a throwaway namespace"]
    fn a_device_can_be_created_and_configured() {
        let tun = Tun::create("paqetz-t0").expect("create");
        assert_eq!(tun.name(), "paqetz-t0");
        tun.configure(
            Ipv4Addr::new(10, 7, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            DEFAULT_MTU,
        )
        .expect("configure");
    }
}
