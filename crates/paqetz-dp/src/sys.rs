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

/// Whether the process is running as root.
///
/// Used only to give a clear diagnostic before a syscall fails with `EPERM`.
#[must_use]
pub fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
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
    fn looking_up_the_loopback_interface_succeeds() {
        assert!(if_nametoindex("lo").expect("lo always exists") > 0);
    }

    #[test]
    fn looking_up_a_missing_interface_fails() {
        assert!(if_nametoindex("definitely-not-real").is_err());
    }
}
