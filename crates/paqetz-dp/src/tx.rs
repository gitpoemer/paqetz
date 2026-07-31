//! The transmit socket: a raw `IPPROTO_TCP` socket with `IP_HDRINCL`.
//!
//! We supply the IP and TCP headers ourselves; the kernel performs the route
//! lookup, resolves the next hop, and frames it for the link. That is what
//! removes the gateway MAC address from the configuration entirely — paqet
//! required the operator to look it up by hand, which broke silently whenever
//! the gateway changed, a DHCP lease moved, or the host roamed to another
//! network.
//!
//! # What the kernel fills in and what we must
//!
//! With `IP_HDRINCL` the kernel computes the IPv4 header checksum, and fills
//! the source address if we leave it zero. It does **not** compute the TCP
//! checksum: no raw-socket path does, because it has no idea what the payload
//! means. So `paqetz-tcpwire` computes it, and that cost is why the
//! `AF_PACKET` transmit path may eventually win — it can ask the NIC to do it.
//! See `docs/decisions/D8-datapath.md`.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};

use crate::sys;

/// The transmit socket.
#[derive(Debug)]
pub struct RawTx {
    fd: OwnedFd,
}

impl RawTx {
    /// Opens the socket.
    ///
    /// Requires `CAP_NET_RAW`.
    ///
    /// # Errors
    /// Returns the underlying OS error, with a clearer message when the failure
    /// is simply a lack of privilege.
    pub fn open() -> io::Result<Self> {
        let fd = sys::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
        .map_err(|e| sys::explain_privilege(e, "opening a raw transmit socket", "CAP_NET_RAW"))?;

        let on: libc::c_int = 1;
        // SAFETY: IP_HDRINCL takes an int.
        unsafe { sys::setsockopt(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, &on) }?;

        Ok(Self { fd })
    }

    /// Sends one packet, which must begin with its own IPv4 header.
    ///
    /// `dst` selects the route and must agree with the destination in the
    /// header. They are passed separately because the kernel reads the address
    /// from the socket address for routing, not from the header we supply.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
        let mut addr: libc::sockaddr_in =
            // SAFETY: `sockaddr_in` is plain old data; all-zero is a valid,
            // if meaningless, value, and every field is set below.
            unsafe { std::mem::zeroed() };
        addr.sin_family = u16::try_from(libc::AF_INET)
            .map_err(|_| io::Error::other("AF_INET does not fit in sa_family_t"))?;
        // The port is ignored for a raw socket — the header carries the real
        // one — but is zeroed rather than left arbitrary.
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());

        // SAFETY: an AF_INET socket sends to a `sockaddr_in`.
        unsafe { sys::sendto(self.fd.as_raw_fd(), packet, &addr) }
    }

    /// Sets the send buffer size, in bytes.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn set_send_buffer(&self, bytes: usize) -> io::Result<()> {
        let size = libc::c_int::try_from(bytes)
            .map_err(|_| io::Error::other("send buffer size is implausibly large"))?;
        // SAFETY: SO_SNDBUF takes an int.
        unsafe {
            sys::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size,
            )
        }
    }

    /// Stamps an `SO_MARK` on transmitted packets.
    ///
    /// Lets a policy-routing rule steer the tunnel's own traffic, which is what
    /// keeps it off an interface the forwarded traffic is being sent out of.
    /// Requires `CAP_NET_ADMIN`.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn set_mark(&self, mark: u32) -> io::Result<()> {
        let value = libc::c_int::try_from(mark)
            .map_err(|_| io::Error::other("mark does not fit in an int"))?;
        // SAFETY: SO_MARK takes an int.
        unsafe { sys::setsockopt(self.fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, &value) }
    }
}

impl std::os::fd::AsRawFd for RawTx {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "opens a raw socket; run with --ignored in a throwaway namespace"]
    fn a_socket_can_be_opened_and_tuned() {
        let tx = RawTx::open().expect("open");
        tx.set_send_buffer(4 * 1024 * 1024).expect("set buffer");
    }
}
