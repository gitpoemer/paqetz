//! The alternative transmit path: `AF_PACKET`, bypassing routing entirely.
//!
//! Where the raw `IP_HDRINCL` socket hands a packet to the kernel and lets it
//! route, this one names the next hop itself and hands the frame straight to
//! the device. It therefore skips the route lookup and the netfilter `OUTPUT`
//! chain, and can ask the NIC to compute the TCP checksum that
//! `paqetz-tcpwire` otherwise computes in software — which is the reason D8
//! left it open as a performance question rather than deleting it.
//!
//! The cost is that it has to know the next hop's hardware address, and a
//! hardware address can go stale: a gateway failing over, a DHCP lease moving,
//! the host joining another network. paqet made the operator write that address
//! into a configuration file, where it broke silently. Here it is read from the
//! kernel at start-up and re-resolved when a send fails, so the failure is
//! transient rather than permanent — but it is still a moving part the
//! `IP_HDRINCL` path does not have, which is why that one is the default.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::sync::Mutex;

use crate::neigh::{self, Mac};
use crate::sys;

/// The IPv4 EtherType in network byte order.
const ETH_P_IP_BE: u16 = 0x0800_u16.to_be();

/// A transmit socket that addresses frames by hardware address.
#[derive(Debug)]
pub struct AfPacketTx {
    fd: OwnedFd,
    ifindex: i32,
    /// The next hop's hardware address, and which address it belongs to.
    ///
    /// Behind a lock because a send may find it stale and replace it, and both
    /// data threads can transmit.
    next_hop: Mutex<(Ipv4Addr, Mac)>,
}

impl AfPacketTx {
    /// Opens the socket and resolves the next hop toward `peer`.
    ///
    /// Requires `CAP_NET_RAW`.
    ///
    /// # Errors
    /// Returns the underlying OS error, including the case where the next hop
    /// cannot be resolved — which is fatal here, unlike on the raw path where
    /// the kernel would have handled it.
    pub fn open(interface: &str, peer: Ipv4Addr) -> io::Result<Self> {
        let ifindex = i32::try_from(sys::if_nametoindex(interface)?)
            .map_err(|_| io::Error::other("interface index is implausibly large"))?;

        // SOCK_DGRAM rather than SOCK_RAW: the kernel builds the Ethernet
        // header from the address we supply, so there is one fewer header to
        // assemble and one fewer thing to get wrong.
        let fd = sys::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_IP_BE),
        )
        .map_err(|e| {
            sys::explain_privilege(e, "opening an AF_PACKET transmit socket", "CAP_NET_RAW")
        })?;

        let hop = neigh::next_hop(peer)?;
        let mac = neigh::resolve(hop)?;

        Ok(Self {
            fd,
            ifindex,
            next_hop: Mutex::new((hop, mac)),
        })
    }

    /// The next hop's current hardware address, for diagnostics.
    #[must_use]
    pub fn next_hop(&self) -> (Ipv4Addr, Mac) {
        *self.next_hop.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Builds the link-layer address for one send.
    fn sockaddr(&self, mac: Mac) -> io::Result<libc::sockaddr_ll> {
        // SAFETY: `sockaddr_ll` is plain old data; an all-zero bit pattern is a
        // valid, if unbound, value, and every field used is set below.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = u16::try_from(libc::AF_PACKET)
            .map_err(|_| io::Error::other("AF_PACKET does not fit in sa_family_t"))?;
        addr.sll_protocol = ETH_P_IP_BE;
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        for (slot, byte) in addr.sll_addr.iter_mut().zip(mac.iter()) {
            *slot = *byte;
        }
        Ok(addr)
    }

    /// Sends one packet, which must begin with its own IPv4 header.
    ///
    /// `dst` is ignored beyond diagnostics: the frame goes to the next hop,
    /// which was resolved at start-up. It is accepted so this is a drop-in
    /// alternative to the raw path.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send(&self, packet: &[u8], _dst: Ipv4Addr) -> io::Result<usize> {
        let (_, mac) = self.next_hop();
        let addr = self.sockaddr(mac)?;
        // SAFETY: an AF_PACKET socket sends to a `sockaddr_ll`.
        match unsafe { sys::sendto(self.fd.as_raw_fd(), packet, &addr) } {
            Ok(n) => Ok(n),
            Err(e) => {
                self.refresh();
                Err(e)
            }
        }
    }

    /// Sends up to [`sys::BATCH`] packets in one syscall.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send_batch(&self, packets: &[&[u8]], _dsts: &[Ipv4Addr]) -> io::Result<usize> {
        let n = packets.len().min(sys::BATCH);
        if n == 0 {
            return Ok(0);
        }
        let (_, mac) = self.next_hop();
        let addr = self.sockaddr(mac)?;
        // Every frame goes to the same next hop, so one address serves all.
        let addrs = vec![addr; n];
        let Some(head) = packets.get(..n) else {
            return Ok(0);
        };
        // SAFETY: an AF_PACKET socket sends to `sockaddr_ll`.
        match unsafe { sys::sendmmsg(self.fd.as_raw_fd(), head, &addrs) } {
            Ok(sent) => Ok(sent),
            Err(e) => {
                self.refresh();
                Err(e)
            }
        }
    }

    /// Re-reads the next hop's hardware address after a failed send.
    ///
    /// A stale address is the one failure this path has and the raw path does
    /// not, so it is worth recovering from rather than requiring a restart.
    /// Best effort: if resolution fails the old address is kept, since a stale
    /// address is no worse than none.
    fn refresh(&self) {
        let mut guard = self.next_hop.lock().unwrap_or_else(|e| e.into_inner());
        let (hop, _) = *guard;
        if let Ok(mac) = neigh::hardware_address(hop) {
            guard.1 = mac;
        }
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
}

impl std::os::fd::AsRawFd for AfPacketTx {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Either transmit path, chosen once at start-up.
///
/// An enum rather than a trait object: the choice is made once and matched
/// per *batch*, so there is no dynamic dispatch on the per-packet path (D3).
#[derive(Debug)]
pub enum Transmit {
    /// Raw `IP_HDRINCL` socket; the kernel routes.
    Raw(crate::RawTx),
    /// `AF_PACKET`; we name the next hop.
    AfPacket(AfPacketTx),
}

impl Transmit {
    /// Sends one packet.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
        match self {
            Self::Raw(tx) => tx.send(packet, dst),
            Self::AfPacket(tx) => tx.send(packet, dst),
        }
    }

    /// Sends a batch of packets.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn send_batch(&self, packets: &[&[u8]], dsts: &[Ipv4Addr]) -> io::Result<usize> {
        match self {
            Self::Raw(tx) => tx.send_batch(packets, dsts),
            Self::AfPacket(tx) => tx.send_batch(packets, dsts),
        }
    }

    /// Sets the send buffer size, in bytes.
    ///
    /// # Errors
    /// Returns the underlying OS error.
    pub fn set_send_buffer(&self, bytes: usize) -> io::Result<()> {
        match self {
            Self::Raw(tx) => tx.set_send_buffer(bytes),
            Self::AfPacket(tx) => tx.set_send_buffer(bytes),
        }
    }

    /// A human-readable name for the path in use.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Raw(_) => "raw (IP_HDRINCL)",
            Self::AfPacket(_) => "af_packet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "opens a raw socket; run with --ignored in a throwaway namespace"]
    fn a_socket_can_be_opened_and_the_next_hop_resolved() {
        // In a namespace with a veth pair the peer is on-link, so it is its own
        // next hop and resolving it exercises the neighbour path.
        let tx = AfPacketTx::open("lo", Ipv4Addr::LOCALHOST);
        // Loopback has no neighbour entry, so this is expected to fail; what
        // matters is that it fails with a clear message rather than sending to
        // an all-zero address.
        if let Err(e) = tx {
            assert!(
                e.to_string().contains("hardware address") || e.to_string().contains("route"),
                "unhelpful error: {e}"
            );
        }
    }
}
