//! Datapath: raw transmit, `AF_PACKET` receive, TUN device (decision D8).
//!
//! Linux only, by decision — so there is one implementation, not a matrix of
//! `cfg` branches. No libpcap and no FFI beyond `libc`, which removes the
//! per-packet allocation the Go implementation paid across the CGo bridge.
//!
//! Transmit is a raw `IPPROTO_TCP` socket with `IP_HDRINCL`: we supply the IP
//! and TCP headers and the kernel handles routing, ARP, and L2 framing, so no
//! gateway MAC address appears in the configuration. Receive is `AF_PACKET`
//! with a kernel-side BPF filter.
//!
//! # Batching
//!
//! Both directions can move up to [`sys::BATCH`] packets per syscall, via
//! `recvmmsg` and `sendmmsg`. That is the large, cheap part of what a
//! `PACKET_MMAP` ring would buy: the syscall dominates the per-packet cost, and
//! it is amortised here for a few dozen lines rather than a few hundred of ring
//! management. What a ring would still add is avoiding the copy out of kernel
//! memory — worth roughly a hundred nanoseconds per packet against a budget
//! where the AEAD is nearer a thousand. Deferred on those grounds, not
//! forgotten.
//!
//! Still absent, and honestly so: `PACKET_FANOUT` across workers, and TUN
//! segmentation offload via `IFF_VNET_HDR`. The latter needs re-segmenting TCP
//! super-packets in userspace, which is several hundred lines of its own.

pub mod bpf;
pub mod neigh;
pub mod rx;
pub mod sys;
pub mod tun;
pub mod tx;
pub mod tx_afpacket;

pub use rx::PacketRx;
pub use tun::Tun;
pub use tx::RawTx;
pub use tx_afpacket::{AfPacketTx, Transmit};

/// Largest frame this crate will read or write.
///
/// Comfortably above any Ethernet MTU, so a jumbo frame is truncated rather
/// than overflowing anything.
pub const MAX_FRAME: usize = 9216;
