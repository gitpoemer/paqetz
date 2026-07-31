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
//! # Scope
//!
//! This phase implements the datapath correctly, not yet quickly. Reads and
//! writes are one syscall per packet. The `PACKET_MMAP` receive ring,
//! `PACKET_FANOUT` across workers, `sendmmsg` batching, and TUN GSO via
//! `IFF_VNET_HDR` all belong to the throughput phase and are deliberately
//! absent here — landing several hundred lines of ring-buffer `unsafe` before
//! anything works end to end would be the wrong order. See
//! `docs/08-rewrite-plan.md` §8.5 phase 3.

pub mod bpf;
pub mod rx;
pub mod sys;
pub mod tun;
pub mod tx;

pub use rx::PacketRx;
pub use tun::Tun;
pub use tx::RawTx;

/// Largest frame this crate will read or write.
///
/// Comfortably above any Ethernet MTU, so a jumbo frame is truncated rather
/// than overflowing anything.
pub const MAX_FRAME: usize = 9216;
