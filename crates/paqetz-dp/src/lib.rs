//! Datapath: raw transmit, `AF_PACKET` receive ring, TUN device (decision D8).
//!
//! Linux only, by decision — so there is one implementation, not a matrix of
//! `cfg` branches. No libpcap and no FFI beyond `libc`, which removes the
//! per-packet allocation the Go implementation paid across the CGo bridge.
//!
//! Transmit is a raw `IPPROTO_TCP` socket with `IP_HDRINCL`: we supply the IP
//! and TCP headers and the kernel handles routing, ARP, and L2 framing, so no
//! gateway MAC address appears in the configuration. An `AF_PACKET` transmit
//! path with an explicit destination MAC is retained as a fallback — and may
//! prove to be the *faster* path, since it skips the routing lookup and the
//! netfilter `OUTPUT` chain and can request NIC checksum offload. Phase 3
//! measures both and picks the default on evidence.
//!
//! Receive is `AF_PACKET` with an attached BPF filter and a `PACKET_MMAP` ring,
//! read in place. `PACKET_FANOUT` spreads across worker threads when packet
//! rate demands it.
//!
//! Performance rules that apply to everything in this crate (see
//! `docs/08-rewrite-plan.md` §8.3): no allocation on the steady-state path, no
//! dynamic dispatch, no locks, no async runtime. Threads block on syscalls and
//! do the crypto inline. TUN reads use `IFF_VNET_HDR` with `TUNSETOFFLOAD` so
//! one syscall returns a GSO super-packet rather than a single segment; that
//! one feature is worth roughly 3x and is not optional.
