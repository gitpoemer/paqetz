//! Fake-TCP wire format (decision D6).
//!
//! Each transport packet is carried as the payload of one hand-crafted TCP
//! segment. No kernel TCP stack owns these segments, so nothing ever
//! retransmits them — the channel is a lossy datagram channel, which is
//! exactly what the tunnel above expects.
//!
//! This crate is deliberately payload-agnostic: it emits and parses opaque
//! byte slices and does not depend on `paqetz-core`. Keeping the framing and
//! the carrier independent is what lets each be fuzzed on its own.
//!
//! Carried over from the Go implementation, because it was correct and fast:
//! per-packet TCP flag cycling, varying IP Identification, and echoing the
//! peer's observed TCP timestamp as `tsEcr`.
//!
//! Fixed here, because each was a fingerprint:
//!
//! - a synthetic `SYN` / `SYN,ACK` / `ACK` at session start, so a flow is not
//!   permanently mid-stream;
//! - **byte-accurate** `seq`/`ack` tracked per endpoint pair, rather than
//!   numbers invented from a counter;
//! - window, MSS, window scale, and TTL drawn from an OS profile instead of
//!   being constants;
//! - `TOS` left at 0 rather than DSCP 46 (Expedited Forwarding), which is a
//!   standout marking on a bulk flow;
//! - `FIN`/`RST` teardown on close;
//! - padding to a small set of length buckets.
