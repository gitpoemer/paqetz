//! Firewall rule management (decision D9).
//!
//! The `NOTRACK` and RST-drop rules are load-bearing, not advisory: without
//! them the kernel sees inbound segments on a port it has no socket for and
//! answers with `RST`, which kills the flow and corrupts NAT state along the
//! path. They are preserved exactly.
//!
//! What changes is that the binary installs them, idempotently, and on **both**
//! ends. The Go implementation documents them for the server only — but the
//! client kernel emits resets for precisely the same reason, which is a real
//! gap rather than an oversight in the docs.
//!
//! Prefers `nftables`, falls back to `iptables`. Exposed as
//! `paqetz firewall apply | status | revert`.
