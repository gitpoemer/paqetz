//! L4 debugging front end (phase 4).
//!
//! L3 is the production path. This exists so a single application can be
//! pointed at the tunnel without touching the routing table — useful for
//! `curl`-level debugging, and for pointing one proxy-aware program at the
//! tunnel while the rest of the host's traffic carries on as normal.
//!
//! **No userspace TCP stack is involved.** Because L3 mode has already created
//! the TUN device, this listener makes *ordinary kernel* TCP and UDP
//! connections with `SO_MARK` set, and a policy-routing rule steers them into
//! the tunnel. The kernel does the TCP. That is the SOCKS5 codec plus a dialler
//! that sets a mark, rather than the several thousand lines an embedded network
//! stack would be — and it is why the one serious argument for writing this
//! program in Go, where gVisor's netstack exists, turned out not to apply.
//!
//! # This is where the per-flow state lives
//!
//! One thread per connection, a relay buffer each, and an entry per UDP
//! association: everything decision D4 refuses to hold in the tunnel. That is
//! the honest cost of a SOCKS5 front end, and the reason it is confined to the
//! client, switched off by default, and described as a debugging convenience
//! rather than the way to run this.

pub mod dial;
pub mod protocol;
pub mod route;
pub mod server;

pub use protocol::Address;
pub use server::{Config, serve};
