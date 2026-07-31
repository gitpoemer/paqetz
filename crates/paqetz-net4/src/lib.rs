//! L4 debugging front end (phase 4).
//!
//! L3 is the production path. This exists so a single application can be
//! pointed at the tunnel without touching the routing table — useful for
//! `curl`-level debugging and for integration tests that must not require
//! root-level routing changes on the test host.
//!
//! **No userspace TCP stack is involved.** Because L3 mode has already created
//! the TUN device, this listener makes *ordinary kernel* TCP and UDP
//! connections to the target with `SO_MARK` set, and a policy-routing rule
//! steers them into the tunnel. The kernel does the TCP. That is the SOCKS5
//! codec plus a dialer that sets a mark, rather than an embedded network stack.
