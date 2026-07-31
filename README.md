# paqetz

A point-to-point L3 tunnel whose packets are hand-crafted TCP segments, injected
with a raw socket so neither host's TCP/IP stack ever sees them.

It exists for networks that block UDP first and inspect what is left. WireGuard's
cryptography and roaming, carried by something that looks like an ordinary TCP
conversation.

**Status: phase 1.** The tunnel works — see [docs/08-rewrite-plan.md](docs/08-rewrite-plan.md)
for what is built, what is deferred, and why.

## What it is

```
  ┌──────────────┐                                    ┌──────────────┐
  │   your app   │                                    │   internet   │
  └──────┬───────┘                                    └──────▲───────┘
         │ ordinary routing                                  │
  ┌──────▼───────┐      crafted TCP segments           ┌──────┴───────┐
  │    paqetz    │ ══════════════════════════════════▶ │    paqetz    │
  │   (client)   │      ChaCha20-Poly1305 inside       │   (server)   │
  └──────────────┘                                     └──────────────┘
```

- **Noise IK** — X25519 identities, ChaCha20-Poly1305, forward secrecy, replay
  protection, and silence toward anything that does not authenticate.
- **No reliability layer.** The tunnel forwards IP packets and lets the inner
  protocol do what it is already good at. There is no KCP, no ARQ, no
  multiplexer. Because it works at L3, anything over IP goes through it —
  TCP, UDP, ICMP, QUIC — and UDP is delivered as UDP, not silently made
  reliable underneath the application.
- **State is per peer, not per flow.** Memory and thread count do not move as
  connections come and go.
- **Roaming.** A peer is a public key, not an address; the endpoint is learned
  from whichever address last authenticated.

It is a ground-up rewrite of [paqet](https://github.com/gitpoemer/paqet), whose
idea it keeps and whose architecture it does not.
[docs/07-analysis.md](docs/07-analysis.md) explains the difference.

## Quick start

Both ends need Linux, and `CAP_NET_ADMIN` + `CAP_NET_RAW` (root will do).

```bash
cargo build --release            # target/release/paqetz
./target/release/paqetz keygen   # once on each end
```

Exchange the two **public** keys — they are not sensitive. Then write a config
on each end, starting from [`example/server.toml`](example/server.toml) and
[`example/client.toml`](example/client.toml), and run:

```bash
sudo paqetz doctor -c /etc/paqetz/paqetz.toml   # read-only; changes nothing
sudo paqetz run    -c /etc/paqetz/paqetz.toml
```

`doctor` checks the things that otherwise fail silently — capabilities, the TUN
driver, a free port, an MTU that fits the path, a routable peer — and says what
to do about each. Run it first; it is why the tunnel not working should be a
short conversation.

For a permanent install, [`example/paqetz.service`](example/paqetz.service) runs
it with two capabilities rather than as root.

The kernel firewall rules the tunnel needs are installed at start-up and removed
on exit. To inspect or manage them yourself:

```bash
paqetz firewall plan -c paqetz.toml    # prints what would run, changes nothing
```

Pick a non-standard port. The rules are scoped to it, and on 80 or 443 they
would disturb the host's own traffic.

## Testing

`cargo test` is safe on a workstation: it creates no device, opens no socket,
and writes no firewall rule. Everything that touches the host is gated behind a
script that confines it to a throwaway namespace. See
[docs/TESTING.md](docs/TESTING.md).

## Documentation

[docs/](docs/) covers the design, a full analysis of the implementation this
replaces, and one record per decision in [docs/decisions/](docs/decisions/).

## License

MIT.
