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
cargo build --release
./target/release/paqetz init 203.0.113.5:9999 --socks5 127.0.0.1:1080
```

That writes `server.toml` and `client.toml` with both keypairs already matched
and the inner addresses mirrored — so the keys are never handled loose, which is
where they get transposed. Copy each file to the host named in its first line,
then on each:

```bash
paqetz doctor -c paqetz.toml    # read-only; changes nothing
paqetz run    -c paqetz.toml
```

`paqetz setup` asks the same questions one at a time, explains each, and offers
to tune the host's kernel settings at the end.

Two settings turn a tunnel that is *up* into one that is *useful*:
`gateway = true` on the server forwards and translates the client's traffic, and
`route_all = true` on the client sends its traffic through the tunnel. `init`
sets the first by default. Without them the two ends reach each other and
nothing beyond — which looks exactly like a broken tunnel while nothing is
broken.

See [docs/09-deployment.md](docs/09-deployment.md) for the whole path,
including pointing an Xray outbound at it.

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
