# paqetz

A point-to-point L3 tunnel whose packets are hand-crafted TCP segments, injected
with a raw socket so neither host's TCP/IP stack ever sees them.

It exists for networks that block UDP first and inspect what is left. WireGuard's
cryptography and roaming, carried by something that looks like an ordinary TCP
conversation.

**Status: working.** Phases 1 through 5 are built: the tunnel, setup tooling,
batched datapath, a SOCKS5 front end, and diagnostics.

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

## Quick start

Linux, and `CAP_NET_ADMIN` + `CAP_NET_RAW` (root will do).

```bash
curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqetz/main/scripts/install.sh | sudo sh && sudo paqetz setup
```

That installs the static binary for this architecture and walks the setup one
question at a time — keys, addresses, whether the server is a way out, whether
to keep it running as a service.

The installer verifies the download against the checksum published with the
release, and **aborts if that checksum cannot be fetched**. It is still a script
piped into a root shell, so if you would rather read it first — which is the
right instinct — that works too:

```bash
curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqetz/main/scripts/install.sh -o install.sh
less install.sh
sudo sh install.sh
```

<details>
<summary>Or build it yourself</summary>

```bash
cargo build --release            # target/release/paqetz
./target/release/paqetz setup
```

</details>

`setup` writes both configuration files with the keypairs already matched and
the inner addresses mirrored, so the keys are never handled loose — which is
where they get transposed, and a transposed key produces silence rather than an
error. Copy the other file to the other host and run `paqetz setup` there.

Non-interactively:

```bash
paqetz init 203.0.113.5:9999 --socks5 127.0.0.1:1080
paqetz doctor -c paqetz.toml    # read-only; changes nothing
paqetz run    -c paqetz.toml
```

Two settings turn a tunnel that is *up* into one that is *useful*:
`gateway = true` on the server forwards and translates the client's traffic, and
`route_all = true` on the client sends its traffic through the tunnel. `init`
sets the first by default. Without them the two ends reach each other and
nothing beyond — which looks exactly like a broken tunnel while nothing is
broken.

`paqetz setup` walks the whole path, including generating an Xray REALITY
inbound and pointing it at the tunnel.

## Testing

`cargo test` is safe on a workstation: it creates no device, opens no socket,
and writes no firewall rule.

Everything that touches the host is gated behind `#[ignore]` and confined to a
throwaway network namespace by the scripts that run it:

```bash
cargo test --workspace                 # safe anywhere
./scripts/test-privileged.sh           # needs CAP_NET_ADMIN/CAP_NET_RAW
./scripts/test-e2e.sh                  # two namespaces, a real tunnel
./scripts/bench.sh                     # datapath comparison, needs iperf3
```

Each compiles as you and runs only the built binaries under `sudo`, so `target/`
never acquires root-owned files. The namespaces are deleted afterwards,
including on failure, and nothing is created in the host's own namespace.

## License

MIT.
