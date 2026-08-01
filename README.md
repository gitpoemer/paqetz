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

That installs the binary for this architecture — static everywhere but riscv64 —
and walks the setup one question at a time: keys, addresses, whether the server
is a way out, whether to keep it running as a service.

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

## Putting a proxy in front of it

The usual arrangement: users reach an Xray REALITY inbound on the client, and
what it forwards leaves through the tunnel. There are two ways to join them, and
the difference is where names are resolved.

**Marked sockets (L3).** Xray sets `SO_MARK` on its outbound connections and a
policy route sends those — and only those — into the tunnel. Its own inbound
connections keep the host's ordinary route, which is what `route_all` cannot
express: that would capture the replies to Xray's own users and break them.

```toml
# client, under [interface]
route_marked = 81
route_table  = 81
```

```bash
paqetz xray config <public-address> --mark 81 -o /etc/xray/config.json
```

**A SOCKS5 listener.** For anything that speaks SOCKS5 but cannot set a mark.
Self-contained: the listener installs its own policy route when it starts.

```toml
# client
[socks5]
listen = "127.0.0.1:1080"
```

```bash
paqetz xray config <public-address> --socks5 127.0.0.1:1080 -o /etc/xray/config.json
```

Both are configurable at once, and keeping the listener even on the L3 path is
worth it for `curl -x socks5h://127.0.0.1:1080 https://ifconfig.me`, which
answers "is the tunnel carrying anything" in one line.

### Names are resolved through the tunnel

This is the part that is easy to get wrong, and it fails in a way that looks
like anything but DNS. The client sits inside the network being tunnelled out
of. Resolve a name with that network's resolver and it sees every destination
before you reach it — and if it answers with an address that goes nowhere, the
connection hangs until it times out, with the tunnel healthy and the counters
moving. Sites that resolve normally work; sites that do not simply stall.

So both paths resolve on the far side, and both default to it:

- The SOCKS5 listener resolves names itself over a marked socket. `socks5.dns`
  chooses the resolver, defaulting to `1.1.1.1`. `dns = "system"` opts out, and
  says so at start-up.
- The generated Xray configuration for `--mark` points Xray's own DNS at the
  same resolver, reached over the same marked outbound.

### What the generated Xray configuration looks like

`paqetz xray config <public-address> --mark 81` writes this. Keys, UUID and
short ID are generated per run; everything else is what makes the two halves fit
together, and is what to copy if you are writing the file yourself.

```json
{
  "log": { "loglevel": "warning" },

  "dns": {
    "servers": ["1.1.1.1"],
    "queryStrategy": "UseIPv4"
  },

  "inbounds": [
    {
      "tag": "reality",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "<uuid>", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": ["www.microsoft.com"],
          "privateKey": "<reality private key>",
          "shortIds": ["<short id>"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],

  "outbounds": [
    {
      "tag": "tunnel",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" },
      "streamSettings": {
        "sockopt": { "mark": 81 }
      }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
```

Four things in there are load-bearing, and dropping any of them leaves a tunnel
that carries traffic while something important goes around it:

- **`sockopt.mark` matching `route_marked`** is the entire join. Without it the
  outbound is an ordinary connection leaving by the ordinary route.
- **`settings.domainStrategy: "UseIPv4"`** makes Xray resolve with its own DNS
  rather than handing the name to the host's resolver. This is the one that is
  easy to leave out, and it fails as a stall rather than an error.
- **`dns.servers`** is where that resolution goes. Queries route through the
  same marked outbound, so they take the tunnel too.
- **`queryStrategy: "UseIPv4"`** stops it asking for AAAA records, which the
  tunnel cannot carry anyway.

The `block` outbound with the `geoip:private` rule keeps proxied traffic off the
host's own LAN — a user asking for `192.168.0.1` should not reach the client's
network.

For the SOCKS5 path the outbound is a `socks` protocol pointing at the listener,
with no `domainStrategy` of its own:

```json
    {
      "tag": "tunnel",
      "protocol": "socks",
      "settings": {
        "servers": [{ "address": "127.0.0.1", "port": 1080 }]
      }
    }
```

and the rest of the file drops the `dns` block and sets
`routing.domainStrategy` to `"AsIs"`. That is the opposite requirement, for the
same reason: the name has to reach paqetz untouched, because paqetz is what
resolves it at the far end. Resolving it early in Xray would put the lookup back
on the local network.

### The SOCKS5 listener does not depend on the routing rule

`SO_MARK` only means something if a policy rule says so, and that rule is state
outside the process. `systemd-networkd` deletes routing policy rules it did not
create — `ManageForeignRoutingPolicyRules` defaults to yes — so an ordinary
network reconfiguration can remove it hours after start-up. The rule goes, the
route stays, and a lookup that finds an empty table does not fail: it falls
through to the main table and the traffic leaves in the clear, with the tunnel
still up and its counters still.

So connections the listener makes are pinned to the tunnel device with
`SO_BINDTODEVICE`, which needs no rule, no table and no route, and cannot be
undone from outside the process. The mark and the rule are still installed, for
anything else pointed at them — Xray on the `route_marked` path, which sets its
own mark and therefore does need the rule. For that path the table also carries
a blackhole default, so if the rule or route goes the traffic stops rather than
escaping.

**The `route_marked` path cannot be protected that way**, because Xray sets the
mark on its own sockets and so genuinely needs the rule. There the fix is to
stop networkd removing it:

```bash
sudo paqetz networkd status               # says whether it will
sudo paqetz networkd protect --restart    # writes it and applies it — use this
sudo paqetz networkd protect              # writes it; applies at the next reboot
sudo paqetz networkd unprotect            # removes it again
```

**It is not in force until networkd restarts.** `networkctl reload` re-reads
`.network` and `.netdev` files, not `networkd.conf` or its drop-ins, so nothing
short of `systemctl restart systemd-networkd` picks this up. That restart
reconfigures every interface on the host — worth thinking about if you are
reading this over one of them — so `protect` writes the file and says so rather
than doing it quietly. `--restart` opts in. Waiting for the next reboot is a
reasonable answer, with one thing to know: until networkd restarts it will still
delete the rule when an interface changes state, and nothing puts it back. The
table fails closed, so that is an outage rather than a leak — but it is an
outage, and `systemctl restart paqetz` is what ends it.

`protect` writes `/etc/systemd/networkd.conf.d/10-paqetz.conf` — a drop-in
rather than an edit to `networkd.conf`, so nothing you wrote is overwritten and
deleting the file is a complete undo:

```ini
[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
```

**This is not only the client.** It applies to any host that installs routing of
its own, which `paqetz doctor` works out for you:

| host | installs | at risk |
| --- | --- | --- |
| client with `route_marked` or `[socks5]` | `ip rule fwmark …` | yes |
| client with `route_all` | routes, not rules | yes — `ManageForeignRoutes` defaults to yes too |
| server with `egress` (WARP) | `ip rule from <subnet> …` | yes |
| plain point-to-point server | nothing | no |

`paqetz setup` offers this, and `paqetz doctor` reports it as a **failure** when
networkd is running, routing of ours is needed, and nothing has turned the
behaviour off. A failure rather than a warning because losing the rule does not stop
traffic — it sends it out unprotected while everything still appears to work.

### Sequence numbers are deliberately incoherent

The segments are numbered so that they do **not** describe a byte stream, and
this is load-bearing rather than laziness.

Numbering them honestly — by the payload bytes actually sent — makes the flow
reassemblable, so anything modelling TCP will track it as a stream. That is free
while every packet arrives. But this carrier never retransmits, so the first
packet the network drops leaves a hole that is never filled: the sequence runs
on past it while the acknowledgement freezes at it, permanently. A sender still
sending to a receiver that stopped acknowledging is not something a real
connection does for more than a few milliseconds.

So the flow reads as ordinary TCP until the first loss and as unmistakably
synthetic from then on, with a stalled reassembly buffer in front of it — which
invites more loss, which adds more holes. It only ratchets one way. It was
observed in the field as a tunnel that ran perfectly and then decayed to
unusable, recovering only on restart.

Numbers that were never coherent cannot become incoherent, so `opaque` is the
default. `sequencing = "stream"` under `[interface]` restores byte-accurate
numbering for a path that rejects implausible sequence numbers outright instead
of tracking them. The two ends need not agree — nothing validates an inbound
`seq` or `ack` — so this can be changed on one host at a time.

### IPv4 only

The tunnel carries IPv4. A destination reachable only over IPv6 is refused
rather than sent around the tunnel — which is what would otherwise happen, since
the policy route is a v4 rule and a marked v6 socket matches nothing and leaves
by the ordinary route. Dual-stack destinations are unaffected.

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
