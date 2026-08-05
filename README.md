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
# client, under [tunnel.interface]
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
[tunnel.socks5]
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

### When it works but feels slow

`paqetz doctor` answers *will this work*. `paqetz doctor --under-load` answers
*how well*, which is the question once a tunnel is already running.

```bash
paqetz doctor --under-load -c paqetz.toml     # add --tunnel <name> if several
```

It times the round trip to the peer's inner address three times: idle, idle
again, and while saturating the tunnel. It sends traffic and changes nothing.
The tunnel has to be up, and the probes need a raw socket, so run it as root.

```
                 loss     min      avg      max     mdev
  idle, first     30.0%    92.9ms   94.2ms   96.8ms   1.18ms
  idle, again      0.0%    92.9ms   93.2ms   96.2ms   0.57ms
  under load       0.0%    92.9ms   93.2ms   96.7ms   0.60ms

  25 of 25 Mbit/s offered during the loaded run.
```

The load is **paced** — 25 Mbit/s by default, `--rate` to change it. That is
deliberate. The question is what a busy tunnel feels like, not what an overrun
one does: a sender with no pacing fills a local queue at memory speed, offers
two gigabits on a one-core VPS, and then drops the probe packets itself, which
reports as packet loss on a path that never saw the traffic. Raise `--rate`
until something moves; the achieved rate is reported either way, and a figure
below what was asked for means this host, not the link, ran out.

Two failures hide from every throughput test, and each has its own line here.

**A path gone cold** is the gap between the two idle runs: identical round trip
times, but the first run lost packets and the second lost none. Nothing is
congested — a mapping had lapsed, and the first packets paid to wake it. That is
the first click after leaving a browser alone, and `keepalive` is the fix.

**A queue rather than a drop** is the gap between idle and loaded. A tunnel can
move thirty megabits while adding a second of delay: the transfer finishes, so a
speed test calls it healthy, and everything interactive is miserable. If the
average climbs by hundreds of milliseconds with no loss at all, something on the
path is buffering. If it climbs and the loss stays at zero *and* a restart cures
it, that is classification rather than congestion, and `rotate` is the fix.

If the loaded run stays flat, as above, the tunnel is not what is slow — look at
whatever sits between you and it.

### Two things you can turn off

Both are on by default, and both were measured on a live path before being made
the default.

```toml
# under [tunnel.interface]
keepalive = false   # stop answering a quiet peer with an empty packet
rotate    = false   # keep one outer port for the life of the process
```

`keepalive` is WireGuard's passive keepalive: one empty packet when the peer has
spoken and this end has not, at most once per thing the peer says. Without it a silent tunnel goes
cold — on a live path, **the first two seconds of traffic after any idle period
were lost** to a mapping that had lapsed, while every packet under load arrived.
It costs a fixed-size packet on a fixed interval, which is a metronome, and that
is a real trade; losing the first click after a pause is the worse side of it.

`rotate` gives the carrier several outer ports at start-up and moves between
them every half hour or so. A five-tuple that lives for hours and carries
gigabytes gets classified and then shaped: throughput collapses **with no packet
loss at all**, latency climbs, and a restart cures it — because a restart is a
new five-tuple. Moving on a timer is the same cure without the outage.

Turn either off if your path does not want it.

### IPv4 only

The tunnel carries IPv4. A destination reachable only over IPv6 is refused
rather than sent around the tunnel — which is what would otherwise happen, since
the policy route is a v4 rule and a marked v6 socket matches nothing and leaves
by the ordinary route. Dual-stack destinations are unaffected.

## Several servers from one client

One client host can carry several tunnels at once, each to a different server,
with the firewall mark choosing between them. Three countries, one VPS, three
Xray outbounds:

```toml
# Settings for the process rather than for any one tunnel.
log = "info"

[[tunnel]]
name = "de"
[tunnel.interface]
private_key  = "..."
address      = "10.7.0.2/24"
device       = "paqetz-de"
route_marked = 81
[tunnel.peer]
public_key     = "..."
endpoint       = "203.0.113.5:8443"
tunnel_address = "10.7.0.1"
allowed_ips    = ["0.0.0.0/0"]

[[tunnel]]
name = "nl"
[tunnel.interface]
private_key  = "..."
address      = "10.8.0.2/24"
device       = "paqetz-nl"
mtu          = 1280
route_marked = 82
[tunnel.peer]
public_key     = "..."
endpoint       = "198.51.100.7:8443"
tunnel_address = "10.8.0.1"
allowed_ips    = ["0.0.0.0/0"]
```

Each tunnel needs its **own device, inner subnet and mark** — sharing any of
them would have two tunnels undoing each other's routing, so the configuration
is refused rather than run. Each also has its own key, which is what you want
when three different people run those servers: a compromise of one teaches
nothing about the others. Everything else is per-tunnel too, including `mtu`,
`profile` and `sequencing`, so a path that needs a smaller MTU gets one without
touching the rest.

One process runs them all. Their status lines are prefixed with the tunnel name,
and one `nft` table carries the rules for every outer port:

```
[  1.024] info  de: up 1s | handshake 3s ago | tx 41 pkt/12.9 kB | rx 38 pkt/44.1 kB
[  1.025] info  nl: up 1s | handshake 4s ago | tx 12 pkt/3.1 kB  | rx 11 pkt/9.8 kB
```

On the Xray side, one outbound per mark, and a routing rule choosing between
them:

```json
"outbounds": [
  { "tag": "de", "protocol": "freedom",
    "settings": { "domainStrategy": "UseIPv4" },
    "streamSettings": { "sockopt": { "mark": 81 } } },
  { "tag": "nl", "protocol": "freedom",
    "settings": { "domainStrategy": "UseIPv4" },
    "streamSettings": { "sockopt": { "mark": 82 } } }
]
```

How users are assigned to countries is Xray's business rather than paqetz's —
by inbound tag, by user, or by destination, whichever suits. paqetz's part ends
at "a socket marked 82 leaves through the Netherlands".

### The original form still works

One `[interface]` and one `[peer]` describes a single tunnel and parses exactly
as it always has, including the process settings written inside `[interface]`.
No existing configuration needs touching.

`setup` and `init` write the `[[tunnel]]` form, even for a single tunnel: one
shape for everyone to learn, and a file that grows a second destination later
does not have to change shape first.

The two forms are the same file at different depths — `[interface]` becomes
`[tunnel.interface]`, every key unchanged — so converting is mechanical:

```bash
sudo paqetz config migrate -c /etc/paqetz/paqetz.toml
```

It shows what the file would become, keeps the original as `.toml.bak`, and
refuses to write unless the result parses to the same configuration. Comments
survive. Mixing the two forms in one file is refused rather than guessed at.

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
