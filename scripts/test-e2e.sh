#!/usr/bin/env bash
#
# Phase 1 acceptance: two tunnel endpoints in network namespaces, joined by a
# virtual Ethernet pair.
#
#   ./scripts/test-e2e.sh
#
# Everything happens inside two namespaces created for the run and deleted
# afterwards. No route, address, device, or firewall rule is created in the
# host's namespace. Compilation happens as you; only the finished binary runs
# under sudo, so `target/` never acquires root-owned files.
#
# Topology:
#
#   ns-srv                                      ns-cli
#   ┌────────────────────┐                      ┌────────────────────┐
#   │ paqetz  10.7.0.1   │                      │ paqetz  10.7.0.2   │
#   │ veth0   10.0.0.1   │ ◀── veth pair ────▶  │ veth0   10.0.0.2   │
#   └────────────────────┘                      └────────────────────┘
#
# The tunnel's outer traffic crosses the veth pair; the inner 10.7.0.0/24
# addresses exist only on the TUN devices at each end.

set -uo pipefail

cd "$(dirname "$0")/.."

SRV_NS=paqetz-srv
CLI_NS=paqetz-cli
SRV_OUTER=10.0.0.1
CLI_OUTER=10.0.0.2
SRV_INNER=10.7.0.1
CLI_INNER=10.7.0.2
PORT=9999

WORK=$(mktemp -d)
PASS=0
FAIL=0

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }

cleanup() {
    sudo ip netns del "${SRV_NS}" 2>/dev/null
    sudo ip netns del "${CLI_NS}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

if [[ ${EUID} -eq 0 ]]; then
    echo "error: run as your normal user; sudo is invoked only where needed." >&2
    exit 1
fi

# --- build, unprivileged ----------------------------------------------------
log "building"
cargo build --release --bin paqetz || exit 1
BIN=$(pwd)/target/release/paqetz

# --- keys and configuration -------------------------------------------------
log "generating keys and configuration"
srv_keys=$("${BIN}" keygen)
cli_keys=$("${BIN}" keygen)
SRV_PRIV=$(echo "${srv_keys}" | awk -F'"' '/private/ {print $2}')
SRV_PUB=$(echo "${srv_keys}"  | awk -F'"' '/public/  {print $2}')
CLI_PRIV=$(echo "${cli_keys}" | awk -F'"' '/private/ {print $2}')
CLI_PUB=$(echo "${cli_keys}"  | awk -F'"' '/public/  {print $2}')

cat > "${WORK}/server.toml" <<EOF
[interface]
private_key = "${SRV_PRIV}"
address = "${SRV_INNER}/24"
listen_port = ${PORT}
device = "pq-srv"

[peer]
public_key = "${CLI_PUB}"
tunnel_address = "${CLI_INNER}"
EOF

cat > "${WORK}/client.toml" <<EOF
[interface]
private_key = "${CLI_PRIV}"
address = "${CLI_INNER}/24"
listen_port = $((PORT + 1))
device = "pq-cli"

[peer]
public_key = "${SRV_PUB}"
endpoint = "${SRV_OUTER}:${PORT}"
tunnel_address = "${SRV_INNER}"
EOF

# --- namespaces -------------------------------------------------------------
log "creating namespaces"
sudo ip netns add "${SRV_NS}" || exit 1
sudo ip netns add "${CLI_NS}" || exit 1
sudo ip link add veth-srv type veth peer name veth-cli || exit 1
sudo ip link set veth-srv netns "${SRV_NS}"
sudo ip link set veth-cli netns "${CLI_NS}"

sudo ip netns exec "${SRV_NS}" ip addr add "${SRV_OUTER}/24" dev veth-srv
sudo ip netns exec "${SRV_NS}" ip link set veth-srv up
sudo ip netns exec "${SRV_NS}" ip link set lo up
sudo ip netns exec "${SRV_NS}" ip route add default dev veth-srv

sudo ip netns exec "${CLI_NS}" ip addr add "${CLI_OUTER}/24" dev veth-cli
sudo ip netns exec "${CLI_NS}" ip link set veth-cli up
sudo ip netns exec "${CLI_NS}" ip link set lo up
sudo ip netns exec "${CLI_NS}" ip route add default dev veth-cli

if sudo ip netns exec "${CLI_NS}" ping -c1 -W2 "${SRV_OUTER}" >/dev/null 2>&1; then
    ok "the namespaces can reach each other"
else
    bad "the namespaces cannot reach each other; nothing below can work"
    exit 1
fi

# --- start both ends --------------------------------------------------------
log "starting the tunnel"
sudo ip netns exec "${SRV_NS}" "${BIN}" run -c "${WORK}/server.toml" \
    > "${WORK}/server.log" 2>&1 &
sleep 1
sudo ip netns exec "${CLI_NS}" "${BIN}" run -c "${WORK}/client.toml" \
    > "${WORK}/client.log" 2>&1 &

# Give the handshake time to complete, including one retry interval.
sleep 7

if sudo ip netns exec "${SRV_NS}" ip link show pq-srv >/dev/null 2>&1; then
    ok "the server's TUN device exists"
else
    bad "the server's TUN device was not created"
fi
if sudo ip netns exec "${CLI_NS}" ip link show pq-cli >/dev/null 2>&1; then
    ok "the client's TUN device exists"
else
    bad "the client's TUN device was not created"
fi

# --- the tunnel carries traffic ---------------------------------------------
log "inner connectivity"
if sudo ip netns exec "${CLI_NS}" ping -c3 -W3 -i0.3 "${SRV_INNER}" >/dev/null 2>&1; then
    ok "ping traverses the tunnel"
else
    bad "ping does not traverse the tunnel"
fi

if sudo ip netns exec "${SRV_NS}" ping -c3 -W3 -i0.3 "${CLI_INNER}" >/dev/null 2>&1; then
    ok "ping traverses the tunnel in reverse"
else
    bad "ping does not traverse the tunnel in reverse"
fi

# A packet larger than one segment exercises the full MTU path.
if sudo ip netns exec "${CLI_NS}" ping -c2 -W3 -s1300 "${SRV_INNER}" >/dev/null 2>&1; then
    ok "a full-size packet traverses the tunnel"
else
    bad "a full-size packet does not traverse the tunnel"
fi

# --- TCP through the tunnel -------------------------------------------------
log "TCP through the tunnel"
cat > "${WORK}/echo_server.py" <<'PYEOF'
import socket, sys
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 7777))
srv.listen(8)
srv.settimeout(180)
while True:
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        break
    with conn:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            conn.sendall(chunk)
PYEOF

cat > "${WORK}/echo_client.py" <<'PYEOF'
import socket, sys, hashlib
host, total = sys.argv[1], int(sys.argv[2])
payload = bytes((i * 7 + 13) & 0xFF for i in range(total))
s = socket.create_connection((host, 7777), timeout=15)
s.settimeout(15)
s.sendall(payload)
s.shutdown(socket.SHUT_WR)
got = bytearray()
while len(got) < total:
    chunk = s.recv(65536)
    if not chunk:
        break
    got += chunk
if bytes(got) != payload:
    print(f"mismatch: sent {total}, got {len(got)}")
    sys.exit(1)
print(hashlib.sha256(payload).hexdigest()[:16])
PYEOF

sudo ip netns exec "${SRV_NS}" python3 "${WORK}/echo_server.py" >/dev/null 2>&1 &
sleep 1

# A single byte first: proves a connection completes at all.
if timeout 20 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/echo_client.py" "${SRV_INNER}" 1 >/dev/null 2>&1; then
    ok "a TCP connection completes through the tunnel"
else
    bad "a TCP connection does not complete through the tunnel"
fi

# Then a volume that must be split across many segments, which exercises the
# MTU and the full seal/emit/parse/open path under load rather than once.
if timeout 25 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/echo_client.py" "${SRV_INNER}" 262144 >/dev/null 2>&1; then
    ok "256 KiB round-trips through the tunnel byte-for-byte"
else
    bad "256 KiB does not round-trip through the tunnel"
fi

# --- UDP through the tunnel -------------------------------------------------
log "UDP through the tunnel"
# This is an L3 tunnel: it forwards IP packets and never looks at the inner
# protocol, so UDP works by the same mechanism TCP does. Worth proving rather
# than assuming, since DNS and QUIC are the reason it matters.
cat > "${WORK}/udp_server.py" <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 7788))
s.settimeout(60)
while True:
    try:
        data, peer = s.recvfrom(65535)
    except socket.timeout:
        break
    s.sendto(data, peer)
PYEOF

cat > "${WORK}/udp_client.py" <<'PYEOF'
import socket, sys
host, size = sys.argv[1], int(sys.argv[2])
payload = bytes((i * 11 + 5) & 0xFF for i in range(size))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(8)
# UDP has no retransmission and the tunnel adds none (D2), so give a lost
# datagram a couple of chances before calling it a failure.
for _ in range(3):
    s.sendto(payload, (host, 7788))
    try:
        got, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    if got == payload:
        sys.exit(0)
    print(f"mismatch: sent {size}, got {len(got)}")
    sys.exit(1)
print("no reply")
sys.exit(1)
PYEOF

sudo ip netns exec "${SRV_NS}" python3 "${WORK}/udp_server.py" >/dev/null 2>&1 &
sleep 1

# A DNS-sized datagram: the common case, and one packet end to end.
if timeout 20 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/udp_client.py" "${SRV_INNER}" 64 >/dev/null 2>&1; then
    ok "a UDP datagram round-trips through the tunnel"
else
    bad "a UDP datagram does not round-trip through the tunnel"
fi

# One that fits a single inner packet exactly at the far end of the MTU.
if timeout 20 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/udp_client.py" "${SRV_INNER}" 1300 >/dev/null 2>&1; then
    ok "a full-MTU UDP datagram round-trips"
else
    bad "a full-MTU UDP datagram does not round-trip"
fi

# And one the kernel must fragment before it reaches the device, which the
# tunnel carries as ordinary payload without knowing it is a fragment.
if timeout 20 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/udp_client.py" "${SRV_INNER}" 4000 >/dev/null 2>&1; then
    ok "a fragmented UDP datagram round-trips"
else
    bad "a fragmented UDP datagram does not round-trip"
fi

# --- the wire looks like TCP ------------------------------------------------
log "what the wire looks like"
sudo ip netns exec "${SRV_NS}" timeout 4 \
    tcpdump -i veth-srv -c 20 -w "${WORK}/wire.pcap" "tcp port ${PORT}" >/dev/null 2>&1 &
DUMP=$!
sleep 1
sudo ip netns exec "${CLI_NS}" ping -c4 -i0.3 -W2 "${SRV_INNER}" >/dev/null 2>&1
wait "${DUMP}" 2>/dev/null

if [[ -s ${WORK}/wire.pcap ]]; then
    captured=$(sudo tcpdump -r "${WORK}/wire.pcap" 2>/dev/null | wc -l)
    if [[ ${captured} -gt 0 ]]; then
        ok "outer traffic is TCP on port ${PORT} (${captured} segments)"
    else
        bad "no outer TCP segments were captured"
    fi

    # Every segment must carry a correct TCP checksum. tcpdump verifies them
    # when asked, and reports "cksum ... (incorrect" when they do not match.
    bad_cksum=$(sudo tcpdump -r "${WORK}/wire.pcap" -vv 2>/dev/null |
        grep -c "incorrect ->" || true)
    if [[ ${bad_cksum} -eq 0 ]]; then
        ok "every segment has a valid TCP checksum"
    else
        bad "${bad_cksum} segments have an invalid TCP checksum"
    fi

    # No SYN should ever appear: the carrier is mid-stream by default (D14).
    syns=$(sudo tcpdump -r "${WORK}/wire.pcap" "tcp[tcpflags] & tcp-syn != 0" 2>/dev/null | wc -l)
    if [[ ${syns} -eq 0 ]]; then
        ok "no SYN was emitted, as mid-stream mode requires"
    else
        bad "${syns} SYN segments were emitted in mid-stream mode"
    fi
else
    bad "no packets were captured on the wire"
fi

# --- roaming ----------------------------------------------------------------
log "roaming"
# Move the client to a different outer address mid-session. The server has never
# been told where the client is; it follows whichever address authenticates.
sudo ip netns exec "${CLI_NS}" ip addr add 10.0.0.22/24 dev veth-cli
sudo ip netns exec "${CLI_NS}" ip addr del "${CLI_OUTER}/24" dev veth-cli
sleep 2
if sudo ip netns exec "${CLI_NS}" ping -c3 -W3 -i0.5 "${SRV_INNER}" >/dev/null 2>&1; then
    ok "the tunnel survives the client changing address"
else
    bad "the tunnel does not survive the client changing address"
fi
sudo ip netns exec "${CLI_NS}" ip addr add "${CLI_OUTER}/24" dev veth-cli 2>/dev/null

# --- state does not grow with connections -----------------------------------
log "state is per peer, not per flow"
# `pgrep -f` also matches the `sudo ip netns exec ...` wrapper, whose thread
# count is 1 and whose memory never moves -- which would make this pass without
# measuring anything. Ask the namespace which processes are in it instead.
srv_pid=""
for p in $(sudo ip netns pids "${SRV_NS}" 2>/dev/null); do
    if [[ $(cat "/proc/${p}/comm" 2>/dev/null) == paqetz ]]; then
        srv_pid=${p}
        break
    fi
done

if [[ -n ${srv_pid} ]]; then
    threads_before=$(awk '/Threads/ {print $2}' "/proc/${srv_pid}/status")
    if [[ ${threads_before} -ge 4 ]]; then
        ok "found the tunnel process (pid ${srv_pid}, ${threads_before} threads)"
    else
        bad "pid ${srv_pid} has ${threads_before} threads; expected the tunnel's 4"
    fi

    rss_before=$(awk '/VmRSS/ {print $2}' "/proc/${srv_pid}/status")

    # Real accepted connections, each carrying data, so the tunnel actually
    # handles them. A design with per-flow state would grow here. Driven from a
    # single process: spawning 200 interpreters would measure process creation
    # rather than the tunnel.
    cat > "${WORK}/churn.py" <<'PYEOF'
import socket, sys
host, count = sys.argv[1], int(sys.argv[2])
done = 0
for _ in range(count):
    try:
        s = socket.create_connection((host, 7777), timeout=5)
        s.settimeout(5)
        s.sendall(b"x" * 512)
        s.shutdown(socket.SHUT_WR)
        while s.recv(4096):
            pass
        s.close()
        done += 1
    except OSError:
        pass
print(done)
PYEOF
    churned=$(timeout 120 sudo ip netns exec "${CLI_NS}" \
        python3 "${WORK}/churn.py" "${SRV_INNER}" 200 2>/dev/null)
    if [[ ${churned:-0} -ge 190 ]]; then
        ok "${churned} of 200 connections completed through the tunnel"
    else
        bad "only ${churned:-0} of 200 connections completed"
    fi
    sleep 1

    rss_after=$(awk '/VmRSS/ {print $2}' "/proc/${srv_pid}/status")
    threads_after=$(awk '/Threads/ {print $2}' "/proc/${srv_pid}/status")
    growth=$((rss_after - rss_before))

    if [[ ${threads_after} -eq ${threads_before} ]]; then
        ok "thread count is unchanged by the churn (${threads_after})"
    else
        bad "threads grew from ${threads_before} to ${threads_after}"
    fi
    if [[ ${growth} -lt 1024 ]]; then
        ok "memory is flat under the churn (${growth} KiB)"
    else
        bad "memory grew by ${growth} KiB under the churn"
    fi
else
    bad "could not find the tunnel process inside ${SRV_NS}"
fi

# --- firewall rules were installed and are removed on exit ------------------
log "firewall rules"
if sudo ip netns exec "${SRV_NS}" nft list table ip paqetz >/dev/null 2>&1; then
    ok "the server installed its firewall rules"
else
    bad "the server did not install its firewall rules"
fi

log "stopping"
sudo pkill -INT -f "paqetz run -c ${WORK}/" 2>/dev/null
sleep 2

if sudo ip netns exec "${SRV_NS}" nft list table ip paqetz >/dev/null 2>&1; then
    bad "firewall rules were left behind after shutdown"
else
    ok "firewall rules were removed on shutdown"
fi

# --- results ----------------------------------------------------------------
log "logs"
echo "--- server ---"; tail -20 "${WORK}/server.log" | sed 's/^/  /'
echo "--- client ---"; tail -20 "${WORK}/client.log" | sed 's/^/  /'

log "result: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
