#!/usr/bin/env bash
#
# Measures the datapath modes against each other, in paired network namespaces.
#
#   ./scripts/bench.sh
#
# Runs the same transfer through each combination of `interface.datapath` and
# `interface.transmit` and prints the throughput, so the defaults can be chosen
# from numbers rather than argument. D8 explicitly leaves the transmit path open
# on these grounds.
#
# Same confinement as the other scripts: two namespaces created for the run and
# deleted afterwards, nothing added to the host's namespace, and compilation as
# you rather than as root.
#
# A veth pair is not a network. It has no loss, no latency, and a software
# datapath of its own, so the absolute numbers mean little — what is comparable
# is the modes against each other under identical conditions.

set -uo pipefail

cd "$(dirname "$0")/.."

SRV_NS=paqetz-bench-srv
CLI_NS=paqetz-bench-cli
SRV_OUTER=10.0.0.1
CLI_OUTER=10.0.0.2
SRV_INNER=10.7.0.1
CLI_INNER=10.7.0.2
PORT=9999
SECONDS_PER_RUN=${SECONDS_PER_RUN:-5}
# Differences here are small enough that one sample says little; the median of
# a few says rather more. Raise for a measurement you intend to act on.
REPEATS=${REPEATS:-3}

WORK=$(mktemp -d)

cleanup() {
    sudo pkill -f "paqetz run -c ${WORK}/" 2>/dev/null
    sudo ip netns del "${SRV_NS}" 2>/dev/null
    sudo ip netns del "${CLI_NS}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

if [[ ${EUID} -eq 0 ]]; then
    echo "error: run as your normal user; sudo is invoked only where needed." >&2
    exit 1
fi

command -v iperf3 >/dev/null || {
    echo "error: iperf3 is needed for this; install it and re-run." >&2
    exit 1
}

cat > "${WORK}/parse.py" <<'PYEOF'
"""Extracts raw throughput figures from iperf3's JSON.

Numbers rather than a formatted line, so several runs can be reduced to a
median before anything is printed. One value per line:

    tcp -> bits_per_second
    udp -> effective_bits_per_second  delivered_packets  lost_percent
"""
import json
import sys

mode = sys.argv[1]
try:
    report = json.load(sys.stdin)
    if mode == "tcp":
        print(report["end"]["sum_received"]["bits_per_second"])
    else:
        summary = report["end"]["sum"]
        # iperf3's client-side sum counts what it *sent*. Without the loss
        # figure a number here can be mostly datagrams the tunnel dropped,
        # which would make the whole comparison meaningless.
        lost = summary.get("lost_percent", 0.0)
        delivered = summary["packets"] - summary.get("lost_packets", 0)
        print(f"{summary['bits_per_second'] * (1.0 - lost / 100.0)} {delivered} {lost}")
except (ValueError, KeyError, TypeError, ZeroDivisionError):
    print("")
PYEOF

# The median run among the lines on stdin, printed whole.
#
# The median *row*, not a median of each column independently: those can come
# from different runs, and a per-packet figure built from one run's packet
# count and another run's CPU is not a measurement of anything. Ranked on the
# first field, which is throughput for both modes.
cat > "${WORK}/median.py" <<'PYEOF'
import sys

rows = [l.split() for l in sys.stdin.read().splitlines() if l.strip()]
try:
    rows.sort(key=lambda r: float(r[0]))
except (ValueError, IndexError):
    rows = []
if not rows:
    print("n/a")
else:
    print(" ".join(rows[len(rows) // 2]))
PYEOF

echo "==> building"
cargo build --release --bin paqetz || exit 1
BIN=$(pwd)/target/release/paqetz

srv_keys=$("${BIN}" keygen)
cli_keys=$("${BIN}" keygen)
SRV_PRIV=$(echo "${srv_keys}" | awk -F'"' '/private/ {print $2}')
SRV_PUB=$(echo "${srv_keys}"  | awk -F'"' '/public/  {print $2}')
CLI_PRIV=$(echo "${cli_keys}" | awk -F'"' '/private/ {print $2}')
CLI_PUB=$(echo "${cli_keys}"  | awk -F'"' '/public/  {print $2}')

echo "==> creating namespaces"
sudo ip netns add "${SRV_NS}" || exit 1
sudo ip netns add "${CLI_NS}" || exit 1
sudo ip link add veth-bsrv type veth peer name veth-bcli || exit 1
sudo ip link set veth-bsrv netns "${SRV_NS}"
sudo ip link set veth-bcli netns "${CLI_NS}"
for ns_dev in "${SRV_NS}:veth-bsrv:${SRV_OUTER}" "${CLI_NS}:veth-bcli:${CLI_OUTER}"; do
    IFS=: read -r ns dev addr <<< "${ns_dev}"
    sudo ip netns exec "${ns}" ip addr add "${addr}/24" dev "${dev}"
    sudo ip netns exec "${ns}" ip link set "${dev}" up
    sudo ip netns exec "${ns}" ip link set lo up
    sudo ip netns exec "${ns}" ip route add default dev "${dev}"
done

TICKS=$(getconf CLK_TCK)

# Clock ticks of CPU used so far by the paqetz processes in both namespaces.
#
# Read straight from /proc rather than sampled with pidstat, because this has
# to line up exactly with one measurement window, and because the two ends are
# separate processes whose cost belongs to the same run. Fields 14 and 15 of
# /proc/pid/stat are utime and stime; the comm field can itself contain spaces,
# so they are counted from the closing parenthesis rather than from the start.
cpu_ticks() {
    local total=0 ns p used
    for ns in "${SRV_NS}" "${CLI_NS}"; do
        for p in $(sudo ip netns pids "${ns}" 2>/dev/null); do
            [[ $(sudo cat "/proc/${p}/comm" 2>/dev/null) == paqetz ]] || continue
            used=$(sudo awk '{
                rest = substr($0, index($0, ") ") + 2)
                split(rest, f, " ")
                print f[12] + f[13]
            }' "/proc/${p}/stat" 2>/dev/null)
            total=$((total + ${used:-0}))
        done
    done
    echo "${total}"
}

# One run of one configuration.
run_one() {
    local datapath=$1 transmit=$2 label=$3 coalesce=${4:-}
    local coalesce_line=""
    if [[ -n ${coalesce} ]]; then
        coalesce_line='coalesce = true'
    fi

    cat > "${WORK}/server.toml" <<EOF
[interface]
private_key = "${SRV_PRIV}"
address = "${SRV_INNER}/24"
listen_port = ${PORT}
device = "pqb-srv"
datapath = "${datapath}"
transmit = "raw"
${coalesce_line}

[peer]
public_key = "${CLI_PUB}"
tunnel_address = "${CLI_INNER}"
EOF

    cat > "${WORK}/client.toml" <<EOF
[interface]
private_key = "${CLI_PRIV}"
address = "${CLI_INNER}/24"
listen_port = $((PORT + 1))
device = "pqb-cli"
datapath = "${datapath}"
transmit = "${transmit}"
${coalesce_line}

[peer]
public_key = "${SRV_PUB}"
endpoint = "${SRV_OUTER}:${PORT}"
tunnel_address = "${SRV_INNER}"
EOF

    sudo ip netns exec "${SRV_NS}" "${BIN}" run -c "${WORK}/server.toml" \
        > "${WORK}/srv.log" 2>&1 &
    sleep 1
    sudo ip netns exec "${CLI_NS}" "${BIN}" run -c "${WORK}/client.toml" \
        > "${WORK}/cli.log" 2>&1 &
    sleep 6

    if ! sudo ip netns exec "${CLI_NS}" ping -c2 -W3 "${SRV_INNER}" >/dev/null 2>&1; then
        printf '  %-31s %s\n' "${label}" "tunnel did not come up"
        sed 's/^/      /' "${WORK}/cli.log" | tail -3
        sudo pkill -INT -f "paqetz run -c ${WORK}/" 2>/dev/null
        sleep 1
        return
    fi

    sudo ip netns exec "${SRV_NS}" iperf3 -s -1 -B "${SRV_INNER}" >/dev/null 2>&1 &
    sleep 1

    # REPEATS samples of each, reduced to a median. This used to announce a
    # median and then take one sample: the variable was read once, to print the
    # word, and never used.
    local tcp_samples="" udp_samples="" before after i
    for ((i = 0; i < REPEATS; i++)); do
        before=$(cpu_ticks)
        local bits
        bits=$(sudo ip netns exec "${CLI_NS}" iperf3 -c "${SRV_INNER}" \
            -t "${SECONDS_PER_RUN}" -J 2>/dev/null |
            python3 "${WORK}/parse.py" tcp)
        after=$(cpu_ticks)
        [[ -n ${bits} ]] && tcp_samples+="${bits} $((after - before))"$'\n'

        sudo ip netns exec "${SRV_NS}" iperf3 -s -1 -B "${SRV_INNER}" >/dev/null 2>&1 &
        sleep 1
        before=$(cpu_ticks)
        local line
        line=$(sudo ip netns exec "${CLI_NS}" iperf3 -c "${SRV_INNER}" -u -b 0 -l 1200 \
            -t "${SECONDS_PER_RUN}" -J 2>/dev/null |
            python3 "${WORK}/parse.py" udp)
        after=$(cpu_ticks)
        [[ -n ${line} ]] && udp_samples+="${line} $((after - before))"$'\n'

        # Another one-shot server for the next repeat, and for the UDP half of
        # this one, which has just consumed the previous one.
        if ((i + 1 < REPEATS)); then
            sudo ip netns exec "${SRV_NS}" iperf3 -s -1 -B "${SRV_INNER}" >/dev/null 2>&1 &
            sleep 1
        fi
    done

    local tcp udp
    tcp=$(printf '%s' "${tcp_samples}" | python3 "${WORK}/median.py" |
        awk -v t="${TICKS}" '{
            if ($1 == "n/a") { print "n/a"; exit }
            printf "%.2f Gbit/s (%.1f cpu-s)", $1 / 1e9, $2 / t
        }')
    # Microseconds of CPU per delivered packet is the figure the TUN-offload
    # question turns on: it is the per-packet cost, with the path's capacity
    # divided out.
    udp=$(printf '%s' "${udp_samples}" | python3 "${WORK}/median.py" |
        awk -v t="${TICKS}" -v d="${SECONDS_PER_RUN}" '{
            if ($1 == "n/a") { print "n/a"; exit }
            pps = $2 / d
            printf "%.2f Gbit/s %.0fk pps %.1f%% lost %.2f us/pkt",
                $1 / 1e9, pps / 1000, $3, ($4 / t) * 1e6 / $2
        }')

    printf "  %-31s TCP %-26s UDP %s\n" "${label}" "${tcp}" "${udp}"

    sudo pkill -INT -f "paqetz run -c ${WORK}/" 2>/dev/null
    sleep 2
}

echo
echo "==> ${SECONDS_PER_RUN}s per measurement, over a veth pair"
echo "    (relative numbers are the point; a veth pair is not a real network)"
echo
# The full matrix, so each variable can be read independently: comparing down a
# column isolates batching, comparing across a row isolates the transmit path.
# Three runs sharing one setting would confound the two.
echo "    ${REPEATS} run(s) per configuration; the median is reported"
echo
run_one simple  raw      "simple  + raw       [default]"
run_one simple  afpacket "simple  + af_packet"
run_one batched raw      "batched + raw"
run_one batched afpacket "batched + af_packet"
# Only with the batched datapath: one packet per read leaves nothing to group.
run_one batched raw      "batched + raw      + coalesce" yes
run_one batched afpacket "batched + af_packet + coalesce" yes

echo
echo "==> reading this"
echo "    Down a column (simple vs batched, same transmit): what batching is"
echo "    worth. If it is not clearly ahead, the syscall was not the bottleneck"
echo "    and the AEAD is — the expected result at these packet sizes, and a"
echo "    sign the deferred PACKET_MMAP ring is correctly deferred."
echo
echo "    Across a row (raw vs af_packet, same datapath): what skipping the"
echo "    route lookup, the netfilter OUTPUT chain, and the software checksum"
echo "    is worth. transmit = \"raw\" is the default because it has no next-hop"
echo "    address to go stale; switch only if this margin justifies that risk."
echo
echo "    UDP packet rate is the more useful of the two figures. TCP throughput"
echo "    here is largely a measure of how few, large packets iperf3 can push;"
echo "    the tunnel is bounded by packets, not bytes."
echo
echo "    us/pkt is the one to watch for anything that claims to reduce"
echo "    per-packet cost, and is the microseconds of CPU both ends spend"
echo "    together per delivered packet. Throughput over a veth pair is bounded"
echo "    by how fast this can push packets, so a change that lowers us/pkt"
echo "    without raising throughput has not been measured properly, and one"
echo "    that raises throughput without lowering us/pkt bought it somewhere"
echo "    other than the datapath."
echo
echo "    The coalesce rows are the TUN side of the same idea: the wire side"
echo "    already takes 32 packets per syscall and a TUN device takes one, so"
echo "    those rows write a run of a flow as a single frame for the kernel to"
echo "    split. Expect them to help the UDP figure more than the TCP one --"
echo "    a flood queues up runs to find, and iperf3's TCP keeps little in"
echo "    flight over a veth pair, which is the same reason batching does"
echo "    nothing for TCP here. One copy per packet is the price, so a run of"
echo "    one is slightly worse than not coalescing at all."
echo
echo "    cpu-s is the same measurement for the TCP run, undivided: the CPU"
echo "    seconds both ends spent during it. On a host with steal time it is"
echo "    the number to compare, since wall-clock throughput there says more"
echo "    about the hypervisor than about this code."
