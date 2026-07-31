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

# One run of one configuration.
run_one() {
    local datapath=$1 transmit=$2 label=$3

    cat > "${WORK}/server.toml" <<EOF
[interface]
private_key = "${SRV_PRIV}"
address = "${SRV_INNER}/24"
listen_port = ${PORT}
device = "pqb-srv"
datapath = "${datapath}"
transmit = "raw"

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
        printf '  %-28s %s\n' "${label}" "tunnel did not come up"
        sed 's/^/      /' "${WORK}/cli.log" | tail -3
        sudo pkill -INT -f "paqetz run -c ${WORK}/" 2>/dev/null
        sleep 1
        return
    fi

    sudo ip netns exec "${SRV_NS}" iperf3 -s -1 -B "${SRV_INNER}" >/dev/null 2>&1 &
    sleep 1

    local tcp udp
    tcp=$(sudo ip netns exec "${CLI_NS}" iperf3 -c "${SRV_INNER}" \
        -t "${SECONDS_PER_RUN}" -J 2>/dev/null |
        python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(f"{d[\"end\"][\"sum_received\"][\"bits_per_second\"]/1e9:.2f}")
except Exception:
    print("n/a")')

    sudo ip netns exec "${SRV_NS}" iperf3 -s -1 -B "${SRV_INNER}" >/dev/null 2>&1 &
    sleep 1
    udp=$(sudo ip netns exec "${CLI_NS}" iperf3 -c "${SRV_INNER}" -u -b 0 -l 1200 \
        -t "${SECONDS_PER_RUN}" -J 2>/dev/null |
        python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    s = d["end"]["sum"]
    print(f"{s[\"bits_per_second\"]/1e9:.2f} ({s[\"packets\"]/'"${SECONDS_PER_RUN}"'/1000:.0f}k pps)")
except Exception:
    print("n/a")')

    printf '  %-28s TCP %-8s UDP %s\n' "${label}" "${tcp} Gbit/s" "${udp}"

    sudo pkill -INT -f "paqetz run -c ${WORK}/" 2>/dev/null
    sleep 2
}

echo
echo "==> ${SECONDS_PER_RUN}s per measurement, over a veth pair"
echo "    (relative numbers are the point; a veth pair is not a real network)"
echo
run_one simple  raw      "simple  + raw"
run_one batched raw      "batched + raw       [default]"
run_one batched afpacket "batched + af_packet"

echo
echo "==> what to do with this"
echo "    If batched is not clearly ahead, the syscall was not the bottleneck"
echo "    and the AEAD is — which is the expected result at small packet sizes."
echo "    If af_packet wins by enough to matter, set transmit = \"afpacket\" and"
echo "    accept that a stale next-hop address becomes a failure mode."
