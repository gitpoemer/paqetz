#!/usr/bin/env bash
#
# Runs the tests that need CAP_NET_ADMIN / CAP_NET_RAW, inside a throwaway
# network namespace.
#
#   ./scripts/test-privileged.sh
#
# Compilation happens as *you*, and only the already-built test binaries are run
# under sudo. Two reasons that matters:
#
#   - `sudo cargo` would leave root-owned files in target/, and every later
#     build as your own user then fails with a permission error.
#   - the compiler and build scripts never run as root, so the privileged
#     surface is the test binaries alone.
#
# The namespace has its own interfaces and routing table, so devices and
# addresses created inside it are invisible to the host and vanish when the
# command exits. Nothing needs cleaning up.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ${EUID} -eq 0 ]]; then
    echo "error: run this as your normal user; it invokes sudo only where needed." >&2
    exit 1
fi

echo "==> building test binaries (as $(id -un))"
mapfile -t binaries < <(
    cargo test --workspace --no-run --message-format=json 2>/dev/null |
        python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
        # Only crates from this workspace, not dependencies.
        if msg.get("target", {}).get("src_path", "").startswith(sys.argv[1]):
            print(msg["executable"])
' "$(pwd)"
)

if [[ ${#binaries[@]} -eq 0 ]]; then
    echo "error: no test binaries were built." >&2
    exit 1
fi

echo "==> running ${#binaries[@]} test binaries in a throwaway network namespace"
echo "    (sudo is needed for CAP_NET_ADMIN and CAP_NET_RAW)"

status=0
for bin in "${binaries[@]}"; do
    echo
    echo "--- $(basename "${bin}")"
    # `unshare --net` gives this command its own network stack. `ip link set lo
    # up` is there because a namespace starts with loopback down, which some
    # tests reasonably expect to be usable.
    sudo unshare --net -- bash -c '
        ip link set lo up 2>/dev/null || true
        exec "$1" --ignored --test-threads=1
    ' _ "${bin}" || status=$?
done

echo
if [[ ${status} -eq 0 ]]; then
    echo "==> all privileged tests passed; the namespace and everything in it is gone"
else
    echo "==> some privileged tests failed (exit ${status})" >&2
fi
exit "${status}"
