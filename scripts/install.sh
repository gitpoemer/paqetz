#!/usr/bin/env sh
#
# Downloads the latest release, verifies it, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqetz/main/scripts/install.sh | sudo sh && sudo paqetz setup
#
# Setup is chained rather than run from here, so that installing inside a
# provisioning script does not drop into an interactive wizard. Set
# PAQETZ_SETUP=1 if you would rather this ran it.
#
# Or, if you would rather read it first — which is the right instinct for
# anything piped into a root shell:
#
#   curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqetz/main/scripts/install.sh -o install.sh
#   less install.sh
#   sudo sh install.sh
#
# The checksum is not optional. paqetz refuses to install an unverified Xray;
# publishing an installer that skipped the same check for itself would be a
# double standard, so a missing or mismatched SHA-256 aborts here too.
#
# Environment:
#   PAQETZ_PREFIX   where the binary goes         (default /usr/local/bin)
#   PAQETZ_TARGET   force a target triple         (default: detected)
#   PAQETZ_SETUP    1 to run `paqetz setup` after (default 0)

set -eu

REPO=${PAQETZ_REPO:-gitpoemer/paqetz}
PREFIX=${PAQETZ_PREFIX:-/usr/local/bin}
BASE="https://github.com/${REPO}/releases/latest/download"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

need curl
need uname

# Static musl wherever there is one: it runs whatever the host's glibc is, which
# for a tool that lands on unfamiliar VPSes matters more than the smaller size of
# a dynamically linked build. riscv64 is the exception -- no static build is
# published for it -- so it gets the glibc one.
detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)   echo "x86_64-unknown-linux-musl" ;;
        aarch64|arm64)  echo "aarch64-unknown-linux-musl" ;;
        armv7l|armv7)   echo "armv7-unknown-linux-musleabihf" ;;
        riscv64)        echo "riscv64gc-unknown-linux-gnu" ;;
        i686|i386)      echo "i686-unknown-linux-musl" ;;
        *)              die "no build published for $arch" ;;
    esac
}

[ "$(uname -s)" = "Linux" ] || die "paqetz is Linux only: the datapath is built on AF_PACKET and TUN"

TARGET=${PAQETZ_TARGET:-$(detect_target)}
NAME="paqetz-${TARGET}"

# Read before anything is replaced, so the report at the end can say what this
# actually did rather than only where it ended up.
previous=""
if [ -x "${PREFIX}/paqetz" ]; then
    previous=$("${PREFIX}/paqetz" --version 2>/dev/null) || previous=""
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "==> downloading ${NAME}"
curl -fsSL --max-time 300 -o "$tmp/paqetz" "${BASE}/${NAME}" \
    || die "could not download ${BASE}/${NAME}"

say "==> verifying"
curl -fsSL --max-time 60 -o "$tmp/SHA256SUMS" "${BASE}/SHA256SUMS" \
    || die "could not fetch SHA256SUMS. Refusing to install an unverified binary."

expected=$(awk -v n="$NAME" '$2 == n || $2 == "*"n {print $1}' "$tmp/SHA256SUMS" | head -n1)
[ -n "$expected" ] || die "SHA256SUMS carries no entry for ${NAME}. Refusing to install."

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/paqetz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/paqetz" | awk '{print $1}')
else
    die "neither sha256sum nor shasum is available, so this cannot be verified"
fi

if [ "$actual" != "$expected" ]; then
    printf 'error: checksum mismatch\n  expected %s\n  got      %s\n' \
        "$expected" "$actual" >&2
    die "not installing"
fi
say "    ok  ${actual}"

say "==> installing to ${PREFIX}/paqetz"
mkdir -p "$PREFIX"
chmod 755 "$tmp/paqetz"
# Replaced rather than written in place, so a running copy is not corrupted
# mid-write and a failure leaves the old one intact.
mv -f "$tmp/paqetz" "${PREFIX}/paqetz" 2>/dev/null \
    || die "could not write ${PREFIX}/paqetz — run this with sudo, or set PAQETZ_PREFIX"

current=$("${PREFIX}/paqetz" --version)
say ""
if [ -z "$previous" ]; then
    say "==> installed ${current}"
elif [ "$previous" = "$current" ]; then
    say "==> reinstalled ${current}"
else
    say "==> replaced ${previous} with ${current}"
fi

# Replacing the file does not touch the process using it. Without this the
# service keeps running the old binary while `paqetz --version` reports the new
# one, which is a confusing place to debug from. Not restarted here: this may be
# the tunnel carrying the session that is running the installer, and dropping
# that is the user's call to make, not an installer's.
if [ -n "$previous" ] && [ "$previous" != "$current" ] \
   && command -v systemctl >/dev/null 2>&1 \
   && systemctl is-active --quiet paqetz 2>/dev/null; then
    say ""
    say "The paqetz service is still running the old binary. Restart it with:"
    say "  sudo systemctl restart paqetz"
fi
say ""

if [ "${PAQETZ_SETUP:-0}" = "1" ]; then
    # Only when asked. An installer that starts an interactive wizard on its own
    # is unpleasant in a provisioning script, and this may well be running in
    # one.
    exec "${PREFIX}/paqetz" setup
fi

say "Next:"
say "  paqetz setup            # walks the whole thing, one question at a time"
say "  paqetz doctor -c FILE   # checks a host, changes nothing"
