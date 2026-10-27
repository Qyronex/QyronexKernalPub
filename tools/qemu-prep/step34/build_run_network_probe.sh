#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/tests/qemu-prep/step34/network_probe.c"
OUT=${KERNAL_STEP34_PROBE_OUT:-/tmp/kernal-step34-network-probe}
CC=${CC:-cc}

fail() { printf 'step34-network-probe: FAIL: %s\n' "$*" >&2; exit 1; }

[ -f "$SRC" ] || fail "missing source: $SRC"
command -v "$CC" >/dev/null 2>&1 || fail "compiler not found: $CC; pin/install the reference compiler through the approved Debian snapshot path before running"

"$CC" \
  -std=c11 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  "$SRC" \
  -o "$OUT"

printf 'step34-network-probe: compiler=%s\n' "$($CC --version | head -n 1)"
printf 'step34-network-probe: tcp_target=%s:%s udp_target=%s:%s dns_name=%s\n' \
  "${KERNAL_TCP_HOST:-10.0.2.2}" "${KERNAL_TCP_PORT:-18081}" \
  "${KERNAL_UDP_HOST:-10.0.2.2}" "${KERNAL_UDP_PORT:-18082}" \
  "${KERNAL_DNS_NAME:-<skipped>}"
sha256sum "$SRC" "$OUT"
"$OUT"
