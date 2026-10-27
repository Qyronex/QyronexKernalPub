#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/tests/qemu-prep/step35/event_fd_probe.c"
OUT=${KERNAL_STEP35_PROBE_OUT:-/tmp/kernal-step35-event-fd-probe}
CC=${CC:-cc}

fail() { printf 'step35-event-probe: FAIL: %s\n' "$*" >&2; exit 1; }

[ -f "$SRC" ] || fail "missing source: $SRC"
command -v "$CC" >/dev/null 2>&1 || fail "compiler not found: $CC; install/pin the reference toolchain through the approved snapshot path before running"

"$CC" \
  -std=c11 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  "$SRC" \
  -o "$OUT"

printf 'step35-event-probe: compiler=%s\n' "$($CC --version | head -n 1)"
sha256sum "$SRC" "$OUT"
"$OUT"
