#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/tests/qemu-prep/step32/pty_probe.c"
OUT=${KERNAL_STEP32_PROBE_OUT:-/tmp/kernal-step32-pty-probe}
CC=${CC:-cc}

fail() { printf 'step32-pty-probe: FAIL: %s\n' "$*" >&2; exit 1; }

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

printf 'step32-pty-probe: compiler=%s\n' "$($CC --version | head -n 1)"
sha256sum "$SRC" "$OUT"
"$OUT"
