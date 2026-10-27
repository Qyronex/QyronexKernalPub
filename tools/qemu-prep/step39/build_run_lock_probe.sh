#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/tests/qemu-prep/step39/lock_probe.c"
OUT=${KERNAL_STEP39_LOCK_PROBE_OUT:-/tmp/kernal-step39-lock-probe}
CC=${CC:-cc}

fail() { printf 'step39-lock-probe: FAIL: %s\n' "$*" >&2; exit 1; }

[ -f "$SRC" ] || fail "missing source: $SRC"
command -v "$CC" >/dev/null 2>&1 || fail "compiler not found: $CC; prepare the reference fixture toolchain through the pinned snapshot path before running"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"

"$CC" \
  -std=c11 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  "$SRC" \
  -o "$OUT"

printf 'step39-lock-probe: compiler=%s\n' "$("$CC" --version | head -n 1)"
sha256sum "$SRC" "$OUT"
"$OUT"
