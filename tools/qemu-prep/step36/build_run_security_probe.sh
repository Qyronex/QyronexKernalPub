#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/tests/qemu-prep/step36/security_api_probe.c"
OUT=${KERNAL_STEP36_SECURITY_PROBE_OUT:-/tmp/kernal-step36-security-api-probe}
CC=${CC:-cc}

fail() { printf 'step36-security-probe: FAIL: %s\n' "$*" >&2; exit 1; }
[ -f "$SRC" ] || fail "missing source: $SRC"
command -v "$CC" >/dev/null 2>&1 || fail "compiler unavailable: $CC"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"

"$CC" -std=c11 -O2 -Wall -Wextra -Werror "$SRC" -o "$OUT"
printf 'step36-security-probe: compiler=%s\n' "$($CC --version | head -n 1)"
sha256sum "$SRC" "$OUT"
"$OUT"
