#!/bin/bash
set -eu

ROOT="${KERNAL_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CC="${KERNAL_AARCH64_MUSL_CC:-aarch64-linux-musl-gcc}"
SOURCE="$ROOT/tests/step29/fd_pipe_roundtrip.c"
OUT_DIR="${KERNAL_STEP29_FD_PIPE_OUT_DIR:-$ROOT/target/step29}"
OUTPUT="$OUT_DIR/fd-pipe-roundtrip"
TEMP="$OUT_DIR/.fd-pipe-roundtrip.$$.tmp"

cleanup() {
  rm -f "$TEMP"
}
trap cleanup EXIT INT TERM

[ -n "$CC" ] || {
  printf 'KERNAL_AARCH64_MUSL_CC must name one compiler executable\n' >&2
  exit 64
}
[ -f "$SOURCE" ] || {
  printf 'Step-29 fd/pipe fixture source not found: %s\n' "$SOURCE" >&2
  exit 1
}

if ! command -v "$CC" >/dev/null 2>&1 && [ ! -x "$CC" ]; then
  printf 'AArch64 musl compiler not found: %s\n' "$CC" >&2
  printf 'set KERNAL_AARCH64_MUSL_CC=/path/to/aarch64-linux-musl-gcc if needed\n' >&2
  exit 1
fi

TARGET_TRIPLE=$("$CC" -dumpmachine 2>/dev/null) || {
  printf 'cannot query compiler target from: %s\n' "$CC" >&2
  exit 1
}
case "$TARGET_TRIPLE" in
  aarch64*-linux-musl*)
    ;;
  *)
    printf 'Step-29 fd/pipe compiler is not an AArch64 musl toolchain: %s reports %s\n' \
      "$CC" "$TARGET_TRIPLE" >&2
    exit 1
    ;;
esac
printf 'Step-29 fd/pipe musl compiler target: %s\n' "$TARGET_TRIPLE"

mkdir -p "$OUT_DIR"
rm -f "$TEMP"

"$CC" \
  -O2 \
  -static \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  -o "$TEMP" \
  "$SOURCE"

[ -s "$TEMP" ] || {
  printf 'AArch64 musl compiler produced no Step-29 fd/pipe fixture payload\n' >&2
  exit 1
}

mv -f "$TEMP" "$OUTPUT"
trap - EXIT INT TERM
printf '%s\n' "$OUTPUT"
