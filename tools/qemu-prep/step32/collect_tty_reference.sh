#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
PROBE="$ROOT/tools/qemu-prep/step32/build_run_pty_probe.sh"
NORMALIZER="$ROOT/tools/qemu-prep/step32/normalize_tty_reference.py"
TARGET="$ROOT/docs/debian13/arm64-target.json"
OUT=${KERNAL_STEP32_REFERENCE_OUT:-/tmp/kernal-step32-tty-reference.raw}
JSON_OUT=${KERNAL_STEP32_REFERENCE_JSON:-}

fail() { printf 'step32-reference: FAIL: %s\n' "$*" >&2; exit 1; }

[ -r /etc/os-release ] || fail "missing /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = "debian" ] || fail "reference collector must run in Debian, found ID=${ID:-missing}"
case "${VERSION_ID:-}" in
  13|13.*) ;;
  *) fail "reference collector requires Debian 13, found VERSION_ID=${VERSION_ID:-missing}" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64) ;;
  *) fail "reference collector requires AArch64 guest, found $ARCH" ;;
esac

[ -f "$PROBE" ] || fail "missing probe runner: $PROBE"
[ -f "$NORMALIZER" ] || fail "missing normalizer: $NORMALIZER"
[ -f "$TARGET" ] || fail "missing pinned target identity: $TARGET"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required for evidence identity"

validate_source_commit() {
  value=$1
  case "$value" in
    ''|*[!0-9a-f]*) fail "unexpected source commit identity: $value" ;;
  esac
  [ "${#value}" -eq 40 ] || fail "source commit identity must be a full 40-character lowercase git SHA"
}

SOURCE_COMMIT=${KERNAL_STEP32_SOURCE_COMMIT:-}
if [ -n "$SOURCE_COMMIT" ]; then
  validate_source_commit "$SOURCE_COMMIT"
  if command -v git >/dev/null 2>&1 &&
     git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    CHECKED_OUT_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
    validate_source_commit "$CHECKED_OUT_COMMIT"
    [ "$CHECKED_OUT_COMMIT" = "$SOURCE_COMMIT" ] ||
      fail "explicit source commit does not match checked-out HEAD"
  fi
else
  command -v git >/dev/null 2>&1 ||
    fail "git is required when KERNAL_STEP32_SOURCE_COMMIT is unset"
  SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
  validate_source_commit "$SOURCE_COMMIT"
fi
TARGET_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
COLLECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
KERNEL_RELEASE=$(uname -r)

mkdir -p "$(dirname "$OUT")"
TMP=$(mktemp "${TMPDIR:-/tmp}/kernal-step32-reference.XXXXXX")
trap 'rm -f "$TMP"' EXIT

{
  printf 'REFERENCE schema=1\n'
  printf 'REFERENCE collected_at=%s\n' "$COLLECTED_AT"
  printf 'REFERENCE os_id=%s\n' "$ID"
  printf 'REFERENCE os_version_id=%s\n' "$VERSION_ID"
  printf 'REFERENCE architecture=%s\n' "$ARCH"
  printf 'REFERENCE kernel_release=%s\n' "$KERNEL_RELEASE"
  printf 'REFERENCE source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'REFERENCE target_sha256=%s\n' "$TARGET_SHA256"
  bash "$PROBE"
} | tee "$TMP"

mv "$TMP" "$OUT"
trap - EXIT
printf 'step32-reference: raw_sha256=%s path=%s\n' "$(sha256sum "$OUT" | awk '{print $1}')" "$OUT"

if [ -n "$JSON_OUT" ]; then
  mkdir -p "$(dirname "$JSON_OUT")"
  python3 -B "$NORMALIZER" "$OUT" "$JSON_OUT"
fi

printf 'STEP32_REFERENCE_COLLECTION_OK source_commit=%s\n' "$SOURCE_COMMIT"
