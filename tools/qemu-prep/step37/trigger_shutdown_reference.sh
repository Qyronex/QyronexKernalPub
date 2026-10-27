#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
MODE=${1:-}
MARKER_DIR=${KERNAL_STEP37_SHUTDOWN_MARKER_DIR:-/var/tmp/kernal-step37-shutdown}

fail() { printf 'step37-shutdown: FAIL: %s\n' "$*" >&2; exit 1; }
case "$MODE" in reboot|poweroff) ;; *) fail "usage: trigger_shutdown_reference.sh reboot|poweroff" ;; esac
[ "${KERNAL_REFERENCE_SHUTDOWN_CONFIRMED:-0}" = "1" ] || fail "requires KERNAL_REFERENCE_SHUTDOWN_CONFIRMED=1"
[ "${KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED:-0}" = "1" ] || fail "requires KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED=1"
[ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ] || fail "reference guest must be ARM64"
[ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || fail "PID 1 is not systemd"
[ -f "$TARGET" ] || fail "pinned target identity missing: $TARGET"
command -v systemctl >/dev/null 2>&1 || fail "systemctl unavailable"
command -v git >/dev/null 2>&1 || fail "git unavailable"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"

SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
TARGET_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
TARGET_ID=$(python3 - "$TARGET" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))['target_id'])
PY
)
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/${MODE}-${SOURCE_COMMIT}.txt"
{
  printf 'schema=1\n'
  printf 'mode=%s\n' "$MODE"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
  printf 'pid1=systemd\n'
  printf 'requested_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MARKER"
sha256sum "$MARKER" > "$MARKER.sha256"
sync "$MARKER" "$MARKER.sha256" 2>/dev/null || sync
printf 'STEP37_SHUTDOWN_TRIGGER mode=%s source_commit=%s target_id=%s marker=%s\n' "$MODE" "$SOURCE_COMMIT" "$TARGET_ID" "$MARKER"
printf 'step37-shutdown: host/QEMU harness must confirm the requested %s completed; this pre-trigger marker alone is not acceptance evidence\n' "$MODE"
exec systemctl "$MODE" --no-wall
