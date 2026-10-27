#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
PROBE="$ROOT/tools/qemu-prep/step35/build_run_event_probe.sh"
OUT=${KERNAL_STEP35_REFERENCE_OUT:-/tmp/kernal-step35-event-fd-reference}
mkdir -p "$OUT"

fail() { printf 'step35-reference: FAIL: %s\n' "$*" >&2; exit 1; }
run_capture() {
  name=$1
  shift
  set +e
  "$@" >"$OUT/$name.stdout" 2>"$OUT/$name.stderr"
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$OUT/$name.status"
  return 0
}

[ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ] || fail "reference guest must be ARM64"
[ -r /etc/os-release ] || fail "/etc/os-release unavailable"
[ -f "$TARGET" ] || fail "pinned target identity missing: $TARGET"
[ -f "$PROBE" ] || fail "event-fd probe runner missing: $PROBE"
command -v git >/dev/null 2>&1 || fail "git unavailable"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"

python3 - <<'PY'
from pathlib import Path
values = {}
for raw in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
    if '=' not in raw or raw.startswith('#'):
        continue
    key, value = raw.split('=', 1)
    values[key] = value.strip().strip('"').strip("'")
if values.get('ID') != 'debian':
    raise SystemExit('reference guest must be Debian')
if values.get('VERSION_ID', '').split('.', 1)[0] != '13':
    raise SystemExit('reference guest must be Debian 13')
if values.get('VERSION_CODENAME') != 'trixie':
    raise SystemExit('reference guest must be Trixie')
PY

SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[ "${#SOURCE_COMMIT}" -eq 40 ] || fail "unexpected source commit length"
case "$SOURCE_COMMIT" in *[!0-9a-f]*) fail "source commit is not lowercase hex: $SOURCE_COMMIT" ;; esac
TARGET_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
TARGET_ID=$(python3 - "$TARGET" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))['target_id'])
PY
)

{
  printf 'schema=1\n'
  printf 'arch=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
} > "$OUT/identity.txt"

run_capture event-fd-probe bash "$PROBE"
PROBE_STATUS=$(cat "$OUT/event-fd-probe.status")
[ "$PROBE_STATUS" = "0" ] || fail "event-fd reference probe failed with exit=$PROBE_STATUS; evidence retained in $OUT"

TRACE_SYSCALLS='epoll_create1,epoll_ctl,epoll_wait,epoll_pwait,epoll_pwait2,eventfd2,timerfd_create,timerfd_settime,signalfd4,inotify_init1,inotify_add_watch,memfd_create,pidfd_open,pidfd_send_signal,close_range'
if command -v strace >/dev/null 2>&1; then
  set +e
  strace -f -s 256 -yy -e "trace=$TRACE_SYSCALLS" -o "$OUT/event-fd-probe.strace" bash "$PROBE" >"$OUT/event-fd-probe-strace.stdout" 2>"$OUT/event-fd-probe-strace.stderr"
  printf '%s\n' "$?" >"$OUT/event-fd-probe-strace.status"
  set -e
else
  printf 'strace_unavailable=1\n' > "$OUT/strace-unavailable.txt"
fi

if command -v systemctl >/dev/null 2>&1; then
  run_capture systemctl-running systemctl is-system-running
  run_capture systemctl-services systemctl list-units --type=service --state=running --no-pager --no-legend
  if command -v strace >/dev/null 2>&1; then
    set +e
    strace -f -s 256 -yy -e "trace=$TRACE_SYSCALLS" -o "$OUT/systemctl-event-api.strace" systemctl list-units --type=service --state=running --no-pager --no-legend >"$OUT/systemctl-strace.stdout" 2>"$OUT/systemctl-strace.stderr"
    printf '%s\n' "$?" >"$OUT/systemctl-strace.status"
    set -e
  fi
fi

if command -v busctl >/dev/null 2>&1; then
  run_capture busctl-system busctl --system list --no-pager
  if command -v strace >/dev/null 2>&1; then
    set +e
    strace -f -s 256 -yy -e "trace=$TRACE_SYSCALLS" -o "$OUT/busctl-event-api.strace" busctl --system list --no-pager >"$OUT/busctl-strace.stdout" 2>"$OUT/busctl-strace.stderr"
    printf '%s\n' "$?" >"$OUT/busctl-strace.status"
    set -e
  fi
fi

rm -f "$OUT/SHA256SUMS"
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

printf 'STEP35_EVENT_FD_REFERENCE_OK source_commit=%s target_id=%s\n' "$SOURCE_COMMIT" "$TARGET_ID"
printf 'step35-reference: NOTE: systemctl/busctl collection is read-only; no service lifecycle mutation is performed by this collector\n'
