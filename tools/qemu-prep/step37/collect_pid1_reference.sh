#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
OUT=${KERNAL_STEP37_OUTPUT:-/tmp/kernal-step37-reference}
CANDIDATES=${KERNAL_STEP37_SERVICE_CANDIDATES:-"ssh.service cron.service systemd-timesyncd.service getty@tty1.service rsyslog.service"}
mkdir -p "$OUT/services"

fail() { printf 'step37-reference: FAIL: %s\n' "$*" >&2; exit 1; }
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
[ -r /proc/1/comm ] || fail "/proc/1/comm unavailable"
[ "$(cat /proc/1/comm)" = systemd ] || fail "PID 1 is not systemd"
[ -f "$TARGET" ] || fail "pinned target identity missing: $TARGET"
command -v systemctl >/dev/null 2>&1 || fail "systemctl unavailable"
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
PID1_EXE=$(readlink -f /proc/1/exe || true)

{
  printf 'schema=2\n'
  printf 'arch=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'pid1_comm=%s\n' "$(cat /proc/1/comm)"
  printf 'pid1_exe=%s\n' "$PID1_EXE"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
  printf 'failure_probe_requested=%s\n' "${KERNAL_STEP37_RUN_FAILURE_PROBE:-0}"
} > "$OUT/identity.txt"

if command -v systemd >/dev/null 2>&1; then
  run_capture systemd-version systemd --version
fi
if command -v dpkg-query >/dev/null 2>&1 && [ -n "$PID1_EXE" ]; then
  set +e
  dpkg-query -S "$PID1_EXE" >"$OUT/pid1-package-owner.stdout" 2>"$OUT/pid1-package-owner.stderr"
  printf '%s\n' "$?" >"$OUT/pid1-package-owner.status"
  set -e
  run_capture systemd-package-version dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' systemd
fi

cp /proc/1/status "$OUT/proc-1-status.txt"
cp /proc/1/cgroup "$OUT/proc-1-cgroup.txt"
cp /proc/mounts "$OUT/proc-mounts.txt"

run_capture systemctl-is-system-running systemctl is-system-running
run_capture systemctl-get-default systemctl get-default
run_capture systemctl-list-running-services systemctl list-units --type=service --state=running --no-pager --no-legend
run_capture systemctl-list-failed systemctl --failed --no-pager --no-legend
run_capture systemctl-show-manager systemctl show --property=SystemState --property=DefaultStandardOutput --property=DefaultStandardError --property=ControlGroup

DEFAULT_TARGET=$(cat "$OUT/systemctl-get-default.stdout" 2>/dev/null | tr -d '\r\n' || true)
if [ -n "$DEFAULT_TARGET" ]; then
  run_capture default-target-dependencies systemctl list-dependencies --after --all --no-pager "$DEFAULT_TARGET"
fi

: > "$OUT/service-candidates.txt"
for unit in $CANDIDATES; do
  safe=$(printf '%s' "$unit" | tr '/@.-' '____')
  printf '%s\n' "$unit" >> "$OUT/service-candidates.txt"
  run_capture "services/$safe" systemctl show "$unit" \
    --property=Id \
    --property=LoadState \
    --property=ActiveState \
    --property=SubState \
    --property=UnitFileState \
    --property=FragmentPath \
    --property=ControlGroup \
    --property=CanStart \
    --property=CanStop \
    --property=RefuseManualStart \
    --property=RefuseManualStop

  fragment=$(grep '^FragmentPath=' "$OUT/services/$safe.stdout" 2>/dev/null | cut -d= -f2- || true)
  if command -v dpkg-query >/dev/null 2>&1 && [ -n "$fragment" ] && [ -e "$fragment" ]; then
    set +e
    owner=$(dpkg-query -S "$fragment" 2>"$OUT/services/$safe.package-owner.stderr")
    owner_rc=$?
    set -e
    printf '%s\n' "$owner_rc" > "$OUT/services/$safe.package-owner.status"
    printf '%s\n' "$owner" > "$OUT/services/$safe.package-owner.stdout"
    if [ "$owner_rc" = "0" ]; then
      package=$(printf '%s\n' "$owner" | head -n 1 | cut -d: -f1)
      if [ -n "$package" ]; then
        run_capture "services/$safe.package" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' "$package"
      fi
    fi
  fi
done

if command -v journalctl >/dev/null 2>&1; then
  run_capture journal-boot-tail journalctl -b --no-pager -n 500
  run_capture journal-warning-errors journalctl -b --no-pager -p warning..alert
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  run_capture systemd-analyze-time systemd-analyze time
  run_capture systemd-analyze-critical-chain systemd-analyze critical-chain
  if [ -n "$DEFAULT_TARGET" ]; then
    run_capture systemd-analyze-critical-chain-default systemd-analyze critical-chain "$DEFAULT_TARGET"
  fi
fi

if [ "${KERNAL_STEP37_RUN_FAILURE_PROBE:-0}" = "1" ]; then
  [ "${KERNAL_REFERENCE_FAILURE_PROBE_CONFIRMED:-0}" = "1" ] || fail "failure diagnostics probe requires KERNAL_REFERENCE_FAILURE_PROBE_CONFIRMED=1"
  command -v systemd-run >/dev/null 2>&1 || fail "systemd-run unavailable for failure diagnostics probe"
  unit="kernal-step37-failure-$$.service"
  run_capture failure-probe-run systemd-run --quiet --wait --unit "$unit" /bin/false
  run_capture failure-probe-status systemctl status "$unit" --no-pager --full
  if command -v journalctl >/dev/null 2>&1; then
    run_capture failure-probe-journal journalctl -u "$unit" --no-pager
  fi
  run_capture failure-probe-reset systemctl reset-failed "$unit"
  if [ "$(cat "$OUT/failure-probe-run.status")" = "0" ]; then
    fail "intentional failed-service probe unexpectedly returned success"
  fi
else
  printf 'SKIPPED explicit KERNAL_STEP37_RUN_FAILURE_PROBE=1 plus KERNAL_REFERENCE_FAILURE_PROBE_CONFIRMED=1 required\n' > "$OUT/failure-probe.status"
fi

rm -f "$OUT/SHA256SUMS"
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

printf 'STEP37_PID1_REFERENCE_OK source_commit=%s target_id=%s\n' "$SOURCE_COMMIT" "$TARGET_ID"
printf 'step37-reference: NOTE: service candidates are discovery input only; exactly three eligible ordinary services must be frozen by normalized evidence before PREP_READY\n'
