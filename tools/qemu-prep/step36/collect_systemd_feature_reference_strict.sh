#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
SECURITY_PROBE="$ROOT/tools/qemu-prep/step36/build_run_security_probe.sh"
RESOURCE_PROBE="$ROOT/tests/qemu-prep/step36/resource_enforcement_probe.py"
OUT=${KERNAL_STEP36_OUTPUT:-/tmp/kernal-step36-reference}
mkdir -p "$OUT"
rm -f "$OUT/SHA256SUMS"

fail() { printf 'step36-reference: FAIL: %s\n' "$*" >&2; exit 1; }
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
[ -f "$SECURITY_PROBE" ] || fail "security probe runner missing: $SECURITY_PROBE"
[ -f "$RESOURCE_PROBE" ] || fail "resource enforcement probe missing: $RESOURCE_PROBE"
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

{
  printf 'schema=2\n'
  printf 'arch=%s\n' "$(uname -m)"
  printf 'pid1=%s\n' "$(cat /proc/1/comm)"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
  printf 'enforcement_requested=%s\n' "${KERNAL_STEP36_RUN_ENFORCEMENT:-0}"
} > "$OUT/identity.txt"

cp /proc/1/status "$OUT/proc-1-status.txt"
cp /proc/1/limits "$OUT/proc-1-limits.txt"
cp /proc/1/cgroup "$OUT/proc-1-cgroup.txt"
cp /proc/mounts "$OUT/proc-mounts.txt"

for path in \
  /sys/fs/cgroup/cgroup.controllers \
  /sys/fs/cgroup/cgroup.subtree_control \
  /sys/fs/cgroup/cgroup.type \
  /sys/fs/cgroup/cgroup.events \
  /sys/fs/cgroup/cgroup.stat \
  /proc/sys/kernel/cap_last_cap; do
  if [ -r "$path" ]; then
    safe=$(printf '%s' "$path" | tr '/' '_')
    cat "$path" > "$OUT/${safe}.txt"
  fi
done

for path in /sys/fs/selinux /sys/fs/smackfs /sys/kernel/security; do
  safe=$(printf '%s' "$path" | tr '/' '_')
  if [ -e "$path" ]; then
    printf 'present\n' > "$OUT/${safe}.state"
    ls -la "$path" > "$OUT/${safe}.listing" 2>&1 || true
  else
    printf 'absent\n' > "$OUT/${safe}.state"
  fi
done

run_capture systemctl-is-system-running systemctl is-system-running
run_capture systemctl-default-target systemctl get-default
run_capture systemctl-manager-show systemctl show --property=DefaultLimitNOFILE --property=DefaultLimitNPROC --property=DefaultTasksMax --property=ControlGroup --property=SystemState
run_capture systemctl-running-services systemctl list-units --type=service --state=running --no-pager --no-legend

if command -v prlimit >/dev/null 2>&1; then
  run_capture prlimit-pid1 prlimit --pid 1
else
  printf 'command-missing\n' > "$OUT/prlimit-pid1.status"
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  run_capture systemd-analyze-features systemd-analyze features
fi

UNITS=${KERNAL_STEP36_UNITS:-"systemd-journald.service dbus.service systemd-udevd.service"}
: > "$OUT/selected-units.txt"
for unit in $UNITS; do
  safe=$(printf '%s' "$unit" | tr '.@/-' '____')
  printf '%s\n' "$unit" >> "$OUT/selected-units.txt"
  run_capture "unit-$safe" systemctl show "$unit" \
    --property=LoadState \
    --property=ActiveState \
    --property=SubState \
    --property=ControlGroup \
    --property=MemoryAccounting \
    --property=MemoryCurrent \
    --property=MemoryMax \
    --property=TasksAccounting \
    --property=TasksCurrent \
    --property=TasksMax \
    --property=CPUAccounting \
    --property=CPUUsageNSec \
    --property=PrivateTmp \
    --property=PrivateDevices \
    --property=PrivateNetwork \
    --property=PrivateUsers \
    --property=PrivateMounts \
    --property=ProtectSystem \
    --property=ProtectHome \
    --property=NoNewPrivileges \
    --property=RestrictNamespaces \
    --property=RestrictAddressFamilies \
    --property=CapabilityBoundingSet \
    --property=AmbientCapabilities

  control_group=$(grep '^ControlGroup=' "$OUT/unit-$safe.stdout" 2>/dev/null | cut -d= -f2- || true)
  if [ -n "$control_group" ] && [ -d "/sys/fs/cgroup$control_group" ]; then
    cgroup_dir="/sys/fs/cgroup$control_group"
    find "$cgroup_dir" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort > "$OUT/unit-$safe-cgroup-files.txt" || true
    for name in cgroup.controllers cgroup.events cpu.max cpu.stat memory.current memory.events memory.max pids.current pids.events pids.max; do
      if [ -r "$cgroup_dir/$name" ]; then
        cp "$cgroup_dir/$name" "$OUT/unit-$safe-cgroup-${name//./_}.txt"
      fi
    done
  fi
done

run_capture security-api-probe bash "$SECURITY_PROBE"
SECURITY_STATUS=$(cat "$OUT/security-api-probe.status")
[ "$SECURITY_STATUS" = "0" ] || fail "security API reference probe failed with exit=$SECURITY_STATUS"
if command -v strace >/dev/null 2>&1; then
  set +e
  strace -f -s 256 -yy -e trace=prctl,seccomp,keyctl,bpf,socket,openat,newfstatat -o "$OUT/security-api-probe.strace" bash "$SECURITY_PROBE" >"$OUT/security-api-probe-strace.stdout" 2>"$OUT/security-api-probe-strace.stderr"
  printf '%s\n' "$?" > "$OUT/security-api-probe-strace.status"
  set -e
fi

if [ "${KERNAL_STEP36_RUN_ENFORCEMENT:-0}" = "1" ]; then
  [ "${KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED:-0}" = "1" ] || fail "resource enforcement probes require KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED=1"
  command -v systemd-run >/dev/null 2>&1 || fail "systemd-run required for resource enforcement reference"
  command -v python3 >/dev/null 2>&1 || fail "python3 required for resource enforcement reference"

  run_capture enforcement-pids systemd-run --quiet --wait --pipe --collect \
    --unit "kernal-step36-pids-$$.service" \
    --property=PidsAccounting=yes --property=TasksMax=8 \
    python3 "$RESOURCE_PROBE" pids

  run_capture enforcement-cpu systemd-run --quiet --wait --pipe --collect \
    --unit "kernal-step36-cpu-$$.service" \
    --property=CPUAccounting=yes --property=CPUQuota=25% \
    python3 "$RESOURCE_PROBE" cpu

  run_capture enforcement-memory systemd-run --quiet --wait --pipe --collect \
    --unit "kernal-step36-memory-$$.service" \
    --property=MemoryAccounting=yes --property=MemoryMax=33554432 \
    python3 "$RESOURCE_PROBE" memory --megabytes 96

  [ "$(cat "$OUT/enforcement-pids.status")" = "0" ] || fail "pids enforcement reference did not pass"
  [ "$(cat "$OUT/enforcement-cpu.status")" = "0" ] || fail "CPU throttling reference did not pass"
  if grep -q 'FAIL memory.enforcement-process-survived' "$OUT/enforcement-memory.stdout"; then
    fail "MemoryMax reference process survived its declared limit"
  fi
  if [ "$(cat "$OUT/enforcement-memory.status")" = "0" ]; then
    fail "MemoryMax reference unexpectedly returned success"
  fi
else
  printf 'SKIPPED explicit KERNAL_STEP36_RUN_ENFORCEMENT=1 plus KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED=1 required\n' > "$OUT/enforcement.status"
fi

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

printf 'STEP36_SYSTEMD_FEATURE_REFERENCE_OK source_commit=%s target_id=%s\n' "$SOURCE_COMMIT" "$TARGET_ID"
printf 'step36-reference: NOTE: default collection is read-only; enforcement runs only under explicit reference authorization\n'
