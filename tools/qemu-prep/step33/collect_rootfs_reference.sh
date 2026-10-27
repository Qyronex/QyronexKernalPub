#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
PROBE="$ROOT/tools/qemu-prep/step33/build_run_filesystem_probe.sh"
OUT=${KERNAL_STEP33_ROOTFS_OUTPUT:-/tmp/kernal-step33-rootfs-reference}
mkdir -p "$OUT"

fail() { printf 'step33-rootfs-reference: FAIL: %s\n' "$*" >&2; exit 1; }
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
[ -f "$PROBE" ] || fail "filesystem probe runner missing: $PROBE"
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
case "$SOURCE_COMMIT" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) fail "unexpected source commit identity: $SOURCE_COMMIT" ;;
esac
TARGET_SHA256=$(sha256sum "$TARGET" | awk '{print $1}')
TARGET_ID=$(python3 - "$TARGET" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))['target_id'])
PY
)

{
  printf 'arch=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
  printf 'root_findmnt='
  if command -v findmnt >/dev/null 2>&1; then
    findmnt -n -o SOURCE,FSTYPE,OPTIONS / || true
  else
    printf 'findmnt-unavailable\n'
  fi
} > "$OUT/identity.txt"

cp /proc/mounts "$OUT/proc-mounts.txt"
run_capture df-types df -T
run_capture stat-root stat -f /

if command -v findmnt >/dev/null 2>&1; then
  run_capture findmnt-root findmnt -o SOURCE,TARGET,FSTYPE,OPTIONS /
  run_capture findmnt-all findmnt -o SOURCE,TARGET,FSTYPE,OPTIONS
  set +e
  findmnt --json -o SOURCE,TARGET,FSTYPE,OPTIONS >"$OUT/findmnt-json.stdout" 2>"$OUT/findmnt-json.stderr"
  printf '%s\n' "$?" >"$OUT/findmnt-json.status"
  set -e
fi

if command -v lsblk >/dev/null 2>&1; then
  run_capture lsblk lsblk -o NAME,MAJ:MIN,SIZE,RO,TYPE,FSTYPE,FSVER,LABEL,UUID,PARTUUID,MOUNTPOINTS
fi
if command -v blkid >/dev/null 2>&1; then
  run_capture blkid blkid
fi

ROOT_SOURCE=""
ROOT_FSTYPE=""
if command -v findmnt >/dev/null 2>&1; then
  ROOT_SOURCE=$(findmnt -n -o SOURCE / 2>/dev/null || true)
  ROOT_FSTYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || true)
fi
printf 'root_source=%s\nroot_fstype=%s\n' "$ROOT_SOURCE" "$ROOT_FSTYPE" > "$OUT/root-selection.txt"

ROOT_REAL=""
if [ -n "$ROOT_SOURCE" ] && [ -e "$ROOT_SOURCE" ]; then
  ROOT_REAL=$(readlink -f "$ROOT_SOURCE" || true)
fi
printf 'root_real=%s\n' "$ROOT_REAL" >> "$OUT/root-selection.txt"

# ext4 metadata inspection is read-only. Do not run fsck or any mutating tool here.
if [ "$ROOT_FSTYPE" = ext4 ] && [ -n "$ROOT_REAL" ] && [ -b "$ROOT_REAL" ]; then
  if command -v tune2fs >/dev/null 2>&1; then
    run_capture ext4-tune2fs tune2fs -l "$ROOT_REAL"
  fi
  if command -v dumpe2fs >/dev/null 2>&1; then
    run_capture ext4-dumpe2fs-header dumpe2fs -h "$ROOT_REAL"
  fi
fi

if command -v mountpoint >/dev/null 2>&1; then
  for path in /proc /sys /dev /dev/pts /run /tmp /sys/fs/cgroup; do
    safe=$(printf '%s' "$path" | tr '/' '_')
    set +e
    mountpoint "$path" >"$OUT/mountpoint-${safe}.stdout" 2>"$OUT/mountpoint-${safe}.stderr"
    printf '%s\n' "$?" >"$OUT/mountpoint-${safe}.status"
    set -e
  done
fi

WRITE_PROBE_STATUS=SKIPPED
if [ "${KERNAL_STEP33_RUN_WRITE_PROBE:-0}" = "1" ]; then
  [ "${KERNAL_REFERENCE_OVERLAY_CONFIRMED:-0}" = "1" ] || fail "write probe requires KERNAL_REFERENCE_OVERLAY_CONFIRMED=1; never write the pinned base image"
  command -v findmnt >/dev/null 2>&1 || fail "findmnt required to bind write probe to reference root"
  PROBE_PARENT=${KERNAL_STEP33_PROBE_PARENT:-/var/tmp}
  [ -d "$PROBE_PARENT" ] || fail "probe parent missing: $PROBE_PARENT"
  ROOT_PROBE_SOURCE=$(findmnt -n -o SOURCE -T "$PROBE_PARENT" 2>/dev/null || true)
  [ -n "$ROOT_SOURCE" ] || fail "root source unavailable; cannot prove write-probe filesystem identity"
  [ "$ROOT_PROBE_SOURCE" = "$ROOT_SOURCE" ] || fail "probe parent $PROBE_PARENT is not on root source $ROOT_SOURCE (found $ROOT_PROBE_SOURCE)"
  run_capture filesystem-probe env KERNAL_STEP33_PROBE_PARENT="$PROBE_PARENT" bash "$PROBE"
  WRITE_PROBE_STATUS=$(cat "$OUT/filesystem-probe.status")
fi
printf 'write_probe_requested=%s\nwrite_probe_status=%s\n' "${KERNAL_STEP33_RUN_WRITE_PROBE:-0}" "$WRITE_PROBE_STATUS" > "$OUT/write-probe.txt"

rm -f "$OUT/SHA256SUMS"
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

if [ "${KERNAL_STEP33_RUN_WRITE_PROBE:-0}" = "1" ] && [ "$WRITE_PROBE_STATUS" != "0" ]; then
  fail "filesystem durability probe failed with exit=$WRITE_PROBE_STATUS; evidence retained in $OUT"
fi

printf 'step33-rootfs-reference: PASS: rootfs layout snapshot staged in %s\n' "$OUT"
if [ "${KERNAL_STEP33_RUN_WRITE_PROBE:-0}" = "1" ]; then
  printf 'step33-rootfs-reference: NOTE: temporary durability writes ran only on the explicitly confirmed COW overlay root and were removed by the probe\n'
else
  printf 'step33-rootfs-reference: NOTE: read-only collection only; set KERNAL_STEP33_RUN_WRITE_PROBE=1 plus KERNAL_REFERENCE_OVERLAY_CONFIRMED=1 for the controlled durability probe\n'
fi
printf 'STEP33_ROOTFS_REFERENCE_OK source_commit=%s target_id=%s\n' "$SOURCE_COMMIT" "$TARGET_ID"
