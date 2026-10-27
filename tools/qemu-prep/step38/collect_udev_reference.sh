#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
OUT=${KERNAL_STEP38_OUTPUT:-/tmp/kernal-step38-reference}
SELECTED_PROFILE=${KERNAL_STEP38_TRANSPORT_PROFILE:-virtio-mmio-fast-path}
mkdir -p "$OUT/devices"

fail() { printf 'step38-reference: FAIL: %s\n' "$*" >&2; exit 1; }
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
copy_if_readable() {
  src=$1
  dst=$2
  [ -r "$src" ] && cp "$src" "$dst" || true
}

[ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ] || fail "reference guest must be ARM64"
[ -r /etc/os-release ] || fail "/etc/os-release unavailable"
[ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || fail "PID 1 is not systemd"
[ -f "$TARGET" ] || fail "pinned target identity missing: $TARGET"
command -v udevadm >/dev/null 2>&1 || fail "udevadm unavailable"
command -v git >/dev/null 2>&1 || fail "git unavailable"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"
case "$SELECTED_PROFILE" in virtio-mmio-fast-path|virtio-pci-fallback) ;; *) fail "unknown Step38 transport profile: $SELECTED_PROFILE" ;; esac

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
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'pid1=systemd\n'
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
  printf 'transport_profile=%s\n' "$SELECTED_PROFILE"
  printf 'udev_test_requested=%s\n' "${KERNAL_STEP38_RUN_UDEV_TEST:-0}"
} > "$OUT/identity.txt"

run_capture udevadm-info-export-db udevadm info --export-db
run_capture udevadm-version udevadm --version
if command -v systemctl >/dev/null 2>&1; then
  run_capture udev-service systemctl show systemd-udevd.service --property=LoadState --property=ActiveState --property=SubState --property=FragmentPath --property=ControlGroup --property=MainPID
fi
if command -v journalctl >/dev/null 2>&1; then
  run_capture udev-journal-boot journalctl -b -u systemd-udevd.service --no-pager
fi
if command -v dpkg-query >/dev/null 2>&1; then
  run_capture udev-package dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' systemd-udev
fi

root_source=""
if command -v findmnt >/dev/null 2>&1; then
  root_source=$(findmnt -n -o SOURCE / 2>/dev/null || true)
fi
printf 'root_source=%s\n' "$root_source" > "$OUT/selected.txt"

net_iface=""
if command -v ip >/dev/null 2>&1; then
  net_iface=$(ip route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}')
  if [ -z "$net_iface" ]; then
    net_iface=$(ip -o link show 2>/dev/null | awk -F': ' '$2 != "lo" {split($2,a,"@"); print a[1]; exit}')
  fi
fi
printf 'net_iface=%s\n' "$net_iface" >> "$OUT/selected.txt"

selected_paths=""
if [ -n "$root_source" ] && [ -e "$root_source" ]; then
  block_name=$(basename "$root_source")
  safe=$(printf '%s' "$block_name" | tr '/@.' '___')
  run_capture "devices/root-$safe" udevadm info --query=all --name "$root_source"
  if [ -e "/sys/class/block/$block_name" ]; then
    block_path=$(readlink -f "/sys/class/block/$block_name")
    printf '%s\n' "$block_path" > "$OUT/devices/root-sysfs-path.txt"
    selected_paths="$selected_paths $block_path"
    copy_if_readable "$block_path/uevent" "$OUT/devices/root-uevent.txt"
    copy_if_readable "$block_path/dev" "$OUT/devices/root-dev.txt"
    copy_if_readable "$block_path/size" "$OUT/devices/root-size.txt"
    copy_if_readable "$block_path/ro" "$OUT/devices/root-ro.txt"
    copy_if_readable "$block_path/removable" "$OUT/devices/root-removable.txt"
    copy_if_readable "$block_path/queue/logical_block_size" "$OUT/devices/root-logical-block-size.txt"
    copy_if_readable "$block_path/queue/physical_block_size" "$OUT/devices/root-physical-block-size.txt"
    run_capture devices/root-attribute-walk udevadm info --attribute-walk --path "$block_path"
  fi
  stat -Lc 'path=%n mode=%a uid=%u gid=%g type=%F major=%t minor=%T' "$root_source" > "$OUT/devices/root-node.stat" || true
fi

if [ -n "$net_iface" ] && [ -e "/sys/class/net/$net_iface" ]; then
  net_path=$(readlink -f "/sys/class/net/$net_iface")
  printf '%s\n' "$net_path" > "$OUT/devices/net-sysfs-path.txt"
  selected_paths="$selected_paths $net_path"
  run_capture devices/net-properties udevadm info --query=all --path "$net_path"
  run_capture devices/net-attribute-walk udevadm info --attribute-walk --path "$net_path"
  for attr in uevent address mtu operstate carrier ifindex type; do
    copy_if_readable "$net_path/$attr" "$OUT/devices/net-${attr//\//_}.txt"
  done
fi

for tty in ttyAMA0 ttyS0 hvc0; do
  if [ -e "/sys/class/tty/$tty" ]; then
    tty_path=$(readlink -f "/sys/class/tty/$tty")
    printf '%s\n' "$tty_path" > "$OUT/devices/$tty-sysfs-path.txt"
    selected_paths="$selected_paths $tty_path"
    run_capture "devices/$tty-properties" udevadm info --query=all --path "$tty_path"
    run_capture "devices/$tty-attribute-walk" udevadm info --attribute-walk --path "$tty_path"
    copy_if_readable "$tty_path/uevent" "$OUT/devices/$tty-uevent.txt"
    copy_if_readable "$tty_path/dev" "$OUT/devices/$tty-dev.txt"
    if [ -e "/dev/$tty" ]; then
      stat -Lc 'path=%n mode=%a uid=%u gid=%g type=%F major=%t minor=%T' "/dev/$tty" > "$OUT/devices/$tty-node.stat" || true
    fi
  fi
done

for path in /dev/console /dev/null /dev/zero /dev/full /dev/ptmx; do
  safe=$(printf '%s' "$path" | tr '/' '_')
  if [ -e "$path" ]; then
    stat -Lc 'path=%n mode=%a uid=%u gid=%g type=%F major=%t minor=%T' "$path" > "$OUT/devices/${safe}.stat"
  else
    printf 'absent\n' > "$OUT/devices/${safe}.stat"
  fi
done

if [ "${KERNAL_STEP38_RUN_UDEV_TEST:-0}" = "1" ]; then
  [ "${KERNAL_REFERENCE_UDEV_TEST_CONFIRMED:-0}" = "1" ] || fail "udevadm test requires KERNAL_REFERENCE_UDEV_TEST_CONFIRMED=1"
  for sysfs_path in $selected_paths; do
    safe=$(printf '%s' "$sysfs_path" | tr '/@.:' '_____')
    run_capture "udev-test-$safe" udevadm test --action=add "$sysfs_path"
  done
else
  printf 'SKIPPED explicit KERNAL_STEP38_RUN_UDEV_TEST=1 plus KERNAL_REFERENCE_UDEV_TEST_CONFIRMED=1 required\n' > "$OUT/udev-test.status"
fi

rm -f "$OUT/SHA256SUMS"
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

printf 'STEP38_UDEV_REFERENCE_OK source_commit=%s target_id=%s profile=%s\n' "$SOURCE_COMMIT" "$TARGET_ID" "$SELECTED_PROFILE"
printf 'step38-reference: NOTE: boot enumeration is always collected; hotplug is required only if the selected transport profile explicitly claims it\n'
