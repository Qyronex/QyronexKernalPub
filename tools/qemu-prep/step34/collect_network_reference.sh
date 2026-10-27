#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
PROBE="$ROOT/tools/qemu-prep/step34/build_run_network_probe.sh"
OUT=${KERNAL_STEP34_NETWORK_OUTPUT:-/tmp/kernal-step34-network-reference}
mkdir -p "$OUT"

fail() { printf 'step34-network-reference: FAIL: %s\n' "$*" >&2; exit 1; }
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
[ -f "$PROBE" ] || fail "network probe runner missing: $PROBE"
command -v ip >/dev/null 2>&1 || fail "iproute2/ip command unavailable"
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
  printf 'arch=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'target_id=%s\n' "$TARGET_ID"
  printf 'target_sha256=%s\n' "$TARGET_SHA256"
} > "$OUT/identity.txt"

run_capture ip-link ip -details link show
run_capture ip-addr ip -details addr show
run_capture ip-route4 ip route show table all
run_capture ip-rule4 ip rule show
run_capture ip-route6 ip -6 route show table all
run_capture ip-rule6 ip -6 rule show
run_capture ip-neigh ip neigh show

cp /proc/net/dev "$OUT/proc-net-dev.txt"
[ -r /proc/net/route ] && cp /proc/net/route "$OUT/proc-net-route.txt"
[ -r /proc/net/ipv6_route ] && cp /proc/net/ipv6_route "$OUT/proc-net-ipv6-route.txt"
[ -r /proc/net/if_inet6 ] && cp /proc/net/if_inet6 "$OUT/proc-net-if-inet6.txt"
[ -r /etc/hosts ] && cp /etc/hosts "$OUT/etc-hosts.txt"
[ -r /etc/hostname ] && cp /etc/hostname "$OUT/etc-hostname.txt"

if [ -L /etc/resolv.conf ]; then
  readlink /etc/resolv.conf > "$OUT/resolv-conf-symlink.txt"
fi
if [ -r /etc/resolv.conf ]; then
  cp /etc/resolv.conf "$OUT/resolv-conf.txt"
fi

DEFAULT_IF=$(ip route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}')
if [ -z "$DEFAULT_IF" ]; then
  DEFAULT_IF=$(ip -o link show 2>/dev/null | awk -F': ' '$2 != "lo" {split($2,a,"@"); print a[1]; exit}')
fi
{
  printf 'default_iface=%s\n' "$DEFAULT_IF"
  printf 'dns_name=%s\n' "${KERNAL_DNS_NAME:-}"
  printf 'active_probe_requested=%s\n' "${KERNAL_STEP34_RUN_ACTIVE_PROBE:-0}"
} > "$OUT/selection.txt"

if [ -n "$DEFAULT_IF" ] && [ -e "/sys/class/net/$DEFAULT_IF" ]; then
  readlink -f "/sys/class/net/$DEFAULT_IF" > "$OUT/default-iface-sysfs-path.txt"
  for attr in address mtu operstate carrier type; do
    if [ -r "/sys/class/net/$DEFAULT_IF/$attr" ]; then
      cat "/sys/class/net/$DEFAULT_IF/$attr" > "$OUT/default-iface-$attr.txt"
    fi
  done
  if command -v ethtool >/dev/null 2>&1; then
    run_capture ethtool-info ethtool -i "$DEFAULT_IF"
    run_capture ethtool-features ethtool -k "$DEFAULT_IF"
  fi
fi

if command -v networkctl >/dev/null 2>&1; then
  run_capture networkctl-list networkctl list --no-pager
  if [ -n "$DEFAULT_IF" ]; then
    run_capture networkctl-default networkctl status "$DEFAULT_IF" --no-pager
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  for unit in systemd-networkd.service NetworkManager.service networking.service systemd-resolved.service; do
    safe=$(printf '%s' "$unit" | tr '.@/' '___')
    run_capture "unit-$safe" systemctl show "$unit" --property=LoadState --property=ActiveState --property=SubState --property=FragmentPath --property=UnitFileState
  done
fi

for dir in /etc/systemd/network /etc/NetworkManager/system-connections /etc/network; do
  safe=$(printf '%s' "$dir" | tr '/' '_')
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 2 -type f -printf '%p\n' 2>/dev/null | sort > "$OUT/${safe}-files.txt" || true
  fi
done
# Do not copy secret-bearing network configuration contents. File names and
# service state are enough to classify the active configuration path.

ACTIVE_PROBE_STATUS=SKIPPED
if [ "${KERNAL_STEP34_RUN_ACTIVE_PROBE:-0}" = "1" ]; then
  [ "${KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED:-0}" = "1" ] || fail "active network probe requires KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED=1"
  run_capture active-network-probe bash "$PROBE"
  ACTIVE_PROBE_STATUS=$(cat "$OUT/active-network-probe.status")
fi
printf 'active_probe_status=%s\n' "$ACTIVE_PROBE_STATUS" >> "$OUT/selection.txt"

if [ -n "${KERNAL_DNS_NAME:-}" ]; then
  command -v getent >/dev/null 2>&1 || fail "getent required for glibc resolver reference"
  run_capture dns-getent getent ahosts "$KERNAL_DNS_NAME"
  if command -v strace >/dev/null 2>&1; then
    set +e
    strace -f -s 256 -yy -e trace=network -o "$OUT/dns-network.strace" getent ahosts "$KERNAL_DNS_NAME" >"$OUT/dns-strace-getent.stdout" 2>"$OUT/dns-strace-getent.stderr"
    printf '%s\n' "$?" >"$OUT/dns-strace-getent.status"
    set -e
  else
    printf 'strace_unavailable=1\n' > "$OUT/dns-strace-unavailable.txt"
  fi
fi

rm -f "$OUT/SHA256SUMS"
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

if [ "${KERNAL_STEP34_RUN_ACTIVE_PROBE:-0}" = "1" ] && [ "$ACTIVE_PROBE_STATUS" != "0" ]; then
  fail "active network probe failed with exit=$ACTIVE_PROBE_STATUS; evidence retained in $OUT"
fi

printf 'step34-network-reference: PASS: network reference snapshot staged in %s\n' "$OUT"
printf 'step34-network-reference: NOTE: no interface, route, resolver or service configuration was changed\n'
printf 'STEP34_NETWORK_REFERENCE_OK source_commit=%s target_id=%s\n' "$SOURCE_COMMIT" "$TARGET_ID"
