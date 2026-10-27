#!/bin/bash
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
COLLECTOR="$ROOT/tools/debian13/collect-reference.py"
KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
PACKAGES="apt busybox dash dbus dpkg iproute2 libc6 strace systemd udev"

[ "$(id -u)" -eq 0 ] || {
  printf 'prepare-reference.sh must run as root inside the Debian reference guest\n' >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || { printf 'python3 is required in the reference guest\n' >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { printf 'apt-get is required in the reference guest\n' >&2; exit 1; }
[ -f "$KEYRING" ] || {
  printf 'Debian archive keyring is missing: %s\n' "$KEYRING" >&2
  exit 1
}

# Fail closed before touching package state. The collector performs the same checks again before
# execution; this short preflight intentionally uses only base-image tools that must already exist.
[ "$(dpkg --print-architecture)" = arm64 ] || {
  printf 'reference guest must use dpkg architecture arm64\n' >&2
  exit 1
}
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
    raise SystemExit(f"reference guest must be Debian 13, got {values.get('VERSION_ID')!r}")
if values.get('VERSION_CODENAME') != 'trixie':
    raise SystemExit(f"reference guest must be trixie, got {values.get('VERSION_CODENAME')!r}")
PY

TMP=$(mktemp -d /tmp/kernal-debian13-snapshot.XXXXXX)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
SOURCES="$TMP/kernal-oracle.sources"

# Generate a temporary Deb822 source file directly from the pinned manifest. Existing guest apt
# sources are ignored rather than rewritten, so no floating mirror can participate in this setup.
python3 - "$TARGET" "$KEYRING" > "$SOURCES" <<'PY'
import json
import sys
from pathlib import Path

target = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
keyring = sys.argv[2]
if target.get('distribution') != 'Debian' or target.get('release') != '13' or target.get('architecture') != 'arm64':
    raise SystemExit('invalid Debian 13 ARM64 target manifest')
for repo in target.get('repositories', []):
    url = repo.get('base_url', '')
    snapshot = repo.get('snapshot', '')
    suite = repo.get('suite', '')
    components = repo.get('components', [])
    if not url.startswith('https://snapshot.debian.org/archive/') or snapshot not in url or '/latest/' in url:
        raise SystemExit(f"repository is not an exact Debian snapshot: {url}")
    if not suite or not components:
        raise SystemExit('snapshot suite/components must be non-empty')
    print('Types: deb')
    print(f'URIs: {url}')
    print(f'Suites: {suite}')
    print('Components: ' + ' '.join(components))
    print(f'Signed-By: {keyring}')
    print('Check-Valid-Until: no')
    print()
PY

APT_COMMON="-o Dir::Etc::sourcelist=$SOURCES -o Dir::Etc::sourceparts=- -o Acquire::Check-Valid-Until=false"
# shellcheck disable=SC2086
apt-get $APT_COMMON update
# shellcheck disable=SC2086
DEBIAN_FRONTEND=noninteractive apt-get $APT_COMMON install --yes --no-install-recommends $PACKAGES

# Preparation is not successful until the exact collector can validate the guest and all probe
# binaries. `--help` is used only to parse/validate arguments; no corpus is collected here.
python3 "$COLLECTOR" --help >/dev/null
printf 'Pinned Debian 13 ARM64 reference packages prepared from snapshot-only sources.\n'
printf 'Next: python3 %s --observation reference-debian.json --inventory reference-syscalls.json\n' "$COLLECTOR"
