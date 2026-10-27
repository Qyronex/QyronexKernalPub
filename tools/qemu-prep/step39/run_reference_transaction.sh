#!/bin/bash
set -euo pipefail

# Run only inside the verified pinned Debian 13 ARM64 reference guest on a
# disposable qcow2 overlay. This script intentionally refuses to infer a package
# version or use the image's default apt sources.

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
SOURCE_WRITER="$ROOT/tools/qemu-prep/step39/write_snapshot_sources.py"
PIN_TOOL="$ROOT/tools/qemu-prep/step39/pin_package.py"
KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
WORK=${KERNAL_STEP39_WORK:-/tmp/kernal-step39-reference}
PACKAGE=${KERNAL_STEP39_PACKAGE:-hello}
VERSION=${KERNAL_STEP39_VERSION:-}
ARCH=${KERNAL_STEP39_ARCH:-arm64}
PACKAGES_INDEX=${KERNAL_STEP39_PACKAGES_INDEX:-}
OUTPUT=${KERNAL_STEP39_OUTPUT:-$WORK/evidence}

fail() { printf 'step39-reference: FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root inside the pinned Debian reference guest"
[ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ] || fail "reference guest must be ARM64"
[ -n "$VERSION" ] || fail "KERNAL_STEP39_VERSION must pin an exact package version"
[ -n "$PACKAGES_INDEX" ] || fail "KERNAL_STEP39_PACKAGES_INDEX must point to an uncompressed Packages file from the pinned snapshot"
[ -f "$PACKAGES_INDEX" ] || fail "Packages index not found: $PACKAGES_INDEX"
[ -f "$KEYRING" ] || fail "Debian archive keyring missing: $KEYRING"

for command in python3 apt-get dpkg dpkg-query strace sha256sum sync; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done

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
    raise SystemExit('reference guest must be trixie')
PY
[ "$(dpkg --print-architecture)" = arm64 ] || fail "dpkg architecture must be arm64"

mkdir -p "$WORK" "$OUTPUT"
SOURCES="$WORK/kernal-step39.sources"
rm -f "$SOURCES"
python3 "$SOURCE_WRITER" --target "$TARGET" --keyring "$KEYRING" --out "$SOURCES" >/dev/null

PIN_JSON="$OUTPUT/package-pin.json"
python3 "$PIN_TOOL" \
  --packages "$PACKAGES_INDEX" \
  --package "$PACKAGE" \
  --arch "$ARCH" \
  --version "$VERSION" > "$PIN_JSON"

APT_COMMON=(
  -o "Dir::Etc::sourcelist=$SOURCES"
  -o "Dir::Etc::sourceparts=-"
  -o Acquire::Check-Valid-Until=false
  -o APT::Get::List-Cleanup=false
)

run_trace() {
  id=$1
  shift
  trace="$OUTPUT/$id.strace"
  stdout="$OUTPUT/$id.stdout"
  stderr="$OUTPUT/$id.stderr"
  status="$OUTPUT/$id.status"
  set +e
  strace -f -qq -s 256 -o "$trace" -- "$@" >"$stdout" 2>"$stderr"
  rc=$?
  set -e
  printf '%s\n' "$rc" > "$status"
  sha256sum "$trace" "$stdout" "$stderr" > "$OUTPUT/$id.sha256"
  return "$rc"
}

# This is reference collection on a disposable overlay. Any failure is retained
# as evidence and stops the happy-path transaction before later mutation.
run_trace dpkg-audit dpkg --audit || fail "dpkg --audit failed"
run_trace apt-update apt-get "${APT_COMMON[@]}" update || fail "pinned apt update failed"

# Use an exact version; never let apt choose a floating candidate.
EXACT="$PACKAGE=$VERSION"
run_trace apt-install env DEBIAN_FRONTEND=noninteractive apt-get "${APT_COMMON[@]}" install --yes --no-install-recommends "$EXACT" || fail "pinned package install failed"

dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' "$PACKAGE" > "$OUTPUT/installed-package.txt"
grep -F "${PACKAGE}" "$OUTPUT/installed-package.txt" >/dev/null || fail "installed package not visible to dpkg-query"
grep -F "${VERSION}" "$OUTPUT/installed-package.txt" >/dev/null || fail "installed package version differs from exact pin"

run_trace apt-remove env DEBIAN_FRONTEND=noninteractive apt-get "${APT_COMMON[@]}" remove --yes "$PACKAGE" || fail "package removal failed"
run_trace dpkg-audit-after dpkg --audit || fail "post-transaction dpkg audit failed"

sync
python3 - "$TARGET" "$PIN_JSON" "$SOURCES" "$OUTPUT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

target = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
pin = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
sources = Path(sys.argv[3])
out = Path(sys.argv[4])

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

records = {}
for status_path in sorted(out.glob('*.status')):
    case = status_path.stem
    records[case] = {
        'exit_status': int(status_path.read_text(encoding='utf-8').strip()),
        'trace_sha256': sha256(out / f'{case}.strace'),
        'stdout_sha256': sha256(out / f'{case}.stdout'),
        'stderr_sha256': sha256(out / f'{case}.stderr'),
    }
summary = {
    'schema_version': 1,
    'target_id': target['target_id'],
    'package': pin,
    'sources_sha256': sha256(sources),
    'transactions': records,
    'environment': 'reference-debian-disposable-overlay',
    'note': 'Raw strace remains local PREP evidence; canonical evidence publication still requires an explicitly released oracle lane and exact source provenance.',
}
(out / 'transaction-summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY

printf 'step39-reference: PASS: transaction evidence staged in %s\n' "$OUTPUT"
