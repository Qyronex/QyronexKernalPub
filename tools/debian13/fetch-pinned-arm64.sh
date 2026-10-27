#!/bin/bash
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
ORACLE="$ROOT/tools/debian13/oracle.py"
CACHE_DIR="${KERNAL_DEBIAN13_CACHE:-$HOME/.cache/kernal/debian13}"

command -v python3 >/dev/null 2>&1 || { printf 'python3 is required\n' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { printf 'curl is required\n' >&2; exit 1; }

read_target_field() {
  field="$1"
  python3 - "$TARGET" "$field" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
value = document["rootfs"][sys.argv[2]]
print(value)
PY
}

ARTIFACT=$(read_target_field artifact)
URL=$(read_target_field immutable_url)
SHA512_MANIFEST_URL=$(read_target_field sha512_manifest_url)
EXPECTED_SHA512=$(read_target_field sha512)

case "$URL:$SHA512_MANIFEST_URL" in
  *'/latest/'*) printf 'refusing unversioned latest Debian artifact or checksum manifest\n' >&2; exit 1 ;;
esac

mkdir -p "$CACHE_DIR"
IMAGE="$CACHE_DIR/$ARTIFACT"
SHA512_MANIFEST="$CACHE_DIR/SHA512SUMS"

if [ ! -f "$IMAGE" ]; then
  printf 'Downloading pinned Debian 13 ARM64 image: %s\n' "$ARTIFACT"
  curl --fail --location --retry 3 --output "$IMAGE.part" "$URL"
  mv "$IMAGE.part" "$IMAGE"
fi

curl --fail --location --retry 3 --output "$SHA512_MANIFEST.part" "$SHA512_MANIFEST_URL"
mv "$SHA512_MANIFEST.part" "$SHA512_MANIFEST"

verify_published_entry() {
  manifest="$1"
  artifact="$2"
  expected="$3"
  label="$4"
  python3 - "$manifest" "$artifact" "$expected" "$label" <<'PY'
import sys
from pathlib import Path

manifest = Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict").splitlines()
artifact = sys.argv[2]
expected = sys.argv[3]
label = sys.argv[4]
matches = []
for line in manifest:
    parts = line.split()
    if len(parts) >= 2 and parts[-1].lstrip("*") == artifact:
        matches.append(parts[0].lower())
if matches != [expected]:
    raise SystemExit(
        f"published {label} entry mismatch for {artifact}: expected one {expected}, got {matches}"
    )
PY
}

# Debian's dated cloud directory provides the authoritative SHA512SUMS entry.
# The manifest pin is checked first. oracle.py then independently checks the
# exact byte size plus both the pinned SHA-512 and independently derived SHA-256
# over the local artifact before QEMU may attach it.
verify_published_entry "$SHA512_MANIFEST" "$ARTIFACT" "$EXPECTED_SHA512" SHA512SUMS
python3 "$ORACLE" verify-rootfs "$IMAGE"
printf 'Pinned Debian 13 ARM64 artifact ready at %s\n' "$IMAGE"
