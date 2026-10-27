#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
STRICT="$ROOT/tools/qemu-prep/step36/collect_systemd_feature_reference_strict.sh"

if [ ! -f "$STRICT" ]; then
  printf 'step36-reference: FAIL: strict collector missing: %s\n' "$STRICT" >&2
  exit 1
fi

# Keep this historical entrypoint only as a compatibility alias. There must be
# one evidence policy: exact source/target binding, read-only default capture,
# and explicit opt-in for transient resource-enforcement probes.
exec bash "$STRICT" "$@"
