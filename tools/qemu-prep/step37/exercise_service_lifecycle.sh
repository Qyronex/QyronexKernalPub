#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
REFERENCE=${1:-}
OUT=${KERNAL_STEP37_LIFECYCLE_OUTPUT:-/tmp/kernal-step37-service-lifecycle}

fail() { printf 'step37-lifecycle: FAIL: %s\n' "$*" >&2; exit 1; }
[ -n "$REFERENCE" ] || fail "usage: exercise_service_lifecycle.sh STEP37_REFERENCE_JSON"
[ -f "$REFERENCE" ] || fail "reference JSON missing: $REFERENCE"
[ "${KERNAL_REFERENCE_SERVICE_LIFECYCLE_CONFIRMED:-0}" = "1" ] || fail "requires KERNAL_REFERENCE_SERVICE_LIFECYCLE_CONFIRMED=1"
[ "${KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED:-0}" = "1" ] || fail "requires KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED=1 so a manipulated service cannot strand the runner"
[ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ] || fail "reference guest must be ARM64"
[ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || fail "PID 1 is not systemd"
command -v systemctl >/dev/null 2>&1 || fail "systemctl unavailable"
command -v git >/dev/null 2>&1 || fail "git unavailable"

SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
mapfile -t UNITS < <(python3 - "$REFERENCE" "$SOURCE_COMMIT" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
expected_commit = sys.argv[2]
data = json.loads(p.read_text(encoding='utf-8'))
if data.get('schema') != 'kernal-step37-debian13-pid1-reference-v1':
    raise SystemExit('wrong Step37 reference schema')
if data.get('provenance', {}).get('source_commit') != expected_commit:
    raise SystemExit('reference source_commit does not match current checkout')
if data.get('services', {}).get('selection_state') != 'FROZEN_THREE_SERVICES':
    raise SystemExit('reference has no frozen three-service set')
units = data.get('services', {}).get('frozen_three', [])
if len(units) != 3 or len(set(units)) != 3:
    raise SystemExit('reference must freeze exactly three unique services')
for unit in units:
    print(unit)
PY
)
[ "${#UNITS[@]}" -eq 3 ] || fail "failed to resolve exactly three frozen services"

mkdir -p "$OUT"
printf 'source_commit=%s\n' "$SOURCE_COMMIT" > "$OUT/identity.txt"
printf 'reference_json=%s\n' "$(readlink -f "$REFERENCE")" >> "$OUT/identity.txt"

restore_services() {
  for unit in "${UNITS[@]}"; do
    systemctl start "$unit" >/dev/null 2>&1 || true
  done
}
trap restore_services EXIT INT TERM

for unit in "${UNITS[@]}"; do
  safe=$(printf '%s' "$unit" | tr '/@.-' '____')
  initial=$(systemctl is-active "$unit" 2>/dev/null || true)
  printf 'initial=%s\n' "$initial" > "$OUT/$safe.states"
  [ "$initial" = active ] || fail "$unit is not active at lifecycle start"

  systemctl restart "$unit"
  after_restart=$(systemctl is-active "$unit" 2>/dev/null || true)
  printf 'after_restart=%s\n' "$after_restart" >> "$OUT/$safe.states"
  [ "$after_restart" = active ] || fail "$unit did not return active after restart"

  systemctl stop "$unit"
  after_stop=$(systemctl is-active "$unit" 2>/dev/null || true)
  printf 'after_stop=%s\n' "$after_stop" >> "$OUT/$safe.states"
  case "$after_stop" in inactive|failed) ;; *) fail "$unit did not stop cleanly: $after_stop" ;; esac

  systemctl start "$unit"
  after_start=$(systemctl is-active "$unit" 2>/dev/null || true)
  printf 'after_start=%s\n' "$after_start" >> "$OUT/$safe.states"
  [ "$after_start" = active ] || fail "$unit did not return active after start"

  systemctl show "$unit" --property=ActiveState --property=SubState --property=Result --property=ExecMainStatus > "$OUT/$safe.final-show"
done

trap - EXIT INT TERM
restore_services
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
printf 'STEP37_SERVICE_LIFECYCLE_OK source_commit=%s units=%s,%s,%s\n' "$SOURCE_COMMIT" "${UNITS[0]}" "${UNITS[1]}" "${UNITS[2]}"
