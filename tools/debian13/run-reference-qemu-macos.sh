#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET="$ROOT/docs/debian13/arm64-target.json"
FETCH="$ROOT/tools/debian13/fetch-pinned-arm64.sh"
SERVER="$ROOT/tools/debian13/reference-host-server.py"
CACHE_DIR="${KERNAL_DEBIAN13_CACHE:-$HOME/.cache/kernal/debian13}"
OUTPUT_DIR="${KERNAL_DEBIAN13_REFERENCE_OUTPUT:-$ROOT/tests/debian13/evidence}"
STEP32_RAW="$OUTPUT_DIR/kernal-step32-tty-reference.raw"
STEP32_JSON="$OUTPUT_DIR/kernal-step32-tty-reference.json"
TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_TIMEOUT_SECONDS:-1200}"
FETCH_TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_FETCH_TIMEOUT_SECONDS:-600}"
PROGRESS_INTERVAL_SECONDS="${KERNAL_DEBIAN13_REFERENCE_PROGRESS_INTERVAL_SECONDS:-60}"
LOG_DIR="${KERNAL_DEBIAN13_REFERENCE_LOG_DIR:-$CACHE_DIR/logs}"

case "$TIMEOUT_SECONDS" in
  ''|*[!0-9]*) printf 'KERNAL_DEBIAN13_REFERENCE_TIMEOUT_SECONDS must be a positive integer\n' >&2; exit 64 ;;
esac
[ "$TIMEOUT_SECONDS" -gt 0 ] || { printf 'reference timeout must be positive\n' >&2; exit 64; }
case "$FETCH_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) printf 'KERNAL_DEBIAN13_REFERENCE_FETCH_TIMEOUT_SECONDS must be a positive integer\n' >&2; exit 64 ;;
esac
[ "$FETCH_TIMEOUT_SECONDS" -gt 0 ] || { printf 'reference fetch timeout must be positive\n' >&2; exit 64; }
case "$PROGRESS_INTERVAL_SECONDS" in
  ''|*[!0-9]*) printf 'KERNAL_DEBIAN13_REFERENCE_PROGRESS_INTERVAL_SECONDS must be a positive integer\n' >&2; exit 64 ;;
esac
[ "$PROGRESS_INTERVAL_SECONDS" -ge 15 ] || { printf 'reference progress interval must be at least 15 seconds\n' >&2; exit 64; }
TOTAL_TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_TOTAL_TIMEOUT_SECONDS:-$((TIMEOUT_SECONDS + FETCH_TIMEOUT_SECONDS + 300))}"
case "$TOTAL_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) printf 'KERNAL_DEBIAN13_REFERENCE_TOTAL_TIMEOUT_SECONDS must be a positive integer\n' >&2; exit 64 ;;
esac
[ "$TOTAL_TIMEOUT_SECONDS" -gt 0 ] || { printf 'reference total timeout must be positive\n' >&2; exit 64; }

if [ "${KERNAL_DEBIAN13_REFERENCE_TOTAL_WATCHDOG_ACTIVE:-0}" != 1 ]; then
  export KERNAL_DEBIAN13_REFERENCE_TOTAL_WATCHDOG_ACTIVE=1
  exec python3 - "$0" "$TOTAL_TIMEOUT_SECONDS" "$PROGRESS_INTERVAL_SECONDS" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time


script, raw_timeout, raw_progress, *args = sys.argv[1:]
timeout = int(raw_timeout)
progress_interval = int(raw_progress)
started = time.monotonic()


def stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(message: str) -> None:
    print(f"[reference-watchdog][{stamp()}] {message}", file=sys.stderr, flush=True)


log(f"start total_timeout={timeout}s progress_interval={progress_interval}s script={script}")
proc = subprocess.Popen(
    ["bash", script, *args],
    env=os.environ.copy(),
    start_new_session=True,
)
log(f"child-started pid={proc.pid} pgid={proc.pid}")


def terminate_process_group(first_signal: int) -> None:
    signal_name = signal.Signals(first_signal).name
    log(f"terminate-process-group pgid={proc.pid} signal={signal_name}")
    try:
        os.killpg(proc.pid, first_signal)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
        log(f"process-group-exited-after-{signal_name} rc={proc.returncode}")
    except subprocess.TimeoutExpired:
        log(f"process-group-still-alive-after-{signal_name}; escalating=SIGKILL")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
            log(f"process-group-exited-after-SIGKILL rc={proc.returncode}")
        except subprocess.TimeoutExpired:
            log("process-group-survived-SIGKILL")


def forward_signal(signum, _frame):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    log(f"forward-signal signal={signal.Signals(signum).name}")
    terminate_process_group(signum)
    raise SystemExit(128 + signum)


signal.signal(signal.SIGINT, forward_signal)
signal.signal(signal.SIGTERM, forward_signal)

next_progress = progress_interval
while True:
    return_code = proc.poll()
    elapsed = int(time.monotonic() - started)
    if return_code is not None:
        normalized = return_code if return_code >= 0 else 128 - return_code
        log(f"complete rc={normalized} elapsed={elapsed}s")
        raise SystemExit(normalized)
    if elapsed >= timeout:
        log(f"timeout elapsed={elapsed}s limit={timeout}s")
        terminate_process_group(signal.SIGTERM)
        raise SystemExit(124)
    if elapsed >= next_progress:
        log(f"alive elapsed={elapsed}s remaining={max(0, timeout - elapsed)}s child_pid={proc.pid}")
        next_progress += progress_interval
    time.sleep(1)
PY
fi

RUN_LOG_FILE=''
log() {
  local timestamp line
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  line="[reference][$timestamp] $*"
  printf '%s\n' "$line" >&2
  if [ -n "$RUN_LOG_FILE" ]; then
    printf '%s\n' "$line" >> "$RUN_LOG_FILE" 2>/dev/null || true
  fi
}


[ "$(uname -s)" = Darwin ] || { printf 'reference QEMU runner requires macOS\n' >&2; exit 78; }
[ "$(uname -m)" = arm64 ] || { printf 'reference QEMU runner requires Apple Silicon arm64\n' >&2; exit 78; }
log "preflight host=$(hostname) os=$(uname -sr) arch=$(uname -m)"

for command in python3 curl git tar qemu-system-aarch64 qemu-img; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing required reference host tool: %s\n' "$command" >&2; exit 69; }
done

SOURCE_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
case "$SOURCE_COMMIT" in
  ''|*[!0-9a-f]* ) printf 'reference collection requires a lowercase exact git commit SHA\n' >&2; exit 1 ;;
esac
[ "${#SOURCE_COMMIT}" -eq 40 ] || { printf 'reference collection requires a full 40-character git commit SHA\n' >&2; exit 1; }

RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')-"$$"-$(printf '%.12s' "$SOURCE_COMMIT")"
RUN_LOG_DIR="$LOG_DIR/$RUN_ID"
mkdir -p "$RUN_LOG_DIR"
RUN_LOG_FILE="$RUN_LOG_DIR/host.log"
{
  printf 'source_commit=%s\n' "$SOURCE_COMMIT"
  printf 'fetch_timeout_seconds=%s\n' "$FETCH_TIMEOUT_SECONDS"
  printf 'guest_timeout_seconds=%s\n' "$TIMEOUT_SECONDS"
  printf 'total_timeout_seconds=%s\n' "$TOTAL_TIMEOUT_SECONDS"
  printf 'progress_interval_seconds=%s\n' "$PROGRESS_INTERVAL_SECONDS"
  printf 'started_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "$RUN_LOG_DIR/run-meta.txt"
log "run-start source=$SOURCE_COMMIT fetch_timeout=${FETCH_TIMEOUT_SECONDS}s guest_timeout=${TIMEOUT_SECONDS}s total_timeout=${TOTAL_TIMEOUT_SECONDS}s progress_interval=${PROGRESS_INTERVAL_SECONDS}s"
log "diagnostics dir=$RUN_LOG_DIR"

read_rootfs_field() {
  python3 - "$TARGET" "$1" <<'PY'
import json
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(doc["rootfs"][sys.argv[2]])
PY
}

find_firmware() {
  code=''
  vars=''
  roots=''
  if command -v brew >/dev/null 2>&1; then
    prefix=$(brew --prefix qemu 2>/dev/null || true)
    [ -z "$prefix" ] || roots="$roots $prefix/share/qemu"
  fi
  roots="$roots /opt/homebrew/share/qemu /usr/local/share/qemu"
  for root in $roots; do
    if [ -f "$root/edk2-aarch64-code.fd" ] && [ -f "$root/edk2-arm-vars.fd" ]; then
      code="$root/edk2-aarch64-code.fd"
      vars="$root/edk2-arm-vars.fd"
      break
    fi
  done
  [ -n "$code" ] && [ -n "$vars" ] || {
    printf 'AArch64 EDK2 firmware not found; install Homebrew qemu with firmware data\n' >&2
    return 1
  }
  printf '%s\n%s\n' "$code" "$vars"
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/kernal-debian13-reference.XXXXXX")
SERVE="$WORK/serve"
UPLOAD="$WORK/upload"
PORT_FILE="$WORK/port"
QEMU_LOG="$RUN_LOG_DIR/qemu.log"
SERVER_LOG="$RUN_LOG_DIR/server.log"
OVERLAY="$WORK/reference-overlay.qcow2"
VARS_COPY="$WORK/edk2-arm-vars.fd"
SERVER_PID=''
QEMU_PID=''

terminate_child_bounded() {
  pid="$1"
  label="$2"
  grace_seconds="${3:-5}"
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || return 0
  elapsed=0
  while kill -0 "$pid" 2>/dev/null && [ "$elapsed" -lt "$grace_seconds" ]; do
    sleep 1
    elapsed=$((elapsed + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    printf '%s did not exit after TERM; sending KILL\n' "$label" >&2
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

run_fetch_bounded() {
  python3 - "$FETCH" "$FETCH_TIMEOUT_SECONDS" "$PROGRESS_INTERVAL_SECONDS" <<'PY'
import os
import signal
import subprocess
import sys
import time


fetch = sys.argv[1]
timeout = int(sys.argv[2])
progress_interval = int(sys.argv[3])
started = time.monotonic()


def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[reference-fetch][{timestamp}] {message}", file=sys.stderr, flush=True)


proc = subprocess.Popen(["bash", fetch], start_new_session=True)
log(f"start pid={proc.pid} pgid={proc.pid} timeout={timeout}s")
next_progress = progress_interval
while True:
    return_code = proc.poll()
    elapsed = int(time.monotonic() - started)
    if return_code is not None:
        log(f"complete rc={return_code} elapsed={elapsed}s")
        raise SystemExit(return_code)
    if elapsed >= timeout:
        log(f"timeout elapsed={elapsed}s limit={timeout}s; sending=SIGTERM")
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log("still-alive-after-SIGTERM; sending=SIGKILL")
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log("process-group-survived-SIGKILL")
        raise SystemExit(124)
    if elapsed >= next_progress:
        log(f"alive elapsed={elapsed}s remaining={max(0, timeout - elapsed)}s")
        next_progress += progress_interval
    time.sleep(1)
PY
}

cleanup() {
  cleanup_rc=$?
  log "cleanup-start rc=$cleanup_rc qemu_pid=${QEMU_PID:-none} server_pid=${SERVER_PID:-none}"
  terminate_child_bounded "$QEMU_PID" 'reference QEMU' 5
  terminate_child_bounded "$SERVER_PID" 'reference transfer server' 5
  rm -rf "$WORK"
  log "cleanup-complete rc=$cleanup_rc diagnostics=$RUN_LOG_DIR"
}
trap cleanup EXIT INT TERM
mkdir -p "$SERVE" "$UPLOAD" "$OUTPUT_DIR"

log "phase=fetch start"
fetch_started=$(date +%s)
run_fetch_bounded
fetch_finished=$(date +%s)
log "phase=fetch complete elapsed=$((fetch_finished - fetch_started))s"
ARTIFACT=$(read_rootfs_field artifact)
IMAGE="$CACHE_DIR/$ARTIFACT"
[ -f "$IMAGE" ] || { printf 'verified image missing after fetch: %s\n' "$IMAGE" >&2; exit 1; }
image_bytes=$(stat -f '%z' "$IMAGE" 2>/dev/null || printf 'unknown')
log "rootfs-ready artifact=$ARTIFACT bytes=$image_bytes"

git -C "$ROOT" diff --quiet -- && git -C "$ROOT" diff --cached --quiet -- || {
  printf 'reference collection requires a clean exact-source worktree\n' >&2
  exit 1
}
log "phase=archive start source=$SOURCE_COMMIT"
archive_started=$(date +%s)
git -C "$ROOT" archive --format=tar.gz --output="$SERVE/repo.tar.gz" HEAD \
  docs/debian13 tests/debian13 tools/debian13 \
  tests/qemu-prep/step32/pty_probe.c \
  tools/qemu-prep/step32/build_run_pty_probe.sh \
  tools/qemu-prep/step32/collect_tty_reference.sh \
  tools/qemu-prep/step32/normalize_tty_reference.py
archive_finished=$(date +%s)
archive_bytes=$(stat -f '%z' "$SERVE/repo.tar.gz" 2>/dev/null || printf 'unknown')
log "phase=archive complete elapsed=$((archive_finished - archive_started))s bytes=$archive_bytes"

cat > "$SERVE/meta-data" <<'EOF'
instance-id: kernal-debian13-reference-v1
local-hostname: kernal-debian13-reference
EOF

TOKEN=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
)
python3 "$SERVER" --root "$SERVE" --output "$UPLOAD" --token "$TOKEN" --port 0 --port-file "$PORT_FILE" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

attempt=0
while [ "$attempt" -lt 100 ]; do
  [ -s "$PORT_FILE" ] && break
  kill -0 "$SERVER_PID" 2>/dev/null || { cat "$SERVER_LOG" >&2; exit 1; }
  attempt=$((attempt + 1))
  sleep 0.05
done
[ -s "$PORT_FILE" ] || { printf 'reference transfer server did not publish a port\n' >&2; cat "$SERVER_LOG" >&2; exit 1; }
PORT=$(tr -d '\r\n' < "$PORT_FILE")
case "$PORT" in ''|*[!0-9]*) printf 'reference transfer server published invalid port\n' >&2; exit 1 ;; esac
HOST_URL="http://10.0.2.2:$PORT"
log "transfer-server ready pid=$SERVER_PID port=$PORT"

cat > "$SERVE/user-data" <<EOF
#cloud-config
write_files:
  - path: /usr/local/sbin/kernal-debian13-reference.sh
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      exec > >(tee -a /var/log/kernal-debian13-reference.log) 2>&1
      echo 'KERNAL/DEBIAN13: reference guest collector starting'
      work=/opt/kernal-debian13-reference
      mkdir -p "\$work"
      python3 - '$HOST_URL/repo.tar.gz' "\$work/repo.tar.gz" <<'PY'
      import sys
      import urllib.request
      from pathlib import Path
      url, destination = sys.argv[1], Path(sys.argv[2])
      with urllib.request.urlopen(url, timeout=120) as response:
          destination.write_bytes(response.read())
      PY
      mkdir -p "\$work/repo"
      tar -xzf "\$work/repo.tar.gz" -C "\$work/repo"
      cd "\$work/repo"
      bash tools/debian13/prepare-reference.sh
      python3 tools/debian13/collect-reference.py \
        --source-commit '$SOURCE_COMMIT' \
        --observation /tmp/reference-debian.json \
        --inventory /tmp/reference-syscalls.json
      KERNAL_STEP32_SOURCE_COMMIT='$SOURCE_COMMIT' \
      KERNAL_STEP32_REFERENCE_OUT=/tmp/kernal-step32-tty-reference.raw \
      KERNAL_STEP32_REFERENCE_JSON=/tmp/kernal-step32-tty-reference.json \
        bash tools/qemu-prep/step32/collect_tty_reference.sh
      python3 - '$HOST_URL/upload/$TOKEN' \
        /tmp/reference-debian.json \
        /tmp/reference-syscalls.json \
        /tmp/kernal-step32-tty-reference.raw \
        /tmp/kernal-step32-tty-reference.json <<'PY'
      import sys
      import urllib.request
      from pathlib import Path
      base = sys.argv[1]
      for raw in sys.argv[2:]:
          path = Path(raw)
          data = path.read_bytes()
          request = urllib.request.Request(
              base + '/' + path.name,
              data=data,
              method='POST',
              headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(len(data))},
          )
          with urllib.request.urlopen(request, timeout=120) as response:
              if response.status != 204:
                  raise SystemExit(f'upload failed for {path.name}: HTTP {response.status}')
      PY
      echo 'KERNAL/DEBIAN13: reference evidence uploaded'
      sync
      systemctl poweroff --no-wall || poweroff
runcmd:
  - [ bash, /usr/local/sbin/kernal-debian13-reference.sh ]
power_state:
  mode: poweroff
  timeout: 60
  condition: true
EOF

firmware_paths=$(find_firmware) || exit 1
FW_CODE=$(printf '%s\n' "$firmware_paths" | sed -n '1p')
FW_VARS=$(printf '%s\n' "$firmware_paths" | sed -n '2p')
[ -n "$FW_CODE" ] && [ -n "$FW_VARS" ] || {
  printf 'AArch64 EDK2 firmware discovery returned an incomplete pair\n' >&2
  exit 1
}
log "firmware-ready code=$FW_CODE vars=$FW_VARS"
cp "$FW_VARS" "$VARS_COPY"
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$OVERLAY"
log "overlay-ready path=$OVERLAY"

printf 'Booting verified Debian 13 ARM64 reference guest from %s at source %s\n' "$ARTIFACT" "$SOURCE_COMMIT"
qemu-system-aarch64 \
  -machine virt,accel=hvf,highmem=on \
  -cpu host \
  -smp 2 \
  -m 2048 \
  -drive if=pflash,format=raw,readonly=on,unit=0,file="$FW_CODE" \
  -drive if=pflash,format=raw,unit=1,file="$VARS_COPY" \
  -drive if=none,id=root,file="$OVERLAY",format=qcow2,cache=none \
  -device virtio-blk-pci,drive=root \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -smbios "type=1,serial=ds=nocloud-net;s=$HOST_URL/" \
  -nographic \
  -no-reboot >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
log "phase=qemu start pid=$QEMU_PID guest_timeout=${TIMEOUT_SECONDS}s qemu_log=$QEMU_LOG"

started=$(date +%s)
next_progress=$PROGRESS_INTERVAL_SECONDS
while :; do
  if [ -s "$UPLOAD/reference-debian.json" ] && \
     [ -s "$UPLOAD/reference-syscalls.json" ] && \
     [ -s "$UPLOAD/kernal-step32-tty-reference.raw" ] && \
     [ -s "$UPLOAD/kernal-step32-tty-reference.json" ]; then
    break
  fi
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    wait "$QEMU_PID" || true
    QEMU_PID=''
    printf 'reference guest exited before publishing both evidence files\n' >&2
    tail -n 200 "$QEMU_LOG" >&2 || true
    exit 1
  fi
  now=$(date +%s)
  elapsed=$((now - started))
  if [ "$elapsed" -ge "$TIMEOUT_SECONDS" ]; then
    log "phase=qemu timeout elapsed=${elapsed}s limit=${TIMEOUT_SECONDS}s"
    tail -n 200 "$QEMU_LOG" >&2 || true
    exit 124
  fi
  if [ "$elapsed" -ge "$next_progress" ]; then
    evidence_count=0
    for evidence in       "$UPLOAD/reference-debian.json"       "$UPLOAD/reference-syscalls.json"       "$UPLOAD/kernal-step32-tty-reference.raw"       "$UPLOAD/kernal-step32-tty-reference.json"; do
      [ -s "$evidence" ] && evidence_count=$((evidence_count + 1))
    done
    log "phase=qemu progress elapsed=${elapsed}s remaining=$((TIMEOUT_SECONDS - elapsed))s evidence=${evidence_count}/4 qemu_pid=$QEMU_PID"
    next_progress=$((next_progress + PROGRESS_INTERVAL_SECONDS))
  fi
  sleep 5
done
evidence_finished=$(date +%s)
log "phase=qemu evidence-complete elapsed=$((evidence_finished - started))s evidence=4/4"

cp "$UPLOAD/reference-debian.json" "$OUTPUT_DIR/reference-debian.json"
cp "$UPLOAD/reference-syscalls.json" "$OUTPUT_DIR/reference-syscalls.json"
cp "$UPLOAD/kernal-step32-tty-reference.raw" "$STEP32_RAW"
cp "$UPLOAD/kernal-step32-tty-reference.json" "$STEP32_JSON"

log "phase=validation start"
validation_started=$(date +%s)
python3 - "$TARGET" "$SOURCE_COMMIT" "$OUTPUT_DIR/reference-debian.json" "$OUTPUT_DIR/reference-syscalls.json" <<'PY'
import json
import sys
from pathlib import Path

target = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
source_commit = sys.argv[2]
target_id = target['target_id']
rootfs = target['rootfs']
observation = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
inventory = json.loads(Path(sys.argv[4]).read_text(encoding='utf-8'))
for label, document in [('observation', observation), ('inventory', inventory)]:
    if document.get('schema_version') != 1:
        raise SystemExit(f'{label}: schema_version must be 1')
    if document.get('target_id') != target_id:
        raise SystemExit(f'{label}: target_id mismatch')
    if document.get('environment') != 'reference-debian':
        raise SystemExit(f'{label}: environment must be reference-debian')
    provenance = document.get('provenance')
    if not isinstance(provenance, dict) or provenance.get('source_commit') != source_commit:
        raise SystemExit(f'{label}: exact source provenance missing or mismatched')
    evidence_rootfs = provenance.get('rootfs')
    expected_rootfs = {key: rootfs[key] for key in ('artifact', 'size_bytes', 'sha256', 'sha512')}
    if evidence_rootfs != expected_rootfs:
        raise SystemExit(f'{label}: pinned rootfs provenance mismatch')
    cases = document.get('cases')
    if not isinstance(cases, list) or not cases:
        raise SystemExit(f'{label}: cases must be a non-empty array')
if not isinstance(inventory.get('packages'), dict) or not inventory['packages']:
    raise SystemExit('inventory: package provenance missing')
requirements = inventory.get('requirements')
if not isinstance(requirements, dict):
    raise SystemExit('inventory: normalized requirements missing')
for key in ('syscalls', 'ioctl_requests', 'paths', 'proc_paths', 'sys_paths', 'dev_paths', 'filesystem_paths', 'socket_families', 'socket_types', 'socket_protocols', 'network_syscalls'):
    if not isinstance(requirements.get(key), list):
        raise SystemExit(f'inventory: explicit requirement category missing: {key}')
print(f"reference evidence validated for {target_id} at {source_commit}: {len(observation['cases'])} cases")
PY

python3 -B "$ROOT/tools/qemu-prep/step32/verify_tty_reference_evidence.py" \
  "$STEP32_RAW" "$STEP32_JSON" "$SOURCE_COMMIT"
validation_finished=$(date +%s)
log "phase=validation complete elapsed=$((validation_finished - validation_started))s"

log "phase=shutdown start qemu_pid=$QEMU_PID"
shutdown_wait=0
while [ "$shutdown_wait" -lt 12 ]; do
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    wait "$QEMU_PID" || true
    QEMU_PID=''
    break
  fi
  shutdown_wait=$((shutdown_wait + 1))
  sleep 1
done
if [ -n "$QEMU_PID" ]; then
  terminate_child_bounded "$QEMU_PID" 'reference QEMU' 5
  QEMU_PID=''
fi
log "phase=shutdown complete"
log "run-complete source=$SOURCE_COMMIT diagnostics=$RUN_LOG_DIR"

printf 'Debian 13 ARM64 reference corpus collected:\n  %s\n  %s\n  %s\n  %s\n' \
  "$OUTPUT_DIR/reference-debian.json" "$OUTPUT_DIR/reference-syscalls.json" \
  "$STEP32_RAW" "$STEP32_JSON"
