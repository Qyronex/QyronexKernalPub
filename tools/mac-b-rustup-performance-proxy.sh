#!/bin/bash
set -eu

WORKER_ID="${KERNAL_WORKER_ID:-}"
REAL_RUSTUP="${KERNAL_MAC_B_REAL_RUSTUP:-$HOME/.cargo/bin/rustup}"
CARGO_JOBS="${KERNAL_MAC_B_CARGO_JOBS:-2}"
HEAVY_LIMIT="${KERNAL_MAC_B_HEAVY_JOB_LIMIT:-2}"
RUNTIME_ROOT="${KERNAL_MAC_B_PERF_RUNTIME:-$HOME/.kernal/runtime/mac-b-m3-24gb}"
HELD_SLOT=''

log() {
  printf '[kernal-mac-b-perf] %s\n' "$*" >&2
}

validate_positive_integer() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) printf '%s must be a positive integer\n' "$name" >&2; exit 64 ;;
  esac
  [ "$value" -gt 0 ] || { printf '%s must be greater than zero\n' "$name" >&2; exit 64; }
}

release_heavy_slot() {
  [ -n "$HELD_SLOT" ] || return 0
  owner="$HELD_SLOT/owner.pid"
  current=$(cat "$owner" 2>/dev/null || true)
  if [ "$current" = "$$" ]; then
    rm -f -- "$owner" 2>/dev/null || true
    rmdir "$HELD_SLOT" 2>/dev/null || true
  fi
  HELD_SLOT=''
}

acquire_heavy_slot() {
  mkdir -p "$RUNTIME_ROOT"
  [ -d "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] || {
    printf 'unsafe mac-b performance runtime: %s\n' "$RUNTIME_ROOT" >&2
    exit 1
  }

  while true; do
    slot=1
    while [ "$slot" -le "$HEAVY_LIMIT" ]; do
      slot_dir="$RUNTIME_ROOT/heavy-$slot.lock"
      owner="$slot_dir/owner.pid"
      if mkdir "$slot_dir" 2>/dev/null; then
        if printf '%s\n' "$$" > "$owner"; then
          HELD_SLOT="$slot_dir"
          log "heavy_slot=$slot/$HEAVY_LIMIT acquired pid=$$"
          return 0
        fi
        rmdir "$slot_dir" 2>/dev/null || true
        exit 1
      fi

      if [ -d "$slot_dir" ] && [ ! -L "$slot_dir" ]; then
        holder=$(cat "$owner" 2>/dev/null || true)
        case "$holder" in
          ''|*[!0-9]*)
            rm -f -- "$owner" 2>/dev/null || true
            rmdir "$slot_dir" 2>/dev/null || true
            ;;
          *)
            if ! kill -0 "$holder" 2>/dev/null; then
              rm -f -- "$owner" 2>/dev/null || true
              rmdir "$slot_dir" 2>/dev/null || true
            fi
            ;;
        esac
      fi
      slot=$((slot + 1))
    done
    sleep 1
  done
}

[ -x "$REAL_RUSTUP" ] || {
  printf 'real rustup is unavailable: %s\n' "$REAL_RUSTUP" >&2
  exit 1
}
validate_positive_integer KERNAL_MAC_B_CARGO_JOBS "$CARGO_JOBS"
validate_positive_integer KERNAL_MAC_B_HEAVY_JOB_LIMIT "$HEAVY_LIMIT"
[ "$HEAVY_LIMIT" -le 4 ] || {
  printf 'KERNAL_MAC_B_HEAVY_JOB_LIMIT must not exceed 4\n' >&2
  exit 64
}

if [ "$WORKER_ID" != mac-b ]; then
  exec "$REAL_RUSTUP" "$@"
fi

export CARGO_BUILD_JOBS="$CARGO_JOBS"
export KERNAL_RUNNER_JOBS="$CARGO_JOBS"

class=light
command=rustup
if [ "$#" -ge 4 ] && [ "$1" = run ] && [ "$3" = cargo ]; then
  command="$4"
  case "$command" in
    test|clippy|build|check|run|bench|rustc|xtask) class=heavy ;;
    *) class=light ;;
  esac
fi

log "profile=m3-24gb cargo_jobs=$CARGO_JOBS heavy_limit=$HEAVY_LIMIT class=$class command=$command"
if [ "$class" = heavy ]; then
  trap 'release_heavy_slot' EXIT
  trap 'release_heavy_slot; exit 130' INT
  trap 'release_heavy_slot; exit 143' TERM
  acquire_heavy_slot
  set +e
  "$REAL_RUSTUP" "$@"
  rc=$?
  set -e
  release_heavy_slot
  trap - EXIT INT TERM
  exit "$rc"
fi

exec "$REAL_RUSTUP" "$@"
