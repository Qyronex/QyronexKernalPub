#!/bin/bash
set -euo pipefail
repo="${KERNAL_AGENT_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
log="${1:?serial log required}"
out="${2:-qemu-repro-manifest.txt}"
vcpu="${KERNAL_QEMU_VCPU:-unknown}"
runner="${KERNAL_RUNNER_ID:-unknown}"
merge_group_sha="${KERNAL_MERGE_GROUP_SHA:-}"
candidate_sha="${KERNAL_CANDIDATE_SHA:-$(git -C "$repo" rev-parse HEAD)}"

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi
}
last_marker="$(grep 'KERNAL/' "$log" | tail -n 1 || true)"
first_error="$(grep -Eim1 'panic|exception|error|timeout|missing|fault|abort' "$log" || true)"
{
  printf 'candidate_sha=%s\n' "$candidate_sha"
  printf 'merge_group_sha=%s\n' "$merge_group_sha"
  printf 'rustc_version=%s\n' "$(rustc --version 2>/dev/null || true)"
  printf 'cargo_version=%s\n' "$(cargo --version 2>/dev/null || true)"
  printf 'musl_compiler=%s\n' "${CC_AARCH64_MUSL:-${STEP15_MUSL_CC:-unknown}}"
  printf 'qemu_version=%s\n' "$(qemu-system-aarch64 --version 2>/dev/null | head -n 1 || true)"
  printf 'vcpu_count=%s\n' "$vcpu"
  printf 'runner_id=%s\n' "$runner"
  printf 'host_os=%s\n' "$(uname -a)"
  printf 'free_disk_before_kb=%s\n' "$(df -Pk "$repo" | awk 'NR==2 {print $4}')"
  printf 'last_kernel_marker=%s\n' "$last_marker"
  printf 'first_error_marker=%s\n' "$first_error"
  printf 'serial_log_sha256=%s\n' "$(sha256 "$log")"
} > "$out"
printf '%s\n' "$out"
