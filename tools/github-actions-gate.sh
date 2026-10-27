#!/bin/bash
set -euo pipefail
GATE="${1:-}"
TOOLCHAIN="${KERNAL_RUST_TOOLCHAIN:-1.98.0}"
REPEAT="${KERNAL_REPEAT:-1}"
usage(){ printf 'usage: %s <gate>\n' "$0" >&2; exit 64; }
[ -n "$GATE" ] || usage
cargo_cmd(){ rustup run "$TOOLCHAIN" cargo "$@"; }
ensure_qemu(){ command -v qemu-system-aarch64 >/dev/null 2>&1 || { printf 'qemu-system-aarch64 is required\n' >&2; return 69; }; }
configure_host_toolchain(){
  [ "$(uname -s 2>/dev/null || true)" = Darwin ] || return 0
  helper="tools/macos-runner-host-toolchain.sh"
  [ -f "$helper" ] && [ ! -L "$helper" ] || { printf 'missing safe macOS host-toolchain helper: %s\n' "$helper" >&2; return 78; }
  . "$helper"
  kernal_configure_macos_runner_host_toolchain
}
run_shell_check(){
  bash -n tools/github-actions-gate.sh tools/enqueue-kernel-runner.sh tools/arm-first-verify.sh tools/distributed-agent-coordinator.sh tools/distributed-agent-coordinator-balanced.sh
  before="$(git status --porcelain=v1 --untracked-files=all)"
  if [ -f tools/qemu-prep/validate_all.py ]; then
    for script in tools/qemu-prep/*.sh tools/qemu-prep/*/*.sh; do [ -f "$script" ] || continue; bash -n "$script"; done
    PYTHONDONTWRITEBYTECODE=1 python3 -B tools/qemu-prep/validate_all.py
  fi
  for script in tools/qemu-prep/step*/*.sh; do [ -f "$script" ] || continue; bash -n "$script"; done
  for test_script in tests/qemu-prep/step*/test_*.py; do [ -f "$test_script" ] || continue; PYTHONDONTWRITEBYTECODE=1 python3 -B "$test_script"; done
  after="$(git status --porcelain=v1 --untracked-files=all)"
  [ "$after" = "$before" ] || { printf 'validation mutated checkout\n%s\n' "$after" >&2; return 1; }
}
configure_host_toolchain
case "$GATE" in
  doctor) cargo_cmd xtask doctor ;;
  workspace-test) CARGO_INCREMENTAL=0 cargo_cmd test --workspace --profile test --lib --tests ;;
  fmt-check) cargo_cmd fmt --all --check ;;
  clippy) CARGO_INCREMENTAL=0 cargo_cmd clippy --workspace --lib --tests -- -D warnings; CARGO_INCREMENTAL=0 cargo_cmd clippy -p xtask --bin xtask -- -D warnings ;;
  shell-check) run_shell_check ;;
  coordination-check) bash tools/check-coordination.sh ;;
  arm-build) cargo_cmd xtask arm-build ;;
  arm-qemu) ensure_qemu; cargo_cmd xtask arm-qemu ;;
  step15-qemu|step16-qemu)
    case "$REPEAT" in ''|*[!0-9]*) exit 64;; esac
    [ "$REPEAT" -ge 1 ] || exit 64
    ensure_qemu
    bin="arm-qemu-${GATE%-qemu}"
    i=1
    while [ "$i" -le "$REPEAT" ]; do cargo_cmd run --locked -p xtask --bin "$bin"; i=$((i+1)); done
    ;;
  compile) bash tools/arm-first-verify.sh ;;
  postmerge) bash tools/arm-first-verify.sh; ensure_qemu; cargo_cmd run --locked -p xtask --bin arm-qemu-step16 ;;
  *) usage ;;
esac
