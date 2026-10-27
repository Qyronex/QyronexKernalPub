#!/bin/bash
set -euo pipefail

REPO="${KERNAL_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
TOOLCHAIN="${KERNAL_RUST_TOOLCHAIN:-1.98.0}"
RUSTUP="${RUSTUP:-$HOME/.cargo/bin/rustup}"

cd "$REPO"

if [ -x "$RUSTUP" ]; then
  "$RUSTUP" component add --toolchain "$TOOLCHAIN" rustfmt clippy >/dev/null
  "$RUSTUP" target add --toolchain "$TOOLCHAIN" aarch64-unknown-none-softfloat >/dev/null
  cargo_cmd=("$RUSTUP" run "$TOOLCHAIN" cargo)
else
  cargo_cmd=(cargo)
fi

printf '%s\n' 'arm-first-verify: 1/5 format'
"${cargo_cmd[@]}" fmt --all --check

printf '%s\n' 'arm-first-verify: 2/5 workspace tests'
"${cargo_cmd[@]}" test --workspace --profile test --lib --tests

printf '%s\n' 'arm-first-verify: 3/5 strict clippy'
"${cargo_cmd[@]}" clippy --workspace --lib --tests -- -D warnings
"${cargo_cmd[@]}" clippy -p xtask --bin xtask -- -D warnings

printf '%s\n' 'arm-first-verify: 4/5 AArch64 build'
"${cargo_cmd[@]}" xtask arm-build

printf '%s\n' 'arm-first-verify: 5/5 AArch64 QEMU'
"${cargo_cmd[@]}" xtask arm-qemu

printf '%s\n' 'arm-first-verify: PASS'
