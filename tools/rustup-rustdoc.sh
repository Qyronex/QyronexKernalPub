#!/bin/sh
set -eu

TOOLCHAIN="${KERNAL_RUST_TOOLCHAIN:-1.98.0}"
RUSTUP="${RUSTUP:-$HOME/.cargo/bin/rustup}"

if [ -x "$RUSTUP" ]; then
  exec "$RUSTUP" run "$TOOLCHAIN" rustdoc "$@"
fi

exec rustdoc "$@"
