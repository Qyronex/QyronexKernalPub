#!/bin/sh
set -eu

compiler="${1:-}"
if [ -z "$compiler" ]; then
  printf '%s\n' 'rustc wrapper invoked without compiler argument' >&2
  exit 64
fi
shift

TOOLCHAIN="${KERNAL_RUST_TOOLCHAIN:-1.98.0}"
RUSTUP="${RUSTUP:-$HOME/.cargo/bin/rustup}"
SCCACHE_BIN="${SCCACHE:-}"
if [ -z "$SCCACHE_BIN" ]; then
  SCCACHE_BIN=$(command -v sccache 2>/dev/null || true)
fi

# Cargo may compose this repository wrapper with another compiler frontend supplied by developer
# tooling (for example rust-analyzer/CLion, sccache, or clippy-driver). Replacing such a frontend
# with plain rustc breaks the tool's crate-discovery/proxy protocol and can surface false
# "can't find crate" diagnostics even though Cargo itself resolves the workspace correctly.
#
# Pin only a genuine rustc invocation. Any other frontend already owns how the real compiler is
# delegated and must remain transparent through this wrapper. When sccache is installed, place it
# in front of the exact rustup-selected rustc so separate runner worktrees can reuse compilation
# results without changing Cargo target paths or the AArch64 proof artifact locations.
case "$(basename "$compiler")" in
  rustc|rustc.exe)
    if [ -x "$RUSTUP" ]; then
      if [ -n "$SCCACHE_BIN" ] && [ -x "$SCCACHE_BIN" ]; then
        pinned_rustc=$("$RUSTUP" which --toolchain "$TOOLCHAIN" rustc 2>/dev/null || true)
        if [ -n "$pinned_rustc" ] && [ -x "$pinned_rustc" ]; then
          exec "$SCCACHE_BIN" "$pinned_rustc" "$@"
        fi
      fi
      exec "$RUSTUP" run "$TOOLCHAIN" rustc "$@"
    fi
    exec "$compiler" "$@"
    ;;
  *)
    exec "$compiler" "$@"
    ;;
esac
