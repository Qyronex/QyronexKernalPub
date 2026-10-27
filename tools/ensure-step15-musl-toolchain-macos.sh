#!/bin/bash
set -eu

ROOT="${KERNAL_REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
AUTO_INSTALL="${KERNAL_AUTO_INSTALL_MUSL_TOOLCHAIN:-1}"
CANONICAL_DIR="${KERNAL_TOOLCHAIN_BIN_DIR:-$HOME/.cargo/bin}"
CANONICAL_CC="$CANONICAL_DIR/aarch64-linux-musl-gcc"
ZIG_BOOTSTRAP="$ROOT/tools/bootstrap-step15-zig.sh"

log() { printf '[step15-musl-toolchain] %s\n' "$*" >&2; }

validate_compiler() {
  compiler="$1"
  [ -n "$compiler" ] || return 1
  if [ -x "$compiler" ]; then
    resolved="$compiler"
  else
    resolved=$(command -v "$compiler" 2>/dev/null || true)
  fi
  [ -n "$resolved" ] || return 1
  triple=$("$resolved" -dumpmachine 2>/dev/null || true)
  case "$triple" in
    aarch64*-linux-musl*)
      printf '%s\n' "$resolved"
      return 0
      ;;
    *) return 1 ;;
  esac
}

if [ "$(uname -s 2>/dev/null || true)" != "Darwin" ]; then
  printf 'this provisioner is macOS-only\n' >&2
  exit 1
fi

if [ -n "${KERNAL_AARCH64_MUSL_CC:-}" ]; then
  if compiler=$(validate_compiler "$KERNAL_AARCH64_MUSL_CC"); then
    printf '%s\n' "$compiler"
    exit 0
  fi
  printf 'KERNAL_AARCH64_MUSL_CC is set but is not a usable AArch64 musl compiler: %s\n' "$KERNAL_AARCH64_MUSL_CC" >&2
  exit 1
fi

for candidate in "$CANONICAL_CC" aarch64-linux-musl-gcc aarch64-unknown-linux-musl-gcc; do
  if compiler=$(validate_compiler "$candidate"); then
    printf '%s\n' "$compiler"
    exit 0
  fi
done

if [ "$AUTO_INSTALL" != "1" ]; then
  printf 'AArch64 musl compiler missing and automatic installation is disabled\n' >&2
  exit 1
fi

[ -f "$ZIG_BOOTSTRAP" ] || {
  printf 'pinned Step-15 Zig bootstrap missing: %s\n' "$ZIG_BOOTSTRAP" >&2
  exit 1
}
bash -n "$ZIG_BOOTSTRAP" || {
  printf 'pinned Step-15 Zig bootstrap fails shell syntax validation: %s\n' "$ZIG_BOOTSTRAP" >&2
  exit 1
}

log 'AArch64 musl compiler missing; provisioning checksum-pinned Zig fallback'
ZIG=$(bash "$ZIG_BOOTSTRAP") || exit $?
[ -x "$ZIG" ] || {
  printf 'pinned Zig bootstrap returned a non-executable path: %s\n' "$ZIG" >&2
  exit 1
}
ZIG_VERSION=$("$ZIG" version 2>/dev/null || true)
[ "$ZIG_VERSION" = "0.16.0" ] || {
  printf 'unexpected Step-15 Zig version: expected 0.16.0, got %s\n' "$ZIG_VERSION" >&2
  exit 1
}

mkdir -p "$CANONICAL_DIR"
WRAPPER_TMP="$CANONICAL_CC.$$.tmp"
cleanup() { rm -f "$WRAPPER_TMP"; }
trap cleanup EXIT INT TERM

cat > "$WRAPPER_TMP" <<EOF_WRAPPER
#!/bin/bash
set -eu
if [ "\${1:-}" = "-dumpmachine" ]; then
  printf '%s\\n' 'aarch64-linux-musl'
  exit 0
fi
exec "$ZIG" cc -target aarch64-linux-musl "\$@"
EOF_WRAPPER
chmod 0755 "$WRAPPER_TMP"
mv -f "$WRAPPER_TMP" "$CANONICAL_CC"
trap - EXIT INT TERM

compiler=$(validate_compiler "$CANONICAL_CC") || {
  printf 'provisioned Zig-backed compiler wrapper failed AArch64 musl target validation: %s\n' "$CANONICAL_CC" >&2
  exit 1
}
log "ready: $compiler ($($compiler -dumpmachine), Zig $ZIG_VERSION)"
printf '%s\n' "$compiler"
