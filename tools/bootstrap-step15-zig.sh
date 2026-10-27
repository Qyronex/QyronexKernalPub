#!/bin/bash
set -eu

PINNED_VERSION="0.16.0"
VERSION="${KERNAL_ZIG_VERSION:-$PINNED_VERSION}"
CACHE_ROOT="${KERNAL_TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kernal/toolchains}"
DOWNLOAD_BASE="${KERNAL_ZIG_DOWNLOAD_BASE:-https://ziglang.org/download/$VERSION}"

fail() {
  printf 'Step-15 Zig bootstrap: %s\n' "$*" >&2
  exit 1
}

[ "$VERSION" = "$PINNED_VERSION" ] || {
  fail "unsupported Zig version $VERSION; acceptance is pinned to $PINNED_VERSION"
}

HOST_OS=$(uname -s 2>/dev/null || true)
HOST_ARCH=$(uname -m 2>/dev/null || true)
case "$HOST_OS:$HOST_ARCH" in
  Darwin:arm64|Darwin:aarch64)
    ARCHIVE="zig-aarch64-macos-$VERSION.tar.xz"
    EXPECTED_SHA256="b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489"
    EXPECTED_BYTES="52238004"
    ;;
  Darwin:x86_64)
    ARCHIVE="zig-x86_64-macos-$VERSION.tar.xz"
    EXPECTED_SHA256="0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7"
    EXPECTED_BYTES="57396836"
    ;;
  Linux:x86_64)
    ARCHIVE="zig-x86_64-linux-$VERSION.tar.xz"
    EXPECTED_SHA256="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
    EXPECTED_BYTES="55478392"
    ;;
  Linux:arm64|Linux:aarch64)
    ARCHIVE="zig-aarch64-linux-$VERSION.tar.xz"
    EXPECTED_SHA256="ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17"
    EXPECTED_BYTES="51211944"
    ;;
  *)
    fail "unsupported host $HOST_OS/$HOST_ARCH"
    ;;
esac

INSTALL_DIR="$CACHE_ROOT/${ARCHIVE%.tar.xz}"
ZIG="$INSTALL_DIR/zig"

valid_install() {
  [ -x "$ZIG" ] && [ "$("$ZIG" version 2>/dev/null || true)" = "$VERSION" ]
}

if valid_install; then
  printf '%s\n' "$ZIG"
  exit 0
fi

mkdir -p "$CACHE_ROOT"
LOCK_DIR="$CACHE_ROOT/.zig-$VERSION-$HOST_OS-$HOST_ARCH.lock"
WAIT_COUNT=0
while ! mkdir "$LOCK_DIR" 2>/dev/null; do
  if valid_install; then
    printf '%s\n' "$ZIG"
    exit 0
  fi
  WAIT_COUNT=$((WAIT_COUNT + 1))
  [ "$WAIT_COUNT" -le 120 ] || fail "timed out waiting for toolchain cache lock"
  sleep 1
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/kernal-step15-zig.XXXXXX")
cleanup() {
  rm -rf "$TMP"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if valid_install; then
  printf '%s\n' "$ZIG"
  exit 0
fi

ARCHIVE_PATH="$TMP/$ARCHIVE"
URL="$DOWNLOAD_BASE/$ARCHIVE"
printf 'Step-15 Zig bootstrap: downloading %s\n' "$ARCHIVE" >&2
if command -v curl >/dev/null 2>&1; then
  curl --fail --location --retry 3 --output "$ARCHIVE_PATH" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$ARCHIVE_PATH" "$URL"
else
  fail "neither curl nor wget is available"
fi

ACTUAL_BYTES=$(wc -c < "$ARCHIVE_PATH" | tr -d ' ')
[ "$ACTUAL_BYTES" = "$EXPECTED_BYTES" ] || {
  fail "archive size mismatch: expected $EXPECTED_BYTES, got $ACTUAL_BYTES"
}

if command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
else
  fail "no SHA-256 implementation is available"
fi
[ "$ACTUAL_SHA256" = "$EXPECTED_SHA256" ] || {
  fail "archive SHA-256 mismatch"
}

tar -xf "$ARCHIVE_PATH" -C "$TMP"
EXTRACTED="$TMP/${ARCHIVE%.tar.xz}"
[ -x "$EXTRACTED/zig" ] || fail "archive did not contain the expected Zig executable"
[ "$("$EXTRACTED/zig" version 2>/dev/null || true)" = "$VERSION" ] || {
  fail "extracted compiler version does not match $VERSION"
}

INSTALL_TMP="$CACHE_ROOT/.${ARCHIVE%.tar.xz}.$$.tmp"
rm -rf "$INSTALL_TMP" "$INSTALL_DIR"
mv "$EXTRACTED" "$INSTALL_TMP"
mv "$INSTALL_TMP" "$INSTALL_DIR"

valid_install || fail "installed Zig compiler failed its version check"
printf '%s\n' "$ZIG"
