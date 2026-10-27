#!/bin/bash
set -euo pipefail
repo="${KERNAL_AGENT_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
old="${1:?old sha/ref required}"
new="${2:?new sha/ref required}"
base="${3:-main}"

old_base="$(git -C "$repo" merge-base "$base" "$old")"
new_base="$(git -C "$repo" merge-base "$base" "$new")"
old_patch="$(mktemp "${TMPDIR:-/tmp}/kernal-old-patch.XXXXXX")"
new_patch="$(mktemp "${TMPDIR:-/tmp}/kernal-new-patch.XXXXXX")"
trap 'rm -f "$old_patch" "$new_patch"' EXIT INT TERM

git -C "$repo" diff --binary "$old_base..$old" | git patch-id --stable > "$old_patch"
git -C "$repo" diff --binary "$new_base..$new" | git patch-id --stable > "$new_patch"
if cmp -s "$old_patch" "$new_patch"; then
  printf 'SOURCE_EQUIVALENT=%s\n' "$(git -C "$repo" rev-parse "$old^{commit}")"
  exit 0
fi
printf 'SOURCE_DIFFERENT\n'
exit 1
