#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COLLECTOR = ROOT / "tools/qemu-prep/step32/collect_tty_reference.sh"
NORMALIZER = ROOT / "tools/qemu-prep/step32/normalize_tty_reference.py"


class Step32ReferenceCollectorContractTest(unittest.TestCase):
    def test_collector_is_pinned_and_fail_closed(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'ID:-}\" = \"debian\"',
            '13|13.*)',
            'aarch64|arm64)',
            'SOURCE_COMMIT=${KERNAL_STEP32_SOURCE_COMMIT:-}',
            'validate_source_commit "$SOURCE_COMMIT"',
            'explicit source commit does not match checked-out HEAD',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'KERNAL_STEP32_REFERENCE_OUT:-/tmp/kernal-step32-tty-reference.raw',
            'python3 -B "$NORMALIZER" "$OUT" "$JSON_OUT"',
            'STEP32_REFERENCE_COLLECTION_OK',
        ):
            self.assertIn(fragment, text)

    def test_collector_does_not_default_to_worktree_evidence(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        self.assertNotIn('tests/qemu-prep/step32/reference.json', text)
        self.assertIn('/tmp/kernal-step32-tty-reference.raw', text)

    def test_collector_supports_git_archive_guest_with_explicit_provenance(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn('KERNAL_STEP32_SOURCE_COMMIT', text)
        self.assertIn('git is required when KERNAL_STEP32_SOURCE_COMMIT is unset', text)
        self.assertIn('[ "${#value}" -eq 40 ]', text)
        self.assertNotIn('command -v git >/dev/null 2>&1 || fail "git is required for exact source identity"', text)

    def test_probe_covers_required_device_baseline(self) -> None:
        probe = (ROOT / "tests/qemu-prep/step32/pty_probe.c").read_text(encoding="utf-8")
        for fragment in (
            'open("/dev/null"',
            'open("/dev/zero"',
            'open("/dev/full"',
            'open("/dev/console"',
            'PASS dev.null-semantics',
            'PASS dev.zero-semantics',
            'PASS dev.full-enospc',
            'PASS dev.console-open',
        ):
            self.assertIn(fragment, probe)

    def test_normalizer_exists_and_is_nonempty(self) -> None:
        self.assertTrue(NORMALIZER.is_file())
        self.assertGreater(NORMALIZER.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
