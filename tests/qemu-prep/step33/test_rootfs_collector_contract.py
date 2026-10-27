#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COLLECTOR = ROOT / "tools/qemu-prep/step33/collect_rootfs_reference.sh"
PROBE = ROOT / "tests/qemu-prep/step33/filesystem_probe.c"


class Step33RootfsCollectorContractTest(unittest.TestCase):
    def test_write_probe_requires_explicit_cow_confirmation(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn('KERNAL_STEP33_RUN_WRITE_PROBE:-0', text)
        self.assertIn('KERNAL_REFERENCE_OVERLAY_CONFIRMED:-0', text)
        self.assertIn('never write the pinned base image', text)
        self.assertIn('ROOT_PROBE_SOURCE=$(findmnt', text)
        self.assertIn('[ "$ROOT_PROBE_SOURCE" = "$ROOT_SOURCE" ]', text)

    def test_reference_is_bound_to_source_and_target(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'target_id=%s',
            'STEP33_ROOTFS_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)

    def test_collector_keeps_reference_inspection_non_destructive(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        executable_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        executable_text = "\n".join(executable_lines)
        self.assertIsNone(
            re.search(r"(?m)^\s*(?:sudo\s+)?(?:fsck|e2fsck)(?:\s|$)", executable_text),
            "reference collector must never run mutating filesystem repair tooling",
        )
        self.assertIn('tune2fs -l', text)
        self.assertIn('dumpe2fs -h', text)

    def test_probe_parent_is_explicitly_selectable(self) -> None:
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn('getenv("KERNAL_STEP33_PROBE_PARENT")', text)
        self.assertIn('INFO fs.probe-parent=', text)
        self.assertIn('parent[0] != \'/\'', text)


if __name__ == "__main__":
    unittest.main()
