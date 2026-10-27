#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests/qemu-prep/step33/ext4_metadata_negative_cases.json"


class Step33Ext4NegativeCorpusTest(unittest.TestCase):
    def test_fixture_is_conditional_and_never_mutates_reference(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["step"], 33)
        self.assertEqual(data["enabled_when"]["equals"], "EXT4_REFERENCE_CONFIRMED")
        policy = data["source_policy"]
        self.assertTrue(policy["reference_base_is_immutable"])
        self.assertTrue(policy["mutate_disposable_copy_only"])
        self.assertTrue(policy["never_run_mutating_fsck_on_reference"])

    def test_required_failure_classes_are_present_once(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        ids = [case["id"] for case in data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        required = {
            "truncated-primary-superblock",
            "bad-superblock-magic",
            "block-size-out-of-supported-range",
            "blocks-count-beyond-device",
            "unknown-required-incompat-feature",
            "inode-table-outside-group",
            "metadata-checksum-mismatch",
        }
        self.assertEqual(set(ids), required)

    def test_evidence_requires_oob_and_hash_accounting(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        fields = set(data["evidence_fields"])
        for field in (
            "tested_commit",
            "input_sha256",
            "mutated_sha256",
            "case_id",
            "kernel_log_hash",
            "out_of_bounds_io_count",
        ):
            self.assertIn(field, fields)


if __name__ == "__main__":
    unittest.main()
