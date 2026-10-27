#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "tests/qemu-prep/step32/reference_transport_contract.json"
VALIDATOR = ROOT / "tools/qemu-prep/step32/validate_reference_transport_contract.py"


class ReferenceTransportContractTest(unittest.TestCase):
    def test_contract_validator_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", str(VALIDATOR)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("STEP32_REFERENCE_TRANSPORT_CONTRACT_OK", completed.stdout)

    def test_archive_payload_is_bounded_to_step32_plus_pinned_target(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        allowed_shared = {"docs/debian13/arm64-target.json"}
        step32_prefixes = (
            "docs/debian13/qemu-prep/step32/",
            "tools/qemu-prep/step32/",
            "tests/qemu-prep/step32/",
        )
        for relative in contract["archive_required_paths"]:
            self.assertTrue(
                relative in allowed_shared or relative.startswith(step32_prefixes),
                f"unexpected cross-lane archive input: {relative}",
            )
        self.assertEqual(
            contract["guest_invocation"]["environment"]["KERNAL_STEP32_SOURCE_COMMIT"],
            "<exact-40-hex-source-sha>",
        )
        self.assertFalse(contract["source_commit"]["guest_git_metadata_required"])
        self.assertTrue(contract["host_verification"]["required"])
        self.assertEqual(
            contract["host_verification"]["argv"],
            [
                "python3",
                "-B",
                "tools/qemu-prep/step32/verify_tty_reference_evidence.py",
                "<returned-raw-artifact>",
                "<returned-normalized-artifact>",
                "<exact-40-hex-source-sha>",
            ],
        )
        self.assertEqual(
            contract["host_verification"]["success_marker"],
            "STEP32_REFERENCE_EVIDENCE_OK",
        )


if __name__ == "__main__":
    unittest.main()
