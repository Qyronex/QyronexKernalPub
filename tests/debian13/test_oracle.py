#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "tools/debian13/oracle.py"
SPEC = importlib.util.spec_from_file_location("debian13_oracle", ORACLE_PATH)
assert SPEC is not None and SPEC.loader is not None
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


class OracleTests(unittest.TestCase):
    def target(self):
        target, _ = oracle.validate_manifests(
            ROOT / "docs/debian13/arm64-target.json",
            ROOT / "docs/debian13/compatibility-matrix.json",
        )
        return target

    def test_repository_manifests_are_valid(self) -> None:
        target, matrix = oracle.validate_manifests(
            ROOT / "docs/debian13/arm64-target.json",
            ROOT / "docs/debian13/compatibility-matrix.json",
        )
        self.assertEqual(target["architecture"], "arm64")
        self.assertEqual(matrix["target_id"], target["target_id"])

    def test_rootfs_checksum_provenance_is_explicit(self) -> None:
        target = json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )
        rootfs = target["rootfs"]
        self.assertTrue(rootfs["sha512_manifest_url"].endswith("/SHA512SUMS"))
        self.assertNotIn("/latest/", rootfs["sha512_manifest_url"])
        self.assertNotIn("sha256_manifest_url", rootfs)
        self.assertEqual(
            rootfs["sha256_provenance"],
            "independently_derived_from_sha512_verified_artifact",
        )

    def test_matching_observations_compare_cleanly(self) -> None:
        target = self.target()
        outcome = {
            "return_value": 0,
            "errno": None,
            "signal": None,
            "exit_status": 0,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": None,
            "file_metadata": {"mode": "0644", "size": 4},
            "socket_behavior": None,
        }
        reference = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "reference-debian",
            "cases": [{"id": "smoke.write", "outcome": outcome}],
        }
        kernal = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "kernal",
            "cases": [{"id": "smoke.write", "outcome": dict(outcome)}],
        }
        report = oracle.compare_observations(reference, kernal, target["target_id"])
        self.assertEqual(report["mismatch_count"], 0)
        self.assertEqual(report["match_count"], 1)

    def test_errno_difference_is_reported_not_forgiven(self) -> None:
        target = self.target()
        reference = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "reference-debian",
            "cases": [
                {
                    "id": "smoke.openat",
                    "outcome": {
                        "return_value": 3,
                        "errno": None,
                        "signal": None,
                        "exit_status": 0,
                    },
                }
            ],
        }
        kernal = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "kernal",
            "cases": [
                {
                    "id": "smoke.openat",
                    "outcome": {
                        "return_value": -1,
                        "errno": "ENOSYS",
                        "signal": None,
                        "exit_status": 0,
                    },
                }
            ],
        }
        report = oracle.compare_observations(reference, kernal, target["target_id"])
        self.assertEqual(report["mismatch_count"], 1)
        self.assertEqual(report["mismatches"][0]["id"], "smoke.openat")

    def test_swapped_reference_environment_is_rejected(self) -> None:
        target = self.target()
        reference = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "kernal",
            "cases": [],
        }
        kernal = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "kernal",
            "cases": [],
        }
        with self.assertRaises(oracle.OracleError):
            oracle.compare_observations(reference, kernal, target["target_id"])

    def test_malformed_stream_digest_is_rejected(self) -> None:
        target = self.target()
        reference = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "reference-debian",
            "cases": [
                {
                    "id": "smoke.digest",
                    "outcome": {"stdout_sha256": "not-a-digest"},
                }
            ],
        }
        kernal = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "kernal",
            "cases": [],
        }
        with self.assertRaises(oracle.OracleError):
            oracle.compare_observations(reference, kernal, target["target_id"])

    def test_latest_rootfs_url_is_rejected(self) -> None:
        target = json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )
        target["rootfs"]["immutable_url"] = (
            "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2"
        )
        with self.assertRaises(oracle.OracleError):
            oracle.validate_target(target)

    def test_rootfs_verification_fails_closed_on_wrong_bytes(self) -> None:
        target = json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / target["rootfs"]["artifact"]
            artifact.write_bytes(b"not the pinned Debian image")
            with self.assertRaises(oracle.OracleError):
                oracle.verify_rootfs(target, artifact)


if __name__ == "__main__":
    unittest.main()
