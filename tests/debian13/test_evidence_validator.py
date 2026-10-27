#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "tools/debian13/evidence-validator.py"
SPEC = importlib.util.spec_from_file_location("debian13_evidence_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class EvidenceValidatorTests(unittest.TestCase):
    def target(self):
        return json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )

    def provenance(self, target, source_commit="1" * 40):
        rootfs = target["rootfs"]
        return {
            "source_commit": source_commit,
            "rootfs": {
                "artifact": rootfs["artifact"],
                "size_bytes": rootfs["size_bytes"],
                "sha256": rootfs["sha256"],
                "sha512": rootfs["sha512"],
            },
        }

    def requirements(self):
        return {
            "syscalls": ["openat"],
            "ioctl_requests": [],
            "paths": ["/etc/os-release"],
            "proc_paths": [],
            "sys_paths": [],
            "dev_paths": [],
            "filesystem_paths": ["/etc/os-release"],
            "socket_families": [],
            "socket_types": [],
            "socket_protocols": [],
            "network_syscalls": [],
        }

    def documents(self):
        target = self.target()
        provenance = self.provenance(target)
        requirements = self.requirements()
        observation = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "reference-debian",
            "provenance": deepcopy(provenance),
            "cases": [{"id": "functional.path", "outcome": {}}],
        }
        inventory = {
            "schema_version": 1,
            "target_id": target["target_id"],
            "environment": "reference-debian",
            "provenance": deepcopy(provenance),
            "host": {
                "machine": "aarch64",
                "version_id": "13",
                "version_codename": "trixie",
                "dpkg_architecture": "arm64",
            },
            "packages": {"busybox": "1.0"},
            "requirements": deepcopy(requirements),
            "cases": [
                {
                    "id": "functional.path",
                    "component": "busybox",
                    "argv": ["/usr/bin/busybox", "stat", "/etc/os-release"],
                    "syscalls": ["openat"],
                    "requirements": deepcopy(requirements),
                }
            ],
        }
        return target, observation, inventory

    def test_valid_pair_is_bound_to_same_source_and_rootfs(self) -> None:
        target, observation, inventory = self.documents()
        self.assertEqual(validator.validate_pair(target, observation, inventory), "1" * 40)

    def test_rootfs_hash_mismatch_fails_closed(self) -> None:
        target, observation, inventory = self.documents()
        inventory["provenance"]["rootfs"]["sha256"] = "0" * 64
        with self.assertRaises(validator.EvidenceError):
            validator.validate_pair(target, observation, inventory)

    def test_source_commit_mismatch_fails_closed(self) -> None:
        target, observation, inventory = self.documents()
        inventory["provenance"]["source_commit"] = "2" * 40
        with self.assertRaises(validator.EvidenceError):
            validator.validate_pair(target, observation, inventory)

    def test_missing_explicit_requirement_category_fails_closed(self) -> None:
        target, observation, inventory = self.documents()
        del inventory["cases"][0]["requirements"]["dev_paths"]
        with self.assertRaises(validator.EvidenceError):
            validator.validate_pair(target, observation, inventory)

    def test_aggregate_must_equal_per_case_union(self) -> None:
        target, observation, inventory = self.documents()
        inventory["requirements"]["network_syscalls"] = ["socket"]
        with self.assertRaises(validator.EvidenceError):
            validator.validate_pair(target, observation, inventory)

    def test_only_allowlisted_evidence_files_may_change_after_source_commit(self) -> None:
        self.assertEqual(
            validator.unexpected_source_paths(
                [
                    "tests/debian13/evidence/reference-debian.json",
                    "tests/debian13/evidence/reference-syscalls.json",
                ]
            ),
            [],
        )
        self.assertEqual(
            validator.unexpected_source_paths(
                [
                    "tests/debian13/evidence/reference-debian.json",
                    "tools/debian13/collect-reference.py",
                ]
            ),
            ["tools/debian13/collect-reference.py"],
        )

    def test_repository_evidence_is_bound_to_unchanged_source_snapshot(self) -> None:
        source_commit = validator.validate_files(
            ROOT / "docs/debian13/arm64-target.json",
            ROOT / "tests/debian13/evidence/reference-debian.json",
            ROOT / "tests/debian13/evidence/reference-syscalls.json",
            ROOT,
        )
        self.assertRegex(source_commit, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
