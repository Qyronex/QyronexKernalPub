#!/usr/bin/env python3
"""Validate a completed Step-40 Debian 13 ARM64 QEMU evidence bundle.

The validator checks identity, pinned rootfs hashes, the complete set of required
checks and repeat-boot records. It does not execute Kernal/QEMU itself and cannot
turn PREP evidence into runtime acceptance without the declared exact-SHA gates.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = ROOT / "tests/qemu-prep/step40/final_acceptance_schema.json"
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"top-level JSON must be an object: {path}")
    return value


def validate(schema: dict[str, Any], target: dict[str, Any], result: dict[str, Any]) -> None:
    require(schema.get("schema_version") == 1, "Step40 schema_version must be 1")
    require(result.get("schema_version") == 1, "result schema_version must be 1")
    require(result.get("profile_id") == schema.get("profile_id"), "result profile_id mismatch")
    require(result.get("target_id") == schema.get("target_id") == target.get("target_id"), "result target_id mismatch")
    require(result.get("bounded_claim") == schema.get("bounded_claim"), "bounded claim mismatch")

    identity_contract = schema.get("exact_identity")
    identity = result.get("exact_identity")
    require(isinstance(identity_contract, dict), "schema exact_identity missing")
    require(isinstance(identity, dict), "result exact_identity missing")
    required_identity = identity_contract.get("required")
    require(isinstance(required_identity, list) and required_identity, "schema exact identity required list missing")
    for key in required_identity:
        require(key in identity, f"exact_identity missing required field: {key}")

    source_sha = identity.get("kernal_source_sha")
    require(isinstance(source_sha, str) and SHA40.fullmatch(source_sha) is not None, "kernal_source_sha must be a lowercase full 40-character SHA")
    require(identity.get("debian_target_id") == target.get("target_id"), "exact_identity Debian target mismatch")

    rootfs = target.get("rootfs")
    require(isinstance(rootfs, dict), "canonical target rootfs missing")
    require(identity.get("rootfs_sha512") == rootfs.get("sha512"), "result rootfs SHA512 mismatch")
    require(identity.get("rootfs_sha256") == rootfs.get("sha256"), "result rootfs SHA256 mismatch")

    qemu_version = identity.get("qemu_version")
    require(isinstance(qemu_version, str) and qemu_version.strip(), "qemu_version must be recorded")
    argv = identity.get("complete_qemu_argv")
    require(isinstance(argv, list) and argv and all(isinstance(arg, str) and arg for arg in argv), "complete_qemu_argv must be a non-empty string array")
    require(isinstance(identity.get("transport_block"), str) and identity["transport_block"], "transport_block must be recorded")
    require(isinstance(identity.get("transport_net"), str) and identity["transport_net"], "transport_net must be recorded")
    require(isinstance(identity.get("cpu_count"), int) and identity["cpu_count"] >= 1, "cpu_count must be >= 1")
    require(isinstance(identity.get("memory_bytes"), int) and identity["memory_bytes"] > 0, "memory_bytes must be > 0")

    required_checks = schema.get("checks")
    checks = result.get("checks")
    require(isinstance(required_checks, list) and required_checks, "schema checks missing")
    require(isinstance(checks, list), "result checks must be an array")
    required_ids = [entry.get("id") for entry in required_checks if isinstance(entry, dict) and entry.get("required") is True]
    result_ids = [entry.get("id") for entry in checks if isinstance(entry, dict)]
    require(len(result_ids) == len(set(result_ids)), "result contains duplicate check ids")
    require(set(result_ids) == set(required_ids), "result check ids must exactly match all required Step40 checks")

    by_id = {entry["id"]: entry for entry in checks}
    for check_id in required_ids:
        entry = by_id[check_id]
        require(entry.get("status") == "PASS", f"required check is not PASS: {check_id}")
        evidence = entry.get("evidence")
        require(isinstance(evidence, list) and evidence and all(isinstance(item, str) and item for item in evidence), f"required check lacks evidence strings: {check_id}")

    repeat_contract = schema.get("repeat_boot_policy")
    repeat_boots = result.get("repeat_boots")
    require(isinstance(repeat_contract, dict), "schema repeat_boot_policy missing")
    minimum = repeat_contract.get("minimum")
    require(isinstance(minimum, int) and minimum >= 1, "schema repeat boot minimum invalid")
    require(isinstance(repeat_boots, list) and len(repeat_boots) >= minimum, f"result must contain at least {minimum} repeat boot records")

    indices: list[int] = []
    required_boot_fields = repeat_contract.get("record_each_boot")
    require(isinstance(required_boot_fields, list) and required_boot_fields, "schema repeat boot fields missing")
    for record in repeat_boots:
        require(isinstance(record, dict), "repeat boot entries must be objects")
        index = record.get("boot_index")
        require(isinstance(index, int) and index >= 1, "repeat boot index must be >= 1")
        indices.append(index)
        require(record.get("status") == "PASS", f"repeat boot {index} is not PASS")
        for field in required_boot_fields:
            value = record.get(field)
            require(isinstance(value, str) and value, f"repeat boot {index} missing field: {field}")
        for field in ("filesystem_check", "service_check", "device_check"):
            require(record.get(field) == "PASS", f"repeat boot {index} {field} is not PASS")
    require(len(indices) == len(set(indices)), "repeat boot indices must be unique")
    require(sorted(indices) == list(range(1, len(indices) + 1)), "repeat boot indices must be contiguous from 1")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(load(args.schema), load(args.target), load(args.result))
    except EvidenceError as exc:
        print(f"step40-evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    print("step40-evidence: PASS: completed evidence bundle satisfies the staged Step40 contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
