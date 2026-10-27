#!/usr/bin/env python3
"""Validate committed Debian 13 ARM64 reference evidence and requirement provenance."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
DEFAULT_OBSERVATION = ROOT / "tests/debian13/evidence/reference-debian.json"
DEFAULT_INVENTORY = ROOT / "tests/debian13/evidence/reference-syscalls.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SOURCE_SCOPES = ("docs/debian13", "tests/debian13", "tools/debian13")
ALLOWED_POST_SOURCE_PATHS = {
    "tests/debian13/evidence/reference-debian.json",
    "tests/debian13/evidence/reference-syscalls.json",
}
REQUIREMENT_KEYS = (
    "syscalls",
    "ioctl_requests",
    "paths",
    "proc_paths",
    "sys_paths",
    "dev_paths",
    "filesystem_paths",
    "socket_families",
    "socket_types",
    "socket_protocols",
    "network_syscalls",
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read JSON {path}: {error}") from error
    require(isinstance(value, dict), f"top-level JSON value must be an object: {path}")
    return value


def validate_string_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(
        all(isinstance(item, str) and item and "\x00" not in item for item in value),
        f"{label} must contain only non-empty strings without NUL",
    )
    require(value == sorted(set(value)), f"{label} must be sorted and duplicate-free")
    return value


def validate_provenance(
    document: dict[str, Any], target: dict[str, Any], label: str
) -> str:
    provenance = document.get("provenance")
    require(isinstance(provenance, dict), f"{label}: provenance must be an object")
    require(
        set(provenance) == {"source_commit", "rootfs"},
        f"{label}: provenance fields must be exactly source_commit and rootfs",
    )
    source_commit = provenance.get("source_commit")
    require(
        isinstance(source_commit, str) and HEX40.fullmatch(source_commit) is not None,
        f"{label}: source_commit must be 40 lowercase hex characters",
    )

    expected_rootfs = target.get("rootfs")
    actual_rootfs = provenance.get("rootfs")
    require(isinstance(expected_rootfs, dict), "target: rootfs must be an object")
    require(isinstance(actual_rootfs, dict), f"{label}: provenance.rootfs must be an object")
    required_rootfs = {"artifact", "size_bytes", "sha256", "sha512"}
    require(
        set(actual_rootfs) == required_rootfs,
        f"{label}: provenance.rootfs fields must be exactly artifact,size_bytes,sha256,sha512",
    )
    require(
        isinstance(actual_rootfs.get("sha256"), str)
        and HEX64.fullmatch(actual_rootfs["sha256"]) is not None,
        f"{label}: provenance rootfs sha256 is malformed",
    )
    require(
        isinstance(actual_rootfs.get("sha512"), str)
        and HEX128.fullmatch(actual_rootfs["sha512"]) is not None,
        f"{label}: provenance rootfs sha512 is malformed",
    )
    for field in sorted(required_rootfs):
        require(
            actual_rootfs.get(field) == expected_rootfs.get(field),
            f"{label}: provenance rootfs {field} does not match pinned target",
        )
    return source_commit


def validate_common(
    document: dict[str, Any], target: dict[str, Any], label: str
) -> str:
    require(document.get("schema_version") == 1, f"{label}: schema_version must be 1")
    require(document.get("target_id") == target.get("target_id"), f"{label}: target_id mismatch")
    require(
        document.get("environment") == "reference-debian",
        f"{label}: environment must be reference-debian",
    )
    return validate_provenance(document, target, label)


def validate_observation(
    document: dict[str, Any], target: dict[str, Any]
) -> tuple[str, set[str]]:
    source_commit = validate_common(document, target, "observation")
    cases = document.get("cases")
    require(isinstance(cases, list) and cases, "observation: cases must be a non-empty array")
    ids: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "observation: case must be an object")
        case_id = case.get("id")
        require(
            isinstance(case_id, str) and case_id and case_id not in ids,
            "observation: case ids must be unique non-empty strings",
        )
        require(isinstance(case.get("outcome"), dict), f"observation:{case_id}: outcome must be an object")
        ids.add(case_id)
    return source_commit, ids


def validate_inventory(
    document: dict[str, Any], target: dict[str, Any]
) -> tuple[str, set[str]]:
    source_commit = validate_common(document, target, "inventory")
    host = document.get("host")
    require(isinstance(host, dict), "inventory: host must be an object")
    require(host.get("dpkg_architecture") == "arm64", "inventory: dpkg architecture must be arm64")
    require(host.get("machine") in {"aarch64", "arm64"}, "inventory: machine must be ARM64")
    require(host.get("version_codename") == "trixie", "inventory: codename must be trixie")
    require(
        str(host.get("version_id", "")).split(".", 1)[0] == "13",
        "inventory: version_id must be Debian 13",
    )

    packages = document.get("packages")
    require(isinstance(packages, dict) and packages, "inventory: packages must be a non-empty object")
    require(
        all(isinstance(name, str) and name and isinstance(version, str) and version for name, version in packages.items()),
        "inventory: package names and versions must be non-empty strings",
    )

    cases = document.get("cases")
    require(isinstance(cases, list) and cases, "inventory: cases must be a non-empty array")
    ids: set[str] = set()
    aggregate: dict[str, set[str]] = {key: set() for key in REQUIREMENT_KEYS}
    for case in cases:
        require(isinstance(case, dict), "inventory: case must be an object")
        case_id = case.get("id")
        require(
            isinstance(case_id, str) and case_id and case_id not in ids,
            "inventory: case ids must be unique non-empty strings",
        )
        require(isinstance(case.get("component"), str) and case["component"], f"inventory:{case_id}: component is required")
        argv = case.get("argv")
        require(
            isinstance(argv, list)
            and argv
            and all(isinstance(arg, str) and "\x00" not in arg for arg in argv),
            f"inventory:{case_id}: argv must be a non-empty string array",
        )
        requirements = case.get("requirements")
        require(isinstance(requirements, dict), f"inventory:{case_id}: requirements must be an object")
        require(
            set(requirements) == set(REQUIREMENT_KEYS),
            f"inventory:{case_id}: requirement categories do not match schema",
        )
        for key in REQUIREMENT_KEYS:
            entries = validate_string_list(requirements[key], f"inventory:{case_id}:{key}")
            aggregate[key].update(entries)
        syscalls = validate_string_list(case.get("syscalls"), f"inventory:{case_id}:syscalls")
        require(
            syscalls == requirements["syscalls"],
            f"inventory:{case_id}: legacy syscalls field must equal requirements.syscalls",
        )
        ids.add(case_id)

    declared = document.get("requirements")
    require(isinstance(declared, dict), "inventory: aggregate requirements must be an object")
    require(set(declared) == set(REQUIREMENT_KEYS), "inventory: aggregate requirement categories do not match schema")
    for key in REQUIREMENT_KEYS:
        entries = validate_string_list(declared[key], f"inventory:requirements:{key}")
        require(
            entries == sorted(aggregate[key]),
            f"inventory: aggregate {key} does not equal per-case union",
        )
    return source_commit, ids


def validate_pair(
    target: dict[str, Any], observation: dict[str, Any], inventory: dict[str, Any]
) -> str:
    observation_source, observation_ids = validate_observation(observation, target)
    inventory_source, inventory_ids = validate_inventory(inventory, target)
    require(
        observation_source == inventory_source,
        "reference evidence files must name the same source_commit",
    )
    require(
        observation_ids == inventory_ids,
        "reference observation and inventory case ids must match exactly",
    )
    return observation_source


def unexpected_source_paths(paths: list[str]) -> list[str]:
    return sorted(path for path in paths if path and path not in ALLOWED_POST_SOURCE_PATHS)


def require_source_snapshot_unchanged(source_commit: str, repository: Path) -> None:
    try:
        ancestor = subprocess.run(
            ["git", "-C", str(repository), "merge-base", "--is-ancestor", source_commit, "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        require(
            ancestor.returncode == 0,
            f"evidence source_commit is not an ancestor of tested HEAD: {source_commit}",
        )
        diff = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "diff",
                "--name-only",
                source_commit,
                "HEAD",
                "--",
                *SOURCE_SCOPES,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
    except OSError as error:
        raise EvidenceError(f"cannot execute git provenance check: {error}") from error
    require(diff.returncode == 0, "cannot compare evidence source snapshot to tested HEAD")
    changed = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
    unexpected = unexpected_source_paths(changed)
    require(
        not unexpected,
        "evidence source snapshot drift after source_commit: " + ",".join(unexpected),
    )


def validate_files(
    target_path: Path,
    observation_path: Path,
    inventory_path: Path,
    repository: Path | None = None,
) -> str:
    target = load_json(target_path)
    observation = load_json(observation_path)
    inventory = load_json(inventory_path)
    source_commit = validate_pair(target, observation, inventory)
    if repository is not None:
        require_source_snapshot_unchanged(source_commit, repository)
    return source_commit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--observation", type=Path, default=DEFAULT_OBSERVATION)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument(
        "--repository",
        type=Path,
        default=ROOT,
        help="repository used to require source snapshot identity after source_commit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source_commit = validate_files(
            args.target,
            args.observation,
            args.inventory,
            args.repository,
        )
    except EvidenceError as error:
        print(f"debian13-evidence: {error}", file=sys.stderr)
        return 2
    print(f"reference evidence valid: source_commit={source_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
