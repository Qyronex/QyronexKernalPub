#!/usr/bin/env python3
"""Deterministic Debian 13 ARM64 compatibility oracle.

The oracle intentionally compares observable Linux userspace behavior only. It does not encode Linux
kernel internals and it never turns a missing Kernal operation into success. Reference and Kernal
observations are JSON documents so collection can happen on different machines while comparison stays
reproducible and reviewable in this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
DEFAULT_MATRIX = ROOT / "docs/debian13/compatibility-matrix.json"

ALLOWED_STATES = {
    "SUPPORTED_PROVEN",
    "SUPPORTED_UNVERIFIED",
    "PARTIAL",
    "ENOSYS_UNSUPPORTED",
    "NOT_REQUIRED",
}
ALLOWED_TRACE_STATES = {"NOT_COLLECTED", "COLLECTED", "VERIFIED"}
REQUIRED_COMPONENTS = {
    "busybox",
    "glibc-loader",
    "bin-sh",
    "systemd",
    "udev",
    "dbus",
    "iproute2",
    "dpkg",
    "apt",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SNAPSHOT = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")


class OracleError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OracleError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise OracleError(f"top-level JSON value must be an object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OracleError(message)


def validate_target(target: dict[str, Any]) -> None:
    require(target.get("schema_version") == 1, "target schema_version must be 1")
    require(target.get("distribution") == "Debian", "target distribution must be Debian")
    require(target.get("release") == "13", "target release must be 13")
    require(target.get("codename") == "trixie", "target codename must be trixie")
    require(target.get("architecture") == "arm64", "target architecture must be arm64")
    target_id = target.get("target_id")
    require(isinstance(target_id, str) and target_id, "target_id must be a non-empty string")

    rootfs = target.get("rootfs")
    require(isinstance(rootfs, dict), "rootfs must be an object")
    artifact = rootfs.get("artifact")
    url = rootfs.get("immutable_url")
    require(isinstance(artifact, str) and artifact.endswith(".qcow2"), "rootfs artifact must be qcow2")
    require(isinstance(url, str) and url.startswith("https://"), "rootfs immutable_url must use https")
    require("/latest/" not in url, "rootfs acceptance URL must not use latest")
    require(artifact in url, "rootfs immutable_url must name the pinned artifact")
    require(
        isinstance(rootfs.get("size_bytes"), int) and rootfs["size_bytes"] > 0,
        "rootfs size_bytes must be positive",
    )
    require(
        isinstance(rootfs.get("sha256"), str) and HEX64.fullmatch(rootfs["sha256"]) is not None,
        "rootfs sha256 must be 64 lowercase hex characters",
    )
    require(
        isinstance(rootfs.get("sha512"), str) and HEX128.fullmatch(rootfs["sha512"]) is not None,
        "rootfs sha512 must be 128 lowercase hex characters",
    )

    repositories = target.get("repositories")
    require(isinstance(repositories, list) and repositories, "at least one pinned repository is required")
    names: set[str] = set()
    for repo in repositories:
        require(isinstance(repo, dict), "repository entry must be an object")
        name = repo.get("name")
        snapshot = repo.get("snapshot")
        base_url = repo.get("base_url")
        require(isinstance(name, str) and name and name not in names, "repository names must be unique")
        names.add(name)
        require(
            isinstance(snapshot, str) and SNAPSHOT.fullmatch(snapshot) is not None,
            f"{name}: invalid snapshot timestamp",
        )
        require(
            isinstance(base_url, str)
            and base_url.startswith("https://snapshot.debian.org/archive/"),
            f"{name}: repository must use snapshot.debian.org",
        )
        require(
            snapshot in base_url and "/latest/" not in base_url,
            f"{name}: base_url must contain its exact snapshot",
        )
        require(
            str(repo.get("release_metadata", "")).endswith("/InRelease"),
            f"{name}: signed InRelease metadata is required",
        )

    integrity = target.get("integrity_policy")
    require(isinstance(integrity, dict), "integrity_policy must be an object")
    require(integrity.get("allow_latest_urls") is False, "latest URLs must be forbidden")
    require(integrity.get("allow_unhashed_rootfs") is False, "unhashed rootfs artifacts must be forbidden")
    require(
        integrity.get("allow_kernal_patched_debian_binaries") is False,
        "Kernal-patched Debian binaries must be forbidden",
    )


def validate_matrix(matrix: dict[str, Any], target_id: str) -> None:
    require(matrix.get("schema_version") == 1, "matrix schema_version must be 1")
    require(matrix.get("target_id") == target_id, "matrix target_id must match target manifest")
    states = matrix.get("allowed_states")
    require(
        isinstance(states, list) and set(states) == ALLOWED_STATES,
        "matrix allowed_states must match the finite oracle schema",
    )

    unknown = matrix.get("unknown_operation_policy")
    require(isinstance(unknown, dict), "unknown_operation_policy must be an object")
    require(
        unknown.get("state") == "ENOSYS_UNSUPPORTED",
        "unknown operations must default to ENOSYS_UNSUPPORTED",
    )
    require(unknown.get("expected_errno") == "ENOSYS", "unknown operations must default to ENOSYS")

    components = matrix.get("components")
    require(isinstance(components, list), "components must be an array")
    component_ids: set[str] = set()
    for component in components:
        require(isinstance(component, dict), "component entry must be an object")
        component_id = component.get("id")
        require(
            isinstance(component_id, str) and component_id and component_id not in component_ids,
            "component ids must be unique non-empty strings",
        )
        component_ids.add(component_id)
        require(
            isinstance(component.get("program"), str) and bool(component["program"]),
            f"{component_id}: program must be a non-empty string",
        )
        require(
            component.get("trace_state") in ALLOWED_TRACE_STATES,
            f"{component_id}: invalid trace_state",
        )
    missing_components = sorted(REQUIRED_COMPONENTS - component_ids)
    require(
        not missing_components,
        f"missing representative Debian components: {','.join(missing_components)}",
    )

    contracts = matrix.get("contracts")
    require(isinstance(contracts, list) and contracts, "contracts must be a non-empty array")
    seen: set[str] = set()
    for contract in contracts:
        require(isinstance(contract, dict), "contract entry must be an object")
        contract_id = contract.get("id")
        state = contract.get("state")
        require(
            isinstance(contract_id, str) and contract_id and contract_id not in seen,
            "contract ids must be unique non-empty strings",
        )
        seen.add(contract_id)
        require(state in ALLOWED_STATES, f"{contract_id}: invalid state {state!r}")
        if state == "SUPPORTED_PROVEN":
            require(bool(contract.get("evidence")), f"{contract_id}: proven state requires evidence")
        if state == "ENOSYS_UNSUPPORTED":
            require(
                bool(contract.get("expected_errno")),
                f"{contract_id}: unsupported state requires explicit expected errno",
            )


def validate_manifests(
    target_path: Path, matrix_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = load_json(target_path)
    matrix = load_json(matrix_path)
    validate_target(target)
    validate_matrix(matrix, str(target["target_id"]))
    return target, matrix


def digest_file(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_rootfs(target: dict[str, Any], artifact_path: Path) -> None:
    rootfs = target["rootfs"]
    require(artifact_path.is_file(), f"rootfs artifact does not exist: {artifact_path}")
    require(
        artifact_path.stat().st_size == rootfs["size_bytes"],
        "rootfs size does not match pinned size_bytes",
    )
    require(digest_file(artifact_path, "sha512") == rootfs["sha512"], "rootfs SHA-512 mismatch")
    require(digest_file(artifact_path, "sha256") == rootfs["sha256"], "rootfs SHA-256 mismatch")


def validate_optional_digest(value: Any, label: str) -> None:
    require(
        value is None or (isinstance(value, str) and HEX64.fullmatch(value) is not None),
        f"{label} must be null or a lowercase SHA-256 digest",
    )


def validate_observation(
    document: dict[str, Any],
    target_id: str,
    label: str,
    expected_environment: str,
) -> dict[str, dict[str, Any]]:
    require(document.get("schema_version") == 1, f"{label}: schema_version must be 1")
    require(document.get("target_id") == target_id, f"{label}: target_id mismatch")
    require(
        document.get("environment") == expected_environment,
        f"{label}: environment must be {expected_environment}",
    )
    cases = document.get("cases")
    require(isinstance(cases, list), f"{label}: cases must be an array")

    result: dict[str, dict[str, Any]] = {}
    for case in cases:
        require(isinstance(case, dict), f"{label}: case must be an object")
        case_id = case.get("id")
        outcome = case.get("outcome")
        require(
            isinstance(case_id, str) and case_id and case_id not in result,
            f"{label}: duplicate or invalid case id",
        )
        require(isinstance(outcome, dict), f"{label}:{case_id}: outcome must be an object")
        allowed = {
            "return_value",
            "errno",
            "signal",
            "exit_status",
            "stdout_sha256",
            "stderr_sha256",
            "file_metadata",
            "socket_behavior",
        }
        unknown = sorted(set(outcome) - allowed)
        require(
            not unknown,
            f"{label}:{case_id}: unknown outcome fields: {','.join(unknown)}",
        )
        require(
            outcome.get("return_value") is None or isinstance(outcome.get("return_value"), int),
            f"{label}:{case_id}: return_value must be an integer or null",
        )
        require(
            outcome.get("exit_status") is None or isinstance(outcome.get("exit_status"), int),
            f"{label}:{case_id}: exit_status must be an integer or null",
        )
        require(
            outcome.get("errno") is None or isinstance(outcome.get("errno"), str),
            f"{label}:{case_id}: errno must be a string or null",
        )
        require(
            outcome.get("signal") is None or isinstance(outcome.get("signal"), str),
            f"{label}:{case_id}: signal must be a string or null",
        )
        validate_optional_digest(outcome.get("stdout_sha256"), f"{label}:{case_id}: stdout_sha256")
        validate_optional_digest(outcome.get("stderr_sha256"), f"{label}:{case_id}: stderr_sha256")
        require(
            outcome.get("file_metadata") is None
            or isinstance(outcome.get("file_metadata"), dict),
            f"{label}:{case_id}: file_metadata must be an object or null",
        )
        require(
            outcome.get("socket_behavior") is None
            or isinstance(outcome.get("socket_behavior"), dict),
            f"{label}:{case_id}: socket_behavior must be an object or null",
        )
        result[case_id] = outcome
    return result


def compare_observations(
    reference: dict[str, Any], kernal: dict[str, Any], target_id: str
) -> dict[str, Any]:
    reference_cases = validate_observation(
        reference, target_id, "reference", "reference-debian"
    )
    kernal_cases = validate_observation(kernal, target_id, "kernal", "kernal")
    all_ids = sorted(set(reference_cases) | set(kernal_cases))
    mismatches: list[dict[str, Any]] = []
    matches = 0
    for case_id in all_ids:
        expected = reference_cases.get(case_id)
        actual = kernal_cases.get(case_id)
        if expected == actual:
            matches += 1
            continue
        mismatches.append({"id": case_id, "reference": expected, "kernal": actual})
    return {
        "schema_version": 1,
        "target_id": target_id,
        "case_count": len(all_ids),
        "match_count": matches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }


def dump_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def command_validate(args: argparse.Namespace) -> int:
    target, _ = validate_manifests(args.target, args.matrix)
    print(f"oracle manifests valid: {target['target_id']}")
    return 0


def command_verify_rootfs(args: argparse.Namespace) -> int:
    target, _ = validate_manifests(args.target, args.matrix)
    verify_rootfs(target, args.artifact)
    print(f"rootfs verified: {target['target_id']} {args.artifact}")
    return 0


def command_compare(args: argparse.Namespace) -> int:
    target, _ = validate_manifests(args.target, args.matrix)
    reference = load_json(args.reference)
    kernal = load_json(args.kernal)
    report = compare_observations(reference, kernal, str(target["target_id"]))
    rendered = dump_json(report)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if report["mismatch_count"] else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate", help="validate pinned target and compatibility matrix"
    )
    validate.set_defaults(func=command_validate)

    verify = subparsers.add_parser(
        "verify-rootfs", help="verify the pinned Debian rootfs artifact"
    )
    verify.add_argument("artifact", type=Path)
    verify.set_defaults(func=command_verify_rootfs)

    compare = subparsers.add_parser(
        "compare", help="compare reference Debian and Kernal observations"
    )
    compare.add_argument("reference", type=Path)
    compare.add_argument("kernal", type=Path)
    compare.add_argument("--output", type=Path)
    compare.set_defaults(func=command_compare)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except OracleError as error:
        print(f"debian13-oracle: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
