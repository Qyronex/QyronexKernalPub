#!/usr/bin/env python3
"""Validate PREP manifests and executable contracts for Steps 22-26."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EXPECTED_STEPS = range(22, 27)
REQUIRED_LIST_FIELDS = (
    "requirements",
    "fixtures",
    "canonical_owners_to_inspect",
    "runtime_only_gaps",
)
EXECUTABLE_PREP = (
    ("step22-vfs", "tools/prep/step22/validate_vfs_contract.py", "STEP22_VFS_PREP_OK cases=9"),
    ("step22-secure", "tools/prep/step22/validate_secure_volume_contract.py", "STEP22_SECURE_PREP_OK cases=10"),
    (
        "step22-secure-runtime-proof-harness",
        "tests/prep/step22/test_secure_storage_runtime_proof.py",
        "STEP22_SECURE_PROOF_HARNESS_OK cases=8",
    ),
    ("step23", "tools/prep/step23/validate_abi_ownership.py", "STEP23_PREP_OK surfaces=8"),
    ("step24", "tools/prep/step24/validate_stress_profiles.py", "STEP24_PREP_OK profiles=5 seed=240026"),
    ("step25", "tools/prep/step25/validate_security_prep.py", "STEP25_PREP_OK fuzz_surfaces=5 repro_identity="),
    ("step26", "tools/prep/step26/validate_hardware_matrix.py", "STEP26_PREP_OK platforms=1 planned=1 accepted=0"),
    ("scientific", "tools/prep/step22/validate_scientific_endpoints.py", "WAVE_B_SCIENTIFIC_ENDPOINTS_OK steps=22,23,24,25,26"),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def validate_manifest(step: int) -> None:
    path = repo_root() / "docs" / "prep" / f"step{step}" / "PREP_MANIFEST.json"
    if not path.is_file():
        raise SystemExit(f"missing manifest: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("step") != step:
        raise SystemExit(f"step mismatch in {path}: {data.get('step')!r}")
    if data.get("prep_state") not in {"PREP_OPEN", "PREP_ACTIVE", "PREP_READY", "PREP_RECONCILE"}:
        raise SystemExit(f"invalid prep_state in {path}")
    if data.get("runtime_state") not in {"RUNTIME_LOCKED", "RUNTIME_ACTIVE", "ACCEPTANCE", "ACCEPTED"}:
        raise SystemExit(f"invalid runtime_state in {path}")
    if data.get("production_write_allowed") is not False:
        raise SystemExit(f"PREP manifest must keep production_write_allowed=false: {path}")
    if not data.get("name") or not data.get("branch") or not data.get("acceptance_intent"):
        raise SystemExit(f"missing identity/acceptance fields in {path}")

    for field in REQUIRED_LIST_FIELDS:
        value = data.get(field)
        if not isinstance(value, list) or not value:
            raise SystemExit(f"{field} must be a non-empty list in {path}")


def validate_executable_contract(relative_path: str, marker: str) -> None:
    root = repo_root()
    path = root / relative_path
    if not path.is_file():
        raise SystemExit(f"missing executable PREP validator: {path}")
    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stdout)
    if marker not in result.stdout:
        raise SystemExit(f"missing validator marker {marker!r}: {result.stdout}")
    # Preserve the child validator's evidence markers in the aggregate output.
    # The paired regression wrapper intentionally verifies these markers so a
    # sub-validator cannot silently disappear behind the final wave marker.
    sys.stdout.write(result.stdout)


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_manifest(step)
    for _step, validator, marker in EXECUTABLE_PREP:
        validate_executable_contract(validator, marker)
    print("PREP_WAVE_B_OK steps=22,23,24,25,26")


if __name__ == "__main__":
    main()
