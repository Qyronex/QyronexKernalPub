#!/usr/bin/env python3
"""Validate PREP manifests and executable contracts for Steps 17-21."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EXPECTED_STEPS = range(17, 22)
REQUIRED_LIST_FIELDS = (
    "requirements",
    "fixtures",
    "canonical_owners_to_inspect",
    "runtime_only_gaps",
)
EXECUTABLE_PREP = (
    ("step17", "tools/prep/step17/validate_pcie_contract.py", "STEP17_PREP_OK cases=10"),
    ("step18", "tools/prep/step18/validate_irq_routing_contract.py", "STEP18_PREP_OK cases=10"),
    ("step19", "tools/prep/step19/validate_iommu_dma_contract.py", "STEP19_PREP_OK cases=11"),
    ("step20", "tools/prep/step20/validate_virtio_block_contract.py", "STEP20_PREP_OK cases=12"),
    ("step21", "tools/prep/step21/validate_virtio_net_contract.py", "STEP21_PREP_OK cases=14"),
    ("scientific", "tools/prep/step17/validate_scientific_endpoints.py", "WAVE_A_SCIENTIFIC_ENDPOINTS_OK steps=17,18,19,20,21"),
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


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_manifest(step)
    for _step, validator, marker in EXECUTABLE_PREP:
        validate_executable_contract(validator, marker)
    print("PREP_WAVE_A_OK steps=17,18,19,20,21")


if __name__ == "__main__":
    main()
