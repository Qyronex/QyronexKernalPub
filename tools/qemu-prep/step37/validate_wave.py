#!/usr/bin/env python3
"""Validate the complete Step 37-40 PREP handoff wave.

This is a host-side PREP gate. It validates only artifacts owned by
prep-wave-e-37-40 and never claims runtime acceptance.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STEPS = range(37, 41)
SNAPSHOT = "7b8cd67ce5d5c3243cf64a843454b28750a180d0"

REQUIRED_BY_STEP = {
    37: (
        "docs/debian13/qemu-prep/step37/PREP_MANIFEST.md",
        "docs/debian13/qemu-prep/step37/WAVE_E_WORK_QUEUE.md",
        "tests/qemu-prep/step37/systemd_pid1_boot_markers.json",
        "tools/qemu-prep/step37/collect_pid1_reference.sh",
    ),
    38: (
        "docs/debian13/qemu-prep/step38/PREP_MANIFEST.md",
        "tests/qemu-prep/step38/udev_device_expectations.json",
        "tools/qemu-prep/step38/collect_udev_reference.sh",
    ),
    39: (
        "docs/debian13/qemu-prep/step39/PREP_MANIFEST.md",
        "tests/qemu-prep/step39/lock_probe.c",
        "tests/qemu-prep/step39/package_transaction_plan.json",
        "tools/qemu-prep/step39/build_run_lock_probe.sh",
        "tools/qemu-prep/step39/pin_package.py",
        "tools/qemu-prep/step39/run_reference_transaction.sh",
        "tools/qemu-prep/step39/write_snapshot_sources.py",
    ),
    40: (
        "docs/debian13/qemu-prep/step40/PREP_MANIFEST.md",
        "docs/debian13/qemu-prep/step40/EXECUTION_HANDOFF.md",
        "tests/qemu-prep/step40/final_acceptance_schema.json",
        "tests/qemu-prep/step40/qemu_argv_contract.json",
        "tests/qemu-prep/step40/serial_marker_contract.json",
        "tools/qemu-prep/step40/check_host_forward.py",
        "tools/qemu-prep/step40/extract_serial_markers.py",
        "tools/qemu-prep/step40/new_evidence_bundle.py",
        "tools/qemu-prep/step40/validate_final_evidence.py",
        "tools/qemu-prep/step40/validate_final_evidence_bundle.py",
    ),
}

COMMON_MANIFEST_HEADINGS = (
    "## Runtime target",
    "## Dependency release condition",
    "## Prepared artifacts",
    "## Canonical owners to consume",
    "## Forbidden duplicates",
    "## Acceptance probes",
)


def fail(message: str) -> int:
    print(f"prep-wave-e: FAIL: {message}", file=sys.stderr)
    return 1


def check_json(path: Path) -> None:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON {path.relative_to(ROOT)}: {exc}") from exc


def check_shell(path: Path) -> None:
    completed = subprocess.run(
        ["bash", "-n", str(path)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or f"exit={completed.returncode}"
        raise RuntimeError(f"shell syntax failed {path.relative_to(ROOT)}: {detail}")


def check_manifest(step: int) -> None:
    path = ROOT / f"docs/debian13/qemu-prep/step{step}/PREP_MANIFEST.md"
    text = path.read_text(encoding="utf-8")
    if f"# PREP manifest — Step {step}" not in text:
        raise RuntimeError(f"Step {step} manifest title mismatch")
    if "Status: `PREP_IN_PROGRESS`" not in text and "Status: `PREP_READY`" not in text:
        raise RuntimeError(f"Step {step} manifest has no valid PREP state")
    for heading in COMMON_MANIFEST_HEADINGS:
        if heading not in text:
            raise RuntimeError(f"Step {step} manifest missing heading: {heading}")
    landing_heading = "## Final proof order" if step == 40 else "## Integration landing order"
    if landing_heading not in text:
        raise RuntimeError(f"Step {step} manifest missing heading: {landing_heading}")
    if step == 40 and "## Failure routing" not in text:
        raise RuntimeError("Step 40 manifest missing explicit failure routing")


def main() -> int:
    try:
        for step in STEPS:
            for relative in REQUIRED_BY_STEP[step]:
                path = ROOT / relative
                if not path.is_file() or path.stat().st_size == 0:
                    raise RuntimeError(f"required Step {step} artifact missing/empty: {relative}")
            check_manifest(step)

        queue = ROOT / "docs/debian13/qemu-prep/step37/WAVE_E_WORK_QUEUE.md"
        queue_text = queue.read_text(encoding="utf-8")
        for fragment in (
            "prep-wave-e-37-40",
            "Steps 37–40",
            SNAPSHOT,
            "PREP_READY",
            "Do not edit production `kernel/**`",
        ):
            if fragment not in queue_text:
                raise RuntimeError(f"Wave-E queue missing contract fragment: {fragment}")

        json_files: list[Path] = []
        shell_files: list[Path] = []
        for step in STEPS:
            json_files.extend(sorted((ROOT / f"tests/qemu-prep/step{step}").glob("*.json")))
            shell_files.extend(sorted((ROOT / f"tools/qemu-prep/step{step}").glob("*.sh")))
        if not json_files:
            raise RuntimeError("Wave E contains no machine-readable JSON fixtures")
        if not shell_files:
            raise RuntimeError("Wave E contains no executable shell helpers")
        for path in json_files:
            check_json(path)
        for path in shell_files:
            check_shell(path)

    except (OSError, RuntimeError) as exc:
        return fail(str(exc))

    print(
        "prep-wave-e: PASS: Steps 37-40 manifests, fixtures, JSON and shell helpers are internally valid"
    )
    print("prep-wave-e: NOTE: PREP evidence only; runtime Steps 37-40 remain dependency-gated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
