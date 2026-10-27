#!/usr/bin/env python3
"""Validate the complete Step 32-36 PREP handoff wave.

This is a host-side PREP gate. It validates only artifacts owned by
prep-wave-d-32-36 and never claims runtime acceptance.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STEPS = range(32, 37)
SNAPSHOT = "7b8cd67ce5d5c3243cf64a843454b28750a180d0"

REQUIRED_BY_STEP = {
    32: (
        "docs/debian13/qemu-prep/step32/PREP_MANIFEST.md",
        "docs/debian13/qemu-prep/step32/WAVE_D_WORK_QUEUE.md",
        "tests/qemu-prep/step32/pty_probe.c",
        "tests/qemu-prep/step32/tty_pty_reference_vectors.json",
        "tools/qemu-prep/step32/build_run_pty_probe.sh",
    ),
    33: (
        "docs/debian13/qemu-prep/step33/PREP_MANIFEST.md",
        "tests/qemu-prep/step33/filesystem_probe.c",
        "tests/qemu-prep/step33/rw_root_reference_vectors.json",
        "tests/qemu-prep/step33/virtio_mmio_block_profile.json",
        "tools/qemu-prep/step33/build_run_filesystem_probe.sh",
        "tools/qemu-prep/step33/classify_rootfs_reference.py",
        "tools/qemu-prep/step33/collect_rootfs_reference.sh",
    ),
    34: (
        "docs/debian13/qemu-prep/step34/PREP_MANIFEST.md",
        "tests/qemu-prep/step34/network_probe.c",
        "tests/qemu-prep/step34/network_reference_topology.json",
        "tools/qemu-prep/step34/build_run_network_probe.sh",
        "tools/qemu-prep/step34/classify_network_reference.py",
        "tools/qemu-prep/step34/collect_network_reference.sh",
        "tools/qemu-prep/step34/host_endpoints.py",
    ),
    35: (
        "docs/debian13/qemu-prep/step35/PREP_MANIFEST.md",
        "tests/qemu-prep/step35/event_fd_probe.c",
        "tests/qemu-prep/step35/event_fd_reference_vectors.json",
        "tools/qemu-prep/step35/build_run_event_probe.sh",
    ),
    36: (
        "docs/debian13/qemu-prep/step36/PREP_MANIFEST.md",
        "tests/qemu-prep/step36/systemd_feature_classification.json",
        "tools/qemu-prep/step36/collect_systemd_feature_reference.sh",
        "tools/qemu-prep/step36/collect_systemd_feature_reference_strict.sh",
    ),
}

MANIFEST_HEADINGS = (
    "## Runtime target",
    "## Dependency release condition",
    "## Prepared artifacts",
    "## Canonical owners to consume",
    "## Forbidden duplicates",
    "## Integration landing order",
    "## Acceptance probes",
)


def fail(message: str) -> int:
    print(f"prep-wave-d: FAIL: {message}", file=sys.stderr)
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
    for heading in MANIFEST_HEADINGS:
        if heading not in text:
            raise RuntimeError(f"Step {step} manifest missing heading: {heading}")


def main() -> int:
    try:
        for step in STEPS:
            for relative in REQUIRED_BY_STEP[step]:
                path = ROOT / relative
                if not path.is_file() or path.stat().st_size == 0:
                    raise RuntimeError(f"required Step {step} artifact missing/empty: {relative}")
            check_manifest(step)

        queue = ROOT / "docs/debian13/qemu-prep/step32/WAVE_D_WORK_QUEUE.md"
        queue_text = queue.read_text(encoding="utf-8")
        for fragment in (
            "prep-wave-d-32-36",
            "Steps 32–36",
            SNAPSHOT,
            "PREP_READY",
            "Do not edit production `kernel/**`",
        ):
            if fragment not in queue_text:
                raise RuntimeError(f"Wave-D queue missing contract fragment: {fragment}")

        json_files: list[Path] = []
        shell_files: list[Path] = []
        for step in STEPS:
            json_files.extend(sorted((ROOT / f"tests/qemu-prep/step{step}").glob("*.json")))
            shell_files.extend(sorted((ROOT / f"tools/qemu-prep/step{step}").glob("*.sh")))
        if not json_files:
            raise RuntimeError("Wave D contains no machine-readable JSON fixtures")
        if not shell_files:
            raise RuntimeError("Wave D contains no executable shell helpers")
        for path in json_files:
            check_json(path)
        for path in shell_files:
            check_shell(path)

    except (OSError, RuntimeError) as exc:
        return fail(str(exc))

    print(
        "prep-wave-d: PASS: Steps 32-36 manifests, fixtures, JSON and shell helpers are internally valid"
    )
    print("prep-wave-d: NOTE: PREP evidence only; runtime Steps 32-36 remain dependency-gated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
