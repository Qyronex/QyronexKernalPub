#!/usr/bin/env python3
"""Validate the coordinator-v4 QEMU/Debian PREP control lane.

Step-local PREP for 32-36 and 37-40 is owned by the dedicated Wave-D/Wave-E
branches.  This gate therefore validates only cross-step control metadata,
queue structure and ownership separation.  It is PREP evidence, never runtime
acceptance.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/debian13/qemu-prep"

REQUIRED_FILES = (
    ROOT / "QEMU_BOOT_PREP_INDEX.md",
    ROOT / "PREP_MANIFEST_TEMPLATE.md",
    DOCS / "00_CURRENT_EXECUTABLE_PREP.md",
    DOCS / "00_READ_FIRST.json",
    DOCS / "ARTIFACT_CATALOG.json",
    DOCS / "ARTIFACT_CATALOG_SUPPLEMENT.json",
    DOCS / "EXECUTABLE_FIXTURE_INDEX.md",
    DOCS / "INTEGRATION_LANDING_MAP.md",
    DOCS / "ORACLE_RUNNER_HANDOFF.md",
    DOCS / "PREP_COMPLETION_MATRIX.json",
    DOCS / "PREP_STATUS.json",
    DOCS / "PREP_WORK_QUEUE.json",
    DOCS / "QEMU_BOOT_PROFILE.json",
    DOCS / "REFERENCE_REQUIREMENT_MAP.md",
    DOCS / "REFERENCE_EXPANSION_PLAN.json",
    ROOT / "tests/qemu-prep/reference-cases-expanded.json",
)

STEP_LOCAL_SCOPE_PREFIXES = (
    "docs/debian13/qemu-prep",
    "tools/qemu-prep",
    "tests/qemu-prep",
)


def fail(message: str) -> int:
    print(f"qemu-prep-control: FAIL: {message}", file=sys.stderr)
    return 1


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON {path.relative_to(ROOT)}: {exc}") from exc


def require_contract(body: str, fragment: str) -> None:
    if fragment not in body:
        raise RuntimeError(f"AGENT_TASKS coordinator v4 missing: {fragment}")


def main() -> int:
    try:
        for path in REQUIRED_FILES:
            if not path.is_file():
                raise RuntimeError(f"required control artifact missing: {path.relative_to(ROOT)}")

        board = (ROOT / "AGENT_TASKS.md").read_text(encoding="utf-8")
        for fragment in (
            "version=4",
            "idle_worker_policy=claim-active-prep-by-priority",
            "max_source_workers=8",
            "lane=qemu-boot-prep-wave|agent/qemu-prep-roadmap-arm64|ACTIVE|source-worker|none",
            "lane=prep-wave-d-32-36|agent/prep-wave-d-32-36-arm64|ACTIVE|source-worker|none",
            "lane=prep-wave-e-37-40|agent/prep-wave-e-37-40-arm64|ACTIVE|source-worker|none",
            "gates=qemu-boot-prep-wave|shell-check",
            "gates=prep-wave-d-32-36|shell-check",
            "gates=prep-wave-e-37-40|shell-check",
        ):
            require_contract(board, fragment)

        control_scope = next(
            (
                line
                for line in board.splitlines()
                if line.startswith("scope=qemu-boot-prep-wave|branch-diff|")
            ),
            "",
        )
        if not control_scope:
            raise RuntimeError(
                "AGENT_TASKS coordinator v4 missing qemu-boot-prep-wave scope"
            )
        for step in range(32, 41):
            for prefix in STEP_LOCAL_SCOPE_PREFIXES:
                forbidden = f"{prefix}/step{step}/**"
                if forbidden in control_scope:
                    raise RuntimeError(
                        "qemu control WRITE scope claims step-local path: "
                        f"{forbidden}"
                    )

        queue = load_json(DOCS / "PREP_WORK_QUEUE.json")
        if not isinstance(queue, dict):
            raise RuntimeError("PREP_WORK_QUEUE.json must be an object")
        if int(queue.get("schema_version", 0)) < 3:
            raise RuntimeError("PREP_WORK_QUEUE schema must be >= 3")
        if int(queue.get("wip_limit", 0)) < 3:
            raise RuntimeError("PREP_WORK_QUEUE wip_limit must permit parallel v4 PREP")
        lanes = {
            item.get("lane")
            for item in queue.get("parallel_lanes", [])
            if isinstance(item, dict)
        }
        required_lanes = {
            "qemu-boot-prep-wave",
            "prep-wave-d-32-36",
            "prep-wave-e-37-40",
        }
        missing = required_lanes - lanes
        if missing:
            raise RuntimeError(f"PREP_WORK_QUEUE missing parallel lanes: {sorted(missing)}")

        status = load_json(DOCS / "PREP_STATUS.json")
        completion = load_json(DOCS / "PREP_COMPLETION_MATRIX.json")
        profile = load_json(DOCS / "QEMU_BOOT_PROFILE.json")
        expansion = load_json(DOCS / "REFERENCE_EXPANSION_PLAN.json")
        cases = load_json(ROOT / "tests/qemu-prep/reference-cases-expanded.json")
        for name, value in (
            ("PREP_STATUS", status),
            ("PREP_COMPLETION_MATRIX", completion),
            ("QEMU_BOOT_PROFILE", profile),
            ("REFERENCE_EXPANSION_PLAN", expansion),
            ("reference-cases-expanded", cases),
        ):
            if not isinstance(value, (dict, list)):
                raise RuntimeError(f"{name} must decode to object/list")

    except (OSError, RuntimeError, ValueError) as exc:
        return fail(str(exc))

    print("qemu-prep-control: PASS: coordinator-v4 control metadata and lane separation are consistent")
    print("qemu-prep-control: NOTE: Step 32-40 artifacts live on Wave-D/Wave-E; runtime remains dependency-gated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
