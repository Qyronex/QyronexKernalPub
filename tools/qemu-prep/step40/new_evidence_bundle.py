#!/usr/bin/env python3
"""Generate a pending Step-40 evidence bundle from the staged schema/target.

The generated document intentionally uses PENDING statuses so it can never pass
the strict completed-bundle validator until real runtime evidence fills it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = ROOT / "tests/qemu-prep/step40/final_acceptance_schema.json"
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    out = args.out.expanduser().resolve()
    if out.exists():
        print(f"step40-evidence-template: FAIL: refusing to overwrite {out}", file=sys.stderr)
        return 1
    try:
        schema = load(args.schema)
        target = load(args.target)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"step40-evidence-template: FAIL: {exc}", file=sys.stderr)
        return 1

    checks = [
        {
            "id": entry["id"],
            "status": "PENDING",
            "evidence": [],
            "owner_on_failure": entry.get("owner_on_failure"),
        }
        for entry in schema.get("checks", [])
        if entry.get("required") is True
    ]
    bundle = {
        "schema_version": 1,
        "profile_id": schema["profile_id"],
        "target_id": schema["target_id"],
        "bounded_claim": schema["bounded_claim"],
        "exact_identity": {
            "kernal_source_sha": "<40-char-lowercase-sha>",
            "debian_target_id": target["target_id"],
            "rootfs_sha512": target["rootfs"]["sha512"],
            "rootfs_sha256": target["rootfs"]["sha256"],
            "qemu_version": "<record-exact-qemu-version>",
            "complete_qemu_argv": [],
            "transport_block": "<virtio-mmio-or-explicit-fallback>",
            "transport_net": "<virtio-mmio-or-explicit-fallback>",
            "cpu_count": 0,
            "memory_bytes": 0,
        },
        "checks": checks,
        "repeat_boots": [],
        "generation_note": "Template only. PENDING values must be replaced by real exact-SHA runtime evidence; do not fabricate PASS markers.",
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"step40-evidence-template: PASS: pending template created at {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
