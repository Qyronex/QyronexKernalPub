#!/usr/bin/env python3
"""Classify Step-33 rootfs reference collector output into an integration decision.

This consumes only the read-only collector output. It never mounts, fscks or
modifies the reference filesystem.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TARGET_ID = "debian-13-trixie-arm64-20260712-2537"


def parse_kv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def read_status(directory: Path, prefix: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for path in sorted(directory.glob(prefix + "*.status")):
        try:
            result[path.stem] = int(path.read_text(encoding="utf-8").strip())
        except ValueError:
            result[path.stem] = -999
    return result


def classify(directory: Path) -> dict:
    selection_path = directory / "root-selection.txt"
    if not selection_path.is_file():
        raise ValueError("root-selection.txt missing")
    selection = parse_kv(selection_path)
    source = selection.get("root_source", "")
    real = selection.get("root_real", "")
    fstype = selection.get("root_fstype", "")
    if not source or not fstype:
        raise ValueError("root source/fstype missing from collector output")

    if fstype == "ext4":
        filesystem_decision = "EXT4_REFERENCE_CONFIRMED"
        integration_target = "ext4-compatible persistent root path"
    else:
        filesystem_decision = "REFERENCE_USES_NON_EXT4_REVIEW_REQUIRED"
        integration_target = f"reference filesystem {fstype}; owner must explicitly retain or choose ext4 after compatibility review"

    mounts = read_status(directory, "mountpoint-")
    mounted = sorted(name.removeprefix("mountpoint-") for name, status in mounts.items() if status == 0)
    not_mounted = sorted(name.removeprefix("mountpoint-") for name, status in mounts.items() if status != 0)

    return {
        "schema_version": 1,
        "step": 33,
        "target_id": TARGET_ID,
        "reference_root": {
            "source": source,
            "real_device": real or None,
            "fstype": fstype,
        },
        "filesystem_decision": filesystem_decision,
        "integration_target": integration_target,
        "observed_mountpoint_checks": {
            "mounted": mounted,
            "not_mounted_or_error": not_mounted,
        },
        "evidence_inputs": [
            "root-selection.txt",
            "proc-mounts.txt",
            "findmnt-root.stdout if present",
            "lsblk.stdout if present",
            "blkid.stdout if present",
            "ext4-tune2fs.stdout/ext4-dumpe2fs-header.stdout if present",
            "SHA256SUMS",
        ],
        "runtime_rule": "This classification selects reference requirements only; Step33 runtime still extends canonical block/VFS/filesystem owners and requires exact-SHA QEMU acceptance.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"step33-rootfs-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step33-rootfs-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step33-rootfs-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
