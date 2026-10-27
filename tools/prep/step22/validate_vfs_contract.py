#!/usr/bin/env python3
"""Validate the Step-22 VFS/mount compatibility contract.

This PREP validator intentionally does not decide the storage-crypto policy. The
separate secure-volume validator proves the protected persistent-volume boundary.
Complete Step-22 acceptance requires both tracks plus runtime evidence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path, PurePosixPath

OPS = {"read", "write", "rename"}


def path_escapes(path: str) -> bool:
    return ".." in PurePosixPath(path).parts


def evaluate(case: dict) -> str:
    if case.get("operation") not in OPS:
        return "reject"
    if case.get("namespace") != case.get("handle_namespace"):
        return "reject"
    if case.get("volume_generation") != case.get("expected_generation"):
        return "reject"
    path = case.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path_escapes(path):
        return "reject"
    hops = case.get("symlink_hops")
    if not isinstance(hops, int) or hops < 0 or hops > 40:
        return "reject"
    if case.get("cross_mount_rename", False):
        return "reject"
    if case.get("operation") == "write" and case.get("read_only", False):
        return "reject"
    return "accept"


def main() -> None:
    path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[3] / "tests/prep/step22/vfs_mount_cases.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("track") != "VFS_COMPAT" or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step22 VFS corpus schema")
    seen: set[str] = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {
        "mount-read-ok",
        "mount-write-ok",
        "stale-volume-generation",
        "cross-namespace-handle",
        "dotdot-escape",
        "symlink-loop",
        "same-mount-rename",
        "cross-mount-rename",
        "write-readonly-mount",
    }
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step22 VFS cases: {missing}")
    print(f"STEP22_VFS_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
