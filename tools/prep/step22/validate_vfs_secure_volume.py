#!/usr/bin/env python3
"""Compatibility entrypoint for the split Step-22 PREP proof tracks.

Historically this file fused VFS compatibility and secure-volume policy into one
oracle. The authoritative PREP now runs both contracts independently so a VFS
semantic failure cannot be confused with a storage-protection failure.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATORS = (
    (ROOT / "tools/prep/step22/validate_vfs_contract.py", "STEP22_VFS_PREP_OK cases=9"),
    (ROOT / "tools/prep/step22/validate_secure_volume_contract.py", "STEP22_SECURE_PREP_OK cases=10"),
)


def main() -> None:
    outputs: list[str] = []
    for validator, marker in VALIDATORS:
        result = subprocess.run(
            [sys.executable, str(validator)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode != 0:
            raise SystemExit(result.stdout)
        if marker not in result.stdout:
            raise SystemExit(f"missing marker {marker!r}: {result.stdout}")
        outputs.append(result.stdout.strip())
    for output in outputs:
        print(output)
    print("STEP22_PREP_OK tracks=VFS_COMPAT,SECURE_STORAGE")


if __name__ == "__main__":
    main()
