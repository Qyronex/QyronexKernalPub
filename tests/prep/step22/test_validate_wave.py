#!/usr/bin/env python3
"""Regression wrapper for the Step 22-26 PREP manifest validator."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools" / "prep" / "step22" / "validate_wave.py"

result = subprocess.run(
    [sys.executable, str(VALIDATOR)],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)
if result.returncode != 0:
    raise SystemExit(result.stdout)
required_markers = (
    "STEP22_VFS_PREP_OK cases=9",
    "STEP22_SECURE_PREP_OK cases=10",
    "PREP_WAVE_B_OK steps=22,23,24,25,26",
)
missing = [marker for marker in required_markers if marker not in result.stdout]
if missing:
    raise SystemExit(f"missing success markers {missing}: {result.stdout}")
print("PREP_WAVE_B_TEST_OK")
