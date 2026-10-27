#!/usr/bin/env python3
"""Regression wrapper for the Step 17-21 PREP manifest validator."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools" / "prep" / "step17" / "validate_wave.py"

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
if "PREP_WAVE_A_OK steps=17,18,19,20,21" not in result.stdout:
    raise SystemExit(f"missing success marker: {result.stdout}")
print("PREP_WAVE_A_TEST_OK")
