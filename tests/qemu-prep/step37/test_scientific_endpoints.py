#!/usr/bin/env python3
"""Regression wrapper for Wave-E scientific endpoint contracts."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools/qemu-prep/step37/validate_scientific_endpoints.py"

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
marker = "WAVE_E_SCIENTIFIC_ENDPOINTS_OK steps=37,38,39,40"
if marker not in result.stdout:
    raise SystemExit(f"missing success marker: {result.stdout}")
print("WAVE_E_SCIENTIFIC_ENDPOINTS_TEST_OK")
