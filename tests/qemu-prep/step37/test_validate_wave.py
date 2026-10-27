#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools/qemu-prep/step37/validate_wave.py"


class WaveEValidatorTest(unittest.TestCase):
    def test_validator_passes_without_mutation(self) -> None:
        before = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        completed = subprocess.run(
            [sys.executable, "-B", str(VALIDATOR)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        after = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertEqual(before, after, "Wave-E validation mutated the worktree")
        self.assertIn("prep-wave-e: PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
