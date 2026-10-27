#!/usr/bin/env python3

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/debian13/run-reference-qemu-macos.sh"


class ReferenceRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RUNNER.read_text(encoding="utf-8")

    def test_default_runtime_budget_is_35_minutes(self) -> None:
        self.assertIn(
            'TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_TIMEOUT_SECONDS:-1200}"',
            self.source,
        )
        self.assertIn(
            'FETCH_TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_FETCH_TIMEOUT_SECONDS:-600}"',
            self.source,
        )
        self.assertIn(
            'TOTAL_TIMEOUT_SECONDS="${KERNAL_DEBIAN13_REFERENCE_TOTAL_TIMEOUT_SECONDS:-$((TIMEOUT_SECONDS + FETCH_TIMEOUT_SECONDS + 300))}"',
            self.source,
        )

    def test_progress_and_persistent_diagnostics_are_enabled(self) -> None:
        self.assertIn(
            'PROGRESS_INTERVAL_SECONDS="${KERNAL_DEBIAN13_REFERENCE_PROGRESS_INTERVAL_SECONDS:-60}"',
            self.source,
        )
        self.assertIn(
            'LOG_DIR="${KERNAL_DEBIAN13_REFERENCE_LOG_DIR:-$CACHE_DIR/logs}"',
            self.source,
        )
        self.assertIn('log "phase=fetch start"', self.source)
        self.assertIn('log "phase=qemu start', self.source)
        self.assertIn('log "phase=qemu progress', self.source)
        self.assertIn('log "phase=validation start"', self.source)
        self.assertIn('log "phase=shutdown complete"', self.source)
        self.assertIn('QEMU_LOG="$RUN_LOG_DIR/qemu.log"', self.source)
        self.assertIn('SERVER_LOG="$RUN_LOG_DIR/server.log"', self.source)

    def test_progress_interval_is_bounded(self) -> None:
        self.assertRegex(
            self.source,
            re.compile(
                r'\[ "\$PROGRESS_INTERVAL_SECONDS" -ge 15 \] \|\| '
                r"\{ printf 'reference progress interval must be at least 15 seconds"
            ),
        )

    def test_outer_watchdog_still_terminates_the_process_group(self) -> None:
        self.assertIn("start_new_session=True", self.source)
        self.assertIn("os.killpg(proc.pid, first_signal)", self.source)
        self.assertIn("os.killpg(proc.pid, signal.SIGKILL)", self.source)


if __name__ == "__main__":
    unittest.main()
