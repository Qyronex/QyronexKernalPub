#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIFECYCLE = ROOT / "tools/qemu-prep/step37/exercise_service_lifecycle.sh"
SHUTDOWN = ROOT / "tools/qemu-prep/step37/trigger_shutdown_reference.sh"


class Step37LifecycleShutdownContractTest(unittest.TestCase):
    def test_lifecycle_requires_frozen_reference_and_console_confirmation(self) -> None:
        text = LIFECYCLE.read_text(encoding="utf-8")
        for fragment in (
            'KERNAL_REFERENCE_SERVICE_LIFECYCLE_CONFIRMED:-0',
            'KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED:-0',
            "FROZEN_THREE_SERVICES",
            "reference source_commit does not match current checkout",
            'trap restore_services EXIT INT TERM',
            'systemctl restart "$unit"',
            'systemctl stop "$unit"',
            'systemctl start "$unit"',
            'STEP37_SERVICE_LIFECYCLE_OK',
        ):
            self.assertIn(fragment, text)

    def test_lifecycle_restores_services_on_failure(self) -> None:
        text = LIFECYCLE.read_text(encoding="utf-8")
        trap_index = text.index("trap restore_services EXIT INT TERM")
        restart_index = text.index('systemctl restart "$unit"')
        self.assertLess(trap_index, restart_index)

    def test_shutdown_trigger_is_exact_source_target_bound_and_opt_in(self) -> None:
        text = SHUTDOWN.read_text(encoding="utf-8")
        for fragment in (
            'case "$MODE" in reboot|poweroff)',
            'KERNAL_REFERENCE_SHUTDOWN_CONFIRMED:-0',
            'KERNAL_REFERENCE_CONSOLE_SESSION_CONFIRMED:-0',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'STEP37_SHUTDOWN_TRIGGER mode=%s source_commit=%s target_id=%s',
            'host/QEMU harness must confirm',
            'exec systemctl "$MODE" --no-wall',
        ):
            self.assertIn(fragment, text)

    def test_shutdown_marker_is_synced_before_systemd_request(self) -> None:
        text = SHUTDOWN.read_text(encoding="utf-8")
        sync_index = text.index('sync "$MARKER" "$MARKER.sha256"')
        systemctl_index = text.index('exec systemctl "$MODE" --no-wall')
        self.assertLess(sync_index, systemctl_index)


if __name__ == "__main__":
    unittest.main()
