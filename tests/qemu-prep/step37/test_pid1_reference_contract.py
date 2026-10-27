#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step37/classify_pid1_reference.py"
SPEC = importlib.util.spec_from_file_location("step37_pid1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COLLECTOR = ROOT / "tools/qemu-prep/step37/collect_pid1_reference.sh"


def write_service(root: Path, unit: str, package: str, *, active: bool = True) -> None:
    safe = MODULE.safe_unit(unit)
    services = root / "services"
    services.mkdir(exist_ok=True)
    (services / f"{safe}.stdout").write_text(
        f"Id={unit}\nLoadState=loaded\nActiveState={'active' if active else 'inactive'}\n"
        "SubState=running\nUnitFileState=enabled\n"
        f"FragmentPath=/usr/lib/systemd/system/{unit}\nControlGroup=/system.slice/{unit}\n"
        "CanStart=yes\nCanStop=yes\nRefuseManualStart=no\nRefuseManualStop=no\n",
        encoding="utf-8",
    )
    (services / f"{safe}.package.stdout").write_text(
        f"{package}\t1.2.3-1\tarm64\n", encoding="utf-8"
    )


class Step37Pid1ReferenceContractTest(unittest.TestCase):
    def make_reference(self, root: Path) -> None:
        (root / "identity.txt").write_text(
            "schema=2\narch=aarch64\nkernel=6.12.0-arm64\n"
            "pid1_comm=systemd\npid1_exe=/usr/lib/systemd/systemd\n"
            "source_commit=" + "a" * 40 + "\n"
            "target_id=debian-13-trixie-arm64-20260712-2537\n"
            "target_sha256=" + "b" * 64 + "\n"
            "failure_probe_requested=1\n",
            encoding="utf-8",
        )
        candidates = ["ssh.service", "cron.service", "systemd-timesyncd.service", "dbus.service"]
        (root / "service-candidates.txt").write_text("\n".join(candidates) + "\n", encoding="utf-8")
        write_service(root, "ssh.service", "openssh-server")
        write_service(root, "cron.service", "cron")
        write_service(root, "systemd-timesyncd.service", "systemd-timesyncd")
        write_service(root, "dbus.service", "dbus")
        (root / "systemctl-is-system-running.status").write_text("0\n", encoding="utf-8")
        (root / "systemctl-is-system-running.stdout").write_text("running\n", encoding="utf-8")
        (root / "systemctl-get-default.stdout").write_text("multi-user.target\n", encoding="utf-8")
        (root / "systemctl-list-failed.stdout").write_text("", encoding="utf-8")
        (root / "default-target-dependencies.stdout").write_text("multi-user.target\n", encoding="utf-8")
        (root / "systemd-analyze-critical-chain.stdout").write_text("graphical.target @1s\n", encoding="utf-8")
        (root / "systemd-analyze-critical-chain-default.stdout").write_text("multi-user.target @1s\n", encoding="utf-8")
        (root / "failure-probe-run.status").write_text("1\n", encoding="utf-8")
        (root / "failure-probe-status.status").write_text("3\n", encoding="utf-8")
        (root / "failure-probe-journal.status").write_text("0\n", encoding="utf-8")
        (root / "failure-probe-reset.status").write_text("0\n", encoding="utf-8")
        (root / "SHA256SUMS").write_text("abcd  identity.txt\n", encoding="utf-8")

    def test_freezes_exactly_three_eligible_ordinary_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            selected = ["ssh.service", "cron.service", "systemd-timesyncd.service"]
            result = MODULE.classify(root, selected)
        self.assertEqual(result["services"]["selection_state"], "FROZEN_THREE_SERVICES")
        self.assertEqual(result["services"]["frozen_three"], selected)
        self.assertNotIn("dbus.service", result["services"]["eligible_ordinary_services"])
        self.assertTrue(result["boot_order_evidence"]["default_target_dependencies_present"])

    def test_rejects_critical_service_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            with self.assertRaisesRegex(ValueError, "not eligible ordinary services"):
                MODULE.classify(root, ["ssh.service", "cron.service", "dbus.service"])

    def test_rejects_less_than_three_frozen_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            with self.assertRaisesRegex(ValueError, "exactly three unique units"):
                MODULE.classify(root, ["ssh.service", "cron.service"])

    def test_collector_is_provenance_bound_and_failure_probe_opt_in(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'reference guest must be Debian 13',
            'PID 1 is not systemd',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'KERNAL_STEP37_RUN_FAILURE_PROBE:-0',
            'KERNAL_REFERENCE_FAILURE_PROBE_CONFIRMED:-0',
            'dpkg-query -S "$fragment"',
            'STEP37_PID1_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
