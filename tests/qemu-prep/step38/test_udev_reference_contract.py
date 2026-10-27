#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step38/classify_udev_reference.py"
SPEC = importlib.util.spec_from_file_location("step38_udev", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COLLECTOR = ROOT / "tools/qemu-prep/step38/collect_udev_reference.sh"
POLICY = ROOT / "tests/qemu-prep/step38/hotplug_policy.json"


class Step38UdevReferenceContractTest(unittest.TestCase):
    def make_reference(self, root: Path, profile: str = "virtio-mmio-fast-path") -> None:
        devices = root / "devices"
        devices.mkdir()
        (root / "identity.txt").write_text(
            "schema=2\narch=aarch64\nkernel=6.12.0-arm64\npid1=systemd\n"
            "source_commit=" + "a" * 40 + "\n"
            "target_id=debian-13-trixie-arm64-20260712-2537\n"
            "target_sha256=" + "b" * 64 + "\n"
            f"transport_profile={profile}\nudev_test_requested=0\n",
            encoding="utf-8",
        )
        (root / "udev-service.stdout").write_text(
            "LoadState=loaded\nActiveState=active\nSubState=running\nFragmentPath=/usr/lib/systemd/system/systemd-udevd.service\n",
            encoding="utf-8",
        )
        (root / "udev-package.stdout").write_text("systemd-udev\t258-1\tarm64\n", encoding="utf-8")
        (root / "udev-journal-boot.stdout").write_text("systemd-udevd started\n", encoding="utf-8")
        (root / "udevadm-info-export-db.stdout").write_text("P: /devices/platform/virtio_mmio\n", encoding="utf-8")
        (root / "selected.txt").write_text("root_source=/dev/vda1\nnet_iface=eth0\n", encoding="utf-8")
        (devices / "root-vda1.stdout").write_text("DEVNAME=/dev/vda1\nID_BUS=virtio\n", encoding="utf-8")
        (devices / "net-properties.stdout").write_text("INTERFACE=eth0\nID_NET_DRIVER=virtio_net\n", encoding="utf-8")
        (devices / "ttyAMA0-properties.stdout").write_text("DEVNAME=/dev/ttyAMA0\n", encoding="utf-8")
        (devices / "root-uevent.txt").write_text("MAJOR=254\nMINOR=1\nDEVNAME=vda1\n", encoding="utf-8")
        (devices / "net-uevent.txt").write_text("INTERFACE=eth0\nIFINDEX=2\n", encoding="utf-8")
        (devices / "ttyAMA0-uevent.txt").write_text("MAJOR=204\nMINOR=64\nDEVNAME=ttyAMA0\n", encoding="utf-8")
        (devices / "root-node.stat").write_text("path=/dev/vda1 mode=660 uid=0 gid=6 type=block major=fe minor=1\n", encoding="utf-8")
        (devices / "_dev_console.stat").write_text("path=/dev/console mode=600 uid=0 gid=0 type=character major=5 minor=1\n", encoding="utf-8")
        (root / "SHA256SUMS").write_text("abcd  identity.txt\n", encoding="utf-8")

    def test_mmio_profile_does_not_invent_hotplug_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            result = MODULE.classify(root)
        self.assertFalse(result["hotplug_claim"]["block"])
        self.assertFalse(result["hotplug_claim"]["network"])
        self.assertFalse(result["hotplug_claim"]["requires_separate_live_hotplug_evidence"])
        self.assertIn("DEVNAME", result["selected_devices"]["uevent_fields"]["root"])

    def test_pci_profile_requires_separate_hotplug_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root, "virtio-pci-fallback")
            result = MODULE.classify(root)
        self.assertTrue(result["hotplug_claim"]["block"])
        self.assertTrue(result["hotplug_claim"]["network"])
        self.assertTrue(result["hotplug_claim"]["requires_separate_live_hotplug_evidence"])

    def test_collector_is_provenance_bound_and_udev_test_opt_in(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'reference guest must be Debian 13',
            'PID 1 is not systemd',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'KERNAL_STEP38_RUN_UDEV_TEST:-0',
            'KERNAL_REFERENCE_UDEV_TEST_CONFIRMED:-0',
            'journalctl -b -u systemd-udevd.service',
            'STEP38_UDEV_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)

    def test_hotplug_policy_has_one_nonclaiming_fast_path(self) -> None:
        data = json.loads(POLICY.read_text(encoding="utf-8"))
        fast = data["profiles"]["virtio-mmio-fast-path"]
        self.assertFalse(fast["block_hotplug_claimed"])
        self.assertFalse(fast["network_hotplug_claimed"])
        self.assertIn("boot-enumeration", fast["required_udev_lifecycle"])


if __name__ == "__main__":
    unittest.main()
