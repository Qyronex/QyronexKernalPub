#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step36/classify_systemd_feature_reference.py"
SPEC = importlib.util.spec_from_file_location("step36_reference", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STRICT = ROOT / "tools/qemu-prep/step36/collect_systemd_feature_reference_strict.sh"
LEGACY = ROOT / "tools/qemu-prep/step36/collect_systemd_feature_reference.sh"
RESOURCE = ROOT / "tests/qemu-prep/step36/resource_enforcement_probe.py"


def security_probe_text() -> str:
    return "\n".join(
        [
            "INFO security.prctl_get_securebits state=success value=0",
            "INFO security.prctl_get_no_new_privs state=success value=0",
            "INFO security.prctl_get_seccomp state=success value=0",
            "INFO security.prctl_capbset_read_sys_admin state=success value=1",
            "INFO security.seccomp_get_action_avail state=success value=0",
            "INFO security.keyctl_get_process_keyring state=error errno=126 name=Required-key-not-available",
            "INFO security.audit_netlink_socket state=success value=3",
            "INFO security.bpf_prog_get_next_id state=error errno=1 name=Operation-not-permitted",
            "INFO namespace.mnt state=present inode=1",
            "PASS step36.security-api-probe.complete",
            "",
        ]
    )


class Step36ReferenceContractTest(unittest.TestCase):
    def make_reference(self, root: Path, *, enforcement: str = "0") -> None:
        (root / "identity.txt").write_text(
            "schema=2\narch=aarch64\npid1=systemd\nkernel=6.12.0-arm64\n"
            "source_commit=" + "a" * 40 + "\n"
            "target_id=debian-13-trixie-arm64-20260712-2537\n"
            "target_sha256=" + "b" * 64 + "\n"
            f"enforcement_requested={enforcement}\n",
            encoding="utf-8",
        )
        (root / "proc-1-status.txt").write_text(
            "CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n"
            "CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n"
            "CapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n",
            encoding="utf-8",
        )
        (root / "proc-1-cgroup.txt").write_text("0::/init.scope\n", encoding="utf-8")
        (root / "_sys_fs_cgroup_cgroup.controllers.txt").write_text(
            "cpuset cpu io memory hugetlb pids rdma misc\n", encoding="utf-8"
        )
        (root / "selected-units.txt").write_text("dbus.service\n", encoding="utf-8")
        (root / "unit-dbus_service.stdout").write_text(
            "LoadState=loaded\nActiveState=active\nControlGroup=/system.slice/dbus.service\n"
            "PrivateTmp=yes\nPrivateDevices=no\nPrivateNetwork=no\nPrivateUsers=no\n"
            "PrivateMounts=no\nProtectSystem=no\nProtectHome=no\nRestrictNamespaces=\n"
            "NoNewPrivileges=no\n",
            encoding="utf-8",
        )
        (root / "security-api-probe.status").write_text("0\n", encoding="utf-8")
        (root / "security-api-probe.stdout").write_text(security_probe_text(), encoding="utf-8")

    def test_classifies_namespaces_cgroups_and_security(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            result = MODULE.classify(root)
        self.assertIn("memory", result["cgroup_v2"]["root_controllers"])
        self.assertEqual(
            result["namespace_requirements"]["inferred_from_selected_unit_properties"]["dbus.service"],
            ["mnt"],
        )
        self.assertEqual(
            result["linux_security_view"]["probe_results"]["bpf_prog_get_next_id"]["errno"], 1
        )
        self.assertEqual(result["cgroup_v2"]["enforcement"]["state"], "SKIPPED")

    def test_rejects_incomplete_security_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            text = (root / "security-api-probe.stdout").read_text(encoding="utf-8")
            (root / "security-api-probe.stdout").write_text(
                text.replace("INFO security.bpf_prog_get_next_id state=error errno=1 name=Operation-not-permitted\n", ""),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing security probe observations"):
                MODULE.classify(root)

    def test_strict_collector_is_provenance_bound_and_enforcement_opt_in(self) -> None:
        text = STRICT.read_text(encoding="utf-8")
        for fragment in (
            'reference guest must be ARM64',
            'reference guest must be Debian 13',
            'PID 1 is not systemd',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'KERNAL_STEP36_RUN_ENFORCEMENT:-0',
            'KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED:-0',
            'STEP36_SYSTEMD_FEATURE_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)
        guard = text.index('if [ "${KERNAL_STEP36_RUN_ENFORCEMENT:-0}" = "1" ]; then')
        first_run = text.index('run_capture enforcement-pids')
        self.assertLess(guard, first_run)

    def test_legacy_entrypoint_delegates_to_one_policy(self) -> None:
        text = LEGACY.read_text(encoding="utf-8")
        self.assertIn("collect_systemd_feature_reference_strict.sh", text)
        self.assertIn('exec bash "$STRICT"', text)
        self.assertNotIn("systemd-run", text)

    def test_resource_probe_has_bounded_cleanup_and_three_modes(self) -> None:
        text = RESOURCE.read_text(encoding="utf-8")
        self.assertIn('choices=("pids", "cpu", "memory")', text)
        self.assertIn("os.kill(pid, signal.SIGTERM)", text)
        self.assertIn("nr_throttled", text)
        self.assertIn("FAIL memory.enforcement-process-survived", text)


if __name__ == "__main__":
    unittest.main()
