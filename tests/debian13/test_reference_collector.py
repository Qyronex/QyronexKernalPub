#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_PATH = ROOT / "tools/debian13/collect-reference.py"
REFERENCE_RUNNER_PATH = ROOT / "tools/debian13/run-reference-qemu-macos.sh"
SPEC = importlib.util.spec_from_file_location("debian13_reference", COLLECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class ReferenceCollectorTests(unittest.TestCase):
    def test_strace_pid_prefixes_normalize_to_same_syscalls(self) -> None:
        trace = "\n".join(
            [
                '1234 execve("/bin/sh", ["/bin/sh"], 0x0) = 0',
                '[pid 1235] read(3, "", 0) = 0',
                'write(1, "", 0) = 0',
                '1234 +++ exited with 0 +++',
            ]
        )
        self.assertEqual(
            collector.parse_requirements(trace)["syscalls"],
            ["execve", "read", "write"],
        )

    def test_strace_column_alignment_does_not_drop_short_syscalls(self) -> None:
        trace = "\n".join(
            [
                "brk(NULL)                               = 0x1234",
                "close(3)                                = 0",
                'write(1, "x", 1)                       = 1',
            ]
        )
        self.assertEqual(
            collector.parse_requirements(trace)["syscalls"],
            ["brk", "close", "write"],
        )

    def test_unfinished_call_still_contributes_syscall_name(self) -> None:
        trace = "\n".join(
            [
                "1234 read(3,  <unfinished ...>",
                '[pid 1234] <... read resumed>"x", 1) = 1',
            ]
        )
        requirements = collector.parse_requirements(trace)
        self.assertEqual(requirements["syscalls"], ["read"])
        self.assertEqual(requirements["paths"], [])

    def test_requirements_capture_ioctl_paths_and_socket_contracts(self) -> None:
        trace = "\n".join(
            [
                '1234 openat(AT_FDCWD, "/proc/self/status", O_RDONLY) = 3',
                '1234 newfstatat(AT_FDCWD, "/sys", {st_mode=S_IFDIR|0755}, 0) = 0',
                '1234 openat(AT_FDCWD, "/dev/null", O_RDONLY) = 4',
                '1234 openat(AT_FDCWD, "/etc/os-release", O_RDONLY) = 5',
                '1234 ioctl(0, TCGETS, 0xffff) = -1 ENOTTY (Inappropriate ioctl for device)',
                '1234 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 6',
                '1234 bind(6, {sa_family=AF_NETLINK}, 12) = 0',
            ]
        )
        requirements = collector.parse_requirements(trace)
        self.assertEqual(requirements["ioctl_requests"], ["TCGETS"])
        self.assertEqual(requirements["proc_paths"], ["/proc/self/status"])
        self.assertEqual(requirements["sys_paths"], ["/sys"])
        self.assertEqual(requirements["dev_paths"], ["/dev/null"])
        self.assertEqual(requirements["filesystem_paths"], ["/etc/os-release"])
        self.assertEqual(requirements["socket_families"], ["AF_NETLINK"])
        self.assertEqual(requirements["socket_types"], ["SOCK_RAW|SOCK_CLOEXEC"])
        self.assertEqual(requirements["socket_protocols"], ["NETLINK_ROUTE"])
        self.assertEqual(requirements["network_syscalls"], ["bind", "socket"])

    def test_path_discovery_uses_path_operands_not_arbitrary_quoted_payloads(self) -> None:
        trace = "\n".join(
            [
                'write(1, "/not-a-filesystem-dependency", 28) = 28',
                'openat(AT_FDCWD, "relative.conf", O_RDONLY) = 3',
                'connect(4, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 30) = 0',
            ]
        )
        requirements = collector.parse_requirements(trace)
        self.assertNotIn("/not-a-filesystem-dependency", requirements["paths"])
        self.assertIn("relative.conf", requirements["filesystem_paths"])
        self.assertIn("/run/dbus/system_bus_socket", requirements["filesystem_paths"])
        self.assertEqual(requirements["network_syscalls"], ["connect"])

    def test_empty_requirement_categories_remain_explicit(self) -> None:
        requirements = collector.parse_requirements('write(1, "x", 1) = 1')
        self.assertEqual(set(requirements), set(collector.REQUIREMENT_KEYS))
        self.assertEqual(requirements["ioctl_requests"], [])
        self.assertEqual(requirements["socket_families"], [])
        self.assertEqual(requirements["proc_paths"], [])

    def test_provenance_binds_source_and_pinned_rootfs(self) -> None:
        target = json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )
        source = "a" * 40
        provenance = collector.evidence_provenance(target, source)
        self.assertEqual(provenance["source_commit"], source)
        self.assertEqual(provenance["rootfs"]["artifact"], target["rootfs"]["artifact"])
        self.assertEqual(provenance["rootfs"]["sha256"], target["rootfs"]["sha256"])
        self.assertEqual(provenance["rootfs"]["sha512"], target["rootfs"]["sha512"])

    def test_provenance_rejects_non_exact_source_sha(self) -> None:
        target = json.loads(
            (ROOT / "docs/debian13/arm64-target.json").read_text(encoding="utf-8")
        )
        with self.assertRaisesRegex(collector.CollectionError, "source_commit"):
            collector.evidence_provenance(target, "deadbeef")

    def test_case_manifest_covers_every_matrix_component_and_exact_program(self) -> None:
        matrix = json.loads(
            (ROOT / "docs/debian13/compatibility-matrix.json").read_text(encoding="utf-8")
        )
        cases = json.loads(
            (ROOT / "tests/debian13/reference-cases.json").read_text(encoding="utf-8")
        )
        matrix_programs = {entry["id"]: entry["program"] for entry in matrix["components"]}
        case_components = {entry["component"] for entry in cases["cases"]}
        self.assertEqual(case_components, set(matrix_programs))
        for entry in cases["cases"]:
            self.assertEqual(entry["argv"][0], matrix_programs[entry["component"]])

    def test_functional_requirement_probes_are_present(self) -> None:
        cases = json.loads(
            (ROOT / "tests/debian13/reference-cases.json").read_text(encoding="utf-8")
        )
        ids = {entry["id"] for entry in cases["cases"]}
        self.assertTrue(
            {
                "functional.busybox.proc-status",
                "functional.busybox.sys-root",
                "functional.busybox.dev-null",
                "functional.busybox.filesystem-path",
                "functional.busybox.tty-ioctl",
                "functional.iproute2.link-loopback",
            }.issubset(ids)
        )

    def test_functional_path_probes_are_quiet_and_deterministic(self) -> None:
        cases = json.loads(
            (ROOT / "tests/debian13/reference-cases.json").read_text(encoding="utf-8")
        )
        by_id = {entry["id"]: entry["argv"] for entry in cases["cases"]}
        self.assertEqual(
            by_id["functional.busybox.proc-status"],
            ["/usr/bin/busybox", "test", "-r", "/proc/self/status"],
        )
        self.assertEqual(
            by_id["functional.busybox.sys-root"],
            ["/usr/bin/busybox", "test", "-d", "/sys"],
        )
        self.assertEqual(
            by_id["functional.busybox.dev-null"],
            ["/usr/bin/busybox", "test", "-e", "/dev/null"],
        )
        self.assertEqual(
            by_id["functional.busybox.filesystem-path"],
            ["/usr/bin/busybox", "test", "-r", "/etc/os-release"],
        )

    def test_os_release_parser_handles_quoted_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "os-release"
            path.write_text(
                "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME='trixie'\n",
                encoding="utf-8",
            )
            self.assertEqual(
                collector.parse_os_release(path),
                {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
            )

    def test_case_ids_must_be_unique(self) -> None:
        cases = {
            "schema_version": 1,
            "target_id": "target",
            "cases": [
                {"id": "same", "component": "a", "argv": ["/bin/true"]},
                {"id": "same", "component": "a", "argv": ["/bin/true"]},
            ],
        }
        with self.assertRaises(collector.CollectionError):
            collector.validate_cases(cases, "target", {"a": "/bin/true"})

    def test_case_program_must_match_matrix_program(self) -> None:
        cases = {
            "schema_version": 1,
            "target_id": "target",
            "cases": [
                {"id": "program-drift", "component": "a", "argv": ["/bin/true"]},
            ],
        }
        with self.assertRaisesRegex(collector.CollectionError, "program must match"):
            collector.validate_cases(cases, "target", {"a": "/bin/false"})

    def test_macos_reference_runner_stays_compatible_with_system_bash(self) -> None:
        runner = REFERENCE_RUNNER_PATH.read_text(encoding="utf-8")
        self.assertTrue(runner.startswith("#!/bin/bash\n"))
        self.assertIsNone(re.search(r"(?m)^\s*(?:mapfile|readarray)\b", runner))
        self.assertIsNone(re.search(r"\$\(\s*seq\b", runner))
        self.assertIn("firmware_paths=$(find_firmware)", runner)
        self.assertIn("--source-commit '$SOURCE_COMMIT'", runner)


if __name__ == "__main__":
    unittest.main()
