#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step35/classify_event_fd_reference.py"
SPEC = importlib.util.spec_from_file_location("step35_reference", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COLLECTOR = ROOT / "tools/qemu-prep/step35/collect_event_fd_reference.sh"


def probe_text() -> str:
    markers = [f"PASS {marker}" for marker in (
        "epoll.level.first-ready",
        "epoll.level.remains-ready",
        "epoll.level.clears-after-drain",
        "epoll.edge.first-transition",
        "epoll.edge.no-repeat-without-transition",
        "epoll.edge.new-transition",
        "epoll.oneshot.first-ready",
        "epoll.oneshot.disabled-after-delivery",
        "epoll.oneshot.rearm",
        "epoll.reuse.old-watch-not-redirected",
        "eventfd.empty-nonblock-eagain",
        "eventfd.epoll-ready",
        "eventfd.read-counter",
        "timerfd.expiration-ready",
        "timerfd.expiration-count",
        "signalfd.masked-delivery",
        "inotify.create-move-delete",
        "memfd.get-seals",
        "memfd.grow-sealed-eperm",
        "close-range.closed-fd",
        "pidfd.release-child",
        "pidfd.exit-readiness",
        "pidfd.child-exit-zero",
        "step35.event-fd-probe.complete",
    )]
    return "\n".join(markers + ["INFO pidfd.open supported=1", ""])


class Step35ReferenceContractTest(unittest.TestCase):
    def make_reference(self, root: Path) -> None:
        (root / "identity.txt").write_text(
            "schema=1\narch=aarch64\nkernel=6.12.0-arm64\n"
            "source_commit=" + "1" * 40 + "\n"
            "target_id=debian-13-trixie-arm64-20260712-2537\n"
            "target_sha256=" + "2" * 64 + "\n",
            encoding="utf-8",
        )
        (root / "event-fd-probe.status").write_text("0\n", encoding="utf-8")
        (root / "event-fd-probe.stdout").write_text(probe_text(), encoding="utf-8")
        (root / "event-fd-probe.strace").write_text(
            "123 epoll_create1(EPOLL_CLOEXEC) = 3\n"
            "123 pidfd_open(44, 0) = 5\n",
            encoding="utf-8",
        )
        (root / "systemctl-event-api.strace").write_text(
            "[pid 10] epoll_pwait(4, [], 16, 0, NULL, 8) = 0\n"
            "[pid 10] eventfd2(0, EFD_CLOEXEC|EFD_NONBLOCK) = 5\n",
            encoding="utf-8",
        )
        (root / "busctl-event-api.strace").write_text(
            "11 memfd_create(\"x\", MFD_CLOEXEC) = 7\n"
            "11 close_range(8, 4294967295, 0) = 0\n",
            encoding="utf-8",
        )

    def test_normalizes_probe_and_consumer_subset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            result = MODULE.classify(root)
        self.assertTrue(result["probe"]["pidfd_open_supported"])
        self.assertTrue(result["consumer_trace_complete"])
        self.assertEqual(
            result["observed_consumer_required_syscalls"],
            ["close_range", "epoll_pwait", "eventfd2", "memfd_create"],
        )

    def test_rejects_missing_readiness_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_reference(root)
            text = (root / "event-fd-probe.stdout").read_text(encoding="utf-8")
            (root / "event-fd-probe.stdout").write_text(
                text.replace("PASS epoll.edge.new-transition\n", ""), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "missing markers"):
                MODULE.classify(root)

    def test_collector_is_pinned_and_read_only_for_consumers(self) -> None:
        text = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            'reference guest must be ARM64',
            'reference guest must be Debian 13',
            'SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)',
            'TARGET_SHA256=$(sha256sum "$TARGET"',
            'systemctl list-units --type=service --state=running',
            'busctl --system list --no-pager',
            'STEP35_EVENT_FD_REFERENCE_OK',
        ):
            self.assertIn(fragment, text)
        for mutation in ("systemctl start", "systemctl stop", "systemctl restart"):
            self.assertNotIn(mutation, text)


if __name__ == "__main__":
    unittest.main()
