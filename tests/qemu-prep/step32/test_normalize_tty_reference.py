#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step32/normalize_tty_reference.py"
SPEC = importlib.util.spec_from_file_location("step32_tty_reference", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sample_reference() -> bytes:
    return b"""REFERENCE schema=1
REFERENCE collected_at=2026-09-09T12:00:00Z
REFERENCE os_id=debian
REFERENCE os_version_id=13
REFERENCE architecture=aarch64
REFERENCE kernel_release=6.12.0-arm64
REFERENCE source_commit=0000000000000000000000000000000000000000
REFERENCE target_sha256=0000000000000000000000000000000000000000000000000000000000000000
step32-pty-probe: compiler=cc (Debian 14.2.0) 14.2.0
INFO tty.flags iflag=1280 oflag=5 cflag=191 lflag=35387
INFO tty.termios-size bytes=60 nccs=4
INFO tty.speeds ispeed=15 ospeed=15
INFO tty.cc hex=03041c7f
INFO tty.winsize rows=24 cols=80 xpixel=0 ypixel=0
PASS tty.bad-pointer-efault
PASS tty.unknown-ioctl-enotty
PASS dev.null-semantics
PASS dev.zero-semantics
PASS dev.full-enospc
PASS dev.console-open
INFO entropy.getrandom bytes=32
INFO entropy.urandom bytes=32
INFO entropy.random_nonblock state=ready
PTY_PGRP_OK
PTY_CHILD_OK
PASS pty.parent-write
PTY_ECHO:hello
PASS pty.child-exit-zero
PASS step32.pty-probe.complete
"""


class Step32ReferenceNormalizerTest(unittest.TestCase):
    def test_normalizes_complete_debian13_aarch64_reference(self) -> None:
        result = MODULE.normalize_bytes(sample_reference())
        self.assertEqual(result["schema"], "kernal-step32-debian13-tty-reference-v1")
        self.assertEqual(result["termios"]["nccs"], 4)
        self.assertEqual(result["termios"]["cc_hex"], "03041c7f")
        self.assertEqual(result["devices"]["null"], "passed")
        self.assertEqual(result["devices"]["zero"], "passed")
        self.assertEqual(result["devices"]["full"], "passed")
        self.assertEqual(result["devices"]["console"], "passed")
        self.assertEqual(result["entropy"]["random_nonblock"], "ready")
        self.assertEqual(result["pty"]["foreground_pgrp"], "passed")

    def test_rejects_non_aarch64_reference(self) -> None:
        bad = sample_reference().replace(b"architecture=aarch64", b"architecture=x86_64")
        with self.assertRaisesRegex(ValueError, "not AArch64"):
            MODULE.normalize_bytes(bad)

    def test_rejects_missing_job_control_marker(self) -> None:
        bad = sample_reference().replace(b"PTY_PGRP_OK\n", b"")
        with self.assertRaisesRegex(ValueError, "missing PTY/TTY proof markers"):
            MODULE.normalize_bytes(bad)

    def test_rejects_missing_device_baseline_marker(self) -> None:
        bad = sample_reference().replace(b"PASS dev.full-enospc\n", b"")
        with self.assertRaisesRegex(ValueError, "missing PTY/TTY proof markers"):
            MODULE.normalize_bytes(bad)

    def test_accepts_debian13_point_release_and_entropy_eagain(self) -> None:
        changed = sample_reference().replace(b"os_version_id=13\n", b"os_version_id=13.1\n")
        changed = changed.replace(b"state=ready", b"state=eagain")
        result = MODULE.normalize_bytes(changed)
        self.assertEqual(result["entropy"]["random_nonblock"], "eagain")


if __name__ == "__main__":
    unittest.main()
