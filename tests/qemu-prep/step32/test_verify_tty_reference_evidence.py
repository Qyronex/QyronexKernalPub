#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NORMALIZER = ROOT / "tools/qemu-prep/step32/normalize_tty_reference.py"
VERIFIER = ROOT / "tools/qemu-prep/step32/verify_tty_reference_evidence.py"
TARGET = ROOT / "docs/debian13/arm64-target.json"
SOURCE = "1111111111111111111111111111111111111111"


def sample_reference(*, source: str = SOURCE, target_sha256: str | None = None) -> bytes:
    target_sha256 = target_sha256 or hashlib.sha256(TARGET.read_bytes()).hexdigest()
    return f"""REFERENCE schema=1
REFERENCE collected_at=2026-09-22T20:00:00Z
REFERENCE os_id=debian
REFERENCE os_version_id=13
REFERENCE architecture=aarch64
REFERENCE kernel_release=6.12.0-arm64
REFERENCE source_commit={source}
REFERENCE target_sha256={target_sha256}
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
""".encode("utf-8")


class Step32ReferenceEvidenceVerifierTest(unittest.TestCase):
    def run_verifier(self, raw: bytes, expected_source: str = SOURCE, mutate_json=None):
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "reference.raw"
            json_path = Path(tmp) / "reference.json"
            raw_path.write_bytes(raw)
            normalized = subprocess.run(
                [sys.executable, "-B", str(NORMALIZER), str(raw_path), str(json_path)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(normalized.returncode, 0, normalized.stderr or normalized.stdout)
            if mutate_json is not None:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                mutate_json(payload)
                json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-B", str(VERIFIER), str(raw_path), str(json_path), expected_source],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    def test_accepts_exact_returned_pair(self) -> None:
        completed = self.run_verifier(sample_reference())
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("STEP32_REFERENCE_EVIDENCE_OK", completed.stdout)

    def test_rejects_wrong_expected_source_commit(self) -> None:
        completed = self.run_verifier(
            sample_reference(),
            expected_source="2222222222222222222222222222222222222222",
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match the requested exact source SHA", completed.stderr)

    def test_rejects_normalized_json_not_derived_from_raw(self) -> None:
        completed = self.run_verifier(
            sample_reference(),
            mutate_json=lambda payload: payload["pty"].update({"child_shell": "tampered"}),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not exactly match the returned raw transcript", completed.stderr)

    def test_rejects_wrong_pinned_target_hash(self) -> None:
        completed = self.run_verifier(sample_reference(target_sha256="0" * 64))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match docs/debian13/arm64-target.json", completed.stderr)


if __name__ == "__main__":
    unittest.main()
