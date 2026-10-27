#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REQUIRED_PASS_MARKERS = (
    "PASS tty.bad-pointer-efault",
    "PASS tty.unknown-ioctl-enotty",
    "PASS dev.null-semantics",
    "PASS dev.zero-semantics",
    "PASS dev.full-enospc",
    "PASS dev.console-open",
    "PASS pty.parent-write",
    "PASS pty.child-exit-zero",
    "PASS step32.pty-probe.complete",
)
REQUIRED_TRANSCRIPT_MARKERS = (
    "PTY_PGRP_OK",
    "PTY_CHILD_OK",
    "PTY_ECHO:hello",
)


def fail(message: str) -> ValueError:
    return ValueError(message)


def parse_kv_line(line: str, prefix: str) -> dict[str, str]:
    if not line.startswith(prefix):
        raise fail(f"line does not start with {prefix!r}: {line!r}")
    values: dict[str, str] = {}
    for token in line[len(prefix):].strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        values[key] = value
    return values


def exactly_one(lines: list[str], prefix: str) -> str:
    matches = [line for line in lines if line.startswith(prefix)]
    if len(matches) != 1:
        raise fail(f"expected exactly one {prefix!r} line, found {len(matches)}")
    return matches[0]


def reference_fields(lines: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in lines:
        if not line.startswith("REFERENCE "):
            continue
        payload = line[len("REFERENCE "):]
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        fields[key] = value
    required = {
        "schema",
        "collected_at",
        "os_id",
        "os_version_id",
        "architecture",
        "kernel_release",
        "source_commit",
        "target_sha256",
    }
    missing = sorted(required - fields.keys())
    if missing:
        raise fail(f"missing REFERENCE fields: {missing}")
    if fields["schema"] != "1":
        raise fail(f"unsupported reference schema: {fields['schema']!r}")
    if fields["os_id"] != "debian":
        raise fail(f"reference is not Debian: {fields['os_id']!r}")
    if not re.fullmatch(r"13(?:\..*)?", fields["os_version_id"]):
        raise fail(f"reference is not Debian 13: {fields['os_version_id']!r}")
    if fields["architecture"] not in {"aarch64", "arm64"}:
        raise fail(f"reference is not AArch64: {fields['architecture']!r}")
    if not re.fullmatch(r"[0-9a-f]{40}", fields["source_commit"]):
        raise fail("source_commit must be a full lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", fields["target_sha256"]):
        raise fail("target_sha256 must be a lowercase SHA-256")
    return fields


def normalize_bytes(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise fail(f"reference output is not UTF-8: {exc}") from exc
    lines = text.splitlines()
    reference = reference_fields(lines)

    flags = parse_kv_line(exactly_one(lines, "INFO tty.flags "), "INFO tty.flags ")
    termios_size = parse_kv_line(
        exactly_one(lines, "INFO tty.termios-size "), "INFO tty.termios-size "
    )
    speeds = parse_kv_line(exactly_one(lines, "INFO tty.speeds "), "INFO tty.speeds ")
    cc = parse_kv_line(exactly_one(lines, "INFO tty.cc "), "INFO tty.cc ")
    winsize = parse_kv_line(exactly_one(lines, "INFO tty.winsize "), "INFO tty.winsize ")
    getrandom = parse_kv_line(
        exactly_one(lines, "INFO entropy.getrandom "), "INFO entropy.getrandom "
    )
    urandom = parse_kv_line(
        exactly_one(lines, "INFO entropy.urandom "), "INFO entropy.urandom "
    )
    random_nonblock = parse_kv_line(
        exactly_one(lines, "INFO entropy.random_nonblock "),
        "INFO entropy.random_nonblock ",
    )

    for name in ("iflag", "oflag", "cflag", "lflag"):
        if name not in flags or not flags[name].isdigit():
            raise fail(f"invalid/missing tty flag {name}")
    for name in ("bytes", "nccs"):
        if name not in termios_size or not termios_size[name].isdigit():
            raise fail(f"invalid/missing termios field {name}")
    for name in ("ispeed", "ospeed"):
        if name not in speeds or not speeds[name].isdigit():
            raise fail(f"invalid/missing tty speed {name}")
    nccs = int(termios_size["nccs"])
    cc_hex = cc.get("hex", "")
    if len(cc_hex) != nccs * 2 or not re.fullmatch(r"[0-9a-f]+", cc_hex):
        raise fail("tty.cc hex length/content does not match NCCS")
    for name in ("rows", "cols", "xpixel", "ypixel"):
        if name not in winsize or not winsize[name].isdigit():
            raise fail(f"invalid/missing winsize field {name}")
    if getrandom.get("bytes") != "32" or urandom.get("bytes") != "32":
        raise fail("entropy probes must each return exactly 32 bytes")
    if random_nonblock.get("state") not in {"ready", "eagain"}:
        raise fail("/dev/random nonblocking reference must be ready or eagain")

    missing_markers = [
        marker
        for marker in (*REQUIRED_PASS_MARKERS, *REQUIRED_TRANSCRIPT_MARKERS)
        if marker not in text
    ]
    if missing_markers:
        raise fail(f"missing PTY/TTY proof markers: {missing_markers}")

    compiler_lines = [
        line for line in lines if line.startswith("step32-pty-probe: compiler=")
    ]
    if len(compiler_lines) != 1:
        raise fail(f"expected exactly one compiler identity, found {len(compiler_lines)}")

    return {
        "schema": "kernal-step32-debian13-tty-reference-v1",
        "provenance": {
            **reference,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "compiler": compiler_lines[0].split("=", 1)[1],
        },
        "termios": {
            "iflag": int(flags["iflag"]),
            "oflag": int(flags["oflag"]),
            "cflag": int(flags["cflag"]),
            "lflag": int(flags["lflag"]),
            "struct_bytes": int(termios_size["bytes"]),
            "nccs": nccs,
            "cc_hex": cc_hex,
            "ispeed": int(speeds["ispeed"]),
            "ospeed": int(speeds["ospeed"]),
        },
        "winsize": {name: int(winsize[name]) for name in ("rows", "cols", "xpixel", "ypixel")},
        "devices": {
            "null": "passed",
            "zero": "passed",
            "full": "passed",
            "console": "passed",
        },
        "entropy": {
            "getrandom_bytes": 32,
            "urandom_bytes": 32,
            "random_nonblock": random_nonblock["state"],
        },
        "pty": {
            "foreground_pgrp": "passed",
            "child_shell": "passed",
            "parent_child_data_exchange": "passed",
            "bad_pointer_errno": "EFAULT",
            "unknown_ioctl_errno": "ENOTTY",
        },
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: normalize_tty_reference.py RAW_REFERENCE OUTPUT_JSON",
            file=sys.stderr,
        )
        return 2
    raw_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    try:
        normalized = normalize_bytes(raw_path.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"step32-reference-normalizer: FAIL: {exc}", file=sys.stderr)
        return 1
    out_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "STEP32_REFERENCE_NORMALIZE_OK "
        f"source_commit={normalized['provenance']['source_commit']} "
        f"raw_sha256={normalized['provenance']['raw_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
