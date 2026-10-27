#!/usr/bin/env python3
"""Extract Step-40 marker lines from a QEMU serial log.

This parser never upgrades INFO/FAIL to PASS and never treats a marker as proof
outside the exact-SHA runtime evidence that produced the serial log.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PREFIX = "KERNAL_STEP40"
ALLOWED_STATUS = {"PASS", "FAIL", "INFO"}


def parse_line(raw: str, line_number: int):
    line = raw.rstrip("\r\n")
    if not line.startswith(PREFIX + "|"):
        return None
    parts = line.split("|", 3)
    if len(parts) != 4:
        raise ValueError(f"line {line_number}: malformed marker field count")
    _, check_id, status, detail = parts
    if not check_id or any(ch.isspace() for ch in check_id):
        raise ValueError(f"line {line_number}: invalid check id")
    if status not in ALLOWED_STATUS:
        raise ValueError(f"line {line_number}: invalid status {status!r}")
    return {
        "line": line_number,
        "id": check_id,
        "status": status,
        "detail": detail,
        "raw": line,
    }


def extract(path: Path) -> list[dict]:
    markers: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, 1):
            marker = parse_line(raw, line_number)
            if marker is not None:
                markers.append(marker)
    return markers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial-log", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--fail-on-marker-fail", action="store_true")
    args = parser.parse_args()

    try:
        markers = extract(args.serial_log.expanduser().resolve())
    except (OSError, ValueError) as exc:
        print(f"step40-serial-markers: FAIL: {exc}", file=sys.stderr)
        return 1
    if not markers:
        print("step40-serial-markers: FAIL: no Step40 markers found", file=sys.stderr)
        return 1

    payload = {
        "schema_version": 1,
        "source_log": str(args.serial_log),
        "markers": markers,
        "counts": {
            status: sum(1 for marker in markers if marker["status"] == status)
            for status in sorted(ALLOWED_STATUS)
        },
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step40-serial-markers: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step40-serial-markers: PASS: {out}")

    if args.fail_on_marker_fail and any(marker["status"] == "FAIL" for marker in markers):
        print("step40-serial-markers: FAIL: serial log contains FAIL marker", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
