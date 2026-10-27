#!/usr/bin/env python3
"""Verify returned Step 32 Debian TTY/PTTY reference evidence.

This PREP-only verifier binds the returned raw transcript and normalized JSON to
one another, to the exact requested source SHA, and to the pinned Debian target
identity. It does not claim runtime acceptance.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from normalize_tty_reference import normalize_bytes

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "docs/debian13/arm64-target.json"


def fail(message: str) -> int:
    print(f"step32-reference-evidence: FAIL: {message}", file=sys.stderr)
    return 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: verify_tty_reference_evidence.py RAW_REFERENCE NORMALIZED_JSON EXPECTED_SOURCE_COMMIT",
            file=sys.stderr,
        )
        return 2

    raw_path = Path(sys.argv[1])
    normalized_path = Path(sys.argv[2])
    expected_source_commit = sys.argv[3]

    try:
        require(
            re.fullmatch(r"[0-9a-f]{40}", expected_source_commit) is not None,
            "expected source commit must be a full lowercase 40-character Git SHA",
        )
        raw = raw_path.read_bytes()
        normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
        require(isinstance(normalized, dict), "normalized evidence must contain a JSON object")

        recomputed = normalize_bytes(raw)
        require(
            normalized == recomputed,
            "normalized evidence does not exactly match the returned raw transcript",
        )

        provenance = normalized.get("provenance")
        require(isinstance(provenance, dict), "normalized provenance must be an object")
        require(
            provenance.get("source_commit") == expected_source_commit,
            "returned source_commit does not match the requested exact source SHA",
        )

        target_sha256 = hashlib.sha256(TARGET.read_bytes()).hexdigest()
        require(
            provenance.get("target_sha256") == target_sha256,
            "returned target_sha256 does not match docs/debian13/arm64-target.json",
        )

        raw_sha256 = hashlib.sha256(raw).hexdigest()
        require(
            provenance.get("raw_sha256") == raw_sha256,
            "returned raw_sha256 does not match the raw transcript",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return fail(str(exc))

    print(
        "STEP32_REFERENCE_EVIDENCE_OK "
        f"source_commit={expected_source_commit} "
        f"target_sha256={target_sha256} "
        f"raw_sha256={raw_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
