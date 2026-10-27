#!/usr/bin/env python3
"""Validate the Step-22 protected persistent-volume contract.

This is a PREP policy oracle. It does not claim that cryptography or key storage
already exists in the runtime. Runtime acceptance still needs real crypto,
recovery, DMA and performance evidence on one exact tested commit.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def evaluate(case: dict) -> str:
    if not case.get("encrypted", False):
        return "reject"
    if not case.get("authenticated_data", False) or not case.get("authenticated_metadata", False):
        return "reject"
    if case.get("authority_namespace") != case.get("key_namespace"):
        return "reject"
    if case.get("key_domain") != case.get("expected_key_domain"):
        return "reject"
    if case.get("key_generation") != case.get("expected_key_generation"):
        return "reject"
    if case.get("volume_authority_revoked", False):
        return "reject"
    if not case.get("nonce_unique", False):
        return "reject"
    if case.get("buffer_generation") != case.get("expected_buffer_generation"):
        return "reject"
    return "accept"


def main() -> None:
    path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[3] / "tests/prep/step22/secure_volume_cases.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("track") != "SECURE_STORAGE" or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step22 secure-storage corpus schema")
    seen: set[str] = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {
        "secure-volume-ok",
        "plaintext-backend",
        "unauthenticated-data",
        "unauthenticated-metadata",
        "cross-namespace-key",
        "wrong-key-domain",
        "stale-key-generation",
        "revoked-volume-authority",
        "nonce-reuse",
        "stale-buffer-generation",
    }
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step22 secure-storage cases: {missing}")
    print(f"STEP22_SECURE_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
