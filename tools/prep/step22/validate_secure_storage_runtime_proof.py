#!/usr/bin/env python3
"""Validate one exact-SHA Step-22 secure-storage runtime evidence bundle.

This validator is intentionally evidence-driven. It does not claim that secure
storage already exists. When runtime implementation is available, the collector
must provide a raw block-device image plus this JSON evidence. The validator
independently scans the raw image for declared plaintext markers and checks the
compartment/key/integrity hard-zero metrics.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "kernal-step22-secure-storage-runtime-proof-v1"
FORBIDDEN_SECRET_FIELDS = {"secret_key", "raw_key", "key_material", "key_hex"}
HARD_ZERO_METRICS = (
    "cross_compartment_read_successes",
    "cross_compartment_write_successes",
    "silent_unauthenticated_recoveries",
    "nonce_reuse_observations",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def is_sha40(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 40:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def reject_secret_material(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_SECRET_FIELDS:
                fail(f"runtime evidence must not contain secret key material: {path}.{key}")
            reject_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_material(child, f"{path}[{index}]")


def require_nonnegative_int(metrics: dict, name: str) -> int:
    value = metrics.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(f"metric {name} must be a non-negative integer")
    return value


def validate(evidence_path: Path) -> None:
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if evidence.get("schema") != SCHEMA:
        fail("invalid Step22 secure-storage runtime proof schema")
    if not is_sha40(evidence.get("tested_commit")):
        fail("tested_commit must be one exact 40-hex commit SHA")
    if evidence.get("architecture") != "aarch64":
        fail("secure-storage runtime proof must be AArch64")

    for field in (
        "platform_profile",
        "storage_transport",
        "filesystem_profile",
        "crypto_profile",
        "fixture_hashes",
        "plaintext_markers",
        "raw_device_image",
        "metrics",
        "raw_artifact_hash",
    ):
        if field not in evidence:
            fail(f"missing runtime evidence field: {field}")

    reject_secret_material(evidence)

    crypto = evidence["crypto_profile"]
    if not isinstance(crypto, dict):
        fail("crypto_profile must be an object")
    for field in ("aead", "key_hierarchy", "nonce_strategy"):
        if not isinstance(crypto.get(field), str) or not crypto[field]:
            fail(f"crypto_profile.{field} must be a non-empty string")
    key_bits = crypto.get("key_bits")
    if not isinstance(key_bits, int) or isinstance(key_bits, bool) or key_bits < 128:
        fail("crypto_profile.key_bits must be at least 128")
    if crypto.get("authenticated_data") is not True:
        fail("secure storage must authenticate data")
    if crypto.get("authenticated_metadata") is not True:
        fail("secure storage must authenticate metadata")
    if crypto.get("nonce_unique_proven") is not True:
        fail("runtime evidence must prove nonce uniqueness for the tested workload")

    fixture_hashes = evidence["fixture_hashes"]
    if not isinstance(fixture_hashes, dict) or not fixture_hashes:
        fail("fixture_hashes must identify the exact tested fixtures")

    markers = evidence["plaintext_markers"]
    if not isinstance(markers, list) or len(markers) < 2:
        fail("plaintext_markers must contain at least two independent markers")
    marker_bytes: list[bytes] = []
    seen: set[str] = set()
    for marker in markers:
        if not isinstance(marker, str) or len(marker) < 16 or marker in seen:
            fail("plaintext markers must be unique strings of at least 16 bytes")
        seen.add(marker)
        marker_bytes.append(marker.encode("utf-8"))

    raw_path_value = evidence["raw_device_image"]
    if not isinstance(raw_path_value, str) or not raw_path_value:
        fail("raw_device_image must be a relative file path")
    raw_path = Path(raw_path_value)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        fail("raw_device_image must stay inside the evidence bundle")
    raw_path = evidence_path.parent / raw_path
    if not raw_path.is_file():
        fail(f"missing raw device image: {raw_path}")
    raw = raw_path.read_bytes()

    actual_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
    if evidence["raw_artifact_hash"] != actual_hash:
        fail("raw device artifact hash mismatch")

    plaintext_hits = sum(raw.count(marker) for marker in marker_bytes)
    metrics = evidence["metrics"]
    if not isinstance(metrics, dict):
        fail("metrics must be an object")

    compartments = require_nonnegative_int(metrics, "storage_compartments_tested")
    domains = require_nonnegative_int(metrics, "independent_effective_key_domains")
    if compartments < 2 or domains < 2:
        fail("proof must exercise at least two compartments and two effective key domains")

    for name in HARD_ZERO_METRICS:
        if require_nonnegative_int(metrics, name) != 0:
            fail(f"hard-zero metric violated: {name}")

    wrong_attempts = require_nonnegative_int(metrics, "wrong_key_attempts")
    wrong_rejections = require_nonnegative_int(metrics, "wrong_key_rejections")
    if wrong_attempts < 1 or wrong_rejections != wrong_attempts:
        fail("every wrong-key attempt must be rejected")

    tamper_attempts = require_nonnegative_int(metrics, "integrity_tamper_attempts")
    integrity_detections = require_nonnegative_int(metrics, "integrity_detections")
    if tamper_attempts < 1 or integrity_detections != tamper_attempts:
        fail("every ciphertext/metadata tamper attempt must be detected")

    reported_hits = require_nonnegative_int(metrics, "plaintext_pattern_scan_hits_on_raw_device")
    if plaintext_hits != reported_hits:
        fail(
            "raw-device plaintext metric does not match independent scan: "
            f"reported={reported_hits} actual={plaintext_hits}"
        )
    if plaintext_hits != 0:
        fail(f"plaintext marker leaked into raw persistent storage: hits={plaintext_hits}")

    print(
        "STEP22_SECURE_RUNTIME_PROOF_OK "
        f"commit={evidence['tested_commit']} compartments={compartments} "
        f"key_domains={domains} plaintext_hits={plaintext_hits}"
    )


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate_secure_storage_runtime_proof.py <evidence.json>")
    validate(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    main()
