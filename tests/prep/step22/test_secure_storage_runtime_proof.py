#!/usr/bin/env python3
"""Self-test the Step-22 secure-storage runtime proof validator.

The cases deliberately include dishonest/unsafe evidence so the harness proves
that plaintext leakage, cross-compartment access, wrong-key acceptance, missed
tamper detection, nonce reuse, unauthenticated metadata and raw-artifact drift
are rejected before any future MEASURED claim can be published.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools/prep/step22/validate_secure_storage_runtime_proof.py"
TESTED_COMMIT = "0123456789abcdef0123456789abcdef01234567"
MARKERS = [
    "KERNAL_STORAGE_PROOF_9F3A72D1",
    "KERNAL_STORAGE_PROOF_SECONDARY_4C11",
]


def base_evidence(raw: bytes) -> dict:
    return {
        "schema": "kernal-step22-secure-storage-runtime-proof-v1",
        "tested_commit": TESTED_COMMIT,
        "architecture": "aarch64",
        "platform_profile": "synthetic-proof-harness",
        "storage_transport": "virtio-blk",
        "filesystem_profile": "synthetic-fs",
        "crypto_profile": {
            "aead": "synthetic-aead-profile",
            "key_bits": 256,
            "authenticated_data": True,
            "authenticated_metadata": True,
            "key_hierarchy": "volume-domain-generation",
            "nonce_strategy": "unique-per-write",
            "nonce_unique_proven": True,
        },
        "fixture_hashes": {
            "payload_a": "sha256:synthetic-a",
            "payload_b": "sha256:synthetic-b",
        },
        "plaintext_markers": MARKERS,
        "raw_device_image": "raw.img",
        "metrics": {
            "storage_compartments_tested": 2,
            "independent_effective_key_domains": 2,
            "cross_compartment_read_successes": 0,
            "cross_compartment_write_successes": 0,
            "wrong_key_attempts": 2,
            "wrong_key_rejections": 2,
            "integrity_tamper_attempts": 2,
            "integrity_detections": 2,
            "plaintext_pattern_scan_hits_on_raw_device": 0,
            "silent_unauthenticated_recoveries": 0,
            "nonce_reuse_observations": 0,
        },
        "raw_artifact_hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def run_case(name: str, evidence: dict, raw: bytes, expect_ok: bool) -> None:
    with tempfile.TemporaryDirectory(prefix=f"step22-{name}-") as tmp:
        root = Path(tmp)
        (root / "raw.img").write_bytes(raw)
        evidence_path = root / "evidence.json"
        evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(evidence_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if expect_ok:
            if result.returncode != 0:
                raise SystemExit(f"{name}: expected accept, got:\n{result.stdout}")
            if "STEP22_SECURE_RUNTIME_PROOF_OK" not in result.stdout:
                raise SystemExit(f"{name}: success marker missing: {result.stdout}")
        elif result.returncode == 0:
            raise SystemExit(f"{name}: unsafe evidence was accepted: {result.stdout}")


def main() -> None:
    opaque_raw = bytes((index * 37 + 11) % 256 for index in range(8192))
    good = base_evidence(opaque_raw)
    run_case("valid-proof", good, opaque_raw, True)

    leaked_raw = opaque_raw + MARKERS[0].encode("utf-8") + b"tail"
    leaked = base_evidence(leaked_raw)
    leaked["metrics"]["plaintext_pattern_scan_hits_on_raw_device"] = 0
    run_case("plaintext-leak", leaked, leaked_raw, False)

    cross_read = copy.deepcopy(good)
    cross_read["metrics"]["cross_compartment_read_successes"] = 1
    run_case("cross-compartment-read", cross_read, opaque_raw, False)

    wrong_key = copy.deepcopy(good)
    wrong_key["metrics"]["wrong_key_rejections"] = 1
    run_case("wrong-key-silent-accept", wrong_key, opaque_raw, False)

    missed_tamper = copy.deepcopy(good)
    missed_tamper["metrics"]["integrity_detections"] = 1
    run_case("missed-integrity-tamper", missed_tamper, opaque_raw, False)

    nonce_reuse = copy.deepcopy(good)
    nonce_reuse["metrics"]["nonce_reuse_observations"] = 1
    run_case("nonce-reuse", nonce_reuse, opaque_raw, False)

    unauthenticated_metadata = copy.deepcopy(good)
    unauthenticated_metadata["crypto_profile"]["authenticated_metadata"] = False
    run_case("unauthenticated-metadata", unauthenticated_metadata, opaque_raw, False)

    wrong_hash = copy.deepcopy(good)
    wrong_hash["raw_artifact_hash"] = "sha256:" + "0" * 64
    run_case("raw-artifact-drift", wrong_hash, opaque_raw, False)

    print("STEP22_SECURE_PROOF_HARNESS_OK cases=8")


if __name__ == "__main__":
    main()
