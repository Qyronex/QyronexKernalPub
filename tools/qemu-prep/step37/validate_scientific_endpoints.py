#!/usr/bin/env python3
"""Validate scientific measurement contracts for Wave-E Steps 37-40."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXPECTED_STEPS = range(37, 41)
REQUIRED_ENV = {"tested_commit", "architecture", "debian_target_id", "qemu_version", "qemu_profile_id", "toolchain", "fixture_hashes"}
REQUIRED_METRICS = {
    37: {"boot_to_pid1_ms", "boot_to_multi_user_ms", "mandatory_unit_successes", "kernel_panic_count"},
    38: {"expected_devices_observed", "expected_devices_total", "stale_device_authority_acceptances", "device_lifecycle_leaks"},
    39: {"dpkg_transactions_passed", "dpkg_transactions_total", "apt_update_success_rate", "database_consistency_failures"},
    40: {"repeated_boots_passed", "repeated_boots_total", "oracle_passed", "oracle_total", "silent_success_count", "boot_time_p99_ms", "network_throughput_mbps", "storage_iops"},
}


def fail(message: str) -> None:
    raise SystemExit(f"scientific-endpoints: FAIL: {message}")


def validate_step(step: int) -> None:
    path = ROOT / f"docs/debian13/qemu-prep/step{step}/SCIENTIFIC_ENDPOINT.json"
    if not path.is_file():
        fail(f"missing Step {step} endpoint: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "kernal-step-scientific-endpoint-v1":
        fail(f"Step {step}: invalid schema")
    if data.get("step") != step:
        fail(f"Step {step}: step mismatch")
    if data.get("state") != "DESIGN_CONTRACT":
        fail(f"Step {step}: PREP endpoint must remain DESIGN_CONTRACT")
    if not isinstance(data.get("research_question"), str) or not data["research_question"].strip():
        fail(f"Step {step}: missing research question")
    if not isinstance(data.get("claim_bindings"), list) or not data["claim_bindings"]:
        fail(f"Step {step}: missing claim bindings")

    metrics = data.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        fail(f"Step {step}: metrics must be non-empty")
    names: list[str] = []
    for metric in metrics:
        if not isinstance(metric, dict):
            fail(f"Step {step}: metric is not an object")
        name = metric.get("name")
        if not isinstance(name, str) or not name:
            fail(f"Step {step}: invalid metric name")
        if metric.get("type") not in {"integer", "number", "boolean", "string"}:
            fail(f"Step {step}: metric {name} has invalid type")
        if not isinstance(metric.get("unit"), str) or not metric["unit"]:
            fail(f"Step {step}: metric {name} missing unit")
        names.append(name)
    if len(names) != len(set(names)):
        fail(f"Step {step}: duplicate metric names")
    missing_metrics = REQUIRED_METRICS[step] - set(names)
    if missing_metrics:
        fail(f"Step {step}: missing required metrics {sorted(missing_metrics)}")

    hard_zero = data.get("hard_zero_metrics")
    if not isinstance(hard_zero, list) or not hard_zero or not set(hard_zero) <= set(names):
        fail(f"Step {step}: invalid hard-zero metrics")
    negatives = data.get("negative_controls")
    if not isinstance(negatives, list) or not negatives:
        fail(f"Step {step}: negative controls must be non-empty")
    environment = data.get("environment_fields")
    if not isinstance(environment, list) or not REQUIRED_ENV <= set(environment):
        fail(f"Step {step}: incomplete environment provenance")
    if not isinstance(data.get("baseline"), dict) or not data["baseline"].get("kind"):
        fail(f"Step {step}: baseline contract missing")
    repetitions = data.get("repetition_policy")
    if not isinstance(repetitions, dict) or not isinstance(repetitions.get("minimum_runs"), int) or repetitions["minimum_runs"] < 2:
        fail(f"Step {step}: invalid repetition policy")
    promotion = data.get("promotion_rule")
    if not isinstance(promotion, dict) or not promotion.get("to_measured") or not promotion.get("to_replicated"):
        fail(f"Step {step}: incomplete promotion rule")
    raw = data.get("raw_evidence_contract")
    if not isinstance(raw, dict) or raw.get("format") != "json" or not raw.get("path_template"):
        fail(f"Step {step}: invalid raw evidence contract")
    raw_fields = raw.get("required_fields")
    if not isinstance(raw_fields, list) or not {"tested_commit", "metrics", "raw_artifact_hash"} <= set(raw_fields):
        fail(f"Step {step}: incomplete raw evidence fields")
    if step == 40:
        claim = data.get("bounded_claim")
        if not isinstance(claim, str) or "Pinned unchanged Debian 13 ARM64" not in claim or "AArch64 QEMU" not in claim:
            fail("Step 40: bounded claim missing pinned Debian/QEMU scope")


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_step(step)
    print("WAVE_E_SCIENTIFIC_ENDPOINTS_OK steps=37,38,39,40")
    print("scientific-endpoints: NOTE: DESIGN_CONTRACT validation is not runtime measurement")


if __name__ == "__main__":
    main()
