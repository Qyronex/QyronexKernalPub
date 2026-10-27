#!/usr/bin/env python3
"""Validate scientific endpoint contracts for Wave-B Steps 22-26."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXPECTED_STEPS = range(22, 27)
REQUIRED_ENV = {"tested_commit", "architecture", "toolchain", "fixture_hashes"}
REQUIRED_METRICS = {
    22: {"vfs_oracle_passed", "vfs_oracle_total", "cross_compartment_read_successes", "plaintext_pattern_scan_hits_on_raw_device", "silent_unauthenticated_recoveries"},
    23: {"abi_oracle_passed", "abi_oracle_total", "silent_success_count", "duplicate_authority_conflicts"},
    24: {"stress_profiles_passed", "stress_profiles_total", "scheduler_latency_p999_us", "starvation_cases", "scaling_efficiency_percent"},
    25: {"reproducible_build_matches", "reproducible_build_total", "fuzz_cases_executed", "confirmed_defects", "unowned_unsafe_or_assembly_sites"},
    26: {"hardware_platforms_tested", "hardware_platforms_passed", "boot_success_rate", "unexpected_degraded_isolation_claims"},
}


def fail(message: str) -> None:
    raise SystemExit(f"scientific-endpoints: FAIL: {message}")


def validate_step(step: int) -> None:
    path = ROOT / f"docs/prep/step{step}/SCIENTIFIC_ENDPOINT.json"
    if not path.is_file():
        fail(f"missing Step {step} endpoint")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "kernal-step-scientific-endpoint-v1" or data.get("step") != step:
        fail(f"Step {step}: invalid identity/schema")
    if data.get("state") != "DESIGN_CONTRACT":
        fail(f"Step {step}: PREP endpoint must remain DESIGN_CONTRACT")
    question = data.get("research_question")
    if not isinstance(question, str) or not question.strip():
        fail(f"Step {step}: missing research question")
    bindings = data.get("claim_bindings")
    if not isinstance(bindings, list) or not bindings:
        fail(f"Step {step}: missing claim bindings")

    metrics = data.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        fail(f"Step {step}: missing metrics")
    names: list[str] = []
    for metric in metrics:
        if not isinstance(metric, dict):
            fail(f"Step {step}: malformed metric")
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
    missing = REQUIRED_METRICS[step] - set(names)
    if missing:
        fail(f"Step {step}: missing required metrics {sorted(missing)}")

    hard_zero = data.get("hard_zero_metrics")
    if not isinstance(hard_zero, list) or not hard_zero or not set(hard_zero) <= set(names):
        fail(f"Step {step}: invalid hard-zero metrics")
    negatives = data.get("negative_controls")
    if not isinstance(negatives, list) or not negatives:
        fail(f"Step {step}: negative controls missing")
    env = data.get("environment_fields")
    if not isinstance(env, list) or not REQUIRED_ENV <= set(env):
        fail(f"Step {step}: incomplete environment provenance")
    baseline = data.get("baseline")
    if not isinstance(baseline, dict) or not baseline.get("kind"):
        fail(f"Step {step}: baseline missing")
    reps = data.get("repetition_policy")
    if not isinstance(reps, dict) or not isinstance(reps.get("minimum_runs"), int) or reps["minimum_runs"] < 2:
        fail(f"Step {step}: repetition policy invalid")
    promotion = data.get("promotion_rule")
    if not isinstance(promotion, dict) or not promotion.get("to_measured") or not promotion.get("to_replicated"):
        fail(f"Step {step}: promotion rule incomplete")
    raw = data.get("raw_evidence_contract")
    if not isinstance(raw, dict) or raw.get("format") != "json" or not raw.get("path_template"):
        fail(f"Step {step}: raw evidence contract invalid")
    raw_fields = raw.get("required_fields")
    if not isinstance(raw_fields, list) or not {"tested_commit", "metrics", "raw_artifact_hash"} <= set(raw_fields):
        fail(f"Step {step}: incomplete raw evidence fields")
    if step == 22:
        controls = " ".join(str(item) for item in negatives).lower()
        if "ram encryption" not in controls:
            fail("Step 22: persistent storage evidence must explicitly reject RAM-encryption conflation")


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_step(step)
    print("WAVE_B_SCIENTIFIC_ENDPOINTS_OK steps=22,23,24,25,26")
    print("scientific-endpoints: NOTE: DESIGN_CONTRACT validation is not runtime measurement")


if __name__ == "__main__":
    main()
