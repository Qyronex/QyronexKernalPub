#!/usr/bin/env python3
"""Validate scientific measurement contracts for Wave-D Steps 32-36.

PREP validation checks schema/completeness only. It never invents measurements and
never promotes DESIGN_CONTRACT to MEASURED.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXPECTED_STEPS = range(32, 37)
REQUIRED_ENV = {"tested_commit", "architecture", "debian_target_id", "qemu_version", "qemu_profile_id", "toolchain", "fixture_hashes"}
REQUIRED_METRICS = {
    32: {"tty_oracle_passed", "tty_oracle_total", "unauthorized_device_access_successes"},
    33: {"filesystem_oracle_passed", "filesystem_oracle_total", "namespace_escape_successes", "crypto_overhead_percent"},
    34: {"network_oracle_passed", "network_oracle_total", "tcp_throughput_mbps", "cross_namespace_or_authority_bypass_count"},
    35: {"event_oracle_passed", "event_oracle_total", "lost_wakeup_count", "invalid_fd_acceptances"},
    36: {"systemd_feature_probe_passed", "systemd_feature_probe_total", "cgroup_limit_escape_successes", "unsupported_security_fake_success_count"},
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
    if not isinstance(hard_zero, list) or not hard_zero:
        fail(f"Step {step}: hard_zero_metrics must be non-empty")
    if not set(hard_zero) <= set(names):
        fail(f"Step {step}: hard-zero metric not declared in metrics")
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


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_step(step)
    print("WAVE_D_SCIENTIFIC_ENDPOINTS_OK steps=32,33,34,35,36")
    print("scientific-endpoints: NOTE: DESIGN_CONTRACT validation is not runtime measurement")


if __name__ == "__main__":
    main()
