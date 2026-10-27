#!/usr/bin/env python3
"""Validate scientific endpoint contracts for Wave-A Steps 17-21."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXPECTED_STEPS = range(17, 22)
REQUIRED_ENV = {"tested_commit", "architecture", "toolchain", "fixture_hashes"}
REQUIRED_METRICS = {
    17: {"enumeration_oracle_passed", "enumeration_oracle_total", "malformed_capability_chain_acceptances", "unauthorized_device_authority_transfers"},
    18: {"irq_oracle_passed", "irq_oracle_total", "unauthorized_irq_destination_successes", "storm_containment_failures"},
    19: {"dma_isolation_oracle_passed", "dma_isolation_oracle_total", "unassigned_dma_successes", "stale_iova_acceptances"},
    20: {"block_oracle_passed", "block_oracle_total", "malformed_descriptor_acceptances", "stale_or_revoked_buffer_acceptances"},
    21: {"net_transport_oracle_passed", "net_transport_oracle_total", "dma_authority_bypass_count", "malformed_descriptor_or_packet_acceptances"},
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
    if not isinstance(data.get("research_question"), str) or not data["research_question"].strip():
        fail(f"Step {step}: missing research question")
    metrics = data.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        fail(f"Step {step}: missing metrics")
    names: list[str] = []
    for metric in metrics:
        if not isinstance(metric, dict) or not isinstance(metric.get("name"), str):
            fail(f"Step {step}: malformed metric")
        if metric.get("type") not in {"integer", "number", "boolean", "string"}:
            fail(f"Step {step}: invalid metric type")
        if not isinstance(metric.get("unit"), str) or not metric["unit"]:
            fail(f"Step {step}: metric unit missing")
        names.append(metric["name"])
    if len(names) != len(set(names)):
        fail(f"Step {step}: duplicate metric names")
    missing = REQUIRED_METRICS[step] - set(names)
    if missing:
        fail(f"Step {step}: missing required metrics {sorted(missing)}")
    hard_zero = data.get("hard_zero_metrics")
    if not isinstance(hard_zero, list) or not hard_zero or not set(hard_zero) <= set(names):
        fail(f"Step {step}: invalid hard-zero metrics")
    if not isinstance(data.get("negative_controls"), list) or not data["negative_controls"]:
        fail(f"Step {step}: negative controls missing")
    env = data.get("environment_fields")
    if not isinstance(env, list) or not REQUIRED_ENV <= set(env):
        fail(f"Step {step}: incomplete environment provenance")
    if not isinstance(data.get("baseline"), dict) or not data["baseline"].get("kind"):
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


def main() -> None:
    for step in EXPECTED_STEPS:
        validate_step(step)
    print("WAVE_A_SCIENTIFIC_ENDPOINTS_OK steps=17,18,19,20,21")


if __name__ == "__main__":
    main()
