#!/usr/bin/env python3
"""Validate the Debian 13 ARM64 QEMU PREP control plane.

This is a host-side preparation gate only. A green result never grants runtime
WRITE authority and never counts as Step 31-40 runtime acceptance evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_STEPS = list(range(31, 41))
EXPECTED_STEP_SET = set(EXPECTED_STEPS)
ALLOWED_PREP_STATES = {"PREP_OPEN", "PREP_ACTIVE", "PREP_READY", "PREP_RECONCILE"}
ALLOWED_RUNTIME_STATES = {"RUNTIME_LOCKED", "RUNTIME_ACTIVE", "ACCEPTANCE", "ACCEPTED"}
ALLOWED_TRANSPORTS = {"virtio-mmio", "virtio-pci"}
ALLOWED_QUEUE_STATES = {
    "READY",
    "WAITING_PREP_RECONCILE",
    "WAITING_REFERENCE_RUN",
    "WAITING_RUNTIME_RELEASE",
    "DONE",
}
EXPECTED_PARALLEL_LANES = {
    "qemu-boot-prep-wave": "agent/qemu-prep-roadmap-arm64",
    "prep-wave-d-32-36": "agent/prep-wave-d-32-36-arm64",
    "prep-wave-e-37-40": "agent/prep-wave-e-37-40-arm64",
}


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    require(isinstance(value, dict), f"top-level JSON value must be an object: {path}")
    return value


def target_id_from_target_manifest(target: dict[str, Any]) -> str:
    target_id = target.get("target_id")
    require(isinstance(target_id, str) and target_id, "arm64 target_id must be a non-empty string")
    return target_id


def validate_profile(profile: dict[str, Any], target_id: str) -> None:
    require(profile.get("schema_version") == 1, "QEMU boot profile schema_version must be 1")
    require(profile.get("target_id") == target_id, "QEMU boot profile target_id does not match arm64 target")
    source_sha = profile.get("baseline_source_sha")
    require(
        isinstance(source_sha, str)
        and len(source_sha) == 40
        and all(ch in "0123456789abcdef" for ch in source_sha),
        "baseline_source_sha must be a full lowercase 40-character SHA",
    )
    baseline = profile.get("baseline_provenance")
    require(isinstance(baseline, dict), "baseline_provenance must be an object")
    require(baseline.get("machine") == "virt,gic-version=3", "baseline QEMU machine drifted unexpectedly")
    require(baseline.get("cpu_matrix") == [1, 2, 4], "baseline CPU matrix must remain [1, 2, 4]")
    rootfs = profile.get("rootfs")
    require(isinstance(rootfs, dict), "profile rootfs must be an object")
    require(rootfs.get("write_policy") == "never_write_pinned_base_directly", "pinned rootfs must remain immutable")
    strategy = profile.get("boot_critical_device_strategy")
    require(isinstance(strategy, dict), "boot_critical_device_strategy must be an object")
    preferred = strategy.get("preferred_transport")
    fallback = strategy.get("fallback_transport")
    require(preferred in ALLOWED_TRANSPORTS, f"unknown preferred transport: {preferred!r}")
    require(fallback in ALLOWED_TRANSPORTS, f"unknown fallback transport: {fallback!r}")
    require(preferred != fallback, "preferred and fallback transports must differ")


def validate_status(status: dict[str, Any], target_id: str, root: Path) -> None:
    require(status.get("schema_version") == 2, "PREP status schema_version must be 2")
    require(status.get("authority") == "OWNER_PREPARATION_DOCTRINE.md", "PREP status authority must be OWNER_PREPARATION_DOCTRINE.md")
    require(status.get("target_id") == target_id, "PREP status target_id does not match arm64 target")
    require(status.get("critical_path") == [30] + EXPECTED_STEPS, "critical_path must be exactly Step 30 through Step 40")
    require(set(status.get("prep_states", [])) == ALLOWED_PREP_STATES, "PREP state enum does not match doctrine")
    require(set(status.get("runtime_states", [])) == ALLOWED_RUNTIME_STATES, "runtime state enum does not match doctrine")

    rules = status.get("global_rules")
    require(isinstance(rules, dict), "global_rules must be an object")
    for key in (
        "runtime_single_writer",
        "runtime_locked_does_not_block_prep",
        "prep_is_not_acceptance",
        "exact_sha_acceptance",
        "aarch64_only",
        "process_name_special_cases_forbidden",
        "fake_success_forbidden",
        "step30_runner_priority",
    ):
        require(rules.get(key) is True, f"global rule {key} must remain true")

    wave = status.get("wave_state")
    require(isinstance(wave, dict), "wave_state must be an object")
    require(wave.get("prep_state") in ALLOWED_PREP_STATES, "wave_state prep_state is invalid")
    require(wave.get("production_runtime_write_allowed") is False, "PREP wave must not gain production runtime WRITE authority")
    host_gate = wave.get("host_gate")
    if host_gate is not None:
        require(isinstance(host_gate, dict), "host_gate must be an object")
        require(host_gate.get("exit_code") == 0, "recorded host_gate must be green")
        tested_commit = host_gate.get("tested_commit")
        require(isinstance(tested_commit, str) and len(tested_commit) == 40, "host_gate tested_commit must be a full SHA")

    steps = status.get("steps")
    require(isinstance(steps, list) and len(steps) == len(EXPECTED_STEPS), "PREP status must contain exactly Steps 31-40")
    step_numbers = [entry.get("step") for entry in steps if isinstance(entry, dict)]
    require(step_numbers == EXPECTED_STEPS, "PREP status must list Steps 31-40 exactly once and in order")
    by_step = {entry["step"]: entry for entry in steps}
    for step in EXPECTED_STEPS:
        entry = by_step[step]
        require(entry.get("prep_state") in ALLOWED_PREP_STATES, f"Step {step}: invalid prep_state")
        runtime_state = entry.get("runtime_state")
        require(runtime_state in ALLOWED_RUNTIME_STATES, f"Step {step}: invalid runtime_state")
        require(runtime_state != "ACCEPTED", f"Step {step}: PREP branch must not pre-claim runtime acceptance")
        manifest = entry.get("manifest")
        require(isinstance(manifest, str) and manifest, f"Step {step}: manifest path missing")
        manifest_path = root / manifest
        require(manifest_path.is_file(), f"Step {step}: manifest not found at {manifest}")
        text = manifest_path.read_text(encoding="utf-8")
        require(f"Step {step}" in text, f"Step {step}: manifest does not identify its step")
        require("Forbidden duplicates" in text, f"Step {step}: manifest lacks Forbidden duplicates section")
        require("Acceptance probes" in text, f"Step {step}: manifest lacks Acceptance probes section")
        require("Handoff freshness" in text, f"Step {step}: manifest lacks Handoff freshness section")
    require(by_step[31].get("prep_state") == "PREP_READY", "Step 31 canonical PREP inputs must remain PREP_READY")
    for step in EXPECTED_STEPS:
        require(by_step[step].get("runtime_state") == "RUNTIME_LOCKED", f"Step {step}: runtime must remain RUNTIME_LOCKED on PREP branch")


def validate_expansion_plan(plan: dict[str, Any], target_id: str) -> None:
    require(plan.get("schema_version") == 1, "reference expansion schema_version must be 1")
    require(plan.get("target_id") == target_id, "reference expansion target_id does not match arm64 target")
    scenarios = plan.get("scenarios")
    require(isinstance(scenarios, list), "reference expansion scenarios must be an array")
    steps = [entry.get("step") for entry in scenarios if isinstance(entry, dict)]
    require(set(steps) == EXPECTED_STEP_SET and len(steps) == len(set(steps)), "reference expansion plan must contain one scenario per Step 31-40")
    for entry in scenarios:
        require(isinstance(entry, dict), "reference scenario entries must be objects")
        require(isinstance(entry.get("id"), str) and entry["id"], "reference scenario id missing")
        require(entry.get("status") in {"PLANNED", "COLLECTED", "REVIEWED"}, f"invalid scenario status for {entry.get('id')}")
        require(isinstance(entry.get("required_observables"), list) and entry["required_observables"], f"scenario {entry.get('id')} must declare required_observables")


def validate_catalog(catalog: dict[str, Any], target_id: str, root: Path) -> None:
    require(catalog.get("schema_version") == 1, "artifact catalog schema_version must be 1")
    require(catalog.get("target_id") == target_id, "artifact catalog target_id does not match arm64 target")
    items = catalog.get("artifacts")
    require(isinstance(items, list) and items, "artifact catalog must contain artifacts")
    seen_ids: set[str] = set()
    for item in items:
        require(isinstance(item, dict), "artifact catalog entries must be objects")
        artifact_id = item.get("id")
        require(isinstance(artifact_id, str) and artifact_id, "artifact id missing")
        require(artifact_id not in seen_ids, f"duplicate artifact id: {artifact_id}")
        seen_ids.add(artifact_id)
        state = item.get("state")
        require(state in {"PRESENT", "EXTERNAL_PINNED", "PLANNED"}, f"artifact {artifact_id}: invalid state {state!r}")
        path = item.get("path")
        if state == "PRESENT":
            require(isinstance(path, str) and path and (root / path).is_file(), f"artifact {artifact_id}: PRESENT path missing: {path}")


def validate_work_queue(queue: dict[str, Any], target_id: str) -> None:
    require(queue.get("schema_version") == 3, "PREP work queue schema_version must be 3")
    require(queue.get("authority") == "OWNER_PREPARATION_DOCTRINE.md", "PREP work queue authority must be OWNER_PREPARATION_DOCTRINE.md")
    require(queue.get("target_id") == target_id, "PREP work queue target_id does not match arm64 target")
    require(queue.get("lane") == "qemu-prep-parallel-program", "PREP work queue must target qemu-prep-parallel-program")
    require(queue.get("wip_limit") == 3, "parallel QEMU PREP WIP limit must be 3")
    require(set(queue.get("states", [])) == ALLOWED_QUEUE_STATES, "PREP work queue states enum is invalid")

    parallel_lanes = queue.get("parallel_lanes")
    require(isinstance(parallel_lanes, list), "parallel_lanes must be an array")
    lane_map: dict[str, dict[str, Any]] = {}
    for lane in parallel_lanes:
        require(isinstance(lane, dict), "parallel lane entries must be objects")
        lane_id = lane.get("lane")
        require(isinstance(lane_id, str) and lane_id and lane_id not in lane_map, f"duplicate or missing parallel lane: {lane_id!r}")
        lane_map[lane_id] = lane
    require(set(lane_map) == set(EXPECTED_PARALLEL_LANES), "parallel PREP lanes must be control + Wave D + Wave E")
    for lane_id, branch in EXPECTED_PARALLEL_LANES.items():
        lane = lane_map[lane_id]
        require(lane.get("branch") == branch, f"parallel lane {lane_id}: unexpected branch")
        require(isinstance(lane.get("write_scope"), list) and lane["write_scope"], f"parallel lane {lane_id}: write_scope missing")
    d_scope = "\n".join(lane_map["prep-wave-d-32-36"]["write_scope"])
    e_scope = "\n".join(lane_map["prep-wave-e-37-40"]["write_scope"])
    for step in range(32, 37):
        require(f"step{step}/**" in d_scope and f"step{step}/**" not in e_scope, f"Step {step}: Wave D/E scope separation is invalid")
    for step in range(37, 41):
        require(f"step{step}/**" in e_scope and f"step{step}/**" not in d_scope, f"Step {step}: Wave D/E scope separation is invalid")

    items = queue.get("items")
    require(isinstance(items, list) and items, "PREP work queue must contain items")
    seen_ids: set[str] = set()
    covered_steps: set[int] = set()
    ready_count = 0
    for item in items:
        require(isinstance(item, dict), "PREP work queue entries must be objects")
        item_id = item.get("id")
        require(isinstance(item_id, str) and item_id and item_id not in seen_ids, f"duplicate or missing PREP work item id: {item_id!r}")
        seen_ids.add(item_id)
        require(isinstance(item.get("priority"), int) and item["priority"] >= 0, f"work item {item_id}: priority must be a non-negative integer")
        state = item.get("state")
        require(state in ALLOWED_QUEUE_STATES, f"work item {item_id}: invalid state {state!r}")
        ready_count += int(state == "READY")
        step = item.get("step")
        require(isinstance(step, int) and (step == 0 or step in EXPECTED_STEP_SET), f"work item {item_id}: invalid step {step!r}")
        if step in EXPECTED_STEP_SET:
            covered_steps.add(step)
        owner_lane = item.get("owner_lane")
        require(owner_lane in lane_map, f"work item {item_id}: owner_lane is not declared")
        require(isinstance(item.get("allowed_write"), list) and item["allowed_write"], f"work item {item_id}: allowed_write must be non-empty")
        require(isinstance(item.get("deliverables"), list) and item["deliverables"], f"work item {item_id}: deliverables must be non-empty")
    require(covered_steps == EXPECTED_STEP_SET, "PREP work queue must cover every Step 31-40")
    require(ready_count <= queue["wip_limit"], "PREP work queue has more READY items than its WIP limit")


def validate_governance(root: Path) -> None:
    doctrine = (root / "OWNER_PREPARATION_DOCTRINE.md").read_text(encoding="utf-8")
    tasks = (root / "AGENT_TASKS.md").read_text(encoding="utf-8")
    require("Status: ACTIVE OWNER DIRECTIVE" in doctrine, "OWNER_PREPARATION_DOCTRINE.md is not active")
    require("Steps 32–44 must each have an explicit PREP package before their runtime release." in doctrine, "preparation doctrine does not require Step 32-44 PREP packages")
    require("version=4" in tasks, "AGENT_TASKS.md coordinator must be version 4")
    require("max_source_workers=8" in tasks, "coordinator v4 source-worker capacity is missing")
    for lane_id, branch in EXPECTED_PARALLEL_LANES.items():
        require(f"lane={lane_id}|{branch}|ACTIVE|source-worker|none" in tasks, f"AGENT_TASKS.md lacks active lane {lane_id}")
        require(f"gates={lane_id}|shell-check" in tasks, f"AGENT_TASKS.md lacks shell-check gate for {lane_id}")
    require("lease=qemu-boot-prep-wave|" in tasks and "|qemu-boot-prep-wave|WRITE|qemu-prep-roadmap-arm64" in tasks, "AGENT_TASKS.md lacks QEMU control WRITE lease")
    require("lease=prep-wave-d-32-36|" in tasks and "|prep-wave-d-32-36|WRITE|prep-wave-d-32-36-arm64" in tasks, "AGENT_TASKS.md lacks Wave D WRITE lease")
    require("lease=prep-wave-e-37-40|" in tasks and "|prep-wave-e-37-40|WRITE|prep-wave-e-37-40-arm64" in tasks, "AGENT_TASKS.md lacks Wave E WRITE lease")
    for step in range(32, 41):
        require(f"lane=step{step}-runtime|main|WAIT|reference|" in tasks, f"AGENT_TASKS.md must keep Step {step} runtime dependency-locked")


def validate(root: Path) -> None:
    target = load_json(root / "docs/debian13/arm64-target.json")
    target_id = target_id_from_target_manifest(target)
    validate_profile(load_json(root / "docs/debian13/qemu-prep/QEMU_BOOT_PROFILE.json"), target_id)
    validate_status(load_json(root / "docs/debian13/qemu-prep/PREP_STATUS.json"), target_id, root)
    validate_expansion_plan(load_json(root / "docs/debian13/qemu-prep/REFERENCE_EXPANSION_PLAN.json"), target_id)
    validate_catalog(load_json(root / "docs/debian13/qemu-prep/ARTIFACT_CATALOG.json"), target_id, root)
    validate_work_queue(load_json(root / "docs/debian13/qemu-prep/PREP_WORK_QUEUE.json"), target_id)
    validate_governance(root)
    for required in (
        "QEMU_BOOT_PREP_INDEX.md",
        "PREP_MANIFEST_TEMPLATE.md",
        "OWNER_PREPARATION_DOCTRINE.md",
        "PREP_ROADMAP_17_44.md",
        "docs/debian13/qemu-prep/README.md",
        "docs/debian13/qemu-prep/QEMU_FAST_PATH_DECISION.md",
        "docs/debian13/qemu-prep/REFERENCE_REQUIREMENT_MAP.md",
        "docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md",
        "docs/debian13/qemu-prep/PREP_WORK_QUEUE.json",
    ):
        require((root / required).is_file(), f"missing required PREP index/contract: {required}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except (ValidationError, OSError) as exc:
        print(f"qemu-prep: FAIL: {exc}", file=sys.stderr)
        return 1
    print("qemu-prep: PASS: Debian 13 ARM64 Steps 31-40 parallel PREP metadata is internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
