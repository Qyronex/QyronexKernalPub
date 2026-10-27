#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

EXPECTED_VCPUS = [1, 2, 4, 8, 16]


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step24/stress_profiles.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("deterministic_seed"), int):
        raise SystemExit("invalid Step24 profile schema/seed")
    required_metrics = set(data.get("required_metrics", []))
    required_workloads = set(data.get("required_workloads", []))
    if not required_metrics or not required_workloads:
        raise SystemExit("Step24 required metrics/workloads must be non-empty")
    profiles = data.get("profiles")
    if not isinstance(profiles, list) or [p.get("vcpus") for p in profiles] != EXPECTED_VCPUS:
        raise SystemExit("Step24 must define exact 1/2/4/8/16-vCPU profiles")
    seen_ids = set()
    for profile in profiles:
        pid = profile.get("id")
        if not pid or pid in seen_ids:
            raise SystemExit(f"duplicate/missing profile id: {pid!r}")
        seen_ids.add(pid)
        if not isinstance(profile.get("numa_nodes"), int) or profile["numa_nodes"] < 1:
            raise SystemExit(f"{pid}: invalid NUMA node count")
        if not isinstance(profile.get("duration_sec"), int) or profile["duration_sec"] < 60:
            raise SystemExit(f"{pid}: duration must be >=60s")
        if not isinstance(profile.get("repetitions"), int) or profile["repetitions"] < 3:
            raise SystemExit(f"{pid}: repetitions must be >=3")
        if not required_workloads <= set(profile.get("workloads", [])):
            raise SystemExit(f"{pid}: missing required workloads")
        if not required_metrics <= set(profile.get("metrics", [])):
            raise SystemExit(f"{pid}: missing required metrics")
    targets = data.get("acceptance_targets", {})
    for key in ("giant_global_lock_forbidden", "record_raw_samples", "record_exact_tested_commit", "record_qemu_argv"):
        if targets.get(key) is not True:
            raise SystemExit(f"Step24 target {key} must be true")
    print(f"STEP24_PREP_OK profiles={len(profiles)} seed={data['deterministic_seed']}")


if __name__ == "__main__":
    main()
