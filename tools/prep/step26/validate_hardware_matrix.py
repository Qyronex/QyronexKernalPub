#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

VALID_STATES = {"PLANNED", "IN_PROGRESS", "EVIDENCE_COMPLETE", "ACCEPTED"}


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step26/hardware_matrix_template.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("platforms"), list) or not data["platforms"]:
        raise SystemExit("invalid Step26 hardware matrix schema")
    required_evidence = set(data.get("required_fields_for_accepted_proof", []))
    if not required_evidence:
        raise SystemExit("Step26 accepted-proof evidence fields must be declared")
    ids = set()
    accepted = 0
    planned = 0
    for platform in data["platforms"]:
        pid = platform.get("platform_id")
        if not pid or pid in ids:
            raise SystemExit(f"duplicate/missing platform id: {pid!r}")
        ids.add(pid)
        if platform.get("architecture") != "aarch64":
            raise SystemExit(f"{pid}: architecture must be aarch64")
        state = platform.get("proof_state")
        if state not in VALID_STATES:
            raise SystemExit(f"{pid}: invalid proof_state")
        if state == "PLANNED":
            planned += 1
        if platform.get("gicv3") != "REQUIRED" or platform.get("psci") != "REQUIRED":
            raise SystemExit(f"{pid}: GICv3/PSCI requirements must remain explicit")
        if not platform.get("firmware_boot") or not platform.get("device_inventory"):
            raise SystemExit(f"{pid}: firmware/device inventory must be non-empty")
        if not platform.get("unsupported_declarations"):
            raise SystemExit(f"{pid}: unsupported-feature declarations required")
        evidence = platform.get("evidence", {})
        if state == "ACCEPTED":
            accepted += 1
            missing = sorted(k for k in required_evidence if not evidence.get(k))
            if missing:
                raise SystemExit(f"{pid}: ACCEPTED without evidence fields {missing}")
        smmu = platform.get("smmuv3", {})
        if smmu.get("presence") not in {"UNKNOWN", "PRESENT", "ABSENT"}:
            raise SystemExit(f"{pid}: invalid SMMUv3 presence")
        if smmu.get("proof_state") not in VALID_STATES:
            raise SystemExit(f"{pid}: invalid SMMUv3 proof_state")
    print(f"STEP26_PREP_OK platforms={len(ids)} planned={planned} accepted={accepted}")


if __name__ == "__main__":
    main()
