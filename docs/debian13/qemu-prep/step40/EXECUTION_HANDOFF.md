# Step 40 execution handoff — final Debian ARM64 QEMU evidence

Status: `PREP STAGED / RUNTIME HOLD`

## Authoritative PREP inputs

- acceptance contract: `tests/qemu-prep/step40/final_acceptance_schema.json`
- QEMU argv contract: `tests/qemu-prep/step40/qemu_argv_contract.json`
- strict completed-bundle validator: `tools/qemu-prep/step40/validate_final_evidence_bundle.py`
- validator regressions: `tests/qemu-prep/test_step40_evidence.py`
- global QEMU profile: `docs/debian13/qemu-prep/QEMU_BOOT_PROFILE.json`
- canonical Debian target: `docs/debian13/arm64-target.json`

Use `validate_final_evidence_bundle.py` for the completed Step-40 evidence document.

## Required result shape

The future completed evidence JSON must contain:

- `schema_version=1`;
- exact `profile_id` and `target_id` from the staged contract;
- the bounded Step-40 claim string exactly as declared;
- `exact_identity` with:
  - full lowercase 40-character Kernal source SHA;
  - Debian target id;
  - pinned rootfs SHA-512 and SHA-256;
  - QEMU version;
  - complete expanded QEMU argv as an array;
  - selected block and network transports;
  - CPU count and memory bytes;
- exactly the 21 required check IDs, each `status=PASS` plus non-empty evidence references;
- at least three repeat-boot records with contiguous `boot_index` values starting at 1;
- every repeat boot marked PASS with PASS filesystem/service/device checks.

## Validation command after runtime evidence exists

```bash
python3 tools/qemu-prep/step40/validate_final_evidence_bundle.py \
  --result <completed-step40-evidence.json>
```

A green result from this command means only that the completed evidence bundle satisfies the staged document contract. The actual Step-40 acceptance still requires:

1. accepted Steps 31–39;
2. one exact frozen Step-40 Kernal SHA;
3. all declared compile/static/QEMU gates for that SHA;
4. the real Debian workload that generated the evidence;
5. merge-owner acceptance.

## Failure routing

Step 40 owns composition and evidence, not compatibility semantics. If any required check fails:

- identify the first deterministic failing contract;
- route it to the smallest canonical Step 31–39 owner;
- do not patch Debian binaries;
- do not add Step-40-only syscall/device/filesystem/network semantics;
- after any source movement, discard the old candidate and restart the exact-SHA final chain.

## Deliberate boundary

The earlier staged draft `tools/qemu-prep/step40/validate_final_evidence.py` is not the handoff validator. The strict bundle validator named above is the one to consume for future Step-40 evidence.