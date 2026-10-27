## Agent handoff

- STATE: READY_FOR_GATE | BLOCKED_SOURCE | BLOCKED_INFRA | READY_FOR_MERGE | HOLD
- LANE:
- OWNER / ROLE:
- BASE_SHA:
- HEAD_SHA:
- SOURCE_EQUIVALENT_TO:
- WRITE_LEASE:
- DEPENDENCIES:
- NEXT_SINGLE_ACTION:
- DO_NOT_TOUCH:

## Scope

- Allowed files / globs:
- FILES_CHANGED:
- Cross-owner paths changed (if any, explain why):
- Existing abstraction searched/reused:
- Supersedes / superseded by:

## Correctness / security

- SECURITY_INVARIANTS_TOUCHED:
- W^X preserved:
- Null page invariant preserved:
- Guarded stack invariant preserved:
- Owner-CPU-only scheduler mutation preserved:
- PAN/usercopy boundary preserved where applicable:
- IRQ/DMA fail-closed behavior preserved where applicable:
- New/changed `unsafe` or assembly reviewed:

## Validation

- GATES_GREEN:
- GATES_MISSING:
- Runner result IDs:
- Exact tested SHA(s):
- QEMU architecture/CPU count proven, if applicable:
- FIRST_CAUSAL_FAILURE:
- Failure class: PASS | INFRA | COMPILE | RUNTIME | UNKNOWN
- Validation not executed and why:

## Integration notes

- Candidate SHA frozen by Merge Owner:
- Main drift classification: CURRENT | DRIFT_SAFE | RESTACK_REQUIRED
- Relevant same-file overlap with main:
- Source-equivalence / patch-id evidence:
- Merge-group SHA/evidence, if used:
- Required fixed merge-SHA validation:
- Merge-owner decision:

Do not mark a worker PR ready merely because source exists. Queueing is not evidence. Exact `tested_commit` and successful required jobs are mandatory. Main behind-count alone is never a restack reason; DRIFT_SAFE branches must not be churned. A byte/source-equivalent patch may preserve prior source-review provenance, but integration evidence must still target the new exact SHA.
