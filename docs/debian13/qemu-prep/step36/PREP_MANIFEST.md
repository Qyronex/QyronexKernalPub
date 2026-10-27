# PREP manifest — Step 36

Status: `PREP_IN_PROGRESS`

## Runtime target

Provide the minimum namespaces, cgroups v2, rlimits and Linux security-facing behavior required by unchanged Debian 13 ARM64 systemd without weakening Kernal capability authority.

## Dependency release condition

Runtime integration starts only after Step 35 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step36/systemd_feature_classification.json` — existing observed cgroup/rlimit/prctl/security probes plus REQUIRED/OPTIONAL_UNTIL_PROVEN classification rules.
- `tests/qemu-prep/step36/security_api_probe.c` + `tools/qemu-prep/step36/build_run_security_probe.sh` — read-only Linux reference probe for `PR_GET_SECUREBITS`, no-new-privs/seccomp state, capability bounding-set visibility, `SECCOMP_GET_ACTION_AVAIL`, process-keyring lookup, audit netlink socket availability, BPF next-id query and namespace FD visibility. The probe records success/error behavior without enabling seccomp, creating BPF programs or widening authority.
- `tests/qemu-prep/step36/resource_enforcement_probe.py` — isolated cgroup-v2 reference probes for bounded pids/fork failure, CPUQuota throttling and a MemoryMax process that is expected not to survive an intentionally oversized allocation.
- `tools/qemu-prep/step36/collect_systemd_feature_reference_strict.sh` — canonical fail-closed Debian-13/Trixie/AArch64 PID1-systemd collector. It binds exact Kernal source SHA and pinned target identity, captures PID1 capability/seccomp/rlimit/cgroup state, root cgroup-v2 files, selected service sandbox/resource properties and read-only security API results. Resource enforcement is disabled by default and requires both `KERNAL_STEP36_RUN_ENFORCEMENT=1` and `KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED=1` before transient `systemd-run` units may execute.
- `tools/qemu-prep/step36/collect_systemd_feature_reference.sh` — compatibility alias delegating to the strict collector so there is only one evidence policy.
- `tools/qemu-prep/step36/classify_systemd_feature_reference.py` — normalizes cgroup controllers, PID1 capability/seccomp state, security API fallback/error observations, selected-unit sandbox properties and inferred namespace requirements. It requires the exact Step-37 service set to be re-run before PREP_READY rather than guessing global namespace requirements.
- `tests/qemu-prep/step36/test_systemd_feature_reference_contract.py` — regressions for classification, missing security evidence, source/target/PID1 guards, opt-in enforcement, single collector policy and bounded resource-probe cleanup.
- Existing reference evidence already shows `/sys/fs/cgroup/`, `/proc/sys/kernel/cap_last_cap`, `prlimit64`, `prctl` and security-filesystem feature probes from systemd and related dynamic consumers.
- `docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md` — namespace/cgroup/rlimit/capability-owner composition rules.

## Still to collect before PREP_READY

- run the strict collector on the exact pinned Debian 13 ARM64 reference guest with PID 1 = systemd and retain the source/target-bound normalized result, including root cgroup-v2 controllers, PID1 capability/seccomp state and read-only seccomp/keyring/audit/BPF fallback observations;
- rerun with `KERNAL_STEP36_UNITS` set to the exact Step-37 ordinary service set once that set is frozen. Review the resulting sandbox properties and bind only the namespace domains actually required by those units;
- on an explicitly approved disposable/reference run, set `KERNAL_STEP36_RUN_ENFORCEMENT=1 KERNAL_REFERENCE_ENFORCEMENT_CONFIRMED=1` and retain the pids failure, CPU throttling and MemoryMax termination evidence. A nonzero memory-run status is not sufficient alone: the evidence must also show the process did not print the prepared `memory.enforcement-process-survived` marker and must be reviewed with the cgroup/unit logs;
- bind the selected-unit capability/securebits matrix and explicit security-API fallback/error results into the frozen Step-36 handoff. If a currently OPTIONAL_UNTIL_PROVEN API appears mandatory in the actual pinned systemd/service trace, prepare its bounded compatibility contract before marking PREP_READY.

Synthetic/macOS behavior and a report-only resource limit are not Step-36 reference evidence.

## Prep focus

- trace pinned systemd/dbus/udev namespace/cgroup/security probes;
- classify each probe REQUIRED, OPTIONAL_WITH_FALLBACK or UNSUPPORTED;
- reference cgroup v2 hierarchy/membership/controller behavior;
- CPU/memory/pids enforcement fixtures;
- rlimit/prlimit oracle;
- Linux capability/securebits observable behavior matrix;
- explicit errno/fallback corpus for unsupported seccomp/keyring/audit/BPF calls.

## Canonical owners to consume

Process identity/lifecycle, scheduler/accounting, VM/memory owner, mount/VFS owner, network owner, Step-30 credentials and capability/object authority.

## Forbidden duplicates

No shadow Process table, scheduler/accounting tree, mount/network namespace state disconnected from canonical owners, or Linux-capability path that grants Kernal object authority.

## Integration landing order

1. target feature oracle;
2. generation-safe namespace identities only where mandatory;
3. cgroup v2 hierarchy + required controllers;
4. rlimit enforcement at canonical resource owners;
5. Linux capability/securebits view;
6. unsupported-security fallback matrix;
7. systemd feature-probe QEMU acceptance.

## Acceptance probes

Systemd mandatory feature detection passes; selected CPU/memory/pids limits are enforced; stale namespace/cgroup/process generations fail closed; unsupported security calls never silently broaden authority.

## Handoff freshness

Stale if Process, scheduler/accounting, VM, mount/VFS, network or Step-30 credential/capability interfaces move incompatibly, or the selected systemd target profile changes.
