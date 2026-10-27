# PREP manifest — Step 37

Status: `PREP_IN_PROGRESS`

## Runtime target

Boot the pinned unchanged Debian 13 ARM64 userspace with Debian's own systemd as PID 1 and reach a documented server target.

## Dependency release condition

Runtime integration starts only after Step 36 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step37/systemd_pid1_boot_markers.json` — deterministic PID1/target/service/reboot/poweroff markers plus first-failure classification record.
- `tools/qemu-prep/step37/collect_pid1_reference.sh` — fail-closed Debian-13/Trixie/AArch64 PID1-systemd collector binding exact Kernal source SHA and pinned target identity. It records PID1/systemd package identity, default target, dependency/critical-chain evidence, running/failed units, candidate service properties, Debian package/version ownership, journal diagnostics and raw SHA-256 evidence. An intentional transient failed-service diagnostic run is disabled by default and requires explicit confirmation.
- `tools/qemu-prep/step37/classify_pid1_reference.py` — normalizes manager/boot evidence and service candidates. A final service set is accepted only when exactly three unique units are loaded, active, manually startable/stoppable, backed by a Debian package and not in the critical-unit exclusion set (`dbus`, journald, udevd, logind, remount-fs).
- `tests/qemu-prep/step37/test_pid1_reference_contract.py` — regressions for exact three-service freezing, critical-unit exclusion, package identity and collector provenance/failure-probe gates.
- `tools/qemu-prep/step37/exercise_service_lifecycle.sh` — guarded start/stop/restart oracle consuming only a source-SHA-matching normalized reference with `FROZEN_THREE_SERVICES`. It requires explicit lifecycle + console-session confirmation and installs an EXIT/INT/TERM restore trap before mutating any selected service.
- `tools/qemu-prep/step37/trigger_shutdown_reference.sh` — guarded `reboot|poweroff` trigger binding exact source/target identity, writing and syncing a pre-trigger marker, then issuing the normal systemd request. The marker explicitly is not completion evidence; the host/QEMU harness must prove the requested transition completed.
- `tests/qemu-prep/step37/test_lifecycle_shutdown_contract.py` — safety regressions for frozen-reference binding, restore-before-mutation and shutdown marker/confirmation order.
- `tests/qemu-prep/step37/first_failure_routing.json` + `tools/qemu-prep/step37/classify_first_failure.py` — stable first-mandatory-failure router: process regressions -> Step 30, loader/TLS -> 31, TTY -> 32, storage/mount -> 33, networking -> 34, modern event APIs -> 35, cgroup/namespace/security -> 36. udev/package-manager classes before their future steps are reported as `ROADMAP_DEPENDENCY_CONFLICT`; unknown classes return `UNCLASSIFIED_STOP` rather than fake success.
- `tests/qemu-prep/step37/test_first_failure_routing.py` — regressions for canonical-owner routing, future-step dependency conflict, unknown-stop and mandatory-only input.
- `docs/debian13/qemu-prep/REFERENCE_REQUIREMENT_MAP.md` — current systemd `--version` requirements are explicitly classified as shallow evidence, not PID1 proof.
- `docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md` — every Step-37 blocker routes back to existing Step-30–36 owners; no `systemd` kernel subsystem.

## Still to collect before PREP_READY

- run `collect_pid1_reference.sh` on the exact pinned Debian 13 ARM64 reference guest, retain the source/target-bound evidence, and normalize it with `classify_pid1_reference.py`;
- from the collected eligible ordinary services, freeze exactly three units with package/version identities using three explicit `--service` selections. Feed this same frozen set back into the Step-36 collector through `KERNAL_STEP36_UNITS` so Step 36 and Step 37 share one service requirement set rather than drifting;
- rerun the PID1 collector with `KERNAL_STEP37_RUN_FAILURE_PROBE=1 KERNAL_REFERENCE_FAILURE_PROBE_CONFIRMED=1` and retain failed-service status + journal + reset evidence;
- from a confirmed local/console reference session, run `exercise_service_lifecycle.sh` against the frozen normalized reference and retain start/stop/restart state + hashes for all three services;
- in separate disposable QEMU reference boots, invoke `trigger_shutdown_reference.sh reboot` and `... poweroff` with explicit confirmation. The host/QEMU harness must retain the serial pre-trigger marker and independently prove reboot continuation / clean QEMU poweroff; a guest-side marker alone is insufficient;
- bind the default-target dependency/critical-chain evidence and the prepared first-failure routing matrix into the frozen handoff. If the normal Step-37 target reveals a mandatory future-step (`udev`/package-manager) dependency, stop and resolve the roadmap dependency rather than pulling that implementation forward silently.

Synthetic/macOS systemd behavior, package guesses or process/unit-name kernel special cases cannot satisfy these reference requirements.

## Prep focus

- deterministic systemd boot trace on reference Debian 13 ARM64;
- ordered list of first mandatory failures by syscall/ioctl/proc/sys/device/mount/cgroup/event/network contract;
- service lifecycle fixtures for exactly three ordinary services;
- shutdown/reboot oracle;
- diagnostics/journal/console expectations for failed services;
- machine-readable blocker classifier linking every failure to the owning prior step.

## Canonical owners to consume

All accepted Step 30–36 owners. No systemd-specific kernel subsystem is allowed.

## Forbidden duplicates

No process-name special cases, fake-success syscalls, shadow service manager, duplicate cgroup/event/device/network/VFS state.

## Integration landing order

1. boot exact pinned rootfs with systemd PID 1;
2. capture first deterministic mandatory failure;
3. reproduce reference behavior;
4. fix the smallest canonical owner;
5. update compatibility matrix;
6. repeat until target reached;
7. run service lifecycle + clean shutdown acceptance.

## Acceptance probes

Unchanged systemd PID 1; documented basic/multi-user server target; three services start/stop/restart; failed services remain diagnosable; clean poweroff/reboot; no Debian binary patched for Kernal.

## Handoff freshness

Stale if pinned Debian snapshot/systemd version changes or any Step 30–36 public contract changes incompatibly, or the frozen three-service package/unit identity changes.
