# PREP manifest — Step 35

Status: `PREP_IN_PROGRESS`

## Runtime target

Provide the modern Linux descriptor/event APIs required by the pinned Debian 13 ARM64 systemd/dbus workload: epoll, eventfd, timerfd, signalfd, required inotify, memfd/seals, required pidfd operations and observed housekeeping syscalls.

## Dependency release condition

Runtime integration starts only after Step 34 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step35/event_fd_reference_vectors.json` — level/edge/oneshot epoll, fd reuse, eventfd, timerfd, signalfd, inotify, memfd, pidfd and observed `close_range` vectors.
- `tests/qemu-prep/step35/event_fd_probe.c` — deterministic Linux reference probe for level/edge/oneshot epoll, old-watch FD-number reuse rejection, eventfd EAGAIN/counter readiness, timerfd readiness/count, signalfd masked delivery, inotify create/move/delete, memfd seals/EPERM, pidfd_open + child-exit readiness and close_range/EBADF.
- `tools/qemu-prep/step35/build_run_event_probe.sh` — warning-clean reference probe build/run helper.
- `tools/qemu-prep/step35/collect_event_fd_reference.sh` — fail-closed Debian-13/Trixie/AArch64 collector binding exact source SHA and pinned target identity; runs the complete probe and, when `strace` is available, records only the selected modern event/pidfd syscall family for the probe plus read-only `systemctl list-units` and `busctl --system list` consumers.
- `tools/qemu-prep/step35/classify_event_fd_reference.py` — normalizes exact probe pass/readiness/errno semantics and separately reports the union of actually observed systemd/dbus event API syscalls. Absence from one trace is explicitly not treated as proof that a syscall is globally unnecessary.
- `tests/qemu-prep/step35/test_event_fd_reference_contract.py` — regressions for normalization, missing readiness markers and the collector's source/target/read-only consumer contract.
- `docs/debian13/qemu-prep/REFERENCE_REQUIREMENT_MAP.md` — identifies where current shallow Debian evidence is insufficient and deeper event-fd reference runs are required.
- `docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md` — single readiness/event owner landing rule.

## Still to collect before PREP_READY

- on the exact pinned Debian 13 ARM64 reference guest, run `collect_event_fd_reference.sh` and retain the source/target-bound hashes and probe transcript; this supplies the Linux return/errno/readiness sequences for the prepared event vectors;
- classify the result with `classify_event_fd_reference.py` and retain both systemd and dbus consumer traces so the exact epoll mode/eventfd/timerfd/signalfd/memfd/close_range subset actually observed by the pinned corpus is separated from the broader explicit compatibility probe;
- review `pidfd_open_supported` and the observed consumer syscall set. Keep pidfd runtime scope limited to the operations observed mandatory by the pinned target plus the prepared lifecycle semantics; do not infer `pidfd_send_signal` support merely because the collector can trace it;
- bind the normalized artifact/raw trace hashes into the frozen Step-35 handoff, then change the manifest to `PREP_READY` only if no additional unprepared mandatory event API is revealed.

Synthetic/macOS behavior is not Step-35 reference evidence.

## Prep focus

- reference traces for epoll level/edge/oneshot behavior actually used by the pinned corpus;
- close/reuse/stale-generation negative cases;
- eventfd/timerfd/signalfd ABI fixtures and errno matrix;
- inotify create/rename/delete oracle;
- memfd/seal probes;
- pidfd lifecycle/generation probes;
- combined systemd/dbus prerequisite test corpus.

## Canonical owners to consume

Canonical FD/OFD, scheduler/wakeup, time/deadline, signal, VFS mutation, VM and Process identity owners.

## Forbidden duplicates

No second FD table, signal queue, timer wheel, process registry, VFS watcher state disconnected from canonical VFS, or scheduler readiness owner.

## Integration landing order

1. one pollable/readiness-source contract;
2. epoll owner;
3. eventfd + timerfd;
4. signalfd;
5. inotify;
6. memfd/seals;
7. pidfd only if the pinned target requires it;
8. combined QEMU acceptance.

## Acceptance probes

Combined epoll/timerfd/eventfd/signalfd test; stale descriptor/process generations fail closed; close/reuse cannot redirect old watches; documented inotify cases; memfd seals; required pidfd lifecycle; unsupported flags return Linux-compatible errors.

## Handoff freshness

Stale if FD/OFD generation rules, scheduler readiness, time, signal, VFS event, VM or Process identity interfaces move incompatibly.
