# PREP manifest — Step 32

Status: `PREP_IN_PROGRESS`

## Runtime target

Unchanged Debian 13 ARM64 userspace gets `/dev` baseline, serial console, TTY/PTY, termios subset, devpts-facing identities and shell job-control behavior.

## Dependency release condition

Runtime integration starts only after Step 31 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step32/tty_pty_reference_vectors.json` — TCGETS/TIOCGWINSZ, invalid-pointer/ioctl, PTY child-shell and stale-generation vectors.
- `tests/qemu-prep/step32/pty_probe.c` — reference probe for `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/console`, `/dev/ptmx`, termios flags/size/NCCS/control bytes/speeds, winsize, ioctl errno behavior, controlling TTY/foreground pgrp, real `/bin/sh` PTY exchange, `getrandom`, `/dev/urandom` and nonblocking `/dev/random` readiness.
- `tools/qemu-prep/step32/build_run_pty_probe.sh` — warning-clean reference-probe build/run helper.
- `tools/qemu-prep/step32/collect_tty_reference.sh` — fail-closed collector that runs only on Debian 13 AArch64, binds the exact Kernal source commit and pinned target identity, and records the probe transcript outside the worktree by default. It accepts `KERNAL_STEP32_SOURCE_COMMIT` for the canonical `git archive` guest transport (which intentionally has no `.git` directory); when Git metadata is present, an explicit SHA must match checked-out `HEAD`.
- `tests/qemu-prep/step32/reference_transport_contract.json` — machine-readable contract for the exact `git archive` payload, source-SHA environment handoff, guest collector invocation and raw/normalized artifacts that the shared Debian transport must return.
- `tools/qemu-prep/step32/validate_reference_transport_contract.py` plus `tests/qemu-prep/step32/test_reference_transport_contract.py` — fail-closed drift checks binding that handoff to the pinned target and current Step-32 collector/normalizer without modifying shared transport code.
- `tools/qemu-prep/step32/normalize_tty_reference.py` — converts one collected transcript into `kernal-step32-debian13-tty-reference-v1` JSON with raw SHA-256, compiler identity, termios/winsize/entropy values and required PTY proof markers.
- `tools/qemu-prep/step32/verify_tty_reference_evidence.py` plus `tests/qemu-prep/step32/test_verify_tty_reference_evidence.py` — host-side fail-closed review that recomputes normalized JSON from the returned raw transcript and requires exact source SHA, pinned target SHA-256 and raw SHA-256 agreement before PREP promotion.
- `tests/qemu-prep/step32/test_normalize_tty_reference.py` — parser regressions for valid Debian 13/AArch64 data, wrong architecture, missing job-control proof and `/dev/random` EAGAIN behavior.
- Existing reference input: `tests/debian13/evidence/reference-syscalls.json` already observes `TCGETS`, `TIOCGWINSZ`, `/dev/console` and `/dev/null` consumers.
- Cross-step owner map: `docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md`.

## Still to collect before PREP_READY

- extend/release the canonical Debian reference transport to implement `tests/qemu-prep/step32/reference_transport_contract.json` exactly: include its five archive inputs, inject the exact 40-character source SHA through `KERNAL_STEP32_SOURCE_COMMIT`, execute the declared collector inside the pinned Debian 13 ARM64 guest, and return both declared artifacts; this one run supplies exact `/dev/null`/`zero`/`full`/`console` baseline semantics, termios/control-byte/speed behavior, PTY master/slave + foreground-pgrp transcript, and entropy-device readiness/fallback behavior;
- run `verify_tty_reference_evidence.py` against the returned raw + normalized pair and the exact requested source SHA; only a `STEP32_REFERENCE_EVIDENCE_OK` result may bind raw SHA-256/source SHA/target SHA into the PREP handoff, after which this manifest may change to `PREP_READY`.

Synthetic parser fixtures and host/macOS output do not satisfy this reference requirement.

## Prep focus

- reference traces for `/dev/null`, `/dev/zero`, `/dev/full`, entropy devices and `/dev/console`;
- termios/ioctl behavior required by pinned shell/systemd corpus;
- PTY allocation/lifetime and `/dev/ptmx` oracle;
- foreground pgrp/session error and signal behavior;
- QEMU PL011 serial-console proof markers.

## Canonical owners to consume

Existing AArch64 serial/PL011 owner, Step-30 process-group/session/signal owners, Step-29 VFS + FD/OFD, scheduler and entropy owner.

## Forbidden duplicates

No second console, process-group/session registry, VFS, FD table, scheduler, signal queue or UART driver.

## Integration landing order

1. architecture-neutral device kinds and FD semantics;
2. TTY state/termios queues;
3. AArch64 serial adapter to existing PL011;
4. PTY/devpts identities;
5. process job-control composition;
6. QEMU dynamic-shell + PTY acceptance.

## Acceptance probes

Interactive serial shell; canonical/raw input subset; PTY child shell data exchange; foreground/background behavior; malformed ioctl/stale PTY/bad pointer fail closed; entropy readiness truthful.

## Handoff freshness

Stale if canonical FD/OFD, VFS, Step-30 job-control/signal, PL011 or scheduler interfaces move incompatibly.
