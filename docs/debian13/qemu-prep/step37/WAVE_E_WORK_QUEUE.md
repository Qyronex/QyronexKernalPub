# Wave E PREP work queue — Steps 37–40

Lane: `prep-wave-e-37-40`
Branch: `agent/prep-wave-e-37-40-arm64`
Runtime authority: **none** — PREP only.
Reference PREP snapshot: `7b8cd67ce5d5c3243cf64a843454b28750a180d0` (validated historical `agent/qemu-prep-roadmap-arm64` handoff).

## Objective

Drive Steps 37–40 from staged design toward `PREP_READY` without touching production kernel owners. Reuse the immutable QEMU/Debian PREP snapshot above as read-only input and copy/normalize only artifacts that belong to the declared Step 37–40 WRITE scope. Do not follow the moving QEMU control branch for step-local content after this snapshot.

## Work order

1. **Step 37 — systemd PID 1**
   - complete PID1 boot requirement/dependency/owner/landing maps;
   - pin first-failure classification and service lifecycle scenarios;
   - add reboot/poweroff and failure-path fixtures;
   - enumerate runtime-only canonical-owner edits.
2. **Step 38 — udev/sysfs/uevent**
   - complete device visibility and lifecycle contracts for console/block/NIC;
   - pin consumed sysfs attributes and uevent expectations;
   - add add/remove/stale-authority negatives and validators;
   - enumerate runtime-only sysfs/device owner edits.
3. **Step 39 — dpkg/apt durability**
   - pin package/version/hash/reference transaction inputs;
   - complete locking, rename, fsync, xattr/ACL and recovery scenarios;
   - add failure-injection and rollback corpus;
   - enumerate runtime-only VFS/storage owner edits.
4. **Step 40 — final Debian 13 ARM64 QEMU acceptance bundle**
   - finalize exact machine/QEMU/rootfs/evidence schema contract;
   - prepare repeated-boot, systemctl, package, network, reboot/poweroff checks;
   - build machine-readable first-failure routing and regression matrix;
   - enumerate all remaining runtime-only dependencies without claiming acceptance.

## PREP_READY gate per step

A step is not ready until it has all of: requirement map, dependency map, canonical owner map, conflict/write-scope map, integration landing map, deterministic fixtures/oracles, negative corpus, executable or machine-readable validator, acceptance manifest, runtime-only gap list, and a frozen handoff record.

Prose-only preparation does not count.

## Hard boundaries

Do not edit production `kernel/**`, Cargo/workspace state, `xtask/**`, Process/Thread/PID/TID, scheduler, AddressSpace, VFS/FD/OFD, ELF loader, usercopy, IRQ/DMA or network-stack authorities. Stop at the integration boundary and record the exact future landing owner instead.

Step 30.7 retains priority for shared owners and QEMU/runner capacity. Host-only PREP work should continue when runtime gates are busy.
