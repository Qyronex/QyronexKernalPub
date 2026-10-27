# Wave D PREP work queue — Steps 32–36

Lane: `prep-wave-d-32-36`
Branch: `agent/prep-wave-d-32-36-arm64`
Runtime authority: **none** — PREP only.
Reference PREP snapshot: `7b8cd67ce5d5c3243cf64a843454b28750a180d0` (validated historical `agent/qemu-prep-roadmap-arm64` handoff).

## Objective

Drive Steps 32–36 from staged design toward `PREP_READY` without touching production kernel owners. Reuse the immutable QEMU/Debian PREP snapshot above as read-only input and copy/normalize only artifacts that belong to the declared Step 32–36 WRITE scope. Do not follow the moving QEMU control branch for step-local content after this snapshot.

## Work order

1. **Step 32 — TTY/PTTY/device**
   - complete requirement/dependency/owner/conflict/landing maps;
   - complete termios/ioctl/PTTY lifecycle fixtures and negatives;
   - add deterministic host validator(s);
   - enumerate runtime-only TTY/device owner edits.
2. **Step 33 — storage/RW root**
   - complete VirtIO-MMIO block and fallback contract;
   - complete mount/root-switch/pseudo-fs/durability fixtures;
   - validate malformed queue and persistence cases;
   - enumerate runtime-only block/VFS/fs integration edits.
3. **Step 34 — networking**
   - complete AF_UNIX, NETLINK_ROUTE, loopback, DNS, TCP/UDP contracts;
   - pin deterministic local endpoints/reference data;
   - add socket/error/rollback negatives and validators;
   - enumerate runtime-only network/socket owner edits.
4. **Step 35 — modern Linux FD APIs**
   - complete epoll/eventfd/timerfd/signalfd/inotify/memfd/pidfd corpus;
   - cover generation, close, stale descriptor, edge/oneshot and sealing negatives;
   - add executable fixture validation;
   - enumerate runtime-only FD/event-owner edits.
5. **Step 36 — cgroups/namespaces/rlimits/systemd-facing security**
   - pin required cgroup-v2/controller/namespace/rlimit/security behavior;
   - classify required behavior versus explicit supported fallback;
   - add deterministic reference fixtures and negative cases;
   - enumerate runtime-only canonical-owner edits.

## PREP_READY gate per step

A step is not ready until it has all of: requirement map, dependency map, canonical owner map, conflict/write-scope map, integration landing map, deterministic fixtures/oracles, negative corpus, executable or machine-readable validator, acceptance manifest, runtime-only gap list, and a frozen handoff record.

Prose-only preparation does not count.

## Hard boundaries

Do not edit production `kernel/**`, Cargo/workspace state, `xtask/**`, Process/Thread/PID/TID, scheduler, AddressSpace, VFS/FD/OFD, ELF loader, usercopy, IRQ/DMA or network-stack authorities. Stop at the integration boundary and record the exact future landing owner instead.

Step 30.7 retains priority for shared owners and QEMU/runner capacity. Host-only PREP work should continue when runtime gates are busy.
