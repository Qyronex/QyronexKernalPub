# Kernal — Debian 13 compatibility roadmap (Steps 27–44)

This file is the canonical **post-v0.1 extension** of `AGENT_PLAN_26.md`.

It does not replace, reorder, or weaken Steps 1–26. Steps 27–44 are blocked until Step 26 is accepted. The project must finish the multi-architecture kernel foundation, userspace, storage/network, Linux ABI baseline, security/reproducibility work and documented v0.1 hardware subset before claiming Debian compatibility work as active.

The distribution target is **Debian 13 (Trixie)** on both primary architectures, x86_64/amd64 and AArch64/arm64. Ubuntu is not a project target. The goal is Linux **userspace ABI compatibility**, not Linux kernel-module ABI compatibility. Kernal does not need to load Linux `.ko` modules. Debian programs should observe Linux-compatible syscall, process, VFS, device, networking and pseudo-filesystem behavior through Kernal's own internal architecture and capability model.

## Debian 13 compatibility definition

A claim such as "Debian 13 runs on Kernal" is allowed only for an explicitly pinned Debian 13 rootfs/repository snapshot and an explicitly documented architecture/platform matrix.

Minimum server-grade claim requires all of the following:

- an unchanged pinned Debian 13 userspace/rootfs boots on Kernal,
- `/sbin/init` is the Debian-provided systemd binary rather than a Kernal-specific replacement,
- dynamic glibc programs execute through the normal ELF/interpreter path,
- a console login or equivalent local shell works,
- filesystems can be mounted read/write with correct basic Linux semantics,
- networking works sufficiently for DNS plus outbound TCP/UDP,
- `dpkg` and `apt` can perform a documented package operation,
- services can be started/stopped by systemd,
- clean shutdown/reboot works,
- no Debian userspace binary is patched specifically for Kernal,
- unsupported syscalls/features fail explicitly with correct Linux-style errors rather than silently pretending to succeed,
- the existing W^X, null-page, guarded-stack, capability and fail-closed DMA/IRQ invariants remain intact.

QEMU is the first compatibility proof platform. Real hardware compatibility is a later acceptance layer, not a prerequisite for the first Debian 13 userspace proof.

## Target discipline

Before implementing compatibility by guesswork, maintain a machine-readable compatibility matrix for the pinned Debian 13 target. Each required syscall, ioctl, proc/sys entry, device node, mount/filesystem feature and observable semantic behavior should be one of:

- `SUPPORTED / PROVEN`,
- `SUPPORTED / UNVERIFIED`,
- `PARTIAL`,
- `ENOSYS / UNSUPPORTED`,
- `NOT REQUIRED BY PINNED TARGET`.

Trace representative Debian 13 programs on a reference Linux system where practical and use those observations as requirements, but do not reproduce Linux internals when a smaller compatible semantic implementation is sufficient.

Finish lines for this extension:

- Steps **27–31**: unchanged BusyBox plus dynamic Debian 13 glibc userspace works.
- Steps **32–36**: Linux runtime environment required by Debian 13 is present.
- Steps **37–40**: unchanged Debian 13 systemd rootfs boots and performs practical server operations in QEMU on x86_64 and AArch64.
- Steps **41–44**: broader Debian deployment, containers/desktop/hardware where documented, conformance, stress and release-quality evidence.

---

## 27 — Pin Debian 13 target and build a compatibility oracle
**Status: TODO / BLOCKED BY STEP 26**

Pin one Debian 13 rootfs/repository snapshot per primary architecture and record exact release, architecture, snapshot identity and cryptographic hashes for local test artifacts. Do not use an unversioned `latest` rootfs as acceptance evidence.

Create a compatibility harness that can run the same small program/test corpus on reference Debian 13/Linux and Kernal and compare observable results: return values, errno, signal outcome, file metadata, socket behavior and process exit status. Build an initial syscall/ioctl/procfs/sysfs requirement inventory from representative binaries including BusyBox, glibc loader, `/bin/sh`, systemd, udev, dbus, iproute2 and apt/dpkg components.

Acceptance:
- pinned amd64 and arm64 Debian 13 test roots are reproducibly identified,
- compatibility matrix exists and is generated/checked by tooling rather than maintained only as prose,
- a reference-Debian trace corpus exists for the first BusyBox/glibc/systemd smoke programs,
- unknown/unsupported operations have an explicit expected failure policy.

## 28 — Initramfs and unchanged static BusyBox shell
**Status: TODO / BLOCKED BY STEP 27**

Add a deterministic initramfs/CPIO ingestion path or equivalent immutable boot filesystem that feeds the normal VFS. Preserve ownership and bounds validation while parsing the archive. The kernel must not special-case BusyBox binaries.

Provide the Linux semantics required for a statically linked BusyBox to become PID 1 or to be launched by a minimal init, including console stdin/stdout/stderr, executable lookup and basic environment/argv handling.

Acceptance on x86_64 and AArch64:
- unchanged static BusyBox ELF is loaded from initramfs,
- `/bin/sh` reaches an interactive serial console,
- `echo`, `cat`, `ls`, `mkdir`, `pwd` and a small shell script execute without Kernal-specific binary patches,
- malformed CPIO entries cannot escape bounds or create illegal VFS state.

## 29 — Linux path, file-descriptor and directory semantics
**Status: TODO / BLOCKED BY STEP 28**

Complete the ordinary filesystem semantics expected by shells and core utilities: cwd/root path resolution, symlinks, `openat`/`openat2`, read/write/pread/pwrite, seek, close/dup/fcntl, pipes, `getdents64`, stat families, directory and link operations, modes/umask/basic ownership/timestamps and descriptor inheritance across exec.

Acceptance:
- a BusyBox filesystem regression script passes on both architectures,
- pipelines and descriptor redirection work,
- directory traversal and symlink edge cases match the reference corpus,
- bad user pointers and invalid FDs return Linux-compatible errors without kernel panic.

## 30 — Linux process lifecycle, exec, wait, signals and credentials
**Status: TODO / BLOCKED BY STEP 29**

Implement `execve`/`execveat`, the clone/fork/vfork subset required by the target, wait/zombie/reaping behavior, process groups/sessions, signal delivery and architecture-correct signal frames, uid/gid credentials, robust lists, thread-exit semantics and required `prctl` behavior.

Acceptance:
- BusyBox shell can execute foreground/background child processes and pipelines,
- exit status and signal termination are observable through wait APIs,
- signal regression corpus passes on x86_64 and AArch64,
- malformed signal frames fail closed.

## 31 — Debian 13 dynamic glibc ELF, TLS, auxv and runtime bootstrap
**Status: TODO / BLOCKED BY STEP 30**

Support the dynamic-loader behavior required by Debian 13: `PT_INTERP`, PIE/ET_DYN mappings, argc/argv/envp/auxv, x86_64 FS/TLS and AArch64 `TPIDR_EL0`, `AT_RANDOM`, IDs, program-header metadata, getrandom, robust futex/thread startup and safe fallback for optional features such as rseq/vDSO when not yet implemented.

Acceptance:
- unchanged dynamically linked glibc hello runs on both architectures,
- selected unchanged Debian 13 core utilities execute through Debian's normal dynamic loader,
- pthread/TLS/futex smoke tests pass,
- loader mappings never become W+X.

## 32 — `/dev`, console, TTY/PTY and pseudo-device baseline
**Status: TODO / BLOCKED BY STEP 31**

Provide `/dev/null`, `/dev/zero`, `/dev/full`, random devices, `/dev/console`, serial TTY, the required TTY ioctl/line-discipline subset, PTYs, `/dev/ptmx`, devpts-facing behavior and session/foreground-process-group semantics. Device nodes remain capability mediated.

Acceptance:
- interactive shell job control works,
- PTY smoke test can run a child shell and exchange data,
- entropy devices do not claim readiness before the explicit entropy policy permits it.

## 33 — Mount model, tmpfs, procfs, sysfs, devpts and persistent root filesystem
**Status: TODO / BLOCKED BY STEP 32**

Add mount/umount semantics, initramfs-to-real-root transition, tmpfs, devpts, procfs and sysfs subsets required by Debian 13, plus one persistent read/write root filesystem. Ext4 is the preferred compatibility target unless another format is explicitly selected. Provide sync/fsync/rename semantics sufficient for package-manager safety.

Acceptance:
- a Debian 13 root image can be mounted read/write,
- boot transitions from initramfs to that root,
- selected proc/sys/devpts consumers work without fake success values,
- package-manager smoke tests do not corrupt the image under normal clean shutdown.

## 34 — Debian networking: Unix sockets, IP semantics, netlink and resolver path
**Status: TODO / BLOCKED BY STEP 33**

Extend networking with AF_UNIX, required IPv4/IPv6 TCP/UDP semantics/options, nonblocking/event interaction, basic interface ioctls, NETLINK_ROUTE minimum, loopback, hostname APIs and the resolver prerequisites required by Debian 13 glibc.

Acceptance:
- AF_UNIX client/server tests pass,
- selected DHCP/static configuration path works,
- DNS lookup succeeds,
- unchanged curl or equivalent Debian client reaches test HTTP/HTTPS endpoints once certificates/time are available,
- malformed netlink messages are bounded.

## 35 — Linux event, notification and modern descriptor APIs
**Status: TODO / BLOCKED BY STEP 34**

Implement the required epoll semantics plus eventfd, timerfd, signalfd, inotify, memfd/sealing, required pidfd operations and modern housekeeping syscalls observed in the Debian 13 corpus.

Acceptance:
- combined epoll + timerfd + eventfd + signalfd test passes,
- inotify covers documented create/rename/delete cases,
- systemd/dbus prerequisite probe no longer fails on missing fundamental event descriptors.

## 36 — Namespaces, cgroups v2 and security-facing syscall contract
**Status: TODO / BLOCKED BY STEP 35**

Implement the minimum namespaces, cgroups-v2 hierarchy/controllers, rlimits, Linux capabilities/securebits view and security-facing syscall behavior required by Debian 13/systemd while preserving Kernal's capability authority model. Unsupported seccomp/keyring/audit/BPF functionality must fail explicitly until genuinely implemented.

Acceptance:
- Debian 13 systemd feature detection reaches the documented supported configuration,
- service resource limits are actually enforced,
- unsupported security/isolation calls do not broaden authority.

## 37 — Unchanged Debian 13 systemd as PID 1
**Status: TODO / BLOCKED BY STEP 36**

Boot the pinned Debian 13 userspace with its own systemd binary as PID 1. Implement missing kernel contracts from observed failures one at a time; never add systemd process-name special cases.

Acceptance on x86_64 and AArch64 QEMU:
- unchanged Debian 13 systemd becomes PID 1,
- it reaches a documented basic/multi-user target rather than emergency-looping on a mandatory missing kernel feature,
- at least three ordinary services can be started/stopped/restarted,
- failed services leave usable diagnostics without panicking Kernal,
- clean poweroff/reboot completes through the normal userspace request path.

## 38 — udev, hotplug and Linux-visible device model
**Status: TODO / BLOCKED BY STEP 37**

Provide the sysfs hierarchy, Linux-visible device identities and uevent delivery required by Debian 13 systemd-udevd for the supported block/network/tty subset, with race-safe device lifecycle and no authority amplification through device nodes.

Acceptance:
- unchanged systemd-udevd starts,
- supported VirtIO block/network/console devices appear through the normal udev path,
- device add/remove does not leak stale authority.

## 39 — `dpkg`/`apt` and package-manager durability semantics
**Status: TODO / BLOCKED BY STEP 38**

Close Debian 13 package-management gaps: file/advisory locks, atomic metadata operations, fsync/fdatasync/syncfs, mmap/truncation behavior, required xattrs/ACLs, network/time/entropy support, shebang/interpreter behavior and ownership/mode preservation.

Acceptance:
- `dpkg --configure` works for a documented package set,
- `apt update` against a pinned Debian 13 snapshot succeeds,
- installation and removal of at least one ordinary package completes with a consistent dpkg database,
- process-failure tests stay within documented filesystem durability guarantees.

## 40 — Unmodified Debian 13 Server rootfs proof in QEMU
**Status: TODO / BLOCKED BY STEP 39**

This is the first point at which the project may claim a bounded form of "Debian 13 runs on Kernal."

Use the pinned unmodified Debian 13 userspace/rootfs for each primary architecture. Kernel command line, initramfs and QEMU configuration may be Kernal-specific; Debian executables/libraries must not be patched for Kernal.

Acceptance on x86_64 QEMU and AArch64 QEMU:
- systemd PID 1 reaches the documented multi-user target,
- console login or equivalent authenticated/local shell works,
- hostname, time and entropy initialization complete,
- supported block root is read/write,
- loopback plus one VirtIO-backed network interface work,
- DNS works,
- `systemctl` can manage services,
- `apt update` and one documented package install succeed,
- a small TCP server is reachable from the host,
- clean reboot and poweroff work,
- repeated boots do not accumulate filesystem/process/device corruption.

After Step 40, the accurate claim is **Kernal boots a pinned Debian 13 Server userspace in QEMU on x86_64 and AArch64**. Do not claim general Linux-kernel drop-in compatibility.

## 41 — Container-oriented Linux compatibility
**Status: TODO / BLOCKED BY STEP 40**

Expand user/network namespaces, veth/bridge, cgroups v2, overlay/union storage or another selected runtime storage path, seccomp, pidfd, mount propagation and `/proc` namespace behavior for one pinned OCI runtime without turning Linux capability bits into ambient Kernal authority.

Acceptance:
- one pinned OCI runtime starts a minimal container image under Debian 13,
- container authority remains delegated and isolated,
- CPU/memory/pid limits are enforced.

## 42 — Practical Debian 13 server hardware expansion
**Status: TODO / BLOCKED BY STEP 40**

Extend the Step-26 hardware subset toward practical server targets: selected NVMe/AHCI storage, additional Ethernet hardware, selected USB/HID/storage support, RTC, reboot/poweroff/watchdog, power/thermal/topology reporting and trustworthy entropy sources.

Acceptance:
- pinned Debian 13 Server rootfs boots on at least one documented real x86_64 machine and one documented real AArch64 server/development platform when hardware is available,
- storage/network survive sustained I/O tests,
- unsupported hardware remains isolated and fails cleanly.

## 43 — Optional Debian desktop enablement
**Status: TODO / OPTIONAL AFTER STEP 40**

Desktop support is not required for the Step-40 Debian Server claim. If pursued, add a documented framebuffer/DRM/KMS target, input stack, evdev semantics, selected audio contract, logind/seat/session behavior and the shared-memory/ioctl contracts required by the selected Wayland/X stack.

Acceptance for a selected desktop profile:
- graphical login/session starts with unmodified Debian 13 desktop userspace for the documented target,
- keyboard/mouse work,
- a terminal and one ordinary GUI application run,
- graphics/device access remains capability mediated.

## 44 — Debian 13 compatibility release gate, conformance and long stress
**Status: TODO / BLOCKED BY REQUIRED PROFILE STEPS**

Freeze supported Debian 13 rootfs/snapshot hashes and platform matrix; generate compatibility reports; run selected LTP-equivalent syscall/VM/filesystem/process tests, glibc/pthread regressions, systemd lifecycle tests, apt/dpkg smoke tests, storage/network/SMP stress, parser/syscall/netlink/filesystem fuzzing, authority audits and performance regressions. Document every intentional incompatibility.

Acceptance:
- Step-40 proof is reproducible on both QEMU architectures,
- selected real-hardware profile passes when hardware is available,
- no known silent-success compatibility stubs remain,
- no W^X/null-page/guard/capability/IOMMU/IRQ invariant is weakened,
- 24-hour or longer mixed stress completes without kernel panic, memory corruption or unbounded resource leak,
- `STATUS.md`, hardware matrix and compatibility matrix accurately describe support.

After Step 44 the project may call the result **Kernal v0.2 Debian-13-compatible developer kernel** for the explicitly documented Debian 13 snapshot and hardware/QEMU matrix. This is not equivalent to complete Linux ABI compatibility or production certification.

---

## Mandatory handoff for Steps 27–44

The normal `AGENT_EXECUTION_PROTOCOL.md` handoff remains mandatory. Once this extension becomes active, every substantive compatibility run must additionally record the pinned Debian 13 target, exact failing program/test, syscall/ioctl/proc/sys/device contract being fixed, reference-Debian behavior, Kernal behavior before/after, compatibility-matrix rows changed, security/authority impact and the next smallest failing compatibility contract.

Never fix a Debian application by adding a process-name-specific kernel special case. Compatibility belongs in shared Linux semantics.
