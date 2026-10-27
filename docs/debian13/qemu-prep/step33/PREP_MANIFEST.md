# PREP manifest — Step 33

Status: `PREP_IN_PROGRESS`

## Runtime target

Provide the storage/runtime environment needed for a pinned Debian 13 ARM64 rootfs: VirtIO block transport, canonical block service, mount/umount, initramfs-to-real-root transition, tmpfs, devpts, bounded procfs/sysfs subsets, persistent read/write root filesystem, and durability primitives required later by dpkg/apt.

## Dependency release condition

Runtime integration starts only after Step 32 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step33/virtio_mmio_block_profile.json` — FDT-discovered VirtIO-MMIO transport contract, queue/security negatives and explicit PCI fallback criteria.
- `tools/qemu-prep/step33/collect_virtio_mmio_fdt.py` — Debian-13/AArch64 reference collector that decodes discovered `virtio,mmio` FDT `reg`/interrupt properties without fixed addresses, correlates live VirtIO sysfs device IDs and requires at least one block device (`device_id=2`) for the selected profile.
- `tests/qemu-prep/step33/test_collect_virtio_mmio_fdt.py` — FDT normalization regressions for valid discovery, missing `reg`, zero-length MMIO ranges and truncated cells.
- `tests/qemu-prep/step33/rw_root_reference_vectors.json` — root transition, tmpfs/procfs/sysfs/devpts and durability smoke vectors.
- `tools/qemu-prep/step33/collect_rootfs_reference.sh` — Debian-13/AArch64 rootfs collector with exact source/target provenance, mount/block/ext4 read-only inspection and an optional durability probe that is permitted only on an explicitly confirmed disposable COW overlay and only when its probe parent resolves to the same root source.
- `tools/qemu-prep/step33/classify_rootfs_reference.py` — converts collected root evidence into `EXT4_REFERENCE_CONFIRMED` or an explicit non-ext4 review decision.
- `tests/qemu-prep/step33/filesystem_probe.c` + `tools/qemu-prep/step33/build_run_filesystem_probe.sh` — controlled create/write/fsync/pwrite/pread/truncate/mmap+msync/rename/directory-fsync/reopen/unlink durability oracle; probe parent is explicit through `KERNAL_STEP33_PROBE_PARENT`.
- `tests/qemu-prep/step33/test_rootfs_collector_contract.py` — enforces COW confirmation, source/target binding, non-destructive reference inspection and explicit filesystem targeting.
- `tests/qemu-prep/step33/ext4_metadata_negative_cases.json` — conditional malformed-ext4 mutation corpus activated only after `EXT4_REFERENCE_CONFIRMED`; immutable base policy plus hashes/OOB accounting are mandatory.
- `tests/qemu-prep/step33/test_ext4_metadata_negative_cases.py` — validates the ext4 negative corpus and immutable-base constraints.
- `tools/qemu-prep/create_verified_overlay.py` — verifies pinned Debian base size/SHA-256/SHA-512 before creating a disposable qcow2 overlay.
- `docs/debian13/qemu-prep/QEMU_FAST_PATH_DECISION.md` — preferred QEMU-only transport decision and fallback rule.
- `docs/debian13/qemu-prep/QEMU_BOOT_PROFILE.json` — exact target/QEMU/rootfs policy.

## Fast-path transport decision

Prefer FDT-discovered `virtio-blk-device`/VirtIO MMIO for the first Debian ARM64 QEMU milestone if runtime proof satisfies queue/IRQ/lifetime/memory-safety invariants. This keeps broad PCIe/MSI-X/ITS/real-hardware SMMUv3 work off the first QEMU critical path. VirtIO PCI remains the explicit fallback and requires its own released PCIe/IRQ/DMA scope.

## Still to collect before PREP_READY

- on the exact pinned Debian 13 ARM64 reference guest using the selected `virtio-blk-device` profile, run `collect_virtio_mmio_fdt.py` and retain the normalized source/target-bound FDT + live VirtIO block-device JSON;
- run `collect_rootfs_reference.sh`, classify it with `classify_rootfs_reference.py`, and retain the hashed mount/root/pseudo-fs/filesystem decision evidence;
- on a verified disposable COW overlay, rerun the rootfs collector with `KERNAL_STEP33_RUN_WRITE_PROBE=1 KERNAL_REFERENCE_OVERLAY_CONFIRMED=1` so the persistent-root fsync/rename/mmap durability sequence is captured on the selected root filesystem;
- if the classifier confirms ext4, bind the prepared malformed-metadata corpus to that reference decision. If it selects another filesystem, replace the conditional ext4 corpus with an equivalent corpus for the actually selected filesystem rather than pretending ext4 was observed.

No QEMU host/macOS output or synthetic FDT may satisfy these reference requirements.

## Prep focus

- freeze exact AArch64 QEMU block-device topology;
- prepare malformed virtqueue/feature-negotiation/DMA test vectors;
- prepare block request lifetime and short/error I/O oracles;
- preserve the pinned Debian base and use deterministic COW overlays;
- reference traces for mount, umount, root transition, tmpfs, devpts, required procfs/sysfs reads;
- filesystem compatibility corpus for create/write/read/truncate/rename/fsync/fdatasync/syncfs;
- ext4 compatibility probes if ext4 remains the selected persistent filesystem.

## Canonical owners to consume

`firmware/fdt-aarch64/**` for preferred QEMU device discovery, canonical IRQ/DMA/memory ownership, canonical linux-vfs namespace/path owner, canonical linux-fd/OFD owner, Step-32 PTY/devpts identities, process/credential owners and the single future block-service owner.

## Forbidden duplicates

No second FDT parser, VFS/path resolver, FD/OFD table, IRQ/DMA authority, mount namespace shadow registry or filesystem-specific device authority.

## Integration landing order

1. bounded FDT-discovered AArch64 VirtIO-MMIO block transport, or explicitly released VirtIO-PCI fallback;
2. architecture-neutral block service owner;
3. mount object/lifetime model and initramfs -> real-root transition;
4. tmpfs + devpts composition;
5. procfs/sysfs projections from canonical owners;
6. selected persistent filesystem + durability primitives;
7. pinned Debian RW-root QEMU proof.

## Acceptance probes

Disk read/write, malformed queue fail-closed, RW root mount, root switch, tmpfs/procfs/sysfs/devpts consumers, fsync/rename/truncate invariants, bad metadata/user pointers fail closed, no ambient DMA authority.

## Handoff freshness

Stale if FDT/IRQ/DMA, VFS, FD/OFD, PTY/devpts, VM/page ownership, selected persistent filesystem or selected QEMU block topology changes incompatibly.
