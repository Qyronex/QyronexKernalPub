# PREP manifest — Step 40

Status: `PREP_IN_PROGRESS`

## Runtime target

Produce the first bounded product proof that an unchanged pinned Debian 13 ARM64 server userspace/rootfs boots and performs practical server operations on Kernal in AArch64 QEMU.

## Dependency release condition

Final acceptance starts only after Step 39 is accepted and the exact Step-40 candidate is frozen.

## Prepared artifacts

- `tests/qemu-prep/step40/final_acceptance_schema.json` — machine-readable required checks, exact identity fields, failure routing and three-boot policy.
- `tests/qemu-prep/step40/qemu_argv_contract.json` — base `virt,gic-version=3`/`cpu=max` command template, preferred VirtIO-MMIO devices and explicit VirtIO-PCI fallback.
- `docs/debian13/qemu-prep/QEMU_BOOT_PROFILE.json` — pinned Debian image hashes, QEMU baseline, transport policy and host-forward preference.
- `tools/qemu-prep/create_verified_overlay.py` — verified COW root preparation.
- `tools/qemu-prep/step34/host_endpoints.py` — deterministic outbound TCP/UDP host fixtures.
- Step-32–39 PREP artifacts are indexed in `docs/debian13/qemu-prep/ARTIFACT_CATALOG.json`.

## Still to collect before PREP_READY

- exact final QEMU version and expanded argv from the approved runner host;
- final accepted block/network transport choice after Step-33/34 runtime proofs;
- exact three services selected by Step 37;
- exact package/version/hash selected by Step 39;
- machine-readable serial marker implementation in the future Step-40 harness;
- final repeated-boot/state-reset script bound to the accepted runtime owners.

## Prep focus

- freeze exact Debian 13 ARM64 rootfs/repository snapshot and cryptographic hashes;
- freeze exact QEMU version, machine, CPU count, memory, block, NIC, serial and command line;
- deterministic verified root-disk overlay generation/reset recipes;
- machine-readable serial markers for systemd target, login/shell, block RW, network, DNS, service management, apt, TCP server, reboot/poweroff;
- repeat-boot corpus and state-reset policy;
- failure evidence bundle format linking every failure to the first owning step;
- final compatibility-matrix export.

## Canonical owners to consume

All accepted Step 27-39 owners. Step 40 should add proof/harness integration, not a new compatibility subsystem.

## Forbidden duplicates

No Step-40-specific syscall/device/filesystem/network semantics, no Debian binary patches, no hidden fallback image, no fake-success markers.

## Final proof order

1. verify exact source SHA, target ID and pinned artifact hashes;
2. record QEMU version + complete expanded argv + selected block/net transports;
3. boot unmodified Debian 13 ARM64 rootfs;
4. systemd reaches documented multi-user/server target;
5. local console/login or equivalent authenticated shell;
6. hostname/time/entropy initialization;
7. persistent root verified read/write plus required pseudo-filesystems/devices;
8. loopback + selected VirtIO NIC + DNS + outbound TCP/UDP;
9. systemctl lifecycle for three documented services;
10. normal udev visibility for selected console/block/NIC set;
11. documented dpkg operation + apt update + one exact package installation;
12. host-reachable guest TCP server;
13. clean reboot + clean poweroff;
14. at least three repeated boot cycles with no accumulating corruption;
15. final exact-SHA gate/evidence bundle.

## Acceptance probes

Every required check in `tests/qemu-prep/step40/final_acceptance_schema.json` must have deterministic machine-readable evidence tied to the same accepted source SHA. Unsupported optional features must fail explicitly rather than pretending to work.

## Failure routing

Step 40 owns composition/evidence, not new compatibility semantics. Any discovered failure is routed back to the smallest Step-31–39 canonical owner; any source movement invalidates the candidate and restarts the final exact-SHA chain.

## Handoff freshness

Stale if any pinned Debian/QEMU artifact changes, the final transport/service/package selection changes, or any Step 31-39 accepted runtime owner changes after candidate freeze.