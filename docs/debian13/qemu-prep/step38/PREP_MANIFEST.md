# PREP manifest — Step 38

Status: `PREP_IN_PROGRESS`

## Runtime target

Expose the supported QEMU block/network/console device subset to unchanged Debian 13 systemd-udevd through Linux-compatible sysfs/uevent/device identities.

## Dependency release condition

Runtime integration starts only after Step 37 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step38/udev_device_expectations.json` — selected console/block/NIC projection, daemon/enumeration/hotplug cases and stale-authority negatives.
- `tools/qemu-prep/step38/collect_udev_reference.sh` — fail-closed Debian-13/Trixie/AArch64 PID1-systemd collector binding exact Kernal source SHA and pinned target identity. It records systemd-udevd service/package/version, boot journal, udev export database, selected root/NIC/TTY sysfs paths, `udevadm info --query=all`, attribute walks, `uevent` properties, selected sysfs attributes and device-node ownership/mode/major/minor values.
- The collector is observational by default. `udevadm test --action=add` for the selected devices is available only with `KERNAL_STEP38_RUN_UDEV_TEST=1 KERNAL_REFERENCE_UDEV_TEST_CONFIRMED=1`, and its logs/hashes are retained for rule/property review.
- `tests/qemu-prep/step38/hotplug_policy.json` — explicit transport-dependent claim boundary. The preferred fixed FDT-discovered `virtio-mmio-fast-path` requires boot enumeration/stable identity but claims no block/network/console hotplug. The `virtio-pci-fallback` may claim block/network hotplug only if Step33/34 explicitly select it and later live add/remove/re-add evidence exists.
- `tools/qemu-prep/step38/classify_udev_reference.py` — normalizes udev service state, selected property/uevent keys, device-node metadata and the chosen hotplug policy. It reports whether separate live hotplug evidence is required and never infers hotplug merely from successful boot enumeration.
- `tests/qemu-prep/step38/test_udev_reference_contract.py` — regressions for MMIO non-hotplug policy, PCI live-evidence requirement, exact provenance/udevadm-test guards and fast-path lifecycle requirements.
- Step-37 marker/reference schema supplies the PID1/service context in which udev must run.
- Step-33/34 PREP profiles supply the selected VirtIO block/NIC identities; Step-32 supplies console/TTY identity.
- `docs/debian13/qemu-prep/INTEGRATION_LANDING_MAP.md` requires sysfs/uevent to project canonical device facts rather than create a shadow hardware registry.

## Still to collect before PREP_READY

- after Steps 33/34 freeze the actual block/network transport, run `collect_udev_reference.sh` on the exact pinned Debian 13 ARM64 guest with `KERNAL_STEP38_TRANSPORT_PROFILE` set to that same profile; retain source/target-bound boot journal, export database, device properties, sysfs attributes/uevent fields and device-node modes;
- rerun with `KERNAL_STEP38_RUN_UDEV_TEST=1 KERNAL_REFERENCE_UDEV_TEST_CONFIRMED=1` for the selected root, NIC and console sysfs paths and review the rule/property logs to bind the actual fields consumed by the pinned udev rules. Available attribute-walk data alone is not sufficient to claim every exposed field is required;
- normalize with `classify_udev_reference.py` and bind stable selected device identities to the Step33 block, Step34 NIC and Step32 console handoffs;
- if the selected transport remains `virtio-mmio-fast-path`, explicitly freeze hotplug as **not claimed** for the Step-38 milestone. If the PCI fallback is selected, PREP_READY additionally requires a separate host/QEMU add/remove/re-add harness and generation-safe evidence for every claimed hotplug device class before this manifest may advance.

Synthetic/macOS udev behavior, boot enumeration presented as hotplug, or sysfs data disconnected from canonical device owners cannot satisfy these requirements.

## Prep focus

- reference sysfs paths/attributes needed by the pinned udev rules and systemd consumers;
- stable device-identity oracle for supported VirtIO block/net/console devices;
- uevent add/change/remove corpus only where the chosen transport claims it;
- device-node ownership/permission observations;
- negative tests for stale generation and malformed uevent/sysfs access.

## Canonical owners to consume

Canonical FDT/device, IRQ/DMA, Step-32 TTY/device nodes, Step-33 sysfs/devtmpfs strategy + block owner and Step-34 network owner.

## Forbidden duplicates

No shadow device registry, second FDT/PCI/IRQ/DMA authority, independent sysfs truth store, or device-node path that grants authority beyond canonical device owners.

## Integration landing order

1. Linux-visible stable device identity;
2. sysfs projection from canonical owners;
3. bounded uevent channel;
4. device-node integration;
5. selected VirtIO block/net/console projection;
6. hotplug teardown only for the explicitly claimed profile;
7. unchanged udev QEMU proof.

## Acceptance probes

systemd-udevd starts; supported devices appear through normal udev path; add/remove cycles are required only where explicitly claimed and then must not leak stale FD/IRQ/DMA/device authority; malformed events remain bounded.

## Handoff freshness

Stale if device identity, FDT/PCI/IRQ/DMA, sysfs, TTY, block or network owner interfaces change incompatibly, the selected QEMU device set/transport changes, or the pinned udev package/rules change.
