# PREP manifest — Step 34

Status: `PREP_IN_PROGRESS`

## Runtime target

Provide Debian 13 ARM64 networking in QEMU: VirtIO-net, loopback, AF_UNIX, IPv4 and required IPv6 subset, UDP/TCP, interface control, minimum NETLINK_ROUTE, hostname APIs and DNS resolver path.

## Dependency release condition

Runtime integration starts only after Step 33 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step34/network_reference_topology.json` — selected QEMU network topology plus AF_UNIX/Netlink/DNS/TCP/UDP/host-forward scenarios.
- `tools/qemu-prep/step34/host_endpoints.py` — deterministic host-local TCP/UDP endpoints for guest outbound tests.
- `tests/qemu-prep/step34/network_probe.c` — reference probe covering pathname AF_UNIX stream lifecycle, IPv6 loopback + observed `IPV6_V6ONLY`, bounded malformed `NETLINK_ROUTE` result capture using non-mutating `RTM_GETLINK`, host TCP/UDP endpoints and optional unchanged-glibc `getaddrinfo` resolution.
- `tests/qemu-prep/step34/test_network_probe_contract.py` — machine contract requiring AF_UNIX/IPv6/NETLINK_ROUTE/TCP/UDP/DNS coverage, parameterized external destinations and no mutating route/link/address Netlink message type.
- `tools/qemu-prep/step34/collect_network_reference.sh` — fail-closed Debian-13/Trixie/AArch64 collector that binds exact Kernal source SHA and pinned target identity; records IPv4/IPv6 interface/route/rule/neighbour state, resolver inputs and active network manager without changing configuration. Active socket probes require explicit `KERNAL_STEP34_RUN_ACTIVE_PROBE=1` plus `KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED=1`.
- When `KERNAL_DNS_NAME` is supplied the collector records `getent ahosts` output and, where available, `strace -f -e trace=network` for the actual glibc resolver path so UDP/TCP fallback is inferred from evidence rather than assumed.
- `tests/qemu-prep/step34/test_network_reference_collector_contract.py` — enforces source/target/architecture binding, explicit active-probe authorization, DNS trace collection and observational/non-mutating behavior.
- `tools/qemu-prep/step34/classify_network_reference.py` — normalizes default interface/route, resolver nameservers and observed network-manager path into the Step-34 integration input.
- Existing reference input: `ip link show lo` already proves the pinned Debian consumer uses `AF_NETLINK`, `NETLINK_ROUTE`, `socket`, `bind`, `getsockname`, `sendmsg`, `recvmsg` and `setsockopt`.
- `docs/debian13/qemu-prep/QEMU_BOOT_PROFILE.json` — preferred VirtIO-MMIO NIC + explicit VirtIO-PCI fallback.

## Fast-path transport decision

Prefer FDT-discovered `virtio-net-device`/VirtIO MMIO if later runtime proof meets queue/IRQ/DMA/lifetime requirements. Do not make broad PCIe/MSI-X/ITS hardware breadth mandatory merely to obtain the first Debian QEMU network path. VirtIO PCI is the explicit fallback.

## Still to collect before PREP_READY

- in the exact pinned Debian 13 ARM64 reference guest, run `collect_network_reference.sh`, classify the result and retain the source/target-bound hashes so the actual static/DHCP/network-manager path, IPv4/IPv6 routes and required interface state are fixed from evidence;
- run `host_endpoints.py` on the reference host and rerun the collector with `KERNAL_STEP34_RUN_ACTIVE_PROBE=1 KERNAL_REFERENCE_NETWORK_PROBE_CONFIRMED=1` so pathname AF_UNIX, IPv6 loopback, malformed NETLINK_ROUTE observation and guest-to-host TCP/UDP are captured on the pinned guest;
- supply one deterministic `KERNAL_DNS_NAME` reachable through the pinned reference resolver and retain `getent` plus network-only strace evidence. TCP resolver fallback is required only if actually observed;
- review the collected IPv6/default socket-option results and the malformed NETLINK_ROUTE outcome, then bind only the observed mandatory subset into the final handoff.

Synthetic/macOS network behavior cannot satisfy these reference requirements, and collection must not mutate the reference network configuration.

## Prep focus

- freeze exact QEMU VirtIO-net transport/device topology;
- prepare bounded queue and malformed descriptor corpus;
- reference packet/socket traces for Ethernet/ARP/IP/ICMP/UDP/TCP;
- AF_UNIX pathname/abstract socket oracle;
- nonblocking/socket option/error corpus used by glibc/systemd/dbus;
- minimum netlink/interface query traces;
- deterministic DNS, outbound TCP and UDP endpoints for acceptance;
- DHCP/static configuration oracle selection.

## Canonical owners to consume

`firmware/fdt-aarch64/**` for preferred QEMU device discovery, canonical IRQ/DMA ownership, canonical FD/OFD, scheduler/wakeup, VFS for pathname sockets, process/credentials, time owner and one architecture-neutral packet/network + Linux socket owner.

## Forbidden duplicates

No second FDT parser, FD table, scheduler, VFS pathname authority, IRQ/DMA stack, independent per-driver IP stack or shadow interface registry.

## Integration landing order

1. bounded FDT-discovered VirtIO-MMIO net transport, or explicitly released VirtIO-PCI fallback;
2. packet/network owner;
3. Linux socket lifecycle integrated with canonical FD/OFD;
4. AF_UNIX;
5. netlink/interface controls;
6. hostname/resolver/DNS;
7. QEMU network acceptance.

## Acceptance probes

VirtIO TX/RX; loopback; AF_UNIX client/server; static or DHCP configuration; DNS through unchanged glibc; outbound TCP/UDP; host-reachable guest TCP server; malformed packets/netlink/descriptor cases bounded; DMA authority confined.

## Handoff freshness

Stale if FDT/IRQ/DMA, FD/OFD, scheduler readiness, VFS pathname semantics, selected QEMU NIC topology, resolver fixture or time source changes incompatibly.
