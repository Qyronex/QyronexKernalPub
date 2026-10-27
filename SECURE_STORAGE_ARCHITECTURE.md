# Kernal Secure Storage Architecture

This document is a mandatory architecture contract for persistent storage in Kernal.

Kernal's storage goal is not merely filesystem compatibility. The target is a capability-secured, encrypted, integrity-protected, high-performance storage architecture in which compromise of one process, tenant, driver, or storage namespace does not automatically grant access to unrelated persistent data.

This contract becomes implementation-critical with ARM Step 20 and MUST be satisfied before Step 22 VFS/storage can be accepted. It applies to later x86_64 and RISC-V64 ports through the shared architecture-neutral storage contracts.

## Security and performance objective

Storage must simultaneously provide:

- explicit capability-mediated authority instead of ambient/global storage access;
- encryption at rest by default for protected persistent data;
- cryptographic integrity/authentication for data and metadata, not encryption-only protection;
- hardware-rooted key protection where the platform provides TPM 2.0, ARM TEE or another documented hardware root of trust;
- DMA confinement through the accepted IOMMU/SMMUv3 ownership model;
- bounded-copy or zero/low-copy data paths where security invariants permit them;
- asynchronous, queue-oriented I/O with batching and per-owner/per-CPU scalability;
- deterministic fail-closed behavior when authority, integrity, key, DMA or ownership validation fails.

Security invariants MUST NOT be disabled merely to improve benchmark numbers. Performance work must optimize within these invariants.

## Mandatory storage authority model

There is no ambient global storage authority.

A process or service may access persistent data only through explicitly delegated storage capabilities. Capabilities may represent a device, volume, tenant, namespace, object, file, extent, queue or another narrowly defined storage authority.

A path name alone is never sufficient authority. VFS name resolution must terminate in capability-authorized objects/handles.

Cross-tenant and cross-namespace access must fail unless an explicit capability grants it. Stale generations, stale handles and revoked capabilities must not regain access after object reuse.

Linux compatibility may expose normal file-descriptor/path semantics to userspace, but those semantics must be translated onto the canonical Kernal capability model rather than creating a parallel ambient Unix authority model inside the kernel.

## Mandatory key hierarchy

Protected persistent storage must use a hierarchical key model rather than one universal disk key.

The canonical conceptual hierarchy is:

`hardware/root key -> system key -> tenant/namespace key -> volume key -> object/extent key`

Implementations may combine levels where justified, but compromise of one tenant or volume key must not automatically expose unrelated tenants or volumes.

Root/master key material must never be stored plaintext on persistent media. Where supported, root key material should be sealed or wrapped by TPM 2.0, ARM TEE or another documented hardware root of trust.

Key material in RAM must have explicit ownership and lifetime. It must not appear in normal logs, crash text, userspace-visible diagnostics, generic IPC payloads or ordinary pageable/shared buffers.

Key rotation and revocation must be possible without requiring one global system-wide storage key replacement.

## Mandatory authenticated storage

Encryption without integrity is insufficient for the Kernal secure-storage target.

Protected data blocks and security-relevant metadata must be authenticated. The design must detect unauthorized modification, substitution and corruption rather than silently decrypting attacker-controlled blocks.

The implementation should use a modern authenticated-encryption construction or an equivalent composition with a documented security argument. Metadata/root structures must have authenticated linkage, for example through authenticated trees, Merkle-style roots, generation/version binding or an equivalent mechanism.

The storage layer must define replay/rollback semantics. Security-sensitive metadata must not silently accept an older valid ciphertext state where rollback resistance is required by the selected threat model.

Cryptographic nonces, counters and generations must be managed so that key/nonce reuse cannot occur across rewrites or object reuse.

## Hardware acceleration

Architecture backends should use vetted hardware acceleration where available without changing the shared cryptographic/storage semantics.

On AArch64 this may include architected AES and polynomial-hash acceleration when supported by the CPU. The portable implementation remains the correctness reference and architecture-specific acceleration must produce identical authenticated results.

Acceleration must never require exposing plaintext keys or buffers to a less-trusted driver/device domain.

## DMA and driver isolation

Step 19 IOMMU/SMMUv3 default-deny policy is a prerequisite for the strongest hardware-isolation mode.

Storage devices and drivers must not receive arbitrary physical-memory authority. DMA mappings must be explicit, bounded, capability-backed and revoked/invalidate translations before frame reuse.

A compromised VirtIO/NVMe/storage driver must not gain DMA access to unrelated kernel memory, key memory or another tenant's buffers solely because it controls a device queue.

If a proof platform lacks an IOMMU, the weaker isolation boundary must be stated explicitly and must not be represented as hardware-proven DMA confinement.

## High-performance data path

The design target is not a chain of unconditional copies such as:

`application -> kernel copy -> crypto copy -> driver copy -> device`

The preferred architecture is:

`authorized application/shared buffer -> storage queue -> crypto/authentication -> bounded DMA mapping -> device`

Buffers must remain ownership-tracked throughout the operation. Zero-copy or shared-buffer fast paths are allowed only when capabilities, lifetime, mutability, DMA ownership and cryptographic boundaries remain explicit.

No fast path may create writable aliases that violate W^X, bypass PAN/usercopy rules for unrelated memory, retain stale DMA mappings, or leave plaintext accessible after ownership transfer/reuse.

## Asynchronous I/O model

The canonical high-performance interface should be asynchronous and queue-oriented.

Design goals:

- per-CPU, per-process, per-service or sharded submission/completion queues where appropriate;
- bounded queue memory and bounded in-flight operations;
- batching to amortize syscall, crypto and device-doorbell costs;
- minimal global locks in the steady-state data path;
- explicit backpressure rather than unbounded allocation;
- generation-safe request identifiers so stale completions cannot target reused objects;
- cancellation/teardown semantics that preserve buffer, key and DMA ownership.

Linux `read`/`write` compatibility may be implemented as a synchronous facade over the canonical asynchronous storage machinery rather than defining the internal architecture.

## Storage service layering

The target layering is:

```text
application / database
        |
storage capability
        |
namespace / storage service
        |
encrypted + authenticated object/extent layer
        |
key service / hardware-root integration
        |
asynchronous block interface
        |
isolated NVMe / VirtIO block transport
        |
IOMMU-confined DMA
        |
storage device
```

The VFS must sit above the secure object/storage layer. Step 22 must not create an unencrypted architecture and defer the security model to a later retrofit.

## Tenant isolation target

Multi-tenant deployments are a first-class threat model.

A tenant compromise must not imply authority over another tenant's namespace, storage capabilities or encryption keys. A database or storage service that intentionally accesses multiple tenants must receive explicit per-tenant authority and should be able to compartmentalize those authorities rather than receiving one unrestricted global disk capability.

Deleting/revoking a tenant must revoke its live capabilities and support cryptographic erasure where the selected key hierarchy permits it.

## Crash consistency and recovery

Security metadata, authenticated roots and key-generation metadata require transactional crash consistency.

Recovery must distinguish:

- clean committed state;
- incomplete writes/transactions;
- integrity failure;
- missing/unavailable key authority;
- detected rollback/replay where anti-rollback is enabled.

Integrity failure must not silently fall back to unauthenticated data.

## Observability and audit

Audit records must describe authority-relevant events without leaking plaintext data or keys.

Security-relevant events include capability delegation/revocation, key generation/rotation, integrity failures, namespace violations and storage-device/IOMMU faults.

Audit logging itself must use bounded resources and must not become an ambient path that exposes protected user data.

## Roadmap binding

### Step 19

SMMUv3/IOMMU establishes default-deny DMA and explicit capability-backed device mappings. This is the hardware memory-isolation prerequisite for strongly isolated storage drivers/devices.

### Step 20

The isolated VirtIO/NVMe-style block service establishes bounded queues, device ownership, mediated DMA buffers and a high-performance asynchronous block transport. Step 20 must preserve the interfaces required by this secure-storage contract.

### Secure Storage Gate — mandatory after Step 20 and before Step 22

Before Step 22 VFS/storage acceptance, Kernal must implement and prove the minimum secure-storage layer:

1. capability-scoped storage/volume/namespace authority with no ambient global storage handle;
2. protected-volume encryption using a documented modern construction;
3. authenticated data and authenticated security-relevant metadata;
4. hierarchical key ownership with at least system/volume separation and an extension path for tenant/object keys;
5. root/master keys absent from persistent plaintext storage and a documented hardware-root integration contract;
6. explicit generation-safe buffer/request ownership through asynchronous block I/O;
7. IOMMU-confined DMA on proof hardware that exposes SMMUv3/IOMMU, with explicit degraded-security documentation where unavailable;
8. bounded-copy/low-copy fast path with no stale plaintext, stale DMA mapping or cross-authority alias;
9. crash/recovery tests demonstrating that torn writes or integrity failures do not produce silently accepted unauthenticated state;
10. performance measurement for sequential throughput, random IOPS, queue scalability, crypto overhead and CPU cost.

The Secure Storage Gate is an acceptance gate, not a new numbered Step, so the canonical 1-26 roadmap numbering remains stable.

### Step 22

VFS, filesystem and Linux `openat`/`read`/`write`/`close`/`stat` must be built on the accepted secure-storage layer. File handles are capabilities or capability-backed objects. Unauthorized namespace access must fail even when the caller can guess a path or identifier.

## Acceptance philosophy

For secure storage, source code is not proof.

Acceptance requires executable evidence covering at minimum:

- authority isolation between two independent tenants/namespaces;
- revoked/stale capability rejection;
- ciphertext-at-rest inspection showing protected plaintext is not present on the block device;
- deliberate ciphertext and metadata corruption causing deterministic integrity failure;
- wrong-key and missing-key failure;
- device/driver DMA confinement on supported IOMMU hardware/proof platform;
- crash/torn-write recovery behavior;
- high-queue-depth throughput and latency measurements with and without encryption so security overhead is quantified rather than guessed;
- regression preservation of all earlier kernel memory, capability, PAN/usercopy and lifecycle invariants.

The final objective is a storage subsystem whose security boundary is narrower and more explicit than a conventional monolithic `root can read the entire disk` model while retaining an I/O architecture capable of driving modern NVMe-class hardware efficiently.
