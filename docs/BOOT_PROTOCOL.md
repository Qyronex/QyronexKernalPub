# Boot protocol v1

The UEFI loader and privileged kernel communicate only through the versioned `kernal-bootinfo` ABI. Firmware-native structures are not passed directly into the kernel.

## Memory map rules

`BootInfoV1.memory_map` identifies a contiguous array of `MemoryRegionV1` records. `memory_region_size` and `memory_region_count` make the layout explicit and allow compatible extension.

The loader must normalize the UEFI memory map before handoff. Unknown firmware types are classified as reserved. Runtime firmware memory is never handed to the physical allocator as usable memory, even if its underlying UEFI type would otherwise be reclaimable.

The kernel validates every region for non-zero length and address overflow before considering it. Only regions explicitly classified as usable can feed the early physical allocator.

## Ownership transition

Before `ExitBootServices`, firmware owns boot-services memory. After a successful exit, the loader freezes the normalized map and passes it to the kernel. Reclaimable memory is not automatically treated as usable until the owning subsystem explicitly releases it.
