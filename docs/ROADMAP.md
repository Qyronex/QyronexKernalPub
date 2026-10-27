# Roadmap

## M0 - Foundation
A fresh checkout must build a UEFI app, boot in QEMU/OVMF, emit a serial marker, and exit QEMU through debug-exit.

## M1 - Boot and memory ownership
- checked ELF64 loader
- versioned BootInfo handoff
- ExitBootServices transition
- kernel-owned page tables
- RX/R/RW mappings with no W+X
- exception reporting
- physical frame ownership
- guarded kernel stacks

## M2 - SMP, capabilities, IPC
- AP startup and per-CPU state
- per-CPU run queues and preemptive scheduler
- scalable CSpace/object table
- endpoint IPC and notifications
- negative authorization tests

## M3 - Userspace and Linux bootstrap
- ring 3 address spaces and threads
- ELF64 user loader
- native capability ABI
- Linux x86_64 syscall entry
- first unchanged static Linux program using write/exit

## M4 - Device isolation
- PCIe ECAM enumeration
- MSI/MSI-X mediation
- Intel VT-d and AMD IOMMU
- VirtIO userspace drivers
- invalid-DMA negative tests

## M5 - Server usability
- VFS/storage and network services
- futex, signals, sockets, epoll
- dynamic ELF support
- increasingly large musl/glibc workloads

## Current M1 slices
The tree now contains a strict `no_std` ELF64 parser, a deterministic 4 KiB physical-frame allocator, and a freestanding kernel entry that validates BootInfo. M1 is not complete until CI exercises UEFI file loading, firmware memory-map normalization, ExitBootServices, kernel-owned W^X page tables, and a real jump into `kernal-core` under QEMU.
