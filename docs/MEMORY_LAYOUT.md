# x86_64 virtual memory layout (initial M1 contract)

Kernal starts x86_64 in the canonical upper half and keeps user virtual addresses in the lower half. The layout is intentionally sparse so that later KASLR, direct-map, per-CPU and MMIO windows can be introduced without ABI churn.

| Region | Initial base | Policy |
| --- | ---: | --- |
| user space | `0x0000000000000000` | ring 3, NX unless explicitly executable |
| kernel image | `0xffffffff80200000` | separate ELF PT_LOAD segments |
| kernel text | linker-defined | R-X, never writable |
| kernel rodata | linker-defined | R--, NX |
| kernel data/bss | linker-defined | RW-, NX |

## Hard invariants

1. No kernel page may be writable and executable at the same time.
2. Page zero stays unmapped once kernel-owned tables are installed.
3. Kernel stacks receive at least one unmapped guard page.
4. User mappings always carry the user/supervisor bit and cannot alias writable kernel text.
5. MMIO mappings are NX and use device-appropriate cache attributes.

This is an M1 contract, not a promise that the final address layout will remain numerically identical.
