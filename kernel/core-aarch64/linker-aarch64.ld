OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(kernal_aarch64_protected_start)

/*
 * QEMU virt bare-metal ELF bring-up.
 * RAM starts at 0x40000000 and QEMU places its generated DTB at the start of RAM for ELF boots.
 * Keep the kernel two MiB above that reserved discovery page so program segments never overlap it.
 *
 * The kernel is linked at its physical load address and executed through an equal-offset canonical
 * TTBR1 alias after the protected entry builds dual mappings. The temporary TTBR0 identity leaves
 * are removed only after all PEs execute high and the established scheduler/IRQ proof has passed.
 */
KERNEL_PHYS_BASE = 0x40200000;
KERNEL_VIRT_BASE = 0xffffffff80200000;
STACK_GUARD_SIZE = 0x1000;
/*
 * Step 29 constructs one bounded OverlayNamespace during the protected BSP callback. The accepted
 * VFS owner keeps per-node file storage and PATH_MAX tombstone metadata inline, so Rust may require
 * a large transient return-place while initializing the final static slot. Keep the bootstrap stack
 * comfortably above that bounded object size instead of reducing filesystem capacity or introducing
 * a second heap/namespace owner in Core.
 */
BOOT_STACK_SIZE = 0x40000;
/*
 * The final Step-29 Overlay path resolver keeps several PATH_MAX-sized bounded work buffers live in
 * one syscall frame. Clone/user-thread stacks share this guarded linker arena with firmware
 * secondary stacks, so use one 256 KiB payload stride for the complete protected arena. The separate
 * scheduler smoke-worker stack remains 64 KiB below.
 */
SECONDARY_STACK_SIZE = 0x40000;
SECONDARY_STACK_COUNT = 4;
CLONE_STACK_COUNT = 16;
SECONDARY_STACK_STRIDE = STACK_GUARD_SIZE + SECONDARY_STACK_SIZE;
SCHEDULER_WORKER_STACK_SIZE = 0x10000;
/*
 * The post-bootstrap verifier and Step-15 live VM share one monotonic page-table pool. Steps 7-14
 * already consume most of the former 96-page reserve; the first live KMap zero may then allocate
 * TTBR1 intermediate tables before a large pthread mmap needs several additional TTBR0 leaf-table
 * pages. Keep bounded headroom for that accepted live owner path rather than treating linker-pool
 * exhaustion as a VM invariant failure. The pool remains fixed-size and fail-closed on exhaustion.
 */
BOOT_PAGE_TABLE_COUNT = 128;
BOOT_PAGE_TABLE_BYTES = BOOT_PAGE_TABLE_COUNT * 0x1000;

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = KERNEL_PHYS_BASE;
  __kernel_start = .;

  .text : ALIGN(0x1000)
  {
    __text_start = .;
    KEEP(*(.text._protected_start))
    KEEP(*(.text._protected_secondary_start))
    KEEP(*(.text._start))
    KEEP(*(.text._secondary_start))
    *(.text .text.*)
    *(.plt .plt.* .iplt .iplt.*)
    . = ALIGN(0x1000);
    __text_end = .;
  } :text

  .rodata : ALIGN(0x1000)
  {
    __rodata_start = .;
    *(.rodata .rodata.*)
    . = ALIGN(0x1000);
    __rodata_end = .;
  } :rodata

  .data : ALIGN(0x1000)
  {
    __data_start = .;
    *(.data .data.*)
    *(.got .got.*)
    *(.data.rel.ro .data.rel.ro.*)
    . = ALIGN(0x1000);
    __data_end = .;
  } :data

  .bss (NOLOAD) : ALIGN(0x1000)
  {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(0x1000);
    __bss_static_end = .;

    __boot_stack_guard_start = .;
    . += STACK_GUARD_SIZE;
    __boot_stack_bottom = .;
    . += BOOT_STACK_SIZE;
    __boot_stack_top = .;

    /*
     * Protected boot already derives every guard hole from the complete
     * [__secondary_stacks_bottom, __secondary_stacks_top) arena and the common stride. Keep the
     * firmware secondary stacks first, then append the Step-15 clone pool to the same guarded arena.
     * Secondary startup indexes only the first SECONDARY_STACK_COUNT slots; clone allocation starts
     * at __clone_stacks_bottom. This reuses the existing dual-alias guard proof without a second
     * kernel-stack mapping policy.
     */
    . = ALIGN(0x1000);
    __secondary_stacks_bottom = .;
    . += SECONDARY_STACK_STRIDE * SECONDARY_STACK_COUNT;
    __secondary_boot_stacks_top = .;
    __clone_stacks_bottom = .;
    . += SECONDARY_STACK_STRIDE * CLONE_STACK_COUNT;
    __clone_stacks_top = .;
    __secondary_stacks_top = .;

    . = ALIGN(0x1000);
    __scheduler_worker_guard_start = .;
    . += STACK_GUARD_SIZE;
    __scheduler_worker_stack_bottom = .;
    . += SCHEDULER_WORKER_STACK_SIZE;
    __scheduler_worker_stack_top = .;

    . = ALIGN(0x1000);
    __boot_page_tables_start = .;
    . += BOOT_PAGE_TABLE_BYTES;
    __boot_page_tables_end = .;

    . = ALIGN(0x1000);
    __bss_end = .;
  } :data

  . = ALIGN(0x1000);
  __kernel_end = .;

  /* Absolute values consumed by the protected transition and Step-15 clone stack owners. */
  __kernel_phys_base = KERNEL_PHYS_BASE;
  __kernel_virt_base = KERNEL_VIRT_BASE;
  __secondary_stack_stride = SECONDARY_STACK_STRIDE;
  __clone_stack_count = CLONE_STACK_COUNT;
  __clone_stack_stride = SECONDARY_STACK_STRIDE;
  __stack_guard_size = STACK_GUARD_SIZE;

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame_hdr)
    *(.comment)
    *(.note .note.*)
  }
}
