OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_BASE = 0xffffffff80000000;

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = KERNEL_BASE + 0x200000;
  __kernel_start = .;

  .text : ALIGN(0x1000)
  {
    KEEP(*(.text._start))
    *(.text .text.*)
    *(.plt .plt.* .iplt .iplt.*)
  } :text

  .rodata : ALIGN(0x1000)
  {
    *(.rodata .rodata.*)
  } :rodata

  .data : ALIGN(0x1000)
  {
    *(.data .data.*)
    *(.got .got.* .got.plt .igot.plt)
    *(.data.rel.ro .data.rel.ro.*)
  } :data

  .bss (NOLOAD) : ALIGN(0x1000)
  {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    __bss_end = .;
  } :data

  . = ALIGN(0x1000);
  __kernel_end = .;

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame_hdr)
    *(.comment)
    *(.note .note.*)
  }
}
