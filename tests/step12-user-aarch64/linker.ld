OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x0000000000200000;

    .text : ALIGN(0x1000)
    {
        KEEP(*(.text.step12_entry))
        *(.text .text.*)
        *(.rodata .rodata.*)
    } :text

    . = ALIGN(0x1000);
    .data : ALIGN(0x1000)
    {
        KEEP(*(.data.step12_seed))
        *(.data .data.*)
    } :data

    .bss (NOLOAD) : ALIGN(8)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}
