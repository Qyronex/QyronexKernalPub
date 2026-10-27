OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
}

SECTIONS
{
    . = 0x0000000000200000;

    .text : ALIGN(0x1000)
    {
        KEEP(*(.text.step14_entry))
        *(.text .text.*)
        *(.rodata .rodata.*)
    } :text

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}
