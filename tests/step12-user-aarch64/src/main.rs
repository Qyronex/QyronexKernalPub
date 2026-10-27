// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .section .text.step12_entry, "ax"
    .global _start
    .type _start, %function
_start:
    adrp x1, step12_bss_probe
    add  x1, x1, :lo12:step12_bss_probe
    ldr  x2, [x1]
    cbnz x2, 1f
    mov  x0, #0x12
    brk  #0x120
2:
    b 2b
1:
    brk  #0x121
    b 2b
    .size _start, . - _start

    // Keep the RW PT_LOAD partly file-backed so the ELF proves p_memsz > p_filesz rather than
    // relying on a zero-filesz NOBITS-only segment whose p_offset may legally sit past EOF.
    .section .data.step12_seed, "aw"
    .balign 8
step12_file_seed:
    .quad 0x534c454631325354

    .section .bss.step12_probe, "aw", %nobits
    .balign 8
step12_bss_probe:
    .zero 8
"#
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
