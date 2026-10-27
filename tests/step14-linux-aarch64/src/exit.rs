// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

// Separate unchanged Linux arm64 process used to prove the thread-scoped `exit` syscall. A
// single-thread process has no surviving threads, so the accepted process lifecycle must complete.
global_asm!(
    r#"
    .section .text.step14_entry, "ax"
    .global _start
    .type _start, %function
_start:
    mov  x0, #0
    mov  x8, #93
    svc  #0

    // `exit(0)` is non-returning. If it incorrectly returns, stay within the public Linux ABI and
    // repeatedly request a distinct process-wide failure exit rather than using a private BRK trap.
.Lreturned_from_exit:
    mov  x0, #239
    mov  x8, #94
    svc  #0
    b    .Lreturned_from_exit
    .size _start, . - _start
"#
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
