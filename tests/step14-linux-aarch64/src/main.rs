// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

// This is a normal Linux arm64 ABI program: syscall number in x8, arguments/results in x0..x5,
// and `svc #0`. It contains no Kernal-specific userspace ABI or test-only kernel entry instruction.
global_asm!(
    r#"
    .section .text.step14_entry, "ax"
    .global _start
    .type _start, %function
_start:
    // getpid() -> a positive Linux task-group ID, stable across repeated calls.
    mov  x8, #172
    svc  #0
    cmp  x0, #0
    b.le .Lfail_pid
    mov  x19, x0
    mov  x8, #172
    svc  #0
    cmp  x0, x19
    b.ne .Lfail_pid_stability

    // gettid() -> a positive stable thread ID. For this single-thread leader, TID == PID.
    mov  x8, #178
    svc  #0
    cmp  x0, #0
    b.le .Lfail_tid
    mov  x20, x0
    mov  x8, #178
    svc  #0
    cmp  x0, x20
    b.ne .Lfail_tid_stability
    cmp  x19, x20
    b.ne .Lfail_identity

    // An unsupported Linux syscall must return -ENOSYS without changing authority/state.
    mov  x8, #0xffff
    svc  #0
    mov  x9, #38
    neg  x9, x9
    cmp  x0, x9
    b.ne .Lfail_enosys

    // write(1, stdout_message, stdout_len)
    mov  x0, #1
    adrp x1, step14_stdout_message
    add  x1, x1, :lo12:step14_stdout_message
    mov  x2, #STEP14_STDOUT_LEN
    mov  x8, #64
    svc  #0
    cmp  x0, x2
    b.ne .Lfail_stdout

    // write(2, stderr_message, stderr_len)
    mov  x0, #2
    adrp x1, step14_stderr_message
    add  x1, x1, :lo12:step14_stderr_message
    mov  x2, #STEP14_STDERR_LEN
    mov  x8, #64
    svc  #0
    cmp  x0, x2
    b.ne .Lfail_stderr

    // exit_group(0) must not return.
    mov  x0, #0
    mov  x8, #94
    svc  #0

    // Reaching this point is itself a lifecycle failure. Remain Linux-ABI-only by repeatedly
    // requesting a distinct failure exit rather than relying on a Kernal-private breakpoint.
    mov  x21, #107
.Lreturned_from_exit:
    mov  x0, x21
    mov  x8, #94
    svc  #0
    b    .Lreturned_from_exit

.Lfail_pid:
    mov x0, #101
    b .Lexit_failure
.Lfail_tid:
    mov x0, #102
    b .Lexit_failure
.Lfail_identity:
    mov x0, #103
    b .Lexit_failure
.Lfail_enosys:
    mov x0, #104
    b .Lexit_failure
.Lfail_stdout:
    mov x0, #105
    b .Lexit_failure
.Lfail_stderr:
    mov x0, #106
    b .Lexit_failure
.Lfail_pid_stability:
    mov x0, #108
    b .Lexit_failure
.Lfail_tid_stability:
    mov x0, #109

.Lexit_failure:
    mov  x21, x0
.Lexit_failure_loop:
    mov  x0, x21
    mov  x8, #94
    svc  #0
    b    .Lexit_failure_loop
    .size _start, . - _start

    .section .rodata.step14_messages, "a"
step14_stdout_message:
    .ascii "step14-linux: stdout write ok\n"
step14_stdout_message_end:
    .equ STEP14_STDOUT_LEN, step14_stdout_message_end - step14_stdout_message

step14_stderr_message:
    .ascii "step14-linux: stderr write ok\n"
step14_stderr_message_end:
    .equ STEP14_STDERR_LEN, step14_stderr_message_end - step14_stderr_message
"#
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
