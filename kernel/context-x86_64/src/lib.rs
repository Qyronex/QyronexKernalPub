// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;

pub const CONTEXT_WORDS: usize = 8;
pub const CONTEXT_BYTES: usize = CONTEXT_WORDS * core::mem::size_of::<u64>();

pub type KernelThreadEntry = extern "C" fn(u64) -> !;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    StackTooSmall,
    StackMisaligned,
    InvalidEntry,
}

/// Builds the initial saved-register frame expected by `switch` at the top of a kernel stack.
///
/// The caller supplies the high-address tail of a mapped kernel stack as u64 words. The returned
/// index identifies the first saved word; its virtual address becomes the thread's saved RSP.
/// SIMD/FPU state is deliberately excluded from this hot path and will use lazy/XSAVE policy.
pub fn build_initial_context(
    stack_words: &mut [u64],
    stack_top_virtual: u64,
    entry: KernelThreadEntry,
    argument: u64,
) -> Result<usize, Error> {
    if stack_words.len() < CONTEXT_WORDS {
        return Err(Error::StackTooSmall);
    }
    if stack_top_virtual & 0xf != 0 {
        return Err(Error::StackMisaligned);
    }
    let entry_address = entry as *const () as usize as u64;
    if entry_address == 0 {
        return Err(Error::InvalidEntry);
    }

    let start = stack_words.len() - CONTEXT_WORDS;
    let frame = &mut stack_words[start..];
    // pop order in assembly: r15,r14,r13,r12,rbx,rbp,ret. r13 carries arg and r12 entry.
    frame[0] = 0; // r15
    frame[1] = 0; // r14
    frame[2] = argument; // r13
    frame[3] = entry_address; // r12
    frame[4] = 0; // rbx
    frame[5] = 0; // rbp
    frame[6] = bootstrap_address(); // ret target
    frame[7] = 0; // ABI padding: bootstrap begins with RSP % 16 == 8
    Ok(start)
}

#[cfg(target_arch = "x86_64")]
fn bootstrap_address() -> u64 {
    kernal_kernel_thread_bootstrap as *const () as usize as u64
}

// Host-side unit tests may run on Apple Silicon. They only validate frame construction and must
// not try to assemble or execute x86_64 context-switch code.
#[cfg(not(target_arch = "x86_64"))]
fn bootstrap_address() -> u64 {
    host_test_bootstrap as *const () as usize as u64
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn host_test_bootstrap() {}

/// Switches between two kernel contexts.
///
/// `old_rsp` receives the outgoing context's saved RSP. `new_rsp` must point at a frame built by
/// this module or one previously saved by this same function.
///
/// A raw pointer is deliberate here: a Rust `&mut u64` borrow would remain live for the entire
/// suspended function call while another context executes and may inspect the context table.
/// The scheduler instead owns the aliasing proof and supplies a stable raw storage location.
///
/// # Safety
/// - Must run at CPL0 with preemption/interrupt policy preventing concurrent reuse of either stack.
/// - `old_rsp` must be non-null, aligned for `u64`, writable, and remain valid until this context is
///   eventually resumed and the assembly call returns.
/// - No concurrent writer may target `*old_rsp` while this context is suspended.
/// - Both stacks must remain mapped RW-NX and satisfy the SysV x86_64 ABI.
#[cfg(target_arch = "x86_64")]
pub unsafe fn switch(old_rsp: *mut u64, new_rsp: u64) {
    debug_assert!(!old_rsp.is_null());
    debug_assert_eq!((old_rsp as usize) & (core::mem::align_of::<u64>() - 1), 0);
    // SAFETY: delegated to caller; assembly stores the old stack pointer before moving to the new
    // stack, preserves SysV callee-saved registers, and returns only when this context is resumed.
    unsafe { kernal_context_switch(old_rsp, new_rsp) }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn kernal_context_switch(old_rsp: *mut u64, new_rsp: u64);
    fn kernal_kernel_thread_bootstrap();
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .global kernal_context_switch
kernal_context_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    .global kernal_kernel_thread_bootstrap
kernal_kernel_thread_bootstrap:
    mov rdi, r13
    jmp r12
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn never_return(_arg: u64) -> ! {
        panic!("test entry must not execute")
    }

    #[test]
    fn initial_frame_matches_switch_pop_order_and_alignment() {
        let mut words = [0xdead_beef_dead_beef; 32];
        let top = 0xffff_ff80_4001_0000;
        let start = build_initial_context(&mut words, top, never_return, 0x1234).unwrap();
        assert_eq!(start, 24);
        assert_eq!(words[start + 2], 0x1234);
        assert_eq!(words[start + 3], never_return as *const () as usize as u64);
        assert_ne!(words[start + 6], 0);
        let saved_rsp = top - CONTEXT_BYTES as u64;
        assert_eq!(saved_rsp & 0xf, 0);
        // Six pops + RET consume 56 bytes, leaving one 8-byte padding slot. SysV entry sees 8 mod16.
        assert_eq!((saved_rsp + 56) & 0xf, 8);
    }

    #[test]
    fn rejects_unaligned_top() {
        let mut words = [0u64; 8];
        assert_eq!(
            build_initial_context(&mut words, 0xffff_ffff_8000_0008, never_return, 0),
            Err(Error::StackMisaligned)
        );
    }
}
