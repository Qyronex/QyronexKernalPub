// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::{asm, global_asm};

pub const INTEGER_CONTEXT_WORDS: usize = 12;
pub const FP_SIMD_CONTEXT_WORDS: usize = 66;
pub const CONTEXT_WORDS: usize = INTEGER_CONTEXT_WORDS + FP_SIMD_CONTEXT_WORDS;
pub const CONTEXT_BYTES: usize = CONTEXT_WORDS * core::mem::size_of::<u64>();
pub const EL0_FPSIMD_VREG_BYTES: usize = 32 * 16;
pub const EL0_FPSIMD_STATE_BYTES: usize = EL0_FPSIMD_VREG_BYTES + 16;

/// First instruction stream entered by the architecture bootstrap after restoring a prepared kernel
/// context. The eventual unsafe context switch must guarantee that `argument` satisfies the entry's
/// contract; [`build_initial_context`] only records the address and never invokes it.
pub type KernelThreadEntry = unsafe extern "C" fn(u64) -> !;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    StackTooSmall,
    StackMisaligned,
    InvalidEntry,
}

/// Exact live EL0 FP/Advanced-SIMD image used by the AArch64 signal-frame owner.
///
/// Layout deliberately matches the 528-byte vector tail already owned by the context-switch frame:
/// q0..q31 occupy the first 512 bytes, followed by zero-extended FPCR and FPSR 64-bit slots. This is
/// copied architectural state only; it is never a scheduler/thread registry or a persistent owner.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El0FpsimdState {
    vregs: [u8; EL0_FPSIMD_VREG_BYTES],
    fpcr: u64,
    fpsr: u64,
}

impl El0FpsimdState {
    pub const fn new(vregs: [u8; EL0_FPSIMD_VREG_BYTES], fpcr: u32, fpsr: u32) -> Self {
        Self {
            vregs,
            fpcr: fpcr as u64,
            fpsr: fpsr as u64,
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    const fn zeroed() -> Self {
        Self::new([0; EL0_FPSIMD_VREG_BYTES], 0, 0)
    }

    pub const fn vregs(&self) -> &[u8; EL0_FPSIMD_VREG_BYTES] {
        &self.vregs
    }

    pub const fn fpcr(self) -> u32 {
        self.fpcr as u32
    }

    pub const fn fpsr(self) -> u32 {
        self.fpsr as u32
    }
}

/// Builds the initial saved-register frame expected by `switch` at the top of an AArch64 kernel
/// stack. The first 12 words preserve the AAPCS64 callee-saved integer frame. The remaining 528
/// bytes are the generation-owned EL0 FP/Advanced-SIMD image: q0..q31 followed by FPCR and FPSR.
/// A fresh generation starts with a fully zeroed FP/SIMD image so no prior kernel/firmware/thread
/// vector state can become user-visible on its first exception return.
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
    frame.fill(0);
    // Restore order in assembly is x29/x30, x27/x28, x25/x26, x23/x24, x21/x22, x19/x20,
    // followed by the generation-owned FP/SIMD image.
    // x19 carries the entry address, x20 the entry argument, and x30 returns into the bootstrap.
    frame[0] = 0; // x29 / frame pointer
    frame[1] = bootstrap_address(); // x30 / link register
    frame[2] = 0; // x27
    frame[3] = 0; // x28
    frame[4] = 0; // x25
    frame[5] = 0; // x26
    frame[6] = 0; // x23
    frame[7] = 0; // x24
    frame[8] = 0; // x21
    frame[9] = 0; // x22
    frame[10] = entry_address; // x19
    frame[11] = argument; // x20
    Ok(start)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn bootstrap_address() -> u64 {
    kernal_kernel_thread_bootstrap_aarch64 as *const () as usize as u64
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn bootstrap_address() -> u64 {
    host_test_bootstrap as *const () as usize as u64
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
extern "C" fn host_test_bootstrap() {}

/// Installs the EL0 thread-pointer value for the user thread selected on the current PE.
///
/// TPIDR_EL0 is user-visible architectural state and is intentionally not added to the hot AAPCS64
/// kernel context-switch frame. Step 15 stores its authoritative value in the exact generation-owned
/// thread metadata and writes this register only at an owner-controlled user-thread selection/resume
/// boundary. TPIDRRO_EL0 is also EL0-readable, so the same boundary clears it rather than allowing a
/// stale privileged/previous-runtime value to become user-visible.
///
/// # Safety
/// - Must execute at EL1 on the CPU/PE that owns the selected scheduler generation.
/// - The caller must hold exclusive local scheduler ownership with IRQ/preemption quiescence.
/// - `value` must belong to the exact generation that will resume before any competing user thread.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn install_el0_thread_pointer(value: u64) {
    // SAFETY: delegated to the caller contract. Both registers are EL1-owned writes and ISB ensures
    // the sanitized/user TLS state is observed before a following exception-return/user boundary.
    unsafe {
        asm!(
            "msr tpidrro_el0, xzr",
            "msr tpidr_el0, {value}",
            "isb",
            value = in(reg) value,
            options(nostack, preserves_flags)
        )
    };
}

/// Reads the live EL0 thread-pointer value for the exact current scheduler generation.
///
/// # Safety
/// Must execute at EL1 while the caller owns the current PE with local scheduling quiesced, so the
/// observed register cannot be attributed to a different user thread across a concurrent switch.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn read_el0_thread_pointer() -> u64 {
    let value: u64;
    // SAFETY: delegated to the caller contract; MRS has no memory side effects.
    unsafe {
        asm!(
            "mrs {value}, tpidr_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Captures the exact current generation's live EL0 FP/Advanced-SIMD image.
///
/// # Safety
/// Must execute at EL1 while the caller owns the current PE, has the exact current user generation
/// selected, and prevents context switches/competing FP use until this short operation completes.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn capture_current_el0_fpsimd() -> El0FpsimdState {
    let mut state = El0FpsimdState::zeroed();
    // SAFETY: delegated caller contract keeps this PE and exact live vector generation quiescent;
    // `state` is aligned writable storage of the exact assembly layout for the duration of the call.
    unsafe { kernal_capture_current_el0_fpsimd(&mut state) };
    state
}

/// Restores the exact current generation's live EL0 FP/Advanced-SIMD image.
///
/// # Safety
/// Must execute at EL1 with the same quiescent exact-current-generation ownership as capture. The
/// supplied image must have been fully validated by the architecture signal-frame integration owner.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn restore_current_el0_fpsimd(state: &El0FpsimdState) {
    // SAFETY: delegated caller contract guarantees the image belongs to the exact generation that
    // will return to EL0 and no context switch/competing vector owner can interleave this restore.
    unsafe { kernal_restore_current_el0_fpsimd(state) };
}

/// Switches between two AArch64 kernel contexts.
///
/// `old_sp` receives the outgoing stack pointer. `new_sp` must point to a frame created by
/// `build_initial_context` or saved by a previous call to this function. In addition to the AAPCS64
/// integer state, every switch eagerly saves/restores q0..q31, FPCR and FPSR. The FP/SIMD image lives
/// on the exact generation-owned kernel stack, so scheduler slot reuse cannot inherit vector state.
/// The switch also enables CPACR_EL1.FPEN before touching vector registers; the kernel itself remains
/// built for the soft-float target and therefore cannot accidentally acquire implicit SIMD state.
///
/// # Safety
/// - Must execute at the kernel exception level with scheduler/preemption policy preventing reuse
///   of either stack while a context is suspended.
/// - `old_sp` must be non-null, aligned, writable, and remain valid until this context resumes.
/// - Both stacks must remain mapped RW-NX and keep the AAPCS64 16-byte SP alignment invariant.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn switch(old_sp: *mut u64, new_sp: u64) {
    debug_assert!(!old_sp.is_null());
    debug_assert_eq!((old_sp as usize) & (core::mem::align_of::<u64>() - 1), 0);
    debug_assert_eq!(new_sp & 0xf, 0);
    // SAFETY: delegated to caller; assembly stores the old SP, preserves all AAPCS64 callee-saved
    // integer registers plus the complete user-visible FP/SIMD state, switches stacks, restores the
    // exact selected generation, and returns only when that context is active.
    unsafe { kernal_context_switch_aarch64(old_sp, new_sp) }
}

/// Host-side support builds expose the symbol so dependent crates compile, but never emulate a
/// privileged kernel context switch.
///
/// # Safety
/// This path always fails immediately and must not be used as runtime evidence.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub unsafe fn switch(_old_sp: *mut u64, _new_sp: u64) {
    panic!("AArch64 kernel context switch requires the freestanding target")
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_context_switch_aarch64(old_sp: *mut u64, new_sp: u64);
    fn kernal_capture_current_el0_fpsimd(state: *mut El0FpsimdState);
    fn kernal_restore_current_el0_fpsimd(state: *const El0FpsimdState);
    fn kernal_kernel_thread_bootstrap_aarch64();
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .arch armv8-a+simd

    .global kernal_capture_current_el0_fpsimd
    .type kernal_capture_current_el0_fpsimd, %function
kernal_capture_current_el0_fpsimd:
    mrs x1, cpacr_el1
    mov x2, #3
    lsl x2, x2, #20
    orr x1, x1, x2
    msr cpacr_el1, x1
    isb
    stp q0, q1, [x0, #0]
    stp q2, q3, [x0, #32]
    stp q4, q5, [x0, #64]
    stp q6, q7, [x0, #96]
    stp q8, q9, [x0, #128]
    stp q10, q11, [x0, #160]
    stp q12, q13, [x0, #192]
    stp q14, q15, [x0, #224]
    stp q16, q17, [x0, #256]
    stp q18, q19, [x0, #288]
    stp q20, q21, [x0, #320]
    stp q22, q23, [x0, #352]
    stp q24, q25, [x0, #384]
    stp q26, q27, [x0, #416]
    stp q28, q29, [x0, #448]
    stp q30, q31, [x0, #480]
    mrs x1, fpcr
    str x1, [x0, #512]
    mrs x1, fpsr
    str x1, [x0, #520]
    ret

    .global kernal_restore_current_el0_fpsimd
    .type kernal_restore_current_el0_fpsimd, %function
kernal_restore_current_el0_fpsimd:
    mrs x1, cpacr_el1
    mov x2, #3
    lsl x2, x2, #20
    orr x1, x1, x2
    msr cpacr_el1, x1
    isb
    ldp q0, q1, [x0, #0]
    ldp q2, q3, [x0, #32]
    ldp q4, q5, [x0, #64]
    ldp q6, q7, [x0, #96]
    ldp q8, q9, [x0, #128]
    ldp q10, q11, [x0, #160]
    ldp q12, q13, [x0, #192]
    ldp q14, q15, [x0, #224]
    ldp q16, q17, [x0, #256]
    ldp q18, q19, [x0, #288]
    ldp q20, q21, [x0, #320]
    ldp q22, q23, [x0, #352]
    ldp q24, q25, [x0, #384]
    ldp q26, q27, [x0, #416]
    ldp q28, q29, [x0, #448]
    ldp q30, q31, [x0, #480]
    ldr x1, [x0, #512]
    msr fpcr, x1
    ldr x1, [x0, #520]
    msr fpsr, x1
    isb
    ret

    .global kernal_context_switch_aarch64
    .type kernal_context_switch_aarch64, %function
kernal_context_switch_aarch64:
    // The kernel target is soft-float. Explicitly opening FPEN here is therefore the sole eager
    // ownership boundary for EL0 FP/Advanced-SIMD, and all vector state is immediately saved below.
    mrs x3, cpacr_el1
    mov x4, #3
    lsl x4, x4, #20
    orr x3, x3, x4
    msr cpacr_el1, x3
    isb

    sub sp, sp, #528
    stp q0, q1, [sp, #0]
    stp q2, q3, [sp, #32]
    stp q4, q5, [sp, #64]
    stp q6, q7, [sp, #96]
    stp q8, q9, [sp, #128]
    stp q10, q11, [sp, #160]
    stp q12, q13, [sp, #192]
    stp q14, q15, [sp, #224]
    stp q16, q17, [sp, #256]
    stp q18, q19, [sp, #288]
    stp q20, q21, [sp, #320]
    stp q22, q23, [sp, #352]
    stp q24, q25, [sp, #384]
    stp q26, q27, [sp, #416]
    stp q28, q29, [sp, #448]
    stp q30, q31, [sp, #480]
    mrs x3, fpcr
    str x3, [sp, #512]
    mrs x3, fpsr
    str x3, [sp, #520]

    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!
    mov x2, sp
    str x2, [x0]
    mov sp, x1
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    ldp q0, q1, [sp, #0]
    ldp q2, q3, [sp, #32]
    ldp q4, q5, [sp, #64]
    ldp q6, q7, [sp, #96]
    ldp q8, q9, [sp, #128]
    ldp q10, q11, [sp, #160]
    ldp q12, q13, [sp, #192]
    ldp q14, q15, [sp, #224]
    ldp q16, q17, [sp, #256]
    ldp q18, q19, [sp, #288]
    ldp q20, q21, [sp, #320]
    ldp q22, q23, [sp, #352]
    ldp q24, q25, [sp, #384]
    ldp q26, q27, [sp, #416]
    ldp q28, q29, [sp, #448]
    ldp q30, q31, [sp, #480]
    ldr x3, [sp, #512]
    msr fpcr, x3
    ldr x3, [sp, #520]
    msr fpsr, x3
    add sp, sp, #528
    ret

    .global kernal_kernel_thread_bootstrap_aarch64
    .type kernal_kernel_thread_bootstrap_aarch64, %function
kernal_kernel_thread_bootstrap_aarch64:
    mov x0, x20
    br x19
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn never_return(_arg: u64) -> ! {
        panic!("test entry must not execute")
    }

    #[test]
    fn initial_frame_matches_restore_order_and_aapcs_alignment() {
        let mut words = [0xdead_beef_dead_beef; 96];
        let top = 0xffff_0000_4001_0000;
        let start = build_initial_context(&mut words, top, never_return, 0x1234).unwrap();
        assert_eq!(start, words.len() - CONTEXT_WORDS);
        assert_ne!(words[start + 1], 0);
        assert_eq!(words[start + 10], never_return as *const () as usize as u64);
        assert_eq!(words[start + 11], 0x1234);
        assert!(
            words[start + INTEGER_CONTEXT_WORDS..]
                .iter()
                .all(|word| *word == 0)
        );
        let saved_sp = top - CONTEXT_BYTES as u64;
        assert_eq!(saved_sp & 0xf, 0);
        assert_eq!((saved_sp + CONTEXT_BYTES as u64) & 0xf, 0);
    }

    #[test]
    fn rejects_unaligned_stack_top() {
        let mut words = [0u64; CONTEXT_WORDS];
        assert_eq!(
            build_initial_context(&mut words, 0xffff_0000_4001_0008, never_return, 0),
            Err(Error::StackMisaligned)
        );
    }

    #[test]
    fn generation_context_size_covers_full_fp_simd_image() {
        assert_eq!(INTEGER_CONTEXT_WORDS, 12);
        assert_eq!(FP_SIMD_CONTEXT_WORDS, 66);
        assert_eq!(CONTEXT_BYTES, 624);
        assert_eq!(CONTEXT_BYTES & 0xf, 0);
    }

    #[test]
    fn signal_fpsimd_state_matches_context_switch_tail_layout() {
        let vregs = core::array::from_fn(|index| (index as u8).wrapping_mul(3));
        let state = El0FpsimdState::new(vregs, 0x1122_3344, 0x5566_7788);
        assert_eq!(
            core::mem::size_of::<El0FpsimdState>(),
            EL0_FPSIMD_STATE_BYTES
        );
        assert_eq!(EL0_FPSIMD_STATE_BYTES, 528);
        assert_eq!(core::mem::align_of::<El0FpsimdState>(), 16);
        assert_eq!(state.vregs(), &vregs);
        assert_eq!(state.fpcr(), 0x1122_3344);
        assert_eq!(state.fpsr(), 0x5566_7788);
    }
}
