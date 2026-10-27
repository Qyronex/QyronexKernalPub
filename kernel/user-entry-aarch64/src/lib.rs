// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::{asm, global_asm};
use kernal_vm::{USER_MAX_EXCLUSIVE, USER_MIN};

/// AArch64 instructions are always 4-byte aligned when returning to AArch64 EL0.
pub const USER_ENTRY_ALIGNMENT: u64 = 4;
/// AAPCS64 requires SP to remain 16-byte aligned at public interfaces.
pub const STACK_ALIGNMENT: u64 = 16;
/// First canonical TTBR1 address for the 48-bit VA regime used by Kernal.
pub const KERNEL_HALF_MIN: u64 = 0xffff_8000_0000_0000;
/// Sanitized PSTATE restored by `eret`: AArch64 EL0t, all condition/mask/control bits cleared.
pub const EL0T_SPSR_EL1: u64 = 0;
/// Step-9 native returns may preserve only the user-visible NZCV condition flags.
///
/// Mode, interrupt-mask, debug, single-step and other control bits must remain zero. This is a
/// deliberately narrow first native ABI; later steps may widen it only with an explicit policy.
const EL0_RETURN_ALLOWED_SPSR_MASK: u64 = 0xf000_0000;
/// Immediate carried by the feature-gated QEMU proof's EL0 `BRK` instruction.
#[cfg(feature = "qemu-proof")]
pub const QEMU_PROBE_BRK_COMMENT: u16 = 0x008a;
/// EL1h plus D/A/I/F masked, used only for the proof's controlled return from EL0.
#[cfg(feature = "qemu-proof")]
pub const QEMU_PROBE_RESUME_SPSR_EL1: u64 = 0x03c5;
#[cfg(feature = "qemu-proof")]
const QEMU_PROBE_SAVED_CONTEXT_BYTES: u64 = 12 * core::mem::size_of::<u64>() as u64;

// CPACR_EL1.{SMEN,FPEN,ZEN}.EL0EN are bits 25, 21 and 17 respectively. Clear only
// the EL0-enable half of each two-bit field so a future EL1 FP/SIMD implementation is not disabled.
#[cfg(test)]
const CPACR_EL0_ACCESS_MASK: u64 = (1 << 25) | (1 << 21) | (1 << 17);
// SCTLR_EL1.UCI bit 26 and UMA bit 9. A first user context must not inherit firmware permission to
// execute EL0 cache maintenance or mask/unmask DAIF, either of which is inappropriate before the
// kernel has explicit user policy for those operations.
#[cfg(test)]
const SCTLR_EL0_PRIVILEGED_ACCESS_MASK: u64 = (1 << 26) | (1 << 9);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EntryOutsideUserRange,
    EntryMisaligned,
    UserStackOutsideUserRange,
    UserStackMisaligned,
    KernelStackOutsideKernelHalf,
    KernelStackMisaligned,
}

/// Validated state for the one-way EL1 -> AArch64 EL0 transition.
///
/// The fields are private so callers cannot bypass the Step-8 entry-state validation. Mapping and
/// ownership are deliberately not duplicated here: the caller must use the accepted Step-7 address
/// space object to prove the entry page and user stack are present with the right permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El0EntryState {
    entry: u64,
    user_sp: u64,
    kernel_exception_sp: u64,
    argument0: u64,
}

impl El0EntryState {
    pub fn new(
        entry: u64,
        user_sp: u64,
        kernel_exception_sp: u64,
        argument0: u64,
    ) -> Result<Self, Error> {
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&entry) {
            return Err(Error::EntryOutsideUserRange);
        }
        if !entry.is_multiple_of(USER_ENTRY_ALIGNMENT) {
            return Err(Error::EntryMisaligned);
        }
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&user_sp) {
            return Err(Error::UserStackOutsideUserRange);
        }
        if !user_sp.is_multiple_of(STACK_ALIGNMENT) {
            return Err(Error::UserStackMisaligned);
        }
        if kernel_exception_sp < KERNEL_HALF_MIN {
            return Err(Error::KernelStackOutsideKernelHalf);
        }
        if !kernel_exception_sp.is_multiple_of(STACK_ALIGNMENT) {
            return Err(Error::KernelStackMisaligned);
        }

        Ok(Self {
            entry,
            user_sp,
            kernel_exception_sp,
            argument0,
        })
    }

    pub const fn entry(self) -> u64 {
        self.entry
    }

    pub const fn user_sp(self) -> u64 {
        self.user_sp
    }

    pub const fn kernel_exception_sp(self) -> u64 {
        self.kernel_exception_sp
    }

    pub const fn argument0(self) -> u64 {
        self.argument0
    }

    pub const fn spsr_el1(self) -> u64 {
        EL0T_SPSR_EL1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnStateError {
    ReturnPcOutsideUserRange,
    ReturnPcMisaligned,
    UserStackOutsideUserRange,
    UserStackMisaligned,
    UnsupportedSpsrEl1,
}

/// Validated architectural state for a native Step-9 `eret` back to AArch64 EL0.
///
/// This type is intentionally independent from the exception-frame implementation so the return
/// policy can be host-tested and reused by later native syscall/runtime code. It validates only the
/// architectural shape of the return state; address-space ownership and mapping permissions remain
/// the caller's responsibility through the accepted Step-7 address-space mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El0ReturnState {
    return_pc: u64,
    user_sp: u64,
    spsr_el1: u64,
}

impl El0ReturnState {
    pub fn new(return_pc: u64, spsr_el1: u64, user_sp: u64) -> Result<Self, ReturnStateError> {
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&return_pc) {
            return Err(ReturnStateError::ReturnPcOutsideUserRange);
        }
        if !return_pc.is_multiple_of(USER_ENTRY_ALIGNMENT) {
            return Err(ReturnStateError::ReturnPcMisaligned);
        }
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&user_sp) {
            return Err(ReturnStateError::UserStackOutsideUserRange);
        }
        if !user_sp.is_multiple_of(STACK_ALIGNMENT) {
            return Err(ReturnStateError::UserStackMisaligned);
        }
        if spsr_el1 & !EL0_RETURN_ALLOWED_SPSR_MASK != 0 {
            return Err(ReturnStateError::UnsupportedSpsrEl1);
        }

        Ok(Self {
            return_pc,
            user_sp,
            spsr_el1,
        })
    }

    pub const fn return_pc(self) -> u64 {
        self.return_pc
    }

    pub const fn user_sp(self) -> u64 {
        self.user_sp
    }

    pub const fn spsr_el1(self) -> u64 {
        self.spsr_el1
    }
}

#[cfg(test)]
const fn sanitize_cpacr_el1_for_el0(value: u64) -> u64 {
    value & !CPACR_EL0_ACCESS_MASK
}

#[cfg(test)]
const fn sanitize_sctlr_el1_for_el0(value: u64) -> u64 {
    value & !SCTLR_EL0_PRIVILEGED_ACCESS_MASK
}

/// Performs the controlled one-way transition from EL1 to AArch64 EL0.
///
/// The assembly masks asynchronous exceptions *before* changing SP/ELR/SPSR, removes inherited EL0
/// access to FP/SIMD/SVE/SME, DAIF and cache-maintenance controls, installs the dedicated EL1
/// exception stack, clears EL0 thread-ID registers and all general-purpose registers except the
/// explicit x0 argument, then executes `eret`. `EL0T_SPSR_EL1 == 0` means EL0 begins in AArch64
/// thread mode with DAIF unmasked and condition/control state cleared.
///
/// # Safety
/// Caller must:
/// - execute at EL1 with a valid VBAR_EL1 lower-EL AArch64 vector path;
/// - have activated the intended Step-7 TTBR0 address space and keep it owned by this context;
/// - ensure `entry` is mapped user RX and `user_sp` belongs to a mapped user RW-NX stack;
/// - ensure `kernel_exception_sp` is the top of a mapped, guarded, RW-NX EL1 exception stack with
///   sufficient space for the architecture exception frame.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn enter_el0(state: El0EntryState) -> ! {
    // SAFETY: the constructor established the register-shape invariants; mapping/EL1 ownership is
    // delegated to the caller contract above. The assembly never returns to this Rust frame.
    unsafe {
        kernal_enter_el0_aarch64(
            state.entry,
            state.user_sp,
            state.spsr_el1(),
            state.kernel_exception_sp,
            state.argument0,
        )
    }
}

/// Host-side stub keeps the API available to dependent crates without emulating privileged state.
///
/// # Safety
/// This path never performs an EL transition and always panics. It is not runtime evidence.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub unsafe fn enter_el0(_state: El0EntryState) -> ! {
    panic!("AArch64 EL0 entry requires the freestanding target")
}

/// Executes a feature-gated QEMU EL0 payload and returns only after the EL1 exception handler
/// redirects the exception frame to [`qemu_probe_resume_address`].
///
/// The wrapper preserves x19..x30 on the current kernel stack before entering EL0. The saved SP is
/// also used as the EL1 exception-stack top, so the vector frame grows below (and cannot overwrite)
/// the saved context. The internal EL1 resume label restores the saved context and returns normally
/// to this Rust call, allowing the proof to deactivate TTBR0 and continue the existing boot flow.
///
/// # Safety
/// Caller must execute on the BSP at EL1 with migration/interrupt ownership, have the intended TTBR0
/// root active, map `entry` user RX and `user_sp` in a user RW-NX stack, and install a lower-EL
/// AArch64 handler that validates the exact expected lower-EL synchronous exception before rewriting
/// ELR_EL1/SPSR_EL1 to the exported proof resume state. The current kernel stack must have room below
/// SP for the exception frame in addition to the saved 96-byte context.
#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
pub unsafe fn enter_el0_qemu_roundtrip(
    entry: u64,
    user_sp: u64,
    argument0: u64,
) -> Result<(), Error> {
    let current_sp: u64;
    // SAFETY: reading SP does not modify machine state.
    unsafe {
        asm!(
            "mov {sp}, sp",
            sp = out(reg) current_sp,
            options(nomem, nostack, preserves_flags)
        )
    };
    let exception_sp = current_sp
        .checked_sub(QEMU_PROBE_SAVED_CONTEXT_BYTES)
        .ok_or(Error::KernelStackOutsideKernelHalf)?;
    let state = El0EntryState::new(entry, user_sp, exception_sp, argument0)?;

    // SAFETY: delegated proof contract above. The assembly returns only through its EL1 resume label.
    unsafe {
        kernal_enter_el0_qemu_roundtrip(
            state.entry,
            state.user_sp,
            state.spsr_el1(),
            state.argument0,
        )
    };
    Ok(())
}

/// Returns the EL1 text address to which the proof handler redirects an accepted EL0 trap.
#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
pub fn qemu_probe_resume_address() -> u64 {
    unsafe extern "C" {
        static kernal_step8_qemu_resume_aarch64: u8;
    }
    core::ptr::addr_of!(kernal_step8_qemu_resume_aarch64) as u64
}

/// Returns the dedicated page containing the QEMU Step-8 user breakpoint payload.
///
/// The page is emitted only in proof builds, is isolated by 4-KiB alignment on both sides, and is
/// executable/read-only kernel text. The runtime proof may therefore share this one explicit page
/// into TTBR0 as user RX without creating a writable alias of kernel memory.
#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
pub fn qemu_probe_payload_page() -> Option<(u64, u64)> {
    unsafe extern "C" {
        static kernal_step8_user_probe_page: u8;
        static kernal_step8_user_probe_page_end: u8;
    }
    let start = core::ptr::addr_of!(kernal_step8_user_probe_page) as u64;
    let end = core::ptr::addr_of!(kernal_step8_user_probe_page_end) as u64;
    (start & (kernal_vm::PAGE_SIZE - 1) == 0
        && end.checked_sub(start) == Some(kernal_vm::PAGE_SIZE))
    .then_some((start, end))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_enter_el0_aarch64(
        entry: u64,
        user_sp: u64,
        spsr_el1: u64,
        kernel_exception_sp: u64,
        argument0: u64,
    ) -> !;
}

#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_enter_el0_qemu_roundtrip(entry: u64, user_sp: u64, spsr_el1: u64, argument0: u64);
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .section .text.kernal_user_entry_aarch64, "ax"
    .global kernal_enter_el0_aarch64
    .type kernal_enter_el0_aarch64, %function
kernal_enter_el0_aarch64:
    // No asynchronous exception may overwrite ELR_EL1/SPSR_EL1 during this transition window.
    msr daifset, #0xf

    // Warm firmware state is not trusted as EL0 policy. Trap user DAIF access and cache maintenance.
    mrs x5, sctlr_el1
    movz x6, #0x0200
    movk x6, #0x0400, lsl #16
    bic x5, x5, x6
    msr sctlr_el1, x5

    // Trap EL0 FP/SIMD, SVE and SME while preserving each field's EL1-enable bit.
    mrs x5, cpacr_el1
    movz x6, #0x0222, lsl #16
    bic x5, x5, x6
    msr cpacr_el1, x5
    isb

    // At EL1 a direct MSR SP_EL1 is architecturally UNDEFINED. Select SP_EL1 as the current stack
    // and update it through the architectural SP alias. No stack memory access occurs in between.
    msr spsel, #1
    mov sp, x3
    msr sp_el0, x1

    msr elr_el1, x0
    msr spsr_el1, x2

    // Do not leak a previous context's EL0 TLS values through architecturally readable registers.
    msr tpidr_el0, xzr
    msr tpidrro_el0, xzr
    isb

    // x0 is the only explicitly initialized user GPR. Clear all other GPRs so kernel register
    // contents cannot become observable at EL0.
    mov x0, x4
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    mov x18, xzr
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x29, xzr
    mov x30, xzr
    eret
"#
);

#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .section .text.kernal_step8_qemu_roundtrip_aarch64, "ax"
    .global kernal_enter_el0_qemu_roundtrip
    .type kernal_enter_el0_qemu_roundtrip, %function
kernal_enter_el0_qemu_roundtrip:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!

    // General entry ABI: x0=entry, x1=user SP, x2=SPSR, x3=kernel exception SP, x4=arg0.
    mov x4, x3
    mov x3, sp
    b kernal_enter_el0_aarch64

    .global kernal_step8_qemu_resume_aarch64
    .type kernal_step8_qemu_resume_aarch64, %function
kernal_step8_qemu_resume_aarch64:
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
"#
);

#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .section .text.kernal_step8_user_probe_aarch64, "ax"
    .balign 4096
    .global kernal_step8_user_probe_page
    .type kernal_step8_user_probe_page, %function
kernal_step8_user_probe_page:
    brk #{comment}
1:
    b 1b
    .balign 4096
    .global kernal_step8_user_probe_page_end
kernal_step8_user_probe_page_end:
"#,
    comment = const QEMU_PROBE_BRK_COMMENT,
);

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: u64 = USER_MIN + 0x20_000;
    const USER_SP: u64 = USER_MIN + 0x80_000;
    const KERNEL_SP: u64 = 0xffff_ffff_8040_0000;

    #[test]
    fn valid_state_is_sanitized_for_el0t() {
        let state = El0EntryState::new(ENTRY, USER_SP, KERNEL_SP, 0x1234).unwrap();
        assert_eq!(state.entry(), ENTRY);
        assert_eq!(state.user_sp(), USER_SP);
        assert_eq!(state.kernel_exception_sp(), KERNEL_SP);
        assert_eq!(state.argument0(), 0x1234);
        assert_eq!(state.spsr_el1(), 0);
    }

    #[test]
    fn valid_return_state_preserves_only_nzcv() {
        let state = El0ReturnState::new(ENTRY, 0xa000_0000, USER_SP).unwrap();
        assert_eq!(state.return_pc(), ENTRY);
        assert_eq!(state.user_sp(), USER_SP);
        assert_eq!(state.spsr_el1(), 0xa000_0000);
        assert_eq!(
            El0ReturnState::new(ENTRY, EL0T_SPSR_EL1, USER_SP)
                .unwrap()
                .spsr_el1(),
            0
        );
    }

    #[test]
    fn rejects_hostile_return_pc_or_stack() {
        assert_eq!(
            El0ReturnState::new(USER_MIN - 4, 0, USER_SP),
            Err(ReturnStateError::ReturnPcOutsideUserRange)
        );
        assert_eq!(
            El0ReturnState::new(USER_MAX_EXCLUSIVE, 0, USER_SP),
            Err(ReturnStateError::ReturnPcOutsideUserRange)
        );
        assert_eq!(
            El0ReturnState::new(ENTRY + 2, 0, USER_SP),
            Err(ReturnStateError::ReturnPcMisaligned)
        );
        assert_eq!(
            El0ReturnState::new(ENTRY, 0, USER_MIN - 16),
            Err(ReturnStateError::UserStackOutsideUserRange)
        );
        assert_eq!(
            El0ReturnState::new(ENTRY, 0, USER_MAX_EXCLUSIVE),
            Err(ReturnStateError::UserStackOutsideUserRange)
        );
        assert_eq!(
            El0ReturnState::new(ENTRY, 0, USER_SP + 8),
            Err(ReturnStateError::UserStackMisaligned)
        );
    }

    #[test]
    fn rejects_privileged_or_masked_return_pstate() {
        for hostile in [
            0x5,     // EL1h mode
            1 << 6,  // FIQ masked
            1 << 7,  // IRQ masked
            1 << 8,  // SError masked
            1 << 9,  // debug masked
            1 << 20, // illegal execution state
            1 << 21, // software single-step
            1 << 22, // PAN
        ] {
            assert_eq!(
                El0ReturnState::new(ENTRY, hostile, USER_SP),
                Err(ReturnStateError::UnsupportedSpsrEl1)
            );
        }
    }

    #[test]
    fn rejects_non_user_or_misaligned_entry() {
        assert_eq!(
            El0EntryState::new(USER_MIN - 4, USER_SP, KERNEL_SP, 0),
            Err(Error::EntryOutsideUserRange)
        );
        assert_eq!(
            El0EntryState::new(USER_MAX_EXCLUSIVE, USER_SP, KERNEL_SP, 0),
            Err(Error::EntryOutsideUserRange)
        );
        assert_eq!(
            El0EntryState::new(ENTRY + 2, USER_SP, KERNEL_SP, 0),
            Err(Error::EntryMisaligned)
        );
    }

    #[test]
    fn rejects_non_user_or_misaligned_user_stack() {
        assert_eq!(
            El0EntryState::new(ENTRY, USER_MIN - 16, KERNEL_SP, 0),
            Err(Error::UserStackOutsideUserRange)
        );
        assert_eq!(
            El0EntryState::new(ENTRY, USER_MAX_EXCLUSIVE, KERNEL_SP, 0),
            Err(Error::UserStackOutsideUserRange)
        );
        assert_eq!(
            El0EntryState::new(ENTRY, USER_SP + 8, KERNEL_SP, 0),
            Err(Error::UserStackMisaligned)
        );
    }

    #[test]
    fn rejects_user_half_or_misaligned_kernel_exception_stack() {
        assert_eq!(
            El0EntryState::new(ENTRY, USER_SP, USER_MAX_EXCLUSIVE, 0),
            Err(Error::KernelStackOutsideKernelHalf)
        );
        assert_eq!(
            El0EntryState::new(ENTRY, USER_SP, KERNEL_SP + 8, 0),
            Err(Error::KernelStackMisaligned)
        );
    }

    #[test]
    fn system_controls_trap_el0_only_fields() {
        let all = u64::MAX;
        let cpacr = sanitize_cpacr_el1_for_el0(all);
        assert_eq!(cpacr & CPACR_EL0_ACCESS_MASK, 0);
        assert_eq!(
            cpacr & ((1 << 24) | (1 << 20) | (1 << 16)),
            (1 << 24) | (1 << 20) | (1 << 16)
        );

        let sctlr = sanitize_sctlr_el1_for_el0(all);
        assert_eq!(sctlr & SCTLR_EL0_PRIVILEGED_ACCESS_MASK, 0);
        assert_eq!(sctlr & (1 << 19), 1 << 19);
    }

    #[test]
    fn qemu_probe_constants_match_roundtrip_contract() {
        #[cfg(feature = "qemu-proof")]
        {
            assert_eq!(QEMU_PROBE_BRK_COMMENT, 0x008a);
            assert_eq!(QEMU_PROBE_RESUME_SPSR_EL1, 0x03c5);
            assert_eq!(QEMU_PROBE_SAVED_CONTEXT_BYTES, 96);
        }
    }
}
