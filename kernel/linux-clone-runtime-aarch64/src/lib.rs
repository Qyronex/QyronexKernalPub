// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
use core::mem::size_of;
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
use kernal_exceptions_aarch64::SYNTHETIC_RETURN_BYTES;
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
use kernal_linux_clone_aarch64::CloneFirstRunRecord;
use kernal_linux_clone_aarch64::{
    CloneChildState, CloneKernelContextError, PreparedCloneKernelContext,
    prepare_clone_kernel_context,
};
use kernal_thread_context::KernelStack;

const RUNTIME_ARGUMENT_NONE: u64 = 0;
#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
const RECORD_ALIGNMENT: u64 = 16;

/// Builds the canonical first-run kernel context for one already-validated AArch64 clone child.
///
/// This wrapper deliberately fixes the kernel entry to this crate's private first-run trampoline.
/// Callers cannot obtain that entry and invoke it without crossing an unsafe boundary. Scheduler,
/// Process and TID publication remain in the existing owners; this function only prepares the
/// already accepted one-shot stack image.
pub fn prepare_first_run_context(
    stack_words: &mut [u64],
    stack: KernelStack,
    child: CloneChildState,
) -> Result<PreparedCloneKernelContext, CloneKernelContextError> {
    prepare_clone_kernel_context(
        stack_words,
        stack,
        clone_first_run_entry,
        child,
        RUNTIME_ARGUMENT_NONE,
    )
}

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordAddressError {
    Null,
    Misaligned,
    NotRepresentable,
    AddressOverflow,
}

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
fn checked_record_pointer(
    record_address: u64,
) -> Result<*const CloneFirstRunRecord, RecordAddressError> {
    validate_record_address(record_address, usize::MAX as u64)?;
    Ok((record_address as usize) as *const CloneFirstRunRecord)
}

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
fn validate_record_address(
    record_address: u64,
    maximum_address: u64,
) -> Result<(), RecordAddressError> {
    if record_address == 0 {
        return Err(RecordAddressError::Null);
    }
    if !record_address.is_multiple_of(RECORD_ALIGNMENT) {
        return Err(RecordAddressError::Misaligned);
    }
    if record_address > maximum_address {
        return Err(RecordAddressError::NotRepresentable);
    }

    let record_last = record_address
        .checked_add(size_of::<CloneFirstRunRecord>() as u64 - 1)
        .ok_or(RecordAddressError::AddressOverflow)?;
    let window_last = record_address
        .checked_add(SYNTHETIC_RETURN_BYTES as u64 - 1)
        .ok_or(RecordAddressError::AddressOverflow)?;
    if record_last > maximum_address || window_last > maximum_address {
        return Err(RecordAddressError::NotRepresentable);
    }
    Ok(())
}

/// First kernel instruction stream executed after the scheduler selects a freshly published clone
/// child for the first time.
///
/// The function is intentionally private and unsafe. The only production address written into a
/// child context is installed by [`prepare_first_run_context`], which also places a validated
/// [`CloneFirstRunRecord`] at exactly the argument address. The scheduler's context bootstrap pops
/// the normal callee-saved frame before branching here, leaving the one-shot record untouched at the
/// current stack top. The record is copied before the canonical synthetic exception frame overwrites
/// that same window.
///
/// # Safety
/// `record_address` must be the exact still-mapped first-run record address produced for the current
/// scheduler generation by [`prepare_first_run_context`]. The caller must own that generation and its
/// kernel stack exclusively, and the complete canonical synthetic-return window beginning at the
/// record must remain readable and writable until exception return.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" fn clone_first_run_entry(record_address: u64) -> ! {
    let record_pointer = match checked_record_pointer(record_address) {
        Ok(pointer) => pointer,
        Err(_) => fail_closed(),
    };

    // SAFETY: delegated to this unsafe entry's contract. The pure checks above reject null,
    // misalignment, target-address truncation and arithmetic wrap before the exact one-shot record is
    // copied. The copy happens before synthetic ERET reuses the same stack window.
    let record = unsafe { core::ptr::read(record_pointer) };
    let state = match record.synthetic_return(record_address) {
        Ok(state) => state,
        Err(_) => fail_closed(),
    };

    // SAFETY: the scheduler has already installed this exact generation's TPIDR_EL0 and selected its
    // kernel stack. clone uses the accepted CLONE_VM contract, so the process TTBR0 remains the same
    // shared address-space owner. `synthetic_return` revalidated the complete EL0 return state and
    // exact frame base immediately before this call.
    unsafe { kernal_exceptions_aarch64::resume_synthetic_el0(state) }
}

/// Host-side builds retain the exact unsafe ABI but never emulate privileged exception return.
///
/// # Safety
/// This stub has no successful call contract and must not be used as runtime evidence.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
unsafe extern "C" fn clone_first_run_entry(_record_address: u64) -> ! {
    panic!("AArch64 clone first-run entry requires the freestanding target")
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn fail_closed() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_context_aarch64::CONTEXT_BYTES;
    use kernal_linux_clone::{ClonePlan, MUSL_PTHREAD_FLAGS};
    use kernal_user_entry_aarch64::{EL0T_SPSR_EL1, El0ReturnState};

    const RETURN_PC: u64 = 0x0000_0000_0003_0000;
    const PARENT_SP: u64 = 0x0000_0000_0008_0000;
    const CHILD_SP: u64 = 0x0000_0000_000a_0000;
    const PTID: u64 = 0x0000_0000_000c_0000;
    const TLS: u64 = 0x0000_0000_000e_0008;
    const CTID: u64 = 0x0000_0000_0010_0000;
    const STACK_GUARD: u64 = 0xffff_ffff_8040_0000;
    const STACK_MAPPED: u64 = STACK_GUARD + 0x1000;
    const STACK_LEN: u64 = 0x4000;
    const STACK_WORDS: usize = STACK_LEN as usize / core::mem::size_of::<u64>();

    fn child() -> CloneChildState {
        let plan = ClonePlan::validate(MUSL_PTHREAD_FLAGS, CHILD_SP, PTID, TLS, CTID).unwrap();
        let parent = core::array::from_fn(|index| 0x1000 + index as u64);
        let parent_return = El0ReturnState::new(RETURN_PC, EL0T_SPSR_EL1, PARENT_SP).unwrap();
        CloneChildState::from_parent(&parent, parent_return, plan).unwrap()
    }

    fn stack() -> KernelStack {
        KernelStack::new(STACK_GUARD, STACK_MAPPED, STACK_LEN).unwrap()
    }

    #[test]
    fn wrapper_installs_only_the_private_unsafe_first_run_entry() {
        let stack = stack();
        let mut words = [0u64; STACK_WORDS];
        let prepared = prepare_first_run_context(&mut words, stack, child()).unwrap();

        assert_eq!(
            prepared.first_run_record(),
            prepared.kernel_exception_sp() - SYNTHETIC_RETURN_BYTES as u64
        );
        assert_eq!(
            prepared.saved_sp() + CONTEXT_BYTES as u64,
            prepared.first_run_record()
        );
        assert_eq!(prepared.user_thread_pointer(), TLS);

        let context_index =
            usize::try_from((prepared.saved_sp() - stack.mapped_start) / 8).unwrap();
        assert_eq!(
            words[context_index + 10],
            clone_first_run_entry as *const () as usize as u64
        );
        assert_eq!(words[context_index + 11], prepared.first_run_record());
    }

    #[test]
    fn wrapper_preserves_upstream_validation_failures() {
        let stack = stack();
        let mut short = [0u64; 8];
        assert!(matches!(
            prepare_first_run_context(&mut short, stack, child()),
            Err(CloneKernelContextError::StackWordsMismatch { .. })
        ));
    }

    #[test]
    fn raw_record_address_is_rejected_before_pointer_construction() {
        assert_eq!(
            validate_record_address(0, u64::MAX),
            Err(RecordAddressError::Null)
        );
        assert_eq!(
            validate_record_address(STACK_MAPPED + 8, u64::MAX),
            Err(RecordAddressError::Misaligned)
        );
        assert_eq!(
            validate_record_address(0x1_0000, 0xffff),
            Err(RecordAddressError::NotRepresentable)
        );
        assert_eq!(
            validate_record_address(u64::MAX - 0xf, u64::MAX),
            Err(RecordAddressError::AddressOverflow)
        );
    }

    #[test]
    fn exact_prepared_record_window_passes_pre_read_validation() {
        let record_address = STACK_MAPPED + STACK_LEN - SYNTHETIC_RETURN_BYTES as u64;
        assert_eq!(validate_record_address(record_address, u64::MAX), Ok(()));
        assert_eq!(
            checked_record_pointer(record_address).unwrap() as usize as u64,
            record_address
        );
    }
}
