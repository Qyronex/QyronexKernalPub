// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::size_of;
use kernal_context_aarch64::CONTEXT_BYTES;
use kernal_exceptions_aarch64::{SYNTHETIC_RETURN_BYTES, SyntheticEl0Return, SyntheticReturnError};
use kernal_thread_context::KernelStack;
use kernal_user_elf_runtime_aarch64::LoadedImage;
use kernal_user_entry_aarch64::{EL0T_SPSR_EL1, El0ReturnState, ReturnStateError, STACK_ALIGNMENT};

const WORD_BYTES: usize = size_of::<u64>();
const SYNTHETIC_RETURN_WORDS: usize = SYNTHETIC_RETURN_BYTES / WORD_BYTES;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitialUserRecord {
    return_pc: u64,
    user_sp: u64,
}

const _: [(); 2 * WORD_BYTES] = [(); size_of::<InitialUserRecord>()];
const _: () = assert!(SYNTHETIC_RETURN_BYTES.is_multiple_of(WORD_BYTES));
const _: () = assert!(size_of::<InitialUserRecord>() <= SYNTHETIC_RETURN_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKernelStack,
    StackWordsMismatch { expected: usize, actual: usize },
    StackAddressMismatch { expected: u64, actual: u64 },
    StackTooSmall,
    RecordMisaligned,
    AddressOverflow,
    Context(kernal_context_aarch64::Error),
    ReturnState(ReturnStateError),
    SyntheticReturn(SyntheticReturnError),
    Invariant,
}

/// One initialized first-run stack image for an already loaded user process.
///
/// This value is intentionally neither `Copy` nor `Clone`: the backing stack and its one-shot record
/// must be published to at most one scheduler generation. Final publication remains an unsafe
/// scheduler-owner operation, but ordinary code cannot duplicate this preparation token by accident.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedInitialUserContext {
    stack: KernelStack,
    saved_sp: u64,
    first_run_record: u64,
    kernel_exception_sp: u64,
}

impl PreparedInitialUserContext {
    pub const fn stack(&self) -> KernelStack {
        self.stack
    }

    pub const fn saved_sp(&self) -> u64 {
        self.saved_sp
    }

    pub const fn first_run_record(&self) -> u64 {
        self.first_run_record
    }

    pub const fn kernel_exception_sp(&self) -> u64 {
        self.kernel_exception_sp
    }

    /// Initial process entry has no inherited userspace TLS value.
    pub const fn user_thread_pointer(&self) -> u64 {
        0
    }
}

/// Builds one scheduler-ready first-run kernel context for an already loaded AArch64 image.
///
/// `loaded` is the output of the canonical AArch64 ELF loader and remains authoritative for the
/// validated entry point and initial userspace stack. This helper proves that `stack_words` is the
/// exact storage named by `stack`, reserves the canonical synthetic exception-return window at the
/// top of that guarded kernel stack and places the accepted AAPCS64 context-switch frame immediately
/// below it. No Process, scheduler, address-space, Linux identity or user-memory state is mutated.
pub fn prepare_initial_user_context(
    stack_words: &mut [u64],
    stack: KernelStack,
    loaded: LoadedImage,
) -> Result<PreparedInitialUserContext, Error> {
    prepare_parts(stack_words, stack, loaded.entry, loaded.initial_sp)
}

fn prepare_parts(
    stack_words: &mut [u64],
    stack: KernelStack,
    entry: u64,
    initial_sp: u64,
) -> Result<PreparedInitialUserContext, Error> {
    let validated = KernelStack::new(stack.guard_start, stack.mapped_start, stack.mapped_len)
        .map_err(|_| Error::InvalidKernelStack)?;
    if validated != stack {
        return Err(Error::InvalidKernelStack);
    }

    let return_state =
        El0ReturnState::new(entry, EL0T_SPSR_EL1, initial_sp).map_err(Error::ReturnState)?;
    let mapped_len = usize::try_from(stack.mapped_len).map_err(|_| Error::AddressOverflow)?;
    let actual_bytes = stack_words
        .len()
        .checked_mul(WORD_BYTES)
        .ok_or(Error::AddressOverflow)?;
    if actual_bytes != mapped_len {
        return Err(Error::StackWordsMismatch {
            expected: mapped_len / WORD_BYTES,
            actual: stack_words.len(),
        });
    }

    let actual_start =
        u64::try_from(stack_words.as_mut_ptr() as usize).map_err(|_| Error::AddressOverflow)?;
    if actual_start != stack.mapped_start {
        return Err(Error::StackAddressMismatch {
            expected: stack.mapped_start,
            actual: actual_start,
        });
    }
    let actual_end = actual_start
        .checked_add(u64::try_from(actual_bytes).map_err(|_| Error::AddressOverflow)?)
        .ok_or(Error::AddressOverflow)?;

    let kernel_exception_sp = stack.top().map_err(|_| Error::InvalidKernelStack)?;
    if actual_end != kernel_exception_sp {
        return Err(Error::Invariant);
    }
    let first_run_record = kernel_exception_sp
        .checked_sub(SYNTHETIC_RETURN_BYTES as u64)
        .ok_or(Error::StackTooSmall)?;
    if !first_run_record.is_multiple_of(STACK_ALIGNMENT) {
        return Err(Error::RecordMisaligned);
    }
    let prefix_bytes = first_run_record
        .checked_sub(stack.mapped_start)
        .ok_or(Error::StackTooSmall)?;
    if prefix_bytes < CONTEXT_BYTES as u64 || !prefix_bytes.is_multiple_of(WORD_BYTES as u64) {
        return Err(Error::StackTooSmall);
    }
    let prefix_words =
        usize::try_from(prefix_bytes / WORD_BYTES as u64).map_err(|_| Error::AddressOverflow)?;
    if stack_words.len().checked_sub(prefix_words) != Some(SYNTHETIC_RETURN_WORDS) {
        return Err(Error::Invariant);
    }

    let record = InitialUserRecord {
        return_pc: return_state.return_pc(),
        user_sp: return_state.user_sp(),
    };
    let state = synthetic_return(record, first_run_record)?;
    if state.kernel_exception_sp() != kernel_exception_sp {
        return Err(Error::Invariant);
    }

    let context_start = kernal_context_aarch64::build_initial_context(
        &mut stack_words[..prefix_words],
        first_run_record,
        initial_user_first_run_entry,
        first_run_record,
    )
    .map_err(Error::Context)?;
    let saved_sp = stack
        .mapped_start
        .checked_add(
            u64::try_from(
                context_start
                    .checked_mul(WORD_BYTES)
                    .ok_or(Error::AddressOverflow)?,
            )
            .map_err(|_| Error::AddressOverflow)?,
        )
        .ok_or(Error::AddressOverflow)?;
    if saved_sp.checked_add(CONTEXT_BYTES as u64) != Some(first_run_record)
        || !stack.contains_rsp(saved_sp)
    {
        return Err(Error::Invariant);
    }

    let synthetic_window = &mut stack_words[prefix_words..];
    synthetic_window.fill(0);
    synthetic_window[0] = record.return_pc;
    synthetic_window[1] = record.user_sp;

    Ok(PreparedInitialUserContext {
        stack,
        saved_sp,
        first_run_record,
        kernel_exception_sp,
    })
}

fn synthetic_return(
    record: InitialUserRecord,
    record_address: u64,
) -> Result<SyntheticEl0Return, Error> {
    if record_address == 0 || !record_address.is_multiple_of(STACK_ALIGNMENT) {
        return Err(Error::RecordMisaligned);
    }
    let kernel_exception_sp = record_address
        .checked_add(SYNTHETIC_RETURN_BYTES as u64)
        .ok_or(Error::AddressOverflow)?;
    let return_state = El0ReturnState::new(record.return_pc, EL0T_SPSR_EL1, record.user_sp)
        .map_err(Error::ReturnState)?;
    let state = SyntheticEl0Return::new([0; 31], return_state, kernel_exception_sp)
        .map_err(Error::SyntheticReturn)?;
    if state.frame_base() != record_address {
        return Err(Error::Invariant);
    }
    Ok(state)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" fn initial_user_first_run_entry(record_address: u64) -> ! {
    if record_address == 0 || !record_address.is_multiple_of(STACK_ALIGNMENT) {
        fail_closed();
    }
    let pointer_address = match usize::try_from(record_address) {
        Ok(address) => address,
        Err(_) => fail_closed(),
    };
    if pointer_address
        .checked_add(size_of::<InitialUserRecord>() - 1)
        .is_none()
    {
        fail_closed();
    }
    let pointer = pointer_address as *const InitialUserRecord;
    // SAFETY: this private entry is installed only by `prepare_initial_user_context`, which proves
    // the exact mapped stack storage and writes the complete aligned record before publication.
    let record = unsafe { core::ptr::read(pointer) };
    let state = match synthetic_return(record, record_address) {
        Ok(state) => state,
        Err(_) => fail_closed(),
    };
    // SAFETY: scheduler selection owns this generation/stack and installed TPIDR_EL0=0 before the
    // first switch. The caller activated the loaded process TTBR0 before making the leader runnable.
    unsafe { kernal_exceptions_aarch64::resume_synthetic_el0(state) }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
unsafe extern "C" fn initial_user_first_run_entry(_record_address: u64) -> ! {
    panic!("AArch64 initial userspace first-run entry requires the freestanding target")
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
    use kernal_thread_context::PAGE_SIZE;

    const STACK_LEN: u64 = 0x4000;
    const STACK_WORDS: usize = STACK_LEN as usize / WORD_BYTES;
    const ENTRY: u64 = 0x0000_0000_0002_0000;
    const USER_SP: u64 = 0x0000_0000_0008_0000;

    #[repr(C, align(4096))]
    struct AlignedStack([u64; STACK_WORDS]);

    fn stack_for(storage: &mut AlignedStack) -> KernelStack {
        let mapped_start = storage.0.as_mut_ptr() as usize as u64;
        let guard_start = mapped_start.checked_sub(PAGE_SIZE).unwrap();
        KernelStack::new(guard_start, mapped_start, STACK_LEN).unwrap()
    }

    #[test]
    fn prepared_context_places_switch_frame_immediately_below_synthetic_window() {
        let mut storage = AlignedStack([0xfeed_face_feed_face; STACK_WORDS]);
        let stack = stack_for(&mut storage);
        let prepared = prepare_parts(&mut storage.0, stack, ENTRY, USER_SP).unwrap();

        assert_eq!(prepared.stack(), stack);
        assert_eq!(prepared.user_thread_pointer(), 0);
        assert_eq!(prepared.kernel_exception_sp(), stack.top().unwrap());
        assert_eq!(
            prepared.first_run_record(),
            prepared.kernel_exception_sp() - SYNTHETIC_RETURN_BYTES as u64
        );
        assert_eq!(
            prepared.saved_sp() + CONTEXT_BYTES as u64,
            prepared.first_run_record()
        );

        let context_index =
            usize::try_from((prepared.saved_sp() - stack.mapped_start) / WORD_BYTES as u64)
                .unwrap();
        assert_eq!(
            storage.0[context_index + 10],
            initial_user_first_run_entry as *const () as usize as u64
        );
        assert_eq!(storage.0[context_index + 11], prepared.first_run_record());

        let record_index =
            usize::try_from((prepared.first_run_record() - stack.mapped_start) / WORD_BYTES as u64)
                .unwrap();
        assert_eq!(storage.0[record_index], ENTRY);
        assert_eq!(storage.0[record_index + 1], USER_SP);
        assert!(storage.0[record_index + 2..].iter().all(|word| *word == 0));
    }

    #[test]
    fn synthetic_state_zeroes_every_general_register_and_preserves_loaded_entry() {
        let mut storage = AlignedStack([0; STACK_WORDS]);
        let stack = stack_for(&mut storage);
        let record = InitialUserRecord {
            return_pc: ENTRY,
            user_sp: USER_SP,
        };
        let address = stack.top().unwrap() - SYNTHETIC_RETURN_BYTES as u64;
        let state = synthetic_return(record, address).unwrap();
        assert!(state.registers().iter().all(|register| *register == 0));
        assert_eq!(state.return_state().return_pc(), ENTRY);
        assert_eq!(state.return_state().user_sp(), USER_SP);
        assert_eq!(state.return_state().spsr_el1(), EL0T_SPSR_EL1);
    }

    #[test]
    fn mismatched_storage_is_rejected_before_any_context_is_published() {
        let mut owner = AlignedStack([0; STACK_WORDS]);
        let stack = stack_for(&mut owner);
        let mut foreign = AlignedStack([0; STACK_WORDS]);
        assert!(matches!(
            prepare_parts(&mut foreign.0, stack, ENTRY, USER_SP),
            Err(Error::StackAddressMismatch { .. })
        ));
    }

    #[test]
    fn invalid_loaded_entry_or_stack_shape_fails_before_scheduler_state_exists() {
        let mut storage = AlignedStack([0; STACK_WORDS]);
        let stack = stack_for(&mut storage);
        assert!(matches!(
            prepare_parts(&mut storage.0, stack, 0, USER_SP),
            Err(Error::ReturnState(_))
        ));

        let mut short = AlignedStack([0; STACK_WORDS]);
        let short_stack = stack_for(&mut short);
        assert!(matches!(
            prepare_parts(&mut short.0[..8], short_stack, ENTRY, USER_SP),
            Err(Error::StackWordsMismatch { .. })
        ));
    }
}
