// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::{mem::size_of, num::NonZeroU32};
use kernal_context_aarch64::{CONTEXT_BYTES, KernelThreadEntry};
use kernal_exceptions_aarch64::{SYNTHETIC_RETURN_BYTES, SyntheticEl0Return, SyntheticReturnError};
use kernal_linux_clone::{ClonePlan, ProcessClonePlan};
use kernal_thread_context::KernelStack;
use kernal_user_entry_aarch64::{El0ReturnState, ReturnStateError, STACK_ALIGNMENT};

const WORD_BYTES: usize = size_of::<u64>();
const REGISTER_WORDS: usize = 31;
pub const CLONE_FIRST_RUN_WORDS: usize = REGISTER_WORDS + 4;
pub const CLONE_FIRST_RUN_BYTES: usize = CLONE_FIRST_RUN_WORDS * WORD_BYTES;
const SYNTHETIC_RETURN_WORDS: usize = SYNTHETIC_RETURN_BYTES / WORD_BYTES;

const _: [(); CLONE_FIRST_RUN_BYTES] = [(); size_of::<CloneFirstRunRecord>()];
const _: () = assert!(CLONE_FIRST_RUN_BYTES <= SYNTHETIC_RETURN_BYTES);
const _: () = assert!(SYNTHETIC_RETURN_BYTES.is_multiple_of(WORD_BYTES));

/// Authority-free first-return state for one AArch64 clone child.
///
/// The accepted exception-frame representation remains owned by `kernal-exceptions-aarch64`.
/// This value only derives the Linux child register view from the parent's already-authorized
/// post-SVC state; scheduler identity, Process authority, TID publication and clear-child-tid
/// lifecycle remain outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloneChildState {
    registers: [u64; 31],
    return_state: El0ReturnState,
    tls: u64,
}

impl CloneChildState {
    pub fn from_parent(
        parent_registers: &[u64; 31],
        parent_return: El0ReturnState,
        plan: ClonePlan,
    ) -> Result<Self, ReturnStateError> {
        let return_state = El0ReturnState::new(
            parent_return.return_pc(),
            parent_return.spsr_el1(),
            plan.child_stack(),
        )?;
        let mut registers = *parent_registers;
        registers[0] = 0;
        Ok(Self {
            registers,
            return_state,
            tls: plan.tls(),
        })
    }

    fn from_process_parent(
        parent_registers: &[u64; 31],
        parent_return: El0ReturnState,
        parent_tls: u64,
        _plan: ProcessClonePlan,
    ) -> Result<Self, ReturnStateError> {
        let return_state = El0ReturnState::new(
            parent_return.return_pc(),
            parent_return.spsr_el1(),
            parent_return.user_sp(),
        )?;
        let mut registers = *parent_registers;
        registers[0] = 0;
        Ok(Self {
            registers,
            return_state,
            tls: parent_tls,
        })
    }

    pub const fn registers(&self) -> &[u64; 31] {
        &self.registers
    }

    pub const fn return_state(self) -> El0ReturnState {
        self.return_state
    }

    pub const fn tls(self) -> u64 {
        self.tls
    }
}

/// Truthful AArch64 return contract for one successfully identified fork/vfork child.
///
/// The child inherits the parent's post-SVC PC, SPSR, user SP and thread pointer, while Linux x0 is
/// forced to zero. The parent receives the already-allocated child PID. Neither scalar return value
/// carries Process, scheduler, address-space or capability authority; publication remains with the
/// existing owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessCloneReturnState {
    child: CloneChildState,
    parent_return_value: u64,
}

impl ProcessCloneReturnState {
    pub fn from_parent(
        parent_registers: &[u64; 31],
        parent_return: El0ReturnState,
        parent_tls: u64,
        plan: ProcessClonePlan,
        child_pid: NonZeroU32,
    ) -> Result<Self, ReturnStateError> {
        Ok(Self {
            child: CloneChildState::from_process_parent(
                parent_registers,
                parent_return,
                parent_tls,
                plan,
            )?,
            parent_return_value: u64::from(child_pid.get()),
        })
    }

    pub const fn child(self) -> CloneChildState {
        self.child
    }

    pub const fn parent_return_value(self) -> u64 {
        self.parent_return_value
    }
}

/// Self-describing first-run data stored at the top of one clone child's mapped kernel stack.
///
/// The record is deliberately authority-free: it contains only the validated EL0 register image and
/// one opaque runtime argument. Process, scheduler, TID and address-space authority remain in their
/// existing owners. The AArch64 context bootstrap passes the record address in x0 to the first-run
/// entry. That entry may copy the `repr(C)` record only while it exclusively owns the exact stack,
/// use `runtime_argument` to resolve higher-level state, and reconstruct the canonical synthetic ERET
/// state with [`Self::synthetic_return`]. The subsequent ERET overwrites this record with the normal
/// exception-frame image, so it is intentionally one-shot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloneFirstRunRecord {
    registers: [u64; REGISTER_WORDS],
    return_pc: u64,
    spsr_el1: u64,
    user_sp: u64,
    runtime_argument: u64,
}

impl CloneFirstRunRecord {
    pub const fn from_child(child: CloneChildState, runtime_argument: u64) -> Self {
        let return_state = child.return_state();
        Self {
            registers: *child.registers(),
            return_pc: return_state.return_pc(),
            spsr_el1: return_state.spsr_el1(),
            user_sp: return_state.user_sp(),
            runtime_argument,
        }
    }

    pub const fn registers(&self) -> &[u64; REGISTER_WORDS] {
        &self.registers
    }

    pub const fn runtime_argument(self) -> u64 {
        self.runtime_argument
    }

    /// Revalidates a copied first-run record and binds it to its exact kernel-stack address.
    ///
    /// `record_address` must be the x0 argument supplied by [`prepare_clone_kernel_context`]. A
    /// corrupted record cannot manufacture an EL0 return because the shared return-state validator
    /// is rerun before `SyntheticEl0Return` is constructed.
    pub fn synthetic_return(
        self,
        record_address: u64,
    ) -> Result<SyntheticEl0Return, CloneKernelContextError> {
        if !record_address.is_multiple_of(STACK_ALIGNMENT) {
            return Err(CloneKernelContextError::RecordMisaligned);
        }
        let kernel_exception_sp = record_address
            .checked_add(SYNTHETIC_RETURN_BYTES as u64)
            .ok_or(CloneKernelContextError::AddressOverflow)?;
        let return_state = El0ReturnState::new(self.return_pc, self.spsr_el1, self.user_sp)
            .map_err(CloneKernelContextError::ReturnState)?;
        let state = SyntheticEl0Return::new(self.registers, return_state, kernel_exception_sp)
            .map_err(CloneKernelContextError::SyntheticReturn)?;
        if state.frame_base() != record_address {
            return Err(CloneKernelContextError::Invariant);
        }
        Ok(state)
    }

    fn write_into(self, destination: &mut [u64]) -> Result<(), CloneKernelContextError> {
        if destination.len() < CLONE_FIRST_RUN_WORDS {
            return Err(CloneKernelContextError::StackTooSmall);
        }
        destination[..REGISTER_WORDS].copy_from_slice(&self.registers);
        destination[REGISTER_WORDS] = self.return_pc;
        destination[REGISTER_WORDS + 1] = self.spsr_el1;
        destination[REGISTER_WORDS + 2] = self.user_sp;
        destination[REGISTER_WORDS + 3] = self.runtime_argument;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneKernelContextError {
    InvalidKernelStack,
    StackWordsMismatch { expected: usize, actual: usize },
    StackTooSmall,
    RecordMisaligned,
    AddressOverflow,
    Context(kernal_context_aarch64::Error),
    ReturnState(ReturnStateError),
    SyntheticReturn(SyntheticReturnError),
    Invariant,
}

/// Exact scheduler input produced after a clone child's initial kernel context and one-shot first-run
/// record have been written to its exclusively owned stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedCloneKernelContext {
    stack: KernelStack,
    saved_sp: u64,
    first_run_record: u64,
    kernel_exception_sp: u64,
    user_thread_pointer: u64,
}

impl PreparedCloneKernelContext {
    pub const fn stack(self) -> KernelStack {
        self.stack
    }

    pub const fn saved_sp(self) -> u64 {
        self.saved_sp
    }

    /// Address passed in x0 to the first-run kernel entry.
    pub const fn first_run_record(self) -> u64 {
        self.first_run_record
    }

    pub const fn kernel_exception_sp(self) -> u64 {
        self.kernel_exception_sp
    }

    /// Exact TPIDR_EL0 value to install in generation-owned scheduler metadata before publication.
    pub const fn user_thread_pointer(self) -> u64 {
        self.user_thread_pointer
    }
}

/// Builds the exact first-run kernel-stack image consumed by the accepted AArch64 scheduler switch.
///
/// `stack_words` must be a unique mutable view of the complete mapped portion of `stack`, in virtual
/// address order. The function reserves the canonical synthetic exception-frame window at the stack
/// top, stores [`CloneFirstRunRecord`] at its base, and places the normal AAPCS64 switch frame directly
/// below it. Consequently, after `kernal-context-aarch64` pops the switch frame, SP equals the record
/// address and the bootstrap can read upward without colliding with its downward-growing call stack.
/// The later synthetic ERET then overwrites the one-shot record with the canonical exception frame.
///
/// No scheduler or Process state is changed here. The caller must retain exclusive ownership of the
/// stack and prepared value until the exact generation is either staged through the scheduler or the
/// stack is reclaimed.
pub fn prepare_clone_kernel_context(
    stack_words: &mut [u64],
    stack: KernelStack,
    entry: KernelThreadEntry,
    child: CloneChildState,
    runtime_argument: u64,
) -> Result<PreparedCloneKernelContext, CloneKernelContextError> {
    let validated = KernelStack::new(stack.guard_start, stack.mapped_start, stack.mapped_len)
        .map_err(|_| CloneKernelContextError::InvalidKernelStack)?;
    if validated != stack {
        return Err(CloneKernelContextError::InvalidKernelStack);
    }

    let mapped_len =
        usize::try_from(stack.mapped_len).map_err(|_| CloneKernelContextError::AddressOverflow)?;
    let actual_bytes = stack_words
        .len()
        .checked_mul(WORD_BYTES)
        .ok_or(CloneKernelContextError::AddressOverflow)?;
    if actual_bytes != mapped_len {
        return Err(CloneKernelContextError::StackWordsMismatch {
            expected: mapped_len / WORD_BYTES,
            actual: stack_words.len(),
        });
    }

    let kernel_exception_sp = stack
        .top()
        .map_err(|_| CloneKernelContextError::InvalidKernelStack)?;
    let first_run_record = kernel_exception_sp
        .checked_sub(SYNTHETIC_RETURN_BYTES as u64)
        .ok_or(CloneKernelContextError::StackTooSmall)?;
    let prefix_bytes = first_run_record
        .checked_sub(stack.mapped_start)
        .ok_or(CloneKernelContextError::StackTooSmall)?;
    if prefix_bytes < CONTEXT_BYTES as u64
        || !prefix_bytes.is_multiple_of(WORD_BYTES as u64)
        || !first_run_record.is_multiple_of(STACK_ALIGNMENT)
    {
        return Err(CloneKernelContextError::StackTooSmall);
    }
    let prefix_words = usize::try_from(prefix_bytes / WORD_BYTES as u64)
        .map_err(|_| CloneKernelContextError::AddressOverflow)?;
    if stack_words.len().checked_sub(prefix_words) != Some(SYNTHETIC_RETURN_WORDS) {
        return Err(CloneKernelContextError::Invariant);
    }

    let record = CloneFirstRunRecord::from_child(child, runtime_argument);
    let synthetic = record.synthetic_return(first_run_record)?;
    if synthetic.kernel_exception_sp() != kernel_exception_sp {
        return Err(CloneKernelContextError::Invariant);
    }

    let context_start = kernal_context_aarch64::build_initial_context(
        &mut stack_words[..prefix_words],
        first_run_record,
        entry,
        first_run_record,
    )
    .map_err(CloneKernelContextError::Context)?;
    let saved_sp = stack
        .mapped_start
        .checked_add(
            u64::try_from(
                context_start
                    .checked_mul(WORD_BYTES)
                    .ok_or(CloneKernelContextError::AddressOverflow)?,
            )
            .map_err(|_| CloneKernelContextError::AddressOverflow)?,
        )
        .ok_or(CloneKernelContextError::AddressOverflow)?;
    if saved_sp.checked_add(CONTEXT_BYTES as u64) != Some(first_run_record)
        || !stack.contains_rsp(saved_sp)
    {
        return Err(CloneKernelContextError::Invariant);
    }

    let synthetic_window = &mut stack_words[prefix_words..];
    synthetic_window.fill(0);
    record.write_into(synthetic_window)?;

    Ok(PreparedCloneKernelContext {
        stack,
        saved_sp,
        first_run_record,
        kernel_exception_sp,
        user_thread_pointer: child.tls(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_clone::{FORK_PROCESS_FLAGS, MUSL_PTHREAD_FLAGS, VFORK_PROCESS_FLAGS};
    use kernal_user_entry_aarch64::EL0T_SPSR_EL1;

    const RETURN_PC: u64 = 0x0000_0000_0003_0000;
    const PARENT_SP: u64 = 0x0000_0000_0008_0000;
    const CHILD_SP: u64 = 0x0000_0000_000a_0000;
    const PTID: u64 = 0x0000_0000_000c_0000;
    const TLS: u64 = 0x0000_0000_000e_0008;
    const CTID: u64 = 0x0000_0000_0010_0000;
    const RUNTIME_ARGUMENT: u64 = 0x55aa_1234_9876_0001;
    const STACK_GUARD: u64 = 0xffff_ffff_8020_0000;
    const STACK_MAPPED: u64 = STACK_GUARD + 0x1000;
    const STACK_LEN: u64 = 0x4000;
    const STACK_WORDS: usize = STACK_LEN as usize / WORD_BYTES;

    fn plan() -> ClonePlan {
        ClonePlan::validate(MUSL_PTHREAD_FLAGS, CHILD_SP, PTID, TLS, CTID).unwrap()
    }

    fn child() -> CloneChildState {
        let parent = core::array::from_fn(|index| 0x1000 + index as u64);
        let parent_return = El0ReturnState::new(RETURN_PC, EL0T_SPSR_EL1, PARENT_SP).unwrap();
        CloneChildState::from_parent(&parent, parent_return, plan()).unwrap()
    }

    fn stack() -> KernelStack {
        KernelStack::new(STACK_GUARD, STACK_MAPPED, STACK_LEN).unwrap()
    }

    extern "C" fn first_run_entry(_record: u64) -> ! {
        panic!("test first-run entry must not execute")
    }

    #[test]
    fn child_keeps_post_svc_pc_and_parent_gprs_except_x0() {
        let parent = core::array::from_fn(|index| 0x1000 + index as u64);
        let parent_return = El0ReturnState::new(RETURN_PC, EL0T_SPSR_EL1, PARENT_SP).unwrap();
        let child = CloneChildState::from_parent(&parent, parent_return, plan()).unwrap();

        assert_eq!(child.registers()[0], 0);
        assert_eq!(&child.registers()[1..], &parent[1..]);
        assert_eq!(child.return_state().return_pc(), RETURN_PC);
        assert_eq!(child.return_state().user_sp(), CHILD_SP);
        assert_eq!(child.return_state().spsr_el1(), EL0T_SPSR_EL1);
        assert_eq!(child.tls(), TLS);
    }

    #[test]
    fn process_clone_return_contract_inherits_parent_context_and_pid_truthfully() {
        let parent = core::array::from_fn(|index| 0x2000 + index as u64);
        let parent_return = El0ReturnState::new(RETURN_PC, EL0T_SPSR_EL1, PARENT_SP).unwrap();
        let child_pid = NonZeroU32::new(42).unwrap();

        for flags in [FORK_PROCESS_FLAGS, VFORK_PROCESS_FLAGS] {
            let plan = ProcessClonePlan::validate(flags, 0, 0, 0, 0).unwrap();
            let returns =
                ProcessCloneReturnState::from_parent(&parent, parent_return, TLS, plan, child_pid)
                    .unwrap();
            let child = returns.child();

            assert_eq!(returns.parent_return_value(), 42);
            assert_eq!(child.registers()[0], 0);
            assert_eq!(&child.registers()[1..], &parent[1..]);
            assert_eq!(child.return_state().return_pc(), RETURN_PC);
            assert_eq!(child.return_state().user_sp(), PARENT_SP);
            assert_eq!(child.return_state().spsr_el1(), EL0T_SPSR_EL1);
            assert_eq!(child.tls(), TLS);
        }
    }

    #[test]
    fn child_state_does_not_duplicate_tid_lifecycle_metadata() {
        assert_eq!(core::mem::size_of::<CloneChildState>(), (31 + 3 + 1) * 8);
    }

    #[test]
    fn prepared_stack_places_context_immediately_below_one_shot_record() {
        let stack = stack();
        let child = child();
        let mut words = [0xdead_beef_dead_beef; STACK_WORDS];

        let prepared = prepare_clone_kernel_context(
            &mut words,
            stack,
            first_run_entry,
            child,
            RUNTIME_ARGUMENT,
        )
        .unwrap();

        assert_eq!(prepared.stack(), stack);
        assert_eq!(prepared.kernel_exception_sp(), stack.top().unwrap());
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
            usize::try_from((prepared.saved_sp() - stack.mapped_start) / WORD_BYTES as u64)
                .unwrap();
        assert_eq!(
            words[context_index + 10],
            first_run_entry as *const () as usize as u64
        );
        assert_eq!(words[context_index + 11], prepared.first_run_record());

        let record_index =
            usize::try_from((prepared.first_run_record() - stack.mapped_start) / WORD_BYTES as u64)
                .unwrap();
        assert_eq!(
            &words[record_index..record_index + REGISTER_WORDS],
            child.registers()
        );
        assert_eq!(words[record_index + REGISTER_WORDS], RETURN_PC);
        assert_eq!(words[record_index + REGISTER_WORDS + 1], EL0T_SPSR_EL1);
        assert_eq!(words[record_index + REGISTER_WORDS + 2], CHILD_SP);
        assert_eq!(words[record_index + REGISTER_WORDS + 3], RUNTIME_ARGUMENT);
        assert!(
            words[record_index + CLONE_FIRST_RUN_WORDS..]
                .iter()
                .all(|word| *word == 0)
        );

        let record = CloneFirstRunRecord::from_child(child, RUNTIME_ARGUMENT);
        let synthetic = record
            .synthetic_return(prepared.first_run_record())
            .unwrap();
        assert_eq!(synthetic.registers(), child.registers());
        assert_eq!(synthetic.return_state(), child.return_state());
        assert_eq!(synthetic.frame_base(), prepared.first_run_record());
        assert_eq!(record.runtime_argument(), RUNTIME_ARGUMENT);
    }

    #[test]
    fn complete_mapped_stack_slice_is_required() {
        let mut short = [0u64; STACK_WORDS - 1];
        assert_eq!(
            prepare_clone_kernel_context(
                &mut short,
                stack(),
                first_run_entry,
                child(),
                RUNTIME_ARGUMENT,
            ),
            Err(CloneKernelContextError::StackWordsMismatch {
                expected: STACK_WORDS,
                actual: STACK_WORDS - 1,
            })
        );
    }

    #[test]
    fn malformed_kernel_stack_fails_before_writing_context() {
        let invalid = KernelStack {
            guard_start: 0xffff_ffff_ffff_e000,
            mapped_start: 0xffff_ffff_ffff_f000,
            mapped_len: 0x2000,
        };
        let mut words = [0u64; 0x2000 / WORD_BYTES];
        assert_eq!(
            prepare_clone_kernel_context(
                &mut words,
                invalid,
                first_run_entry,
                child(),
                RUNTIME_ARGUMENT,
            ),
            Err(CloneKernelContextError::InvalidKernelStack)
        );
    }

    #[test]
    fn corrupted_first_run_record_cannot_recreate_el0_return_authority() {
        let mut record = CloneFirstRunRecord::from_child(child(), RUNTIME_ARGUMENT);
        record.user_sp = CHILD_SP + 8;
        assert_eq!(
            record.synthetic_return(0xffff_ffff_8040_0000),
            Err(CloneKernelContextError::ReturnState(
                ReturnStateError::UserStackMisaligned
            ))
        );
        assert_eq!(
            CloneFirstRunRecord::from_child(child(), RUNTIME_ARGUMENT)
                .synthetic_return(0xffff_ffff_8040_0008),
            Err(CloneKernelContextError::RecordMisaligned)
        );
    }

    #[test]
    fn first_run_record_fits_inside_canonical_synthetic_window() {
        assert_eq!(size_of::<CloneFirstRunRecord>(), CLONE_FIRST_RUN_BYTES);
        assert_eq!(CLONE_FIRST_RUN_BYTES, 35 * 8);
    }
}
