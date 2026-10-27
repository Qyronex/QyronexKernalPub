// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::num::NonZeroU32;
use kernal_capability::{CapError, CapHandle};
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::{Errno, MinimumRuntimeCall, SyscallReturn};
use kernal_linux_clone::ClonePlan;
use kernal_linux_clone_aarch64::{
    CloneChildState, CloneKernelContextError, PreparedCloneKernelContext,
};
use kernal_linux_clone_runtime_aarch64::prepare_first_run_context;
use kernal_linux_clone_usercopy_aarch64::{ParentTidWriteError, write_parent_tid};
use kernal_linux_exit_lifecycle::{Error as LifecycleError, ExitCoordinator};
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_object::{Error as ObjectError, ObjectTable};
use kernal_process::{Error as ProcessError, Process, ThreadBindingError, ThreadObjectBindings};
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_scheduler::{Error as SchedulerCoreError, RunQueue, ThreadId};
use kernal_scheduler_cpu::{CpuSchedulerCell, Error as SchedulerError};
use kernal_scheduler_smp::{GlobalThreadId, StagedThreadProof};
use kernal_syscall_entry_aarch64::{
    Error as EntryError, apply_linux_return, validate_linux_return,
};
use kernal_thread_context::KernelStack;

/// The only first-run builder passed to a clone stack owner by this transaction.
pub type CloneContextBuilder = fn(
    &mut [u64],
    KernelStack,
    CloneChildState,
) -> Result<PreparedCloneKernelContext, CloneKernelContextError>;

/// Failure while obtaining and preparing one not-yet-owned child kernel stack.
#[derive(Debug, Eq, PartialEq)]
pub enum StackPrepareError<E> {
    /// No stack is currently available. No stack ownership may remain outstanding.
    Exhausted,
    /// The canonical first-run builder rejected the supplied stack image.
    Context(CloneKernelContextError),
    /// Stack allocator/backend invariant failure.
    Backend(E),
}

/// External owner of clone kernel-stack storage.
///
/// The clone transaction deliberately does not add a second AArch64 stack allocator. `prepare` must
/// allocate one exclusive stack, expose its complete mapped words to the supplied `build` function,
/// and return the resulting prepared context. On every `Err`, the provider must leave no outstanding
/// stack allocation. Once this transaction stages the returned context, ownership moves to the
/// scheduler until either normal reap or `bootstrap_cancel_staged` returns the exact `KernelStack` to
/// [`Self::reclaim`].
pub trait CloneStackProvider {
    type Error;

    fn prepare(
        &mut self,
        child: CloneChildState,
        build: CloneContextBuilder,
    ) -> Result<PreparedCloneKernelContext, StackPrepareError<Self::Error>>;

    fn reclaim(&mut self, stack: KernelStack) -> Result<(), Self::Error>;
}

/// Privileged failures that must not be translated into Linux errno.
#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    NotCloneCall,
    Entry(EntryError),
    ProcessAddressSpace(ProcessAddressSpaceError),
    ChildContext(CloneKernelContextError),
    StackBackend(E),
    StackReclaim(E),
    Scheduler(SchedulerError),
    Lifecycle(LifecycleError),
    Identity(IdentityError),
    Process(ProcessError),
    Invariant,
}

impl<E> From<SchedulerError> for Error<E> {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

struct PreparedCommit {
    tid: NonZeroU32,
    handle: CapHandle,
}

enum SetupOutcome<E> {
    Ready(PreparedCommit),
    CancelRecoverable(Errno),
    CancelFatal(Error<E>),
    /// External authority rollback failed. The staged generation must remain fail-closed; cancelling
    /// it could allow slot/stack reuse while Process or Linux identity still names the generation.
    FatalNoCancel(Error<E>),
}

#[derive(Debug, Eq, PartialEq)]
enum CommitError {
    ParentTid(Errno),
    Scheduler(SchedulerError),
}

impl From<SchedulerError> for CommitError {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

/// Executes the complete Step-15 minimum musl-pthread `clone` transaction on AArch64.
///
/// Commit order is deliberately one-way:
/// 1. validate the exact supported clone shape and parent EL0 return state;
/// 2. obtain a canonical #418 first-run stack image from the caller's existing stack owner;
/// 3. create one Blocked+Staged scheduler generation inheriting the exact current address-space token;
/// 4. under the scheduler's scoped immutable RunQueue proof, attach Process/CSpace Thread authority
///    through the existing ExitCoordinator and allocate one Linux TID;
/// 5. validate/write parent x0 while rollback remains possible;
/// 6. enter the scheduler-owned atomic commit: Ready+Staged -> PARENT_SETTID -> Published+Ready.
///
/// A normal PARENT_SETTID EFAULT is the only recoverable commit failure. The scheduler restores the
/// exact generation to Blocked+Staged before returning that error; this function then obtains a fresh
/// staged proof and rolls back Process/CSpace -> Linux TID -> scheduler generation -> kernel stack.
/// Privileged usercopy/address-space failures cannot prove whether the store became visible and fail
/// closed inside the commit closure rather than returning across the irreversible boundary.
///
/// Success writes the child's Linux TID into parent x0 and parent_tid memory, leaves child x0=0 in the
/// #418 first-run image, stores TLS in generation-owned scheduler metadata and records child_tid as the
/// mandatory clear-child-tid exit obligation.
///
/// # Safety
/// The caller must hold the scheduler owner's quiescent window for the complete call: local IRQs
/// masked, irq_depth=0, preempt_count=0, migration suppressed, and the current Process/TTBR0 binding
/// unchanged. The same exclusive ownership must cover ExitCoordinator, Process/Object/Binding,
/// LinuxIdentityTable, stack-provider and parent usercopy mutation. No callback may context-switch,
/// publish/cancel scheduler work, drain wakes or replace the active address space.
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_clone<
    P,
    const CAPS: usize,
    const VMAS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const PROCESSES: usize,
    const IDS: usize,
    const GROUPS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
>(
    call: MinimumRuntimeCall,
    frame: &mut ExceptionFrame,
    process: &mut Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    exits: &ExitCoordinator<GROUPS>,
    scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    stacks: &mut P,
    priority: u8,
) -> Result<(), Error<P::Error>>
where
    P: CloneStackProvider,
{
    let plan = match clone_plan(call) {
        Ok(plan) => plan,
        Err(CloneCallError::Invalid) => {
            write_errno(process, address_space, frame, Errno::EINVAL)?;
            return Ok(());
        }
        Err(CloneCallError::NotClone) => return Err(Error::NotCloneCall),
    };

    let parent_return = {
        let active = address_space
            .current_owner(process)
            .map_err(Error::ProcessAddressSpace)?;
        validate_linux_return(&active, frame).map_err(Error::Entry)?
    };
    let child = match CloneChildState::from_parent(&frame.x, parent_return, plan) {
        Ok(child) => child,
        Err(_) => {
            write_errno(process, address_space, frame, Errno::EINVAL)?;
            return Ok(());
        }
    };

    let prepared = match stacks.prepare(child, prepare_first_run_context) {
        Ok(prepared) => prepared,
        Err(StackPrepareError::Exhausted) => {
            write_errno(process, address_space, frame, Errno::EAGAIN)?;
            return Ok(());
        }
        Err(StackPrepareError::Context(error)) => return Err(Error::ChildContext(error)),
        Err(StackPrepareError::Backend(error)) => return Err(Error::StackBackend(error)),
    };

    // SAFETY: delegated transaction contract provides owner-local quiescence. The scheduler copies
    // the exact current parent's private address-space token internally, so CLONE_VM never relies on
    // a caller-reconstructed scalar.
    let staged = match unsafe {
        scheduler.bootstrap_create_staged_user_thread_shared_current_address_space(
            priority,
            prepared.saved_sp(),
            prepared.stack(),
            prepared.user_thread_pointer(),
            Some(plan.child_tid()),
        )
    } {
        Ok(staged) => staged,
        Err(error) => {
            if scheduler_create_error_releases_stack(&error) {
                stacks
                    .reclaim(prepared.stack())
                    .map_err(Error::StackReclaim)?;
            }
            if scheduler_create_errno(&error) == Some(Errno::EAGAIN) {
                write_errno(process, address_space, frame, Errno::EAGAIN)?;
                return Ok(());
            }
            return Err(Error::Scheduler(error));
        }
    };

    // SAFETY: the just-created generation remains Blocked+Staged under the uninterrupted owner
    // transaction. The closure performs only external Process/TID/frame setup and never reenters
    // scheduler mutation.
    let setup = unsafe {
        scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
            external_setup(
                process,
                address_space,
                objects,
                bindings,
                identities,
                exits,
                run_queue,
                owner,
                staged,
                proof,
                frame,
            )
        })
    }?;

    let PreparedCommit { tid, handle } = match setup {
        SetupOutcome::Ready(commit) => commit,
        SetupOutcome::CancelRecoverable(errno) => {
            // SAFETY: every external authority edge was rolled back inside the scoped proof closure.
            unsafe { cancel_and_reclaim(scheduler, staged, stacks)? };
            return write_errno(process, address_space, frame, errno);
        }
        SetupOutcome::CancelFatal(error) => {
            // SAFETY: every external authority edge was rolled back inside the scoped proof closure.
            unsafe { cancel_and_reclaim(scheduler, staged, stacks)? };
            return Err(error);
        }
        SetupOutcome::FatalNoCancel(error) => return Err(error),
    };

    // SAFETY: all external authority setup is complete while `staged` is still exact Blocked+Staged.
    // The commit owner makes it Ready before invoking the closure, but uninterrupted owner quiescence
    // prevents selection until the same transaction consumes Staged -> Published.
    let commit = unsafe {
        scheduler.bootstrap_commit_staged_ready(staged, || {
            // SAFETY: delegated dispatch contract keeps the exact parent Process/TTBR0 generation
            // stable for this fault-safe four-byte write.
            match write_parent_tid(process, address_space, plan, tid) {
                Ok(()) => Ok(()),
                Err(ParentTidWriteError::Errno(errno)) => Err(CommitError::ParentTid(errno)),
                Err(_) => fail_closed_after_possible_parent_tid(),
            }
        })
    };

    match commit {
        Ok(()) => Ok(()),
        Err(CommitError::Scheduler(error)) => {
            // Returned scheduler errors do not provide the exact restored-Staged proof promised by a
            // normal failed external commit. Keep Process/TID/stack authority fail-closed.
            Err(Error::Scheduler(error))
        }
        Err(CommitError::ParentTid(errno)) => {
            // #424 guarantees this path restored exact Blocked+Staged authority. Mint a *fresh* proof
            // after the Ready rollback rather than reusing the proof that existed before commit.
            // SAFETY: owner quiescence is uninterrupted and no successful external commit occurred.
            let rollback = unsafe {
                scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
                    // SAFETY: fresh proof attests the exact restored Blocked+Staged generation.
                    rollback_process_and_tid(
                        process, objects, bindings, identities, run_queue, owner, proof, handle,
                        tid,
                    )
                })
            };
            rollback?;
            // SAFETY: Process/TID authority is now gone and this generation never became Published.
            unsafe { cancel_and_reclaim(scheduler, staged, stacks)? };
            write_errno(process, address_space, frame, errno)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn external_setup<
    E,
    const CAPS: usize,
    const VMAS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const PROCESSES: usize,
    const IDS: usize,
    const GROUPS: usize,
    const SCHED_THREADS: usize,
>(
    process: &mut Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    exits: &ExitCoordinator<GROUPS>,
    run_queue: &RunQueue<SCHED_THREADS>,
    owner: kernal_percpu::CpuIndex,
    staged: ThreadId,
    proof: StagedThreadProof,
    frame: &mut ExceptionFrame,
) -> Result<SetupOutcome<E>, Error<E>> {
    let global = proof.thread();
    if global != GlobalThreadId::new(owner, staged) {
        return Ok(SetupOutcome::FatalNoCancel(Error::Invariant));
    }

    let handle = match exits.attach_thread(process, objects, bindings, run_queue, owner, global) {
        Ok(handle) => handle,
        Err(error) => return Ok(classify_lifecycle_attach_error(error)),
    };

    let tid = match identities.tid_for(process, objects, bindings, run_queue, owner, handle) {
        Ok(tid) => tid,
        Err(error) => {
            let original_errno = identity_errno(&error);
            // SAFETY: the scoped scheduler proof is still live, exact and Staged+Blocked; no Linux
            // TID record exists when tid_for returns Err.
            return Ok(
                match unsafe {
                    rollback_process_without_tid(
                        process, objects, bindings, run_queue, owner, proof, handle,
                    )
                } {
                    Ok(()) => match original_errno {
                        Some(errno) => SetupOutcome::CancelRecoverable(errno),
                        None => SetupOutcome::CancelFatal(Error::Identity(error)),
                    },
                    Err(rollback) => SetupOutcome::FatalNoCancel(rollback),
                },
            );
        }
    };

    let result = SyscallReturn::success(tid.get() as i64).ok_or(Error::Invariant);
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            // SAFETY: no external user-memory commit exists; exact Process+TID rollback is legal.
            return Ok(
                match unsafe {
                    rollback_process_and_tid(
                        process, objects, bindings, identities, run_queue, owner, proof, handle,
                        tid,
                    )
                } {
                    Ok(()) => SetupOutcome::CancelFatal(error),
                    Err(rollback) => SetupOutcome::FatalNoCancel(rollback),
                },
            );
        }
    };

    if let Err(error) = write_result(process, address_space, frame, result) {
        // SAFETY: no external user-memory commit exists; exact Process+TID rollback is legal.
        return Ok(
            match unsafe {
                rollback_process_and_tid(
                    process, objects, bindings, identities, run_queue, owner, proof, handle, tid,
                )
            } {
                Ok(()) => SetupOutcome::CancelFatal(error),
                Err(rollback) => SetupOutcome::FatalNoCancel(rollback),
            },
        );
    }

    Ok(SetupOutcome::Ready(PreparedCommit { tid, handle }))
}

#[allow(clippy::too_many_arguments)]
unsafe fn rollback_process_without_tid<
    E,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const SCHED_THREADS: usize,
>(
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    run_queue: &RunQueue<SCHED_THREADS>,
    owner: kernal_percpu::CpuIndex,
    proof: StagedThreadProof,
    handle: CapHandle,
) -> Result<(), Error<E>> {
    let expected = proof.thread();
    // SAFETY: delegated caller retains the same owner-quiescent Staged+Blocked proof window.
    let rollback = unsafe {
        process.rollback_staged_thread(objects, bindings, run_queue, owner, proof, handle)
    }
    .map_err(Error::Process)?;
    if rollback.scheduler_thread() != expected {
        return Err(Error::Invariant);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
unsafe fn rollback_process_and_tid<
    E,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const PROCESSES: usize,
    const IDS: usize,
    const SCHED_THREADS: usize,
>(
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    run_queue: &RunQueue<SCHED_THREADS>,
    owner: kernal_percpu::CpuIndex,
    proof: StagedThreadProof,
    handle: CapHandle,
    tid: NonZeroU32,
) -> Result<(), Error<E>> {
    let expected = proof.thread();
    // SAFETY: delegated caller retains the same owner-quiescent Staged+Blocked proof window.
    let rollback = unsafe {
        process.rollback_staged_thread(objects, bindings, run_queue, owner, proof, handle)
    }
    .map_err(Error::Process)?;
    if rollback.scheduler_thread() != expected {
        return Err(Error::Invariant);
    }
    let cancelled = identities
        .rollback_unpublished_thread_tid(process, rollback, tid)
        .map_err(Error::Identity)?;
    if cancelled != expected {
        return Err(Error::Invariant);
    }
    Ok(())
}

unsafe fn cancel_and_reclaim<P, const SCHED_THREADS: usize, const WAKES: usize>(
    scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    staged: ThreadId,
    stacks: &mut P,
) -> Result<(), Error<P::Error>>
where
    P: CloneStackProvider,
{
    // SAFETY: caller has already removed every external Process/TID authority and retained owner
    // quiescence; this exact generation was never successfully published.
    let stack = unsafe { scheduler.bootstrap_cancel_staged(staged) }.map_err(Error::Scheduler)?;
    stacks.reclaim(stack).map_err(Error::StackReclaim)
}

fn write_result<E, const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    frame: &mut ExceptionFrame,
    result: SyscallReturn,
) -> Result<(), Error<E>> {
    let active = address_space
        .current_owner(process)
        .map_err(Error::ProcessAddressSpace)?;
    apply_linux_return(&active, frame, result).map_err(Error::Entry)
}

fn write_errno<E, const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    frame: &mut ExceptionFrame,
    errno: Errno,
) -> Result<(), Error<E>> {
    write_result(process, address_space, frame, SyscallReturn::error(errno))
}

fn fail_closed_after_possible_parent_tid() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloneCallError {
    NotClone,
    Invalid,
}

fn clone_plan(call: MinimumRuntimeCall) -> Result<ClonePlan, CloneCallError> {
    let MinimumRuntimeCall::Clone {
        flags,
        child_stack,
        parent_tid,
        tls,
        child_tid,
    } = call
    else {
        return Err(CloneCallError::NotClone);
    };
    ClonePlan::validate(flags, child_stack, parent_tid, tls, child_tid)
        .map_err(|_| CloneCallError::Invalid)
}

fn scheduler_create_errno(error: &SchedulerError) -> Option<Errno> {
    match error {
        SchedulerError::Scheduler(SchedulerCoreError::Capacity) => Some(Errno::EAGAIN),
        _ => None,
    }
}

fn scheduler_create_error_releases_stack(error: &SchedulerError) -> bool {
    matches!(
        error,
        SchedulerError::Scheduler(
            SchedulerCoreError::Capacity | SchedulerCoreError::InvalidPriority
        ) | SchedulerError::Context(_)
    )
}

fn classify_lifecycle_attach_error<E>(error: LifecycleError) -> SetupOutcome<E> {
    match lifecycle_errno(&error) {
        Some(errno) => SetupOutcome::CancelRecoverable(errno),
        None => SetupOutcome::FatalNoCancel(Error::Lifecycle(error)),
    }
}

fn lifecycle_errno(error: &LifecycleError) -> Option<Errno> {
    match error {
        LifecycleError::GroupExitDraining => Some(Errno::EAGAIN),
        LifecycleError::Process(ProcessError::Object(ObjectError::Capacity))
        | LifecycleError::Process(ProcessError::Capability(CapError::TableFull))
        | LifecycleError::Process(ProcessError::ThreadBinding(ThreadBindingError::Capacity))
        | LifecycleError::Process(ProcessError::ThreadBinding(ThreadBindingError::Object(
            ObjectError::Capacity,
        ))) => Some(Errno::EAGAIN),
        _ => None,
    }
}

fn identity_errno(error: &IdentityError) -> Option<Errno> {
    match error {
        IdentityError::Exhausted
        | IdentityError::ProcessCapacity
        | IdentityError::ThreadCapacity => Some(Errno::EAGAIN),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_clone::MUSL_PTHREAD_FLAGS;

    const STACK: u64 = 0x0000_0000_0002_0000;
    const PTID: u64 = 0x0000_0000_0003_0000;
    const TLS: u64 = 0x0000_0000_0004_0008;
    const CTID: u64 = 0x0000_0000_0005_0000;

    #[test]
    fn clone_classifier_accepts_only_the_exact_minimum_clone_shape() {
        let call = MinimumRuntimeCall::Clone {
            flags: MUSL_PTHREAD_FLAGS,
            child_stack: STACK,
            parent_tid: PTID,
            tls: TLS,
            child_tid: CTID,
        };
        let plan = clone_plan(call).unwrap();
        assert_eq!(plan.child_stack(), STACK);
        assert_eq!(plan.parent_tid(), PTID);
        assert_eq!(plan.tls(), TLS);
        assert_eq!(plan.child_tid(), CTID);

        assert_eq!(
            clone_plan(MinimumRuntimeCall::Clone {
                flags: MUSL_PTHREAD_FLAGS ^ 0x100,
                child_stack: STACK,
                parent_tid: PTID,
                tls: TLS,
                child_tid: CTID,
            }),
            Err(CloneCallError::Invalid)
        );
        assert_eq!(
            clone_plan(MinimumRuntimeCall::Brk { address: STACK }),
            Err(CloneCallError::NotClone)
        );
    }

    #[test]
    fn only_scheduler_capacity_is_linux_eagain_at_creation() {
        assert_eq!(
            scheduler_create_errno(&SchedulerError::Scheduler(SchedulerCoreError::Capacity)),
            Some(Errno::EAGAIN)
        );
        assert_eq!(
            scheduler_create_errno(&SchedulerError::Scheduler(
                SchedulerCoreError::InvalidPriority
            )),
            None
        );
    }

    #[test]
    fn stack_reclaim_is_allowed_only_for_creation_errors_that_prove_no_live_child() {
        assert!(scheduler_create_error_releases_stack(
            &SchedulerError::Scheduler(SchedulerCoreError::Capacity)
        ));
        assert!(scheduler_create_error_releases_stack(
            &SchedulerError::Scheduler(SchedulerCoreError::InvalidPriority)
        ));
        assert!(scheduler_create_error_releases_stack(
            &SchedulerError::Context(kernal_thread_context::Error::InvalidRsp)
        ));
        assert!(!scheduler_create_error_releases_stack(
            &SchedulerError::Invariant
        ));
    }

    #[test]
    fn unclassified_lifecycle_attach_failure_must_not_authorize_cancellation() {
        let outcome: SetupOutcome<()> =
            classify_lifecycle_attach_error(LifecycleError::Process(ProcessError::Exited));
        assert!(matches!(
            outcome,
            SetupOutcome::FatalNoCancel(Error::Lifecycle(LifecycleError::Process(
                ProcessError::Exited
            )))
        ));
    }

    #[test]
    fn bounded_authority_exhaustion_maps_to_eagain_but_invariants_do_not() {
        assert_eq!(
            lifecycle_errno(&LifecycleError::GroupExitDraining),
            Some(Errno::EAGAIN)
        );
        assert_eq!(
            lifecycle_errno(&LifecycleError::Process(ProcessError::Capability(
                CapError::TableFull
            ))),
            Some(Errno::EAGAIN)
        );
        assert_eq!(
            identity_errno(&IdentityError::ThreadCapacity),
            Some(Errno::EAGAIN)
        );
        assert_eq!(identity_errno(&IdentityError::LeaderNotBound), None);
    }
}
