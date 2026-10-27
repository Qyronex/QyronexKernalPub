// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_capability::{CapHandle, ObjectId};
use kernal_frame_allocator::{ExtentAllocator, FrameRange};
use kernal_linux_clone::{ProcessCloneKind, ProcessClonePlan};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::BoundProcessAddressSpace;
use kernal_vm::{Backing, PAGE_SIZE, Vma};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::{memory::Step15FramePool, runtime::Step15LinuxRuntime};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::num::NonZeroU32;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_core_aarch64::{
    PreparedProcessCloneStack, ProcessCloneStackError, prepare_process_clone_with_core_stack,
    reclaim_unpublished_process_clone_core_stack,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_kmap_aarch64::KmapController;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_clone_aarch64::ProcessCloneReturnState;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_wait::ChildExitPublication;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_scheduler::Error as SchedulerCoreError;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler::ThreadId;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_scheduler_cpu::Error as SchedulerError;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_smp::GlobalThreadId;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_entry_aarch64::{El0ReturnState, ReturnStateError};

#[derive(Debug)]
pub(super) enum Error {
    UnsupportedBacking,
    ChildNotEmpty,
    AddressSpace,
    Frame(kernal_frame_allocator::Error),
    InvalidAllocatedFrame,
    Invariant,
    UnsupportedProcessClonePlan,
    RollbackFailed,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Kmap(kernal_kmap_aarch64::Error),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Runtime(super::runtime::Error),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    ReturnState(ReturnStateError),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Stack(ProcessCloneStackError),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Scheduler(SchedulerError),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Lifecycle(kernal_linux_exit_lifecycle::Error),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Identity(kernal_linux_identity::Error),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Process(kernal_process::Error),
    #[cfg(test)]
    InjectedCopyFailure,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl From<SchedulerError> for Error {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

fn require_private_fork_plan(plan: ProcessClonePlan) -> Result<(), Error> {
    if plan.kind() != ProcessCloneKind::Fork
        || plan.shares_address_space()
        || plan.suspends_parent()
    {
        return Err(Error::UnsupportedProcessClonePlan);
    }
    Ok(())
}

/// Linear Core-owned receipt for one completely staged but still scheduler-invisible fork child.
///
/// `runtime_slot` is a private installation receipt and `child_process` / `address_space_token` are
/// generation observations only. None of those scalar values grants Process, AddressSpace, scheduler
/// or capability authority. The prepared stack is still owned by this transaction because no staged
/// scheduler generation exists yet.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct UnpublishedForkReceipt {
    parent_thread: GlobalThreadId,
    child_process: ObjectId,
    address_space_token: u64,
    runtime_slot: usize,
    child_pid: NonZeroU32,
    prepared_stack: PreparedProcessCloneStack,
    wait_publication: ChildExitPublication,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl UnpublishedForkReceipt {
    pub(super) const fn parent_thread(&self) -> GlobalThreadId {
        self.parent_thread
    }

    pub(super) const fn child_process(&self) -> ObjectId {
        self.child_process
    }

    pub(super) const fn address_space_token(&self) -> u64 {
        self.address_space_token
    }

    pub(super) const fn runtime_slot(&self) -> usize {
        self.runtime_slot
    }

    pub(super) const fn child_pid(&self) -> NonZeroU32 {
        self.child_pid
    }

    pub(super) const fn prepared_stack(&self) -> PreparedProcessCloneStack {
        self.prepared_stack
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        GlobalThreadId,
        ObjectId,
        u64,
        usize,
        NonZeroU32,
        PreparedProcessCloneStack,
        ChildExitPublication,
    ) {
        (
            self.parent_thread,
            self.child_process,
            self.address_space_token,
            self.runtime_slot,
            self.child_pid,
            self.prepared_stack,
            self.wait_publication,
        )
    }
}

/// Linear receipt after the prepared fork stack has moved into one exact scheduler generation.
///
/// The generation remains Blocked+Staged and therefore cannot execute. Process/CSpace Thread
/// authority, leader TID and Ready/Published visibility are deliberately absent. `unpublished` still
/// carries the exact runtime-slot/snapshot/identity rollback receipt, but its stack descriptor may be
/// reclaimed only after `bootstrap_cancel_staged` returns that exact scheduler-owned allocation.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct StagedForkSchedulerReceipt {
    unpublished: UnpublishedForkReceipt,
    scheduler_thread: ThreadId,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl StagedForkSchedulerReceipt {
    pub(super) const fn scheduler_thread(&self) -> ThreadId {
        self.scheduler_thread
    }

    pub(super) const fn child_process(&self) -> ObjectId {
        self.unpublished.child_process()
    }

    pub(super) const fn child_pid(&self) -> NonZeroU32 {
        self.unpublished.child_pid()
    }

    pub(super) const fn runtime_slot(&self) -> usize {
        self.unpublished.runtime_slot()
    }
}

/// Creation failure classification for the first scheduler ownership transfer.
///
/// `Recoverable` proves the scheduler retained no generation/stack ownership and returns the exact
/// linear unpublished receipt. `FatalNoRollback` deliberately withholds that receipt when the error
/// class cannot prove the stack was not consumed; callers must fail-stop rather than recycle a
/// possibly scheduler-owned stack or runtime slot.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) enum ForkSchedulerStageError {
    Recoverable {
        error: SchedulerError,
        receipt: UnpublishedForkReceipt,
    },
    FatalNoRollback(SchedulerError),
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl ForkSchedulerStageError {
    pub(super) fn into_recoverable(self) -> Option<(SchedulerError, UnpublishedForkReceipt)> {
        match self {
            Self::Recoverable { error, receipt } => Some((error, receipt)),
            Self::FatalNoRollback(_) => None,
        }
    }
}

/// Transfers one fully reversible fork receipt's protected Core stack into a new exact
/// Blocked+Staged scheduler generation, without attaching Process Thread authority or publishing it.
///
/// # Safety
/// Caller must own `scheduler`'s PE with IRQs masked, irq_depth/preempt_count zero and migration
/// suppressed. `receipt` must be the exact never-scheduler-visible receipt returned by
/// `stage_unpublished_fork_transaction`, and its Process/address-space slot must remain live and
/// unchanged. No context switch or runtime-slot retirement may occur during this transfer.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(dead_code)]
pub(super) unsafe fn stage_fork_scheduler_generation<const THREADS: usize, const WAKES: usize>(
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    receipt: UnpublishedForkReceipt,
    priority: u8,
) -> Result<StagedForkSchedulerReceipt, ForkSchedulerStageError> {
    let prepared = receipt.prepared_stack();
    let context = prepared.context();
    let stack = context.stack();
    let staged = match unsafe {
        scheduler.bootstrap_create_staged_user_thread(
            priority,
            context.saved_sp(),
            stack,
            receipt.address_space_token(),
            context.user_thread_pointer(),
            None,
        )
    } {
        Ok(staged) => staged,
        Err(error) if scheduler_creation_error_releases_unpublished_stack(&error) => {
            return Err(ForkSchedulerStageError::Recoverable { error, receipt });
        }
        Err(error) => return Err(ForkSchedulerStageError::FatalNoRollback(error)),
    };

    Ok(StagedForkSchedulerReceipt {
        unpublished: receipt,
        scheduler_thread: staged,
    })
}

/// Cancels one never-published fork scheduler generation and resumes the earlier receipt rollback.
///
/// # Safety
/// `receipt` must describe the exact current Blocked+Staged generation created by
/// `stage_fork_scheduler_generation`; no Process Thread/TID authority may have been attached and the
/// generation must never have become Ready or Published. The original fork snapshot owner window and
/// parent VMA policy must still satisfy `rollback_unpublished_fork_transaction`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn rollback_staged_fork_scheduler_generation<
    B: Backend,
    const THREADS: usize,
    const WAKES: usize,
>(
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    receipt: StagedForkSchedulerReceipt,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
) -> Result<(), Error> {
    let expected_stack = receipt.unpublished.prepared_stack().context().stack();
    let recovered = unsafe { scheduler.bootstrap_cancel_staged(receipt.scheduler_thread) }
        .map_err(Error::Scheduler)?;
    if recovered != expected_stack {
        return Err(Error::RollbackFailed);
    }
    unsafe {
        rollback_unpublished_fork_transaction(
            runtime,
            current,
            receipt.unpublished,
            backend,
            frame_pool,
        )
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn scheduler_creation_error_releases_unpublished_stack(error: &SchedulerError) -> bool {
    matches!(
        error,
        SchedulerError::NotInitialized
            | SchedulerError::WrongOwner
            | SchedulerError::InterruptsEnabled
            | SchedulerError::Busy
            | SchedulerError::Scheduler(
                SchedulerCoreError::Capacity | SchedulerCoreError::InvalidPriority
            )
            | SchedulerError::Context(_)
    )
}

/// Linear receipt after the exact fork leader has acquired Process/CSpace Thread authority and its
/// canonical Linux leader TID while the scheduler generation remains Blocked+Staged.
///
/// `tid` must equal the already-bound child PID. No Ready/Published transition has occurred, so the
/// complete transaction is still reversible under a fresh staged proof.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct StagedForkLeaderReceipt {
    scheduler: StagedForkSchedulerReceipt,
    thread_handle: CapHandle,
    tid: NonZeroU32,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl StagedForkLeaderReceipt {
    pub(super) const fn scheduler_thread(&self) -> ThreadId {
        self.scheduler.scheduler_thread()
    }

    pub(super) const fn child_pid(&self) -> NonZeroU32 {
        self.tid
    }
}

/// Any returned error after scheduler staging is fail-stop only: an external lifecycle/identity
/// owner may have observed the staged generation. The receipt is deliberately withheld so callers
/// cannot cancel/reuse scheduler or stack authority without a proof-preserving rollback path.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(dead_code)]
pub(super) enum ForkLeaderStageError {
    FatalNoRollback(Error),
}

/// Attaches canonical Process/CSpace Thread authority and binds the fork leader TID to the already
/// allocated child PID, while leaving the exact scheduler generation Blocked+Staged.
///
/// # Safety
/// Caller must retain the scheduler owner/quiescent window from `stage_fork_scheduler_generation`.
/// `receipt` must be the exact live staged receipt, its runtime slot must not be retired, and no
/// scheduler publication/cancellation/context switch may occur during this call.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(dead_code)]
pub(super) unsafe fn stage_fork_leader_authority<const THREADS: usize, const WAKES: usize>(
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    runtime: &mut Step15LinuxRuntime,
    receipt: StagedForkSchedulerReceipt,
) -> Result<StagedForkLeaderReceipt, ForkLeaderStageError> {
    let staged = receipt.scheduler_thread();
    let expected_global = GlobalThreadId::new(
        scheduler
            .owner()
            .map_err(|error| ForkLeaderStageError::FatalNoRollback(Error::Scheduler(error)))?,
        staged,
    );
    let parent_thread = receipt.unpublished.parent_thread();
    let child_process = receipt.child_process();
    let runtime_slot = receipt.runtime_slot();
    let expected_pid = receipt.child_pid();

    let setup: Result<(CapHandle, NonZeroU32), Error> = unsafe {
        scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
            if proof.thread() != expected_global
                || proof.thread() != GlobalThreadId::new(owner, staged)
            {
                return Err(Error::Invariant);
            }
            runtime
                .with_unpublished_additional_process_authority(
                    runtime_slot,
                    child_process,
                    |process, objects, bindings, identities, exits| {
                        let bound_pid = identities.pid_for(process).map_err(Error::Identity)?;
                        if bound_pid != expected_pid {
                            return Err(Error::Invariant);
                        }
                        let handle = exits
                            .attach_thread(
                                process,
                                objects,
                                bindings,
                                run_queue,
                                owner,
                                proof.thread(),
                            )
                            .map_err(Error::Lifecycle)?;
                        let tid = identities
                            .bind_leader(process, objects, bindings, run_queue, owner, handle)
                            .map_err(Error::Identity)?;
                        if tid != expected_pid {
                            return Err(Error::Invariant);
                        }
                        Ok((handle, tid))
                    },
                )
                .map_err(Error::Runtime)?
        })
    };

    match setup {
        Ok((thread_handle, tid)) => {
            runtime
                .inherit_unpublished_fork_child_signal_mask(
                    parent_thread,
                    runtime_slot,
                    child_process,
                    expected_global,
                )
                .map_err(|error| ForkLeaderStageError::FatalNoRollback(Error::Runtime(error)))?;
            Ok(StagedForkLeaderReceipt {
                scheduler: receipt,
                thread_handle,
                tid,
            })
        }
        Err(error) => Err(ForkLeaderStageError::FatalNoRollback(error)),
    }
}

/// Linear proof that one exact fork leader crossed the final scheduler Ready+Published boundary.
///
/// The child Wait publication token no longer lives in this receipt: immediately before scheduler
/// publication it is transferred into the exact retained runtime Process slot, where it remains bound
/// to that Process generation until exit publishes a zombie. Scalar fields here are observations for
/// the parent-return/runtime handoff only and grant no Process/PID/scheduler authority.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct PublishedForkLeaderReceipt {
    scheduler_thread: ThreadId,
    thread_handle: CapHandle,
    child_process: ObjectId,
    runtime_slot: usize,
    child_pid: NonZeroU32,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl PublishedForkLeaderReceipt {
    pub(super) const fn scheduler_thread(&self) -> ThreadId {
        self.scheduler_thread
    }

    pub(super) const fn child_pid(&self) -> NonZeroU32 {
        self.child_pid
    }

    pub(super) const fn runtime_slot(&self) -> usize {
        self.runtime_slot
    }

    pub(super) const fn child_process(&self) -> ObjectId {
        self.child_process
    }

    pub(super) const fn thread_handle(&self) -> CapHandle {
        self.thread_handle
    }
}

/// Publication failure classification for the final fork Ready+Published edge.
///
/// `Recoverable` proves the scheduler retained/restored Blocked+Staged state and returns the complete
/// leader receipt with its exact Wait token restored to transaction ownership. `FatalNoRollback`
/// deliberately withholds authority when the scheduler outcome or token transfer cannot be proven.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) enum ForkLeaderPublishError {
    Recoverable {
        error: Error,
        receipt: StagedForkLeaderReceipt,
    },
    FatalNoRollback(Error),
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl ForkLeaderPublishError {
    pub(super) fn into_recoverable(self) -> Option<(Error, StagedForkLeaderReceipt)> {
        match self {
            Self::Recoverable { error, receipt } => Some((error, receipt)),
            Self::FatalNoRollback(_) => None,
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn rebuild_staged_fork_leader_with_wait(
    parent_thread: GlobalThreadId,
    child_process: ObjectId,
    address_space_token: u64,
    runtime_slot: usize,
    child_pid: NonZeroU32,
    prepared_stack: PreparedProcessCloneStack,
    wait_publication: ChildExitPublication,
    scheduler_thread: ThreadId,
    thread_handle: CapHandle,
    tid: NonZeroU32,
) -> StagedForkLeaderReceipt {
    StagedForkLeaderReceipt {
        scheduler: StagedForkSchedulerReceipt {
            unpublished: UnpublishedForkReceipt {
                parent_thread,
                child_process,
                address_space_token,
                runtime_slot,
                child_pid,
                prepared_stack,
                wait_publication,
            },
            scheduler_thread,
        },
        thread_handle,
        tid,
    }
}

/// Commits one exact fork leader from Blocked+Staged to Ready+Published while transferring the
/// one-shot Wait publication token into the exact retained child Process slot.
///
/// No fallible userspace access occurs here. The Wait token is adopted before the scheduler commit so
/// a successfully runnable child can never exist without a zombie-publication token. If the scheduler
/// reports an error class for which its contract guarantees Blocked+Staged was retained/restored, the
/// same token is taken back from the exact slot and the full staged receipt is returned for canonical
/// rollback. Any other scheduler result or token-recovery failure is fail-stop/no-rollback.
///
/// # Safety
/// Caller must retain the same owner/quiescence window used for leader staging. `receipt` must be the
/// exact never-published leader receipt, its runtime slot/Process generation must remain live, and no
/// competing operation may publish/cancel the staged scheduler generation or mutate that slot.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(dead_code)]
pub(super) unsafe fn publish_staged_fork_leader<const THREADS: usize, const WAKES: usize>(
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    runtime: &mut Step15LinuxRuntime,
    receipt: StagedForkLeaderReceipt,
) -> Result<PublishedForkLeaderReceipt, ForkLeaderPublishError> {
    let StagedForkLeaderReceipt {
        scheduler: staged_scheduler,
        thread_handle,
        tid,
    } = receipt;
    let StagedForkSchedulerReceipt {
        unpublished,
        scheduler_thread,
    } = staged_scheduler;
    let (
        parent_thread,
        child_process,
        address_space_token,
        runtime_slot,
        child_pid,
        prepared_stack,
        wait_publication,
    ) = unpublished.into_parts();

    if tid != child_pid {
        return Err(ForkLeaderPublishError::FatalNoRollback(Error::Invariant));
    }

    if let Err((error, wait_publication)) = runtime.adopt_additional_process_wait_publication(
        runtime_slot,
        child_process,
        wait_publication,
    ) {
        let receipt = rebuild_staged_fork_leader_with_wait(
            parent_thread,
            child_process,
            address_space_token,
            runtime_slot,
            child_pid,
            prepared_stack,
            wait_publication,
            scheduler_thread,
            thread_handle,
            tid,
        );
        return Err(ForkLeaderPublishError::Recoverable {
            error: Error::Runtime(error),
            receipt,
        });
    }

    // SAFETY: all external Process/CSpace/Linux identity and persistent Wait ownership is complete;
    // delegated caller contract retains exact scheduler owner/quiescence for this staged generation.
    match unsafe { scheduler.bootstrap_publish_staged_ready(scheduler_thread) } {
        Ok(()) => Ok(PublishedForkLeaderReceipt {
            scheduler_thread,
            thread_handle,
            child_process,
            runtime_slot,
            child_pid,
        }),
        Err(error) if fork_scheduler_publish_error_allows_rollback(&error) => {
            let wait_publication = match runtime
                .take_additional_process_wait_publication(runtime_slot, child_process)
            {
                Ok(publication) => publication,
                Err(_) => {
                    return Err(ForkLeaderPublishError::FatalNoRollback(
                        Error::RollbackFailed,
                    ));
                }
            };
            let receipt = rebuild_staged_fork_leader_with_wait(
                parent_thread,
                child_process,
                address_space_token,
                runtime_slot,
                child_pid,
                prepared_stack,
                wait_publication,
                scheduler_thread,
                thread_handle,
                tid,
            );
            Err(ForkLeaderPublishError::Recoverable {
                error: Error::Scheduler(error),
                receipt,
            })
        }
        Err(error) => Err(ForkLeaderPublishError::FatalNoRollback(Error::Scheduler(
            error,
        ))),
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn fork_scheduler_publish_error_allows_rollback(error: &SchedulerError) -> bool {
    matches!(
        error,
        SchedulerError::Scheduler(_) | SchedulerError::Context(_)
    )
}

/// Reverses a successful staged fork-leader authority transaction before any Ready/Published edge.
/// Process/CSpace Thread authority is removed first under a fresh staged proof, then the exact Linux
/// unpublished TID relation is removed. Only after those external references are gone may the
/// scheduler generation be cancelled and the earlier fork receipt reclaim its stack/snapshot/Process.
///
/// # Safety
/// `receipt` must be the exact never-published leader receipt and caller must retain the original
/// scheduler plus fork snapshot owner/quiescence contracts. No user-visible child execution or
/// parent VMA policy change may have occurred.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn rollback_staged_fork_leader_authority<
    B: Backend,
    const THREADS: usize,
    const WAKES: usize,
>(
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    receipt: StagedForkLeaderReceipt,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
) -> Result<(), Error> {
    let staged = receipt.scheduler.scheduler_thread();
    let expected_global = GlobalThreadId::new(scheduler.owner()?, staged);
    let child_process = receipt.scheduler.child_process();
    let runtime_slot = receipt.scheduler.runtime_slot();
    let handle = receipt.thread_handle;
    let tid = receipt.tid;

    unsafe {
        scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
            if proof.thread() != expected_global
                || proof.thread() != GlobalThreadId::new(owner, staged)
            {
                return Err(Error::RollbackFailed);
            }
            runtime
                .retire_unpublished_fork_child_signal_thread(
                    runtime_slot,
                    child_process,
                    expected_global,
                )
                .map_err(|_| Error::RollbackFailed)?;
            runtime
                .with_unpublished_additional_process_authority(
                    runtime_slot,
                    child_process,
                    |process, objects, bindings, identities, _exits| {
                        let rollback = unsafe {
                            process.rollback_staged_thread(
                                objects, bindings, run_queue, owner, proof, handle,
                            )
                        }
                        .map_err(Error::Process)?;
                        if rollback.scheduler_thread() != expected_global {
                            return Err(Error::RollbackFailed);
                        }
                        let cancelled = identities
                            .rollback_unpublished_leader_identity(process, rollback, tid)
                            .map_err(Error::Identity)?;
                        if cancelled != expected_global {
                            return Err(Error::RollbackFailed);
                        }
                        Ok(())
                    },
                )
                .map_err(Error::Runtime)?
        })
    }?;

    unsafe {
        rollback_staged_fork_scheduler_generation(
            scheduler,
            runtime,
            current,
            receipt.scheduler,
            backend,
            frame_pool,
        )
    }
}

/// Copies one exact anonymous parent address-space snapshot into one empty unpublished fork child.
///
/// This function deliberately owns no Process, scheduler, identity or TTBR0 publication. All policy
/// observation and mapping mutation pass through the existing capability-checked architecture owner.
/// `copy_frame` is private dependency injection for host regressions; production supplies only the
/// persistent hardened AArch64 KMap controller.
#[allow(clippy::too_many_arguments)]
fn snapshot_exact_anonymous<
    const PARENT_CAPS: usize,
    const CHILD_CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const EXTENTS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    parent: &Process<PARENT_CAPS>,
    parent_space: &BoundProcessAddressSpace<VMAS>,
    child: &Process<CHILD_CAPS>,
    child_space: &mut BoundProcessAddressSpace<VMAS>,
    objects: &ObjectTable<OBJECTS>,
    backend: &mut B,
    allocator: &mut ExtentAllocator<EXTENTS>,
    reservations: &ReservationSet<RESERVED>,
    mut copy_frame: impl FnMut(&mut B, u64, u64) -> Result<(), Error>,
) -> Result<(), Error> {
    // The child must start with no policy. Checking through its own MAP capability also revalidates
    // that the supplied Process and BoundProcessAddressSpace are the exact paired owners.
    if child_space
        .user_vma_at(child, objects, child.address_space_handle(), 0)
        .map_err(|_| Error::AddressSpace)?
        .is_some()
    {
        return Err(Error::ChildNotEmpty);
    }

    // Preflight the complete currently representable policy before the first physical allocation.
    // File/SharedMemory mappings need semantics not encoded by the present VMA model, so this first
    // fork slice refuses them rather than silently pretending private-copy behavior.
    let mut vma_count = 0usize;
    while let Some(vma) = parent_space
        .user_vma_at(parent, objects, parent.address_space_handle(), vma_count)
        .map_err(|_| Error::AddressSpace)?
    {
        if !matches!(vma.backing, Backing::Anonymous) {
            return Err(Error::UnsupportedBacking);
        }
        vma_count = vma_count.checked_add(1).ok_or(Error::Invariant)?;
    }

    for vma_index in 0..vma_count {
        let vma = parent_space
            .user_vma_at(parent, objects, parent.address_space_handle(), vma_index)
            .map_err(|_| Error::AddressSpace)?
            .ok_or(Error::Invariant)?;
        if !matches!(vma.backing, Backing::Anonymous) {
            return abort_snapshot(
                Error::Invariant,
                None,
                vma_index,
                0,
                parent,
                parent_space,
                child,
                child_space,
                objects,
                backend,
                allocator,
            );
        }

        let mut offset = 0u64;
        while offset < vma.len {
            let virtual_address = match vma.start.checked_add(offset) {
                Some(address) => address,
                None => {
                    return abort_snapshot(
                        Error::Invariant,
                        None,
                        vma_index,
                        offset,
                        parent,
                        parent_space,
                        child,
                        child_space,
                        objects,
                        backend,
                        allocator,
                    );
                }
            };
            let parent_physical = match parent_space.translate_user(
                parent,
                objects,
                parent.address_space_handle(),
                backend,
                virtual_address,
            ) {
                Ok(physical) => physical,
                Err(_) => {
                    return abort_snapshot(
                        Error::AddressSpace,
                        None,
                        vma_index,
                        offset,
                        parent,
                        parent_space,
                        child,
                        child_space,
                        objects,
                        backend,
                        allocator,
                    );
                }
            };

            let range = match allocator.allocate(1, 1) {
                Ok(range) => range,
                Err(error) => {
                    return abort_snapshot(
                        Error::Frame(error),
                        None,
                        vma_index,
                        offset,
                        parent,
                        parent_space,
                        child,
                        child_space,
                        objects,
                        backend,
                        allocator,
                    );
                }
            };
            let Some(child_frame) = PhysFrame::from_start_address(range.start) else {
                return abort_snapshot(
                    Error::InvalidAllocatedFrame,
                    Some(range),
                    vma_index,
                    offset,
                    parent,
                    parent_space,
                    child,
                    child_space,
                    objects,
                    backend,
                    allocator,
                );
            };

            if let Err(error) = copy_frame(backend, parent_physical, child_frame.start_address()) {
                return abort_snapshot(
                    error,
                    Some(range),
                    vma_index,
                    offset,
                    parent,
                    parent_space,
                    child,
                    child_space,
                    objects,
                    backend,
                    allocator,
                );
            }

            // The architecture owner performs the canonical VMA validation (W^X, null/user range,
            // reserved-frame checks) and compacts adjacent anonymous per-page policy.
            let child_vma = Vma {
                start: virtual_address,
                len: PAGE_SIZE,
                perms: vma.perms,
                backing: Backing::Anonymous,
            };
            if child_space
                .map_user_page_coalescing_anonymous(
                    child,
                    objects,
                    child.address_space_handle(),
                    backend,
                    child_vma,
                    child_frame,
                    reservations,
                )
                .is_err()
            {
                return abort_snapshot(
                    Error::AddressSpace,
                    Some(range),
                    vma_index,
                    offset,
                    parent,
                    parent_space,
                    child,
                    child_space,
                    objects,
                    backend,
                    allocator,
                );
            }

            offset = offset.checked_add(PAGE_SIZE).ok_or(Error::Invariant)?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn abort_snapshot<
    const PARENT_CAPS: usize,
    const CHILD_CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const EXTENTS: usize,
    B: Backend,
>(
    original: Error,
    current_unpublished: Option<FrameRange>,
    current_vma_index: usize,
    published_bytes_in_current_vma: u64,
    parent: &Process<PARENT_CAPS>,
    parent_space: &BoundProcessAddressSpace<VMAS>,
    child: &Process<CHILD_CAPS>,
    child_space: &mut BoundProcessAddressSpace<VMAS>,
    objects: &ObjectTable<OBJECTS>,
    backend: &mut B,
    allocator: &mut ExtentAllocator<EXTENTS>,
) -> Result<(), Error> {
    let mut rollback_failed = false;

    if let Some(range) = current_unpublished
        && allocator.free(range).is_err()
    {
        rollback_failed = true;
    }

    if rollback_published_prefix(
        current_vma_index,
        published_bytes_in_current_vma,
        parent,
        parent_space,
        child,
        child_space,
        objects,
        backend,
        allocator,
    )
    .is_err()
    {
        rollback_failed = true;
    }

    if rollback_failed {
        child_space.poison();
        Err(Error::RollbackFailed)
    } else {
        Err(original)
    }
}

#[allow(clippy::too_many_arguments)]
fn rollback_published_prefix<
    const PARENT_CAPS: usize,
    const CHILD_CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const EXTENTS: usize,
    B: Backend,
>(
    mut vma_index: usize,
    mut published_bytes: u64,
    parent: &Process<PARENT_CAPS>,
    parent_space: &BoundProcessAddressSpace<VMAS>,
    child: &Process<CHILD_CAPS>,
    child_space: &mut BoundProcessAddressSpace<VMAS>,
    objects: &ObjectTable<OBJECTS>,
    backend: &mut B,
    allocator: &mut ExtentAllocator<EXTENTS>,
) -> Result<(), ()> {
    loop {
        let vma = parent_space
            .user_vma_at(parent, objects, parent.address_space_handle(), vma_index)
            .map_err(|_| ())?
            .ok_or(())?;
        while published_bytes != 0 {
            published_bytes = published_bytes.checked_sub(PAGE_SIZE).ok_or(())?;
            let virtual_address = vma.start.checked_add(published_bytes).ok_or(())?;
            let frame = child_space
                .unmap_user_page_coalescing_anonymous(
                    child,
                    objects,
                    child.address_space_handle(),
                    backend,
                    virtual_address,
                )
                .map_err(|_| ())?;
            let range = FrameRange::new(frame.start_address(), 1).map_err(|_| ())?;
            allocator.free(range).map_err(|_| ())?;
        }

        if vma_index == 0 {
            return Ok(());
        }
        vma_index -= 1;
        let previous = parent_space
            .user_vma_at(parent, objects, parent.address_space_handle(), vma_index)
            .map_err(|_| ())?
            .ok_or(())?;
        published_bytes = previous.len;
    }
}

/// Reverses one previously successful anonymous fork snapshot while the child is still unpublished.
///
/// This is a transaction rollback edge, not a general unmap API. The caller must keep the exact
/// parent VMA policy unchanged from the successful snapshot through this call. The parent policy is
/// re-observed only to recover the deterministic reverse page order; any drift, unsupported backing,
/// missing child mapping, unmap failure or frame-free failure makes exact rollback unprovable and
/// permanently poisons the child address-space before the error escapes.
#[allow(clippy::too_many_arguments)]
fn rollback_completed_anonymous_snapshot<
    const PARENT_CAPS: usize,
    const CHILD_CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const EXTENTS: usize,
    B: Backend,
>(
    parent: &Process<PARENT_CAPS>,
    parent_space: &BoundProcessAddressSpace<VMAS>,
    child: &Process<CHILD_CAPS>,
    child_space: &mut BoundProcessAddressSpace<VMAS>,
    objects: &ObjectTable<OBJECTS>,
    backend: &mut B,
    allocator: &mut ExtentAllocator<EXTENTS>,
) -> Result<(), Error> {
    let rollback = (|| -> Result<(), ()> {
        let mut vma_count = 0usize;
        while let Some(vma) = parent_space
            .user_vma_at(parent, objects, parent.address_space_handle(), vma_count)
            .map_err(|_| ())?
        {
            if !matches!(vma.backing, Backing::Anonymous) {
                return Err(());
            }
            vma_count = vma_count.checked_add(1).ok_or(())?;
        }

        if vma_count != 0 {
            let last_index = vma_count.checked_sub(1).ok_or(())?;
            let last = parent_space
                .user_vma_at(parent, objects, parent.address_space_handle(), last_index)
                .map_err(|_| ())?
                .ok_or(())?;
            rollback_published_prefix(
                last_index,
                last.len,
                parent,
                parent_space,
                child,
                child_space,
                objects,
                backend,
                allocator,
            )?;
        }

        if child_space
            .user_vma_at(child, objects, child.address_space_handle(), 0)
            .map_err(|_| ())?
            .is_some()
        {
            return Err(());
        }
        Ok(())
    })();

    if rollback.is_err() {
        child_space.poison();
        Err(Error::RollbackFailed)
    } else {
        Ok(())
    }
}

/// Production rollback edge for a completed, still-unpublished anonymous fork snapshot.
///
/// # Safety
/// The caller must retain the same canonical local CPU/page-table mutation window used by
/// `snapshot_current_anonymous_fork`; the exact parent generation and its VMA policy must be
/// unchanged, the child must still be unpublished and inactive, and `frame_pool`/`backend` must be
/// their sole live owners. No blocking, context switch, scheduler/identity publication or TTBR0
/// activation may occur until this rollback either succeeds or poisons the child address-space.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn rollback_current_anonymous_fork<B: Backend>(
    runtime: &Step15LinuxRuntime,
    current: GlobalThreadId,
    child: &Process<{ super::runtime::STEP15_RUNTIME_CAPS }>,
    child_space: &mut BoundProcessAddressSpace<{ super::runtime::STEP15_RUNTIME_VMAS }>,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
) -> Result<(), Error> {
    runtime
        .with_fork_snapshot_parent(current, |parent, parent_space, objects| {
            let (allocator, _) = frame_pool.split();
            rollback_completed_anonymous_snapshot(
                parent,
                parent_space,
                child,
                child_space,
                objects,
                backend,
                allocator,
            )
        })
        .map_err(Error::Runtime)?
}

/// Production AArch64 entry for the private snapshot stage.
///
/// The parent is never selected by a scalar PID/TID/ObjectId: the existing runtime first resolves the
/// exact current scheduler generation through the canonical Linux identity owner, then scopes the
/// matching retained Process, AddressSpace and ObjectTable references to this synchronous callback.
/// The child is already-created but unpublished and must own an empty fork-staging AddressSpace.
///
/// # Safety
/// The caller must hold the canonical local CPU/page-table mutation window, keep source and child
/// TTBR0 roots inactive for the snapshot operation, and guarantee that `child`/`child_space` remain
/// unpublished. `backend`, `frame_pool` and `kmap` must be their sole live owners for the duration.
/// No blocking, context switch, scheduler/identity publication or TTBR0 activation may occur.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn snapshot_current_anonymous_fork<B: Backend>(
    runtime: &Step15LinuxRuntime,
    current: GlobalThreadId,
    child: &Process<{ super::runtime::STEP15_RUNTIME_CAPS }>,
    child_space: &mut BoundProcessAddressSpace<{ super::runtime::STEP15_RUNTIME_VMAS }>,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
    kmap: &mut KmapController,
) -> Result<(), Error> {
    let selected = runtime
        .with_fork_snapshot_parent(current, |parent, parent_space, objects| {
            let (allocator, reservations) = frame_pool.split();
            snapshot_exact_anonymous(
                parent,
                parent_space,
                child,
                child_space,
                objects,
                backend,
                allocator,
                reservations,
                |backend, source, destination| {
                    // SAFETY: delegated function contract owns both physical frames and the exact
                    // active TTBR1/KMap mutation window for this synchronous copy.
                    unsafe { kmap.copy_frame(backend, source, destination) }.map_err(Error::Kmap)
                },
            )
        })
        .map_err(Error::Runtime)?;
    selected
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn inherit_unpublished_fork_break(
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    child: &Process<{ super::runtime::STEP15_RUNTIME_CAPS }>,
) -> Result<(), Error> {
    let parent_process = runtime
        .with_fork_snapshot_parent(current, |parent, _parent_space, _objects| parent.id())
        .map_err(Error::Runtime)?;
    let child_process = child.id();
    let (vm, _initial_process, _objects, _initial_space) = runtime.minimum_vm_parts();
    vm.inherit_process_break(parent_process, child_process)
        .map_err(|_| Error::Invariant)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn retire_unpublished_fork_break(
    runtime: &mut Step15LinuxRuntime,
    child_process: ObjectId,
) -> Result<(), Error> {
    let (vm, _initial_process, _objects, _initial_space) = runtime.minimum_vm_parts();
    match vm.remove_process_break(child_process) {
        Ok(()) | Err(kernal_linux_vm::Error::MissingBreakState) => Ok(()),
        Err(_) => Err(Error::RollbackFailed),
    }
}

/// Stages every reversible owner needed by a private fork child but deliberately stops before
/// scheduler generation creation/publication.
///
/// The successful receipt proves: a fresh child Process/private AddressSpace exists in one bounded
/// runtime slot, its complete anonymous snapshot is copied, canonical Linux child identity is bound,
/// and a protected first-return stack contains x0=0 plus the inherited parent return state. The child
/// remains scheduler-invisible; no ThreadId/TID/Ready/Published authority is created here.
///
/// # Safety
/// `current` must be the exact Running+Published scheduler generation whose Process/TTBR0 is active.
/// Caller owns the local page-table/frame/KMap mutation window and must keep IRQ/preemption/migration
/// and address-space switching suppressed until this transaction returns. `parent_registers`,
/// `parent_return`, and `parent_tls` must be the already-authorized post-SVC state of that generation.
/// `backend`, `frame_pool`, and `kmap` must be their sole live mutation owners. On success the caller
/// must either publish the returned receipt through the later exact staged-scheduler transaction or
/// call `rollback_unpublished_fork_transaction` before allowing parent VMA policy to change.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn stage_unpublished_fork_transaction<B: Backend>(
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    plan: ProcessClonePlan,
    parent_registers: &[u64; 31],
    parent_return: El0ReturnState,
    parent_tls: u64,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
    kmap: &mut KmapController,
) -> Result<UnpublishedForkReceipt, Error> {
    require_private_fork_plan(plan)?;

    let (mut child, mut child_space) = runtime
        .create_unpublished_fork_child_for_scheduler_thread(current, backend)
        .map_err(Error::Runtime)?;

    // SAFETY: delegated transaction contract keeps both roots inactive/unpublished and owns every
    // physical/page-table mutation input for this synchronous snapshot.
    if let Err(snapshot_error) = unsafe {
        snapshot_current_anonymous_fork(
            runtime,
            current,
            &child,
            &mut child_space,
            backend,
            frame_pool,
            kmap,
        )
    } {
        return match runtime.retire_unpublished_fork_child_identity(&mut child) {
            Ok(()) => Err(snapshot_error),
            Err(_) => Err(Error::RollbackFailed),
        };
    }

    let child_pid = match runtime.bind_unpublished_fork_child_identity(current, &child) {
        Ok(pid) => pid,
        Err(error) => {
            // SAFETY: snapshot succeeded and parent policy is unchanged in this same transaction.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    None,
                    backend,
                    frame_pool,
                    Error::Runtime(error),
                )
            };
        }
    };

    if let Err(error) = inherit_unpublished_fork_break(runtime, current, &child) {
        // SAFETY: no scheduler authority exists; snapshot and Linux identity/policy remain under the
        // same reversible staging transaction. Break inheritance is atomic, and rollback tolerates
        // MissingBreakState when the owner rejected the inheritance before mutation.
        return unsafe {
            abort_completed_fork_staging(
                runtime,
                current,
                child,
                child_space,
                None,
                backend,
                frame_pool,
                error,
            )
        };
    }

    let returns = match ProcessCloneReturnState::from_parent(
        parent_registers,
        parent_return,
        parent_tls,
        plan,
        child_pid,
    ) {
        Ok(returns) => returns,
        Err(error) => {
            // SAFETY: no scheduler authority exists and snapshot/identity are still reversible.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    None,
                    backend,
                    frame_pool,
                    Error::ReturnState(error),
                )
            };
        }
    };

    let prepared_stack = match prepare_process_clone_with_core_stack(returns) {
        Ok(prepared) => prepared,
        Err(error) => {
            // SAFETY: stack preparation transferred no scheduler ownership on failure.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    None,
                    backend,
                    frame_pool,
                    Error::Stack(error),
                )
            };
        }
    };

    let child_process = child.id();
    let address_space_token = child.address_space().0;
    if address_space_token == 0 || child_space.address_space_object().0 != address_space_token {
        // SAFETY: prepared stack remains unpublished and all earlier stages are reversible.
        return unsafe {
            abort_completed_fork_staging(
                runtime,
                current,
                child,
                child_space,
                Some(prepared_stack),
                backend,
                frame_pool,
                Error::Invariant,
            )
        };
    }

    let wait_publication = match runtime.track_unpublished_fork_child_wait(current, &child) {
        Ok(publication) => publication,
        Err(error) => {
            // SAFETY: Wait tracking failed before publishing observation state; all earlier fork
            // stages remain reversible in this same owner/quiescence transaction.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    Some(prepared_stack),
                    backend,
                    frame_pool,
                    Error::Runtime(error),
                )
            };
        }
    };

    let runtime_slot = match runtime.install_additional_process(child, child_space) {
        Ok(runtime_slot) => runtime_slot,
        Err((error, child, child_space)) => {
            if runtime
                .cancel_unpublished_fork_child_wait(wait_publication)
                .is_err()
            {
                return Err(Error::RollbackFailed);
            }
            // SAFETY: installation returned exact ownership to this transaction; no slot escaped.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    Some(prepared_stack),
                    backend,
                    frame_pool,
                    Error::Runtime(error),
                )
            };
        }
    };

    #[cfg(feature = "step29-qemu-proof")]
    {
        let path_bound = runtime
            .with_fork_snapshot_parent(current, |parent, _parent_space, _objects| parent.id())
            .map_err(|_| ())
            .and_then(|parent_process| {
                super::step29_runtime::fork_process(parent_process, child_process).map_err(|_| ())
            });
        if path_bound.is_err() {
            if runtime
                .cancel_unpublished_fork_child_wait(wait_publication)
                .is_err()
            {
                return Err(Error::RollbackFailed);
            }
            let (child, child_space) = runtime
                .take_unpublished_additional_process(runtime_slot, child_process)
                .map_err(|_| Error::RollbackFailed)?;
            // SAFETY: Step29 fork staging is transactional; failure published no child path view.
            // The exact Process/AddressSpace slot and Wait token are back under this transaction.
            return unsafe {
                abort_completed_fork_staging(
                    runtime,
                    current,
                    child,
                    child_space,
                    Some(prepared_stack),
                    backend,
                    frame_pool,
                    Error::Invariant,
                )
            };
        }
    }

    Ok(UnpublishedForkReceipt {
        parent_thread: current,
        child_process,
        address_space_token,
        runtime_slot,
        child_pid,
        prepared_stack,
        wait_publication,
    })
}

/// Rolls back one successful `stage_unpublished_fork_transaction` receipt before any scheduler
/// generation has been created. This is the sole reverse edge for a successful staging receipt.
///
/// # Safety
/// `receipt` must be the exact current unpublished receipt and may not have been copied into any
/// scheduler/identity publication path. Parent VMA policy and the page-table/frame ownership window
/// must still match the original staging transaction. A rollback failure is fatal evidence: poisoned
/// child mappings/stack ownership are never reused or converted into a Linux errno.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn rollback_unpublished_fork_transaction<B: Backend>(
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    receipt: UnpublishedForkReceipt,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
) -> Result<(), Error> {
    let UnpublishedForkReceipt {
        parent_thread: _,
        child_process,
        address_space_token,
        runtime_slot,
        child_pid: _,
        prepared_stack,
        wait_publication,
    } = receipt;

    runtime
        .cancel_unpublished_fork_child_wait(wait_publication)
        .map_err(|_| Error::RollbackFailed)?;

    #[cfg(feature = "step29-qemu-proof")]
    super::step29_runtime::retire_process(child_process).map_err(|_| Error::RollbackFailed)?;

    let (mut child, mut child_space) = runtime
        .take_unpublished_additional_process(runtime_slot, child_process)
        .map_err(|_| Error::RollbackFailed)?;
    if child.address_space().0 != address_space_token
        || child_space.address_space_object().0 != address_space_token
    {
        return Err(Error::RollbackFailed);
    }

    let stack_failed =
        unsafe { reclaim_unpublished_process_clone_core_stack(prepared_stack.context().stack()) }
            .is_err();

    // SAFETY: delegated receipt contract proves snapshot is still complete and unpublished.
    if unsafe {
        rollback_current_anonymous_fork(
            runtime,
            current,
            &child,
            &mut child_space,
            backend,
            frame_pool,
        )
    }
    .is_err()
    {
        return Err(Error::RollbackFailed);
    }

    retire_unpublished_fork_break(runtime, child_process)?;
    runtime
        .retire_unpublished_fork_child_identity(&mut child)
        .map_err(|_| Error::RollbackFailed)?;
    if stack_failed {
        Err(Error::RollbackFailed)
    } else {
        Ok(())
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
unsafe fn abort_completed_fork_staging<B: Backend>(
    runtime: &mut Step15LinuxRuntime,
    current: GlobalThreadId,
    mut child: Process<{ super::runtime::STEP15_RUNTIME_CAPS }>,
    mut child_space: BoundProcessAddressSpace<{ super::runtime::STEP15_RUNTIME_VMAS }>,
    prepared_stack: Option<PreparedProcessCloneStack>,
    backend: &mut B,
    frame_pool: &mut Step15FramePool,
    original: Error,
) -> Result<UnpublishedForkReceipt, Error> {
    let stack_failed = if let Some(prepared) = prepared_stack {
        // SAFETY: no scheduler generation ever received this exact prepared stack.
        unsafe { reclaim_unpublished_process_clone_core_stack(prepared.context().stack()) }.is_err()
    } else {
        false
    };

    // SAFETY: snapshot succeeded earlier in this same never-published transaction and parent policy
    // has not been allowed to change.
    if unsafe {
        rollback_current_anonymous_fork(
            runtime,
            current,
            &child,
            &mut child_space,
            backend,
            frame_pool,
        )
    }
    .is_err()
    {
        return Err(Error::RollbackFailed);
    }

    if retire_unpublished_fork_break(runtime, child.id()).is_err()
        || runtime
            .retire_unpublished_fork_child_identity(&mut child)
            .is_err()
        || stack_failed
    {
        Err(Error::RollbackFailed)
    } else {
        Err(original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_frame_allocator::Error as FrameError;
    use kernal_process::Personality;
    use kernal_vm::{USER_MIN, VmPerms};

    const TABLES: usize = 64;
    const TABLE_BASE: u64 = 0x10_0000;
    const PARENT_FRAME_BASE: u64 = 0x2000_0000;
    const CHILD_FRAME_BASE: u64 = 0x3000_0000;
    const TRACKED_FRAMES: usize = 16;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
        frame_addresses: [u64; TRACKED_FRAMES],
        frame_markers: [u64; TRACKED_FRAMES],
        frame_len: usize,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TABLES],
                used: 0,
                frame_addresses: [0; TRACKED_FRAMES],
                frame_markers: [0; TRACKED_FRAMES],
                frame_len: 0,
            }
        }

        fn table_index(physical: u64) -> Option<usize> {
            if physical < TABLE_BASE || !(physical - TABLE_BASE).is_multiple_of(PAGE_SIZE) {
                return None;
            }
            let index = usize::try_from((physical - TABLE_BASE) / PAGE_SIZE).ok()?;
            (index < TABLES).then_some(index)
        }

        fn marker(&self, physical: u64) -> Option<u64> {
            self.frame_addresses[..self.frame_len]
                .iter()
                .position(|address| *address == physical)
                .map(|index| self.frame_markers[index])
        }

        fn set_marker(&mut self, physical: u64, marker: u64) {
            if let Some(index) = self.frame_addresses[..self.frame_len]
                .iter()
                .position(|address| *address == physical)
            {
                self.frame_markers[index] = marker;
                return;
            }
            assert!(self.frame_len < TRACKED_FRAMES);
            self.frame_addresses[self.frame_len] = physical;
            self.frame_markers[self.frame_len] = marker;
            self.frame_len += 1;
        }

        fn copy_marker(&mut self, source: u64, destination: u64) -> Result<(), Error> {
            let marker = self.marker(source).ok_or(Error::Invariant)?;
            self.set_marker(destination, marker);
            Ok(())
        }
    }

    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == TABLES {
                return None;
            }
            let index = self.used;
            self.used += 1;
            self.tables[index] = [0; 512];
            Some(TABLE_BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(
                *self
                    .tables
                    .get(Self::table_index(table_phys)?)?
                    .get(index)?,
            )
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) =
                Self::table_index(table_phys).and_then(|index| self.tables.get_mut(index))
            else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    fn allocator(pages: u64) -> ExtentAllocator<8> {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(CHILD_FRAME_BASE, pages).unwrap())
            .unwrap();
        allocator
    }

    fn setup() -> (
        ObjectTable<16>,
        Process<8>,
        BoundProcessAddressSpace<8>,
        Process<8>,
        BoundProcessAddressSpace<8>,
        TestBackend,
    ) {
        let mut objects = ObjectTable::<16>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let parent_space =
            BoundProcessAddressSpace::<8>::create(&parent, &objects, &mut backend).unwrap();
        let child = Process::<8>::create_fork_child(&parent, &mut objects).unwrap();
        let child_space = BoundProcessAddressSpace::<8>::create_fork_child_staging(
            &parent_space,
            &parent,
            &child,
            &objects,
            &mut backend,
        )
        .unwrap();
        (objects, parent, parent_space, child, child_space, backend)
    }

    fn map_parent_anonymous(
        parent: &Process<8>,
        parent_space: &mut BoundProcessAddressSpace<8>,
        objects: &ObjectTable<16>,
        backend: &mut TestBackend,
        reservations: &ReservationSet<1>,
        virtual_address: u64,
        physical_address: u64,
    ) {
        let frame = PhysFrame::from_start_address(physical_address).unwrap();
        parent_space
            .map_user_page_coalescing_anonymous(
                parent,
                objects,
                parent.address_space_handle(),
                backend,
                Vma::new(
                    virtual_address,
                    PAGE_SIZE,
                    VmPerms::READ.union(VmPerms::WRITE),
                    Backing::Anonymous,
                )
                .unwrap(),
                frame,
                reservations,
            )
            .unwrap();
    }

    #[test]
    fn scheduler_creation_release_classifier_is_fail_closed() {
        assert!(scheduler_creation_error_releases_unpublished_stack(
            &SchedulerError::NotInitialized
        ));
        assert!(scheduler_creation_error_releases_unpublished_stack(
            &SchedulerError::Scheduler(SchedulerCoreError::Capacity)
        ));
        assert!(scheduler_creation_error_releases_unpublished_stack(
            &SchedulerError::Scheduler(SchedulerCoreError::InvalidPriority)
        ));
        assert!(!scheduler_creation_error_releases_unpublished_stack(
            &SchedulerError::Invariant
        ));
        assert!(!scheduler_creation_error_releases_unpublished_stack(
            &SchedulerError::NoRunnableThread
        ));
    }

    #[test]
    fn fork_publish_error_classifier_is_conservative() {
        assert!(fork_scheduler_publish_error_allows_rollback(
            &SchedulerError::Scheduler(SchedulerCoreError::InvalidState)
        ));
        assert!(!fork_scheduler_publish_error_allows_rollback(
            &SchedulerError::WrongOwner
        ));
        assert!(!fork_scheduler_publish_error_allows_rollback(
            &SchedulerError::InterruptsEnabled
        ));
    }

    #[test]
    fn unpublished_transaction_accepts_only_private_fork_plan() {
        let fork =
            ProcessClonePlan::validate(kernal_linux_clone::FORK_PROCESS_FLAGS, 0, 0, 0, 0).unwrap();
        assert!(require_private_fork_plan(fork).is_ok());

        let vfork = ProcessClonePlan::validate(kernal_linux_clone::VFORK_PROCESS_FLAGS, 0, 0, 0, 0)
            .unwrap();
        assert!(matches!(
            require_private_fork_plan(vfork),
            Err(Error::UnsupportedProcessClonePlan)
        ));
    }

    #[test]
    fn adjacent_anonymous_pages_copy_to_independent_child_frames() {
        let (objects, parent, mut parent_space, child, mut child_space, mut backend) = setup();
        let reservations = ReservationSet::<1>::new();
        let base = USER_MIN + 0x40_000;
        map_parent_anonymous(
            &parent,
            &mut parent_space,
            &objects,
            &mut backend,
            &reservations,
            base,
            PARENT_FRAME_BASE,
        );
        backend.set_marker(PARENT_FRAME_BASE, 0x1111);
        map_parent_anonymous(
            &parent,
            &mut parent_space,
            &objects,
            &mut backend,
            &reservations,
            base + PAGE_SIZE,
            PARENT_FRAME_BASE + PAGE_SIZE,
        );
        backend.set_marker(PARENT_FRAME_BASE + PAGE_SIZE, 0x2222);
        let mut frames = allocator(8);
        let free_before = frames.free_pages();

        snapshot_exact_anonymous(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
            &reservations,
            |backend, source, destination| backend.copy_marker(source, destination),
        )
        .unwrap();

        let copied = child_space
            .user_vma_at(&child, &objects, child.address_space_handle(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(copied.start, base);
        assert_eq!(copied.len, 2 * PAGE_SIZE);
        assert_eq!(copied.backing, Backing::Anonymous);
        assert_eq!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 1)
                .unwrap(),
            None
        );

        let child_first = child_space
            .translate_user(
                &child,
                &objects,
                child.address_space_handle(),
                &mut backend,
                base,
            )
            .unwrap();
        let child_second = child_space
            .translate_user(
                &child,
                &objects,
                child.address_space_handle(),
                &mut backend,
                base + PAGE_SIZE,
            )
            .unwrap();
        assert_ne!(child_first, PARENT_FRAME_BASE);
        assert_ne!(child_second, PARENT_FRAME_BASE + PAGE_SIZE);
        assert_ne!(child_first, child_second);
        assert_eq!(backend.marker(child_first), Some(0x1111));
        assert_eq!(backend.marker(child_second), Some(0x2222));

        backend.set_marker(PARENT_FRAME_BASE, 0xaaaa);
        assert_eq!(backend.marker(PARENT_FRAME_BASE), Some(0xaaaa));
        assert_eq!(backend.marker(child_first), Some(0x1111));
        assert_eq!(frames.free_pages(), free_before - 2);
    }

    #[test]
    fn completed_snapshot_rollback_restores_empty_child_and_all_frames() {
        let (objects, parent, mut parent_space, child, mut child_space, mut backend) = setup();
        let reservations = ReservationSet::<1>::new();
        let base = USER_MIN + 0x50_000;
        for page in 0..2u64 {
            map_parent_anonymous(
                &parent,
                &mut parent_space,
                &objects,
                &mut backend,
                &reservations,
                base + page * PAGE_SIZE,
                PARENT_FRAME_BASE + page * PAGE_SIZE,
            );
            backend.set_marker(PARENT_FRAME_BASE + page * PAGE_SIZE, 0x3000 + page);
        }
        let mut frames = allocator(8);
        let free_before = frames.free_pages();

        snapshot_exact_anonymous(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
            &reservations,
            |backend, source, destination| backend.copy_marker(source, destination),
        )
        .unwrap();
        assert_eq!(frames.free_pages(), free_before - 2);
        assert!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 0)
                .unwrap()
                .is_some()
        );

        rollback_completed_anonymous_snapshot(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
        )
        .unwrap();

        assert_eq!(frames.free_pages(), free_before);
        assert_eq!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 0)
                .unwrap(),
            None
        );
        assert!(
            child_space
                .translate_user(
                    &child,
                    &objects,
                    child.address_space_handle(),
                    &mut backend,
                    base,
                )
                .is_err()
        );
        assert!(!child_space.is_poisoned());
    }

    #[test]
    fn unsupported_backing_fails_before_child_publication_or_allocation() {
        let (objects, parent, mut parent_space, child, mut child_space, mut backend) = setup();
        let reservations = ReservationSet::<1>::new();
        let base = USER_MIN + 0x60_000;
        parent_space
            .map_user_page(
                &parent,
                &objects,
                parent.address_space_handle(),
                &mut backend,
                Vma::new(
                    base,
                    PAGE_SIZE,
                    VmPerms::READ,
                    Backing::File {
                        object: 7,
                        offset: 0,
                    },
                )
                .unwrap(),
                PhysFrame::from_start_address(PARENT_FRAME_BASE).unwrap(),
                &reservations,
            )
            .unwrap();
        let mut frames = allocator(4);
        let free_before = frames.free_pages();
        let mut copy_calls = 0usize;

        let result = snapshot_exact_anonymous(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
            &reservations,
            |_, _, _| {
                copy_calls += 1;
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::UnsupportedBacking)));
        assert_eq!(copy_calls, 0);
        assert_eq!(frames.free_pages(), free_before);
        assert_eq!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 0)
                .unwrap(),
            None
        );
    }

    #[test]
    fn injected_mid_copy_failure_restores_empty_child_and_all_frames() {
        let (objects, parent, mut parent_space, child, mut child_space, mut backend) = setup();
        let reservations = ReservationSet::<1>::new();
        let base = USER_MIN + 0x80_000;
        for page in 0..3u64 {
            map_parent_anonymous(
                &parent,
                &mut parent_space,
                &objects,
                &mut backend,
                &reservations,
                base + page * PAGE_SIZE,
                PARENT_FRAME_BASE + page * PAGE_SIZE,
            );
            backend.set_marker(PARENT_FRAME_BASE + page * PAGE_SIZE, 0x1000 + page);
        }
        let mut frames = allocator(8);
        let free_before = frames.free_pages();
        let mut copy_calls = 0usize;

        let result = snapshot_exact_anonymous(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
            &reservations,
            |backend, source, destination| {
                copy_calls += 1;
                if copy_calls == 2 {
                    Err(Error::InjectedCopyFailure)
                } else {
                    backend.copy_marker(source, destination)
                }
            },
        );
        assert!(matches!(result, Err(Error::InjectedCopyFailure)));
        assert_eq!(copy_calls, 2);
        assert_eq!(frames.free_pages(), free_before);
        assert_eq!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 0)
                .unwrap(),
            None
        );
        assert!(
            child_space
                .translate_user(
                    &child,
                    &objects,
                    child.address_space_handle(),
                    &mut backend,
                    base,
                )
                .is_err()
        );
    }

    #[test]
    fn allocator_failure_rolls_back_published_prefix() {
        let (objects, parent, mut parent_space, child, mut child_space, mut backend) = setup();
        let reservations = ReservationSet::<1>::new();
        let base = USER_MIN + 0xa0_000;
        for page in 0..2u64 {
            map_parent_anonymous(
                &parent,
                &mut parent_space,
                &objects,
                &mut backend,
                &reservations,
                base + page * PAGE_SIZE,
                PARENT_FRAME_BASE + page * PAGE_SIZE,
            );
            backend.set_marker(PARENT_FRAME_BASE + page * PAGE_SIZE, 0x2000 + page);
        }
        let mut frames = allocator(1);
        let free_before = frames.free_pages();

        let result = snapshot_exact_anonymous(
            &parent,
            &parent_space,
            &child,
            &mut child_space,
            &objects,
            &mut backend,
            &mut frames,
            &reservations,
            |backend, source, destination| backend.copy_marker(source, destination),
        );
        assert!(matches!(result, Err(Error::Frame(FrameError::NoMemory))));
        assert_eq!(frames.free_pages(), free_before);
        assert_eq!(
            child_space
                .user_vma_at(&child, &objects, child.address_space_handle(), 0)
                .unwrap(),
            None
        );
    }
}
