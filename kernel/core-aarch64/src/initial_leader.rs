// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;

use kernal_capability::CapHandle;
use kernal_linux_exit_lifecycle::{Error as LifecycleError, ExitCoordinator};
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_object::ObjectTable;
use kernal_process::{
    Error as ProcessError, Personality, Process, ProcessState, ThreadObjectBindings,
};
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_scheduler::{Error as SchedulerCoreError, ThreadId};
use kernal_scheduler_cpu::{CpuSchedulerCell, Error as SchedulerError};
use kernal_user_elf_runtime_aarch64::LoadedImage;

use crate::clone_stack::{
    InitialUserStackError, prepare_initial_user_with_core_stack, reclaim_initial_user_core_stack,
};

/// Successful publication metadata for the first Linux thread in one Process.
///
/// The values are diagnostic/runtime lookup keys only. The actual scheduler, Process/CSpace,
/// Linux-identity and kernel-stack authorities remain owned by their existing canonical tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedInitialLinuxLeader {
    scheduler_thread: ThreadId,
    thread_handle: CapHandle,
    pid: NonZeroU32,
}

impl PublishedInitialLinuxLeader {
    pub const fn scheduler_thread(self) -> ThreadId {
        self.scheduler_thread
    }

    pub const fn thread_handle(self) -> CapHandle {
        self.thread_handle
    }

    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    pub const fn tid(self) -> NonZeroU32 {
        self.pid
    }
}

/// Failures from the initial Linux leader publication transaction.
#[derive(Debug, Eq, PartialEq)]
pub enum InitialLeaderPublishError {
    WrongPersonality,
    ProcessAddressSpace(ProcessAddressSpaceError),
    InitialContext(InitialUserStackError),
    Scheduler(SchedulerError),
    Lifecycle(LifecycleError),
    Identity(IdentityError),
    Process(ProcessError),
    Reclaim(InitialUserStackError),
    Invariant,
}

impl From<SchedulerError> for InitialLeaderPublishError {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

enum SetupOutcome {
    Ready {
        handle: CapHandle,
        pid: NonZeroU32,
    },
    Rollback {
        handle: CapHandle,
        error: InitialLeaderPublishError,
    },
    /// The failing owner could not prove that no external authority escaped. The staged scheduler
    /// generation and stack must remain quarantined rather than being reused under uncertainty.
    FatalNoCancel(InitialLeaderPublishError),
}

/// Builds and transactionally publishes the first Linux EL0 thread on the real Core scheduler.
///
/// The transaction reuses the exact protected Core stack pool used by pthread `clone`, stages the
/// canonical initial AArch64 context, attaches normal Process/CSpace Thread authority and binds the
/// Linux leader (`TID == PID`) before the scheduler generation becomes Ready+Published. No proof-only
/// RunQueue, leader-only stack pool, PID namespace or context path is introduced.
///
/// The scheduler's opaque address-space metadata is derived internally from the generation-safe
/// AddressSpace ObjectId already owned by the exact [`BoundProcessAddressSpace`]. A raw TTBR0 value or
/// caller-selected scalar is never accepted as that identity. Architectural TTBR0 activation remains
/// the separate responsibility of the existing Process/address-space owner before the scheduler is
/// allowed to select this newly published userspace generation.
///
/// If Linux identity setup or final scheduler publication fails in a state that still proves exact
/// Blocked+Staged ownership, rollback is ordered strictly as:
///
/// 1. consume a fresh scheduler-owned staged proof and remove Process/CSpace Thread authority;
/// 2. exit the now-threadless Process and retire its bounded Linux identity records;
/// 3. cancel/reap the exact staged scheduler generation;
/// 4. return the exact kernel stack to the shared protected Core pool.
///
/// Any failure that cannot prove those prerequisites returns without cancellation or stack reuse.
/// This intentionally leaks/quarantines the generation on an invariant failure rather than allowing
/// stale Process/TID authority to alias a recycled scheduler slot or stack.
///
/// # Safety
/// The caller must execute on `scheduler`'s owner CPU/PE with local IRQ delivery masked,
/// `irq_depth=0`, `preempt_count=0` and migration suppressed for the whole call. `process` and
/// `address_space` must remain the exact live Linux Process/binding pair, and the supplied owner tables
/// must remain exclusive for the complete transaction. The scheduler must not select the published
/// generation until the caller activates this same bound address space through the accepted
/// Process/TTBR0 owner path. On rollback success the Process is Exited and `address_space` must no
/// longer be used as live authority by the caller.
#[allow(clippy::too_many_arguments)]
pub unsafe fn publish_initial_linux_leader_with_core_stack<
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
    loaded: LoadedImage,
    process: &mut Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    exits: &ExitCoordinator<GROUPS>,
    scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    priority: u8,
) -> Result<PublishedInitialLinuxLeader, InitialLeaderPublishError> {
    let scheduler_address_space = validated_address_space_token(process, address_space)?;

    let prepared = prepare_initial_user_with_core_stack(loaded)
        .map_err(InitialLeaderPublishError::InitialContext)?;
    let prepared_stack = prepared.stack();

    // SAFETY: delegated owner-quiescence contract; the prepared context is canonical and unpublished.
    let staged = match unsafe {
        scheduler.bootstrap_create_staged_user_thread(
            priority,
            prepared.saved_sp(),
            prepared_stack,
            scheduler_address_space,
            prepared.user_thread_pointer(),
            None,
        )
    } {
        Ok(staged) => staged,
        Err(error) => {
            if scheduler_creation_error_releases_stack(&error) {
                // SAFETY: this error class proves the scheduler owns no live/staged generation for
                // `prepared_stack`; the exact claim can therefore return to the shared pool.
                unsafe { reclaim_initial_user_core_stack(prepared_stack) }
                    .map_err(InitialLeaderPublishError::Reclaim)?;
            }
            return Err(InitialLeaderPublishError::Scheduler(error));
        }
    };

    // SAFETY: the exact child remains Blocked+Staged under uninterrupted scheduler-owner quiescence.
    let setup = unsafe {
        scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
            let global = proof.thread();
            if global.cpu != owner || global.local != staged {
                return Ok::<_, InitialLeaderPublishError>(SetupOutcome::FatalNoCancel(
                    InitialLeaderPublishError::Invariant,
                ));
            }

            let handle =
                match exits.attach_thread(process, objects, bindings, run_queue, owner, global) {
                    Ok(handle) => handle,
                    Err(error) => {
                        // An unclassified Process/CSpace attach failure may include a failed internal
                        // rollback. Do not infer cancellation authority merely from an error return.
                        return Ok(SetupOutcome::FatalNoCancel(
                            InitialLeaderPublishError::Lifecycle(error),
                        ));
                    }
                };

            match identities.bind_leader(process, objects, bindings, run_queue, owner, handle) {
                Ok(pid) => Ok(SetupOutcome::Ready { handle, pid }),
                Err(error) => Ok(SetupOutcome::Rollback {
                    handle,
                    error: InitialLeaderPublishError::Identity(error),
                }),
            }
        })
    }?;

    let (handle, pid) = match setup {
        SetupOutcome::Ready { handle, pid } => (handle, pid),
        SetupOutcome::Rollback { handle, error } => {
            // SAFETY: setup never published the generation; the delegated owner window is unchanged.
            unsafe {
                rollback_initial_linux_leader(
                    staged, process, objects, bindings, identities, scheduler, handle,
                )
            }?;
            return Err(error);
        }
        SetupOutcome::FatalNoCancel(error) => return Err(error),
    };

    // SAFETY: all external Process/CSpace/Linux identity setup is complete while the exact generation
    // is still Blocked+Staged, and no user-visible commit remains after this publication boundary.
    match unsafe { scheduler.bootstrap_publish_staged_ready(staged) } {
        Ok(()) => Ok(PublishedInitialLinuxLeader {
            scheduler_thread: staged,
            thread_handle: handle,
            pid,
        }),
        Err(error) if scheduler_publish_error_allows_rollback(&error) => {
            // SAFETY: this error class guarantees exact Blocked+Staged state was retained/restored.
            unsafe {
                rollback_initial_linux_leader(
                    staged, process, objects, bindings, identities, scheduler, handle,
                )
            }?;
            Err(InitialLeaderPublishError::Scheduler(error))
        }
        Err(error) => Err(InitialLeaderPublishError::Scheduler(error)),
    }
}

fn validated_address_space_token<const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
) -> Result<u64, InitialLeaderPublishError> {
    if process.personality() != Personality::Linux {
        return Err(InitialLeaderPublishError::WrongPersonality);
    }
    if process.state() != ProcessState::Live {
        return Err(InitialLeaderPublishError::ProcessAddressSpace(
            ProcessAddressSpaceError::InactiveProcess,
        ));
    }
    if address_space.is_poisoned() {
        return Err(InitialLeaderPublishError::ProcessAddressSpace(
            ProcessAddressSpaceError::Poisoned,
        ));
    }
    if address_space.owner_process() != process.id() {
        return Err(InitialLeaderPublishError::ProcessAddressSpace(
            ProcessAddressSpaceError::WrongProcess,
        ));
    }
    if address_space.address_space_object() != process.address_space() {
        return Err(InitialLeaderPublishError::ProcessAddressSpace(
            ProcessAddressSpaceError::WrongAddressSpace,
        ));
    }
    let token = address_space.address_space_object().0;
    if token == 0 {
        return Err(InitialLeaderPublishError::Invariant);
    }
    Ok(token)
}

#[allow(clippy::too_many_arguments)]
unsafe fn rollback_initial_linux_leader<
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const PROCESSES: usize,
    const IDS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
>(
    staged: ThreadId,
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    handle: CapHandle,
) -> Result<(), InitialLeaderPublishError> {
    // SAFETY: caller guarantees exact Blocked+Staged state and uninterrupted owner quiescence. The
    // fresh proof is consumed by the canonical Process rollback before scheduler cancellation.
    unsafe {
        scheduler.bootstrap_with_staged_thread(staged, |run_queue, owner, proof| {
            process
                .rollback_staged_thread(objects, bindings, run_queue, owner, proof, handle)
                .map(|_| ())
                .map_err(InitialLeaderPublishError::Process)
        })
    }?;

    // Only after Process/CSpace Thread authority is gone may the whole failed initial process be
    // retired. This also gives the Linux identity owner a legitimate Process::Exited proof point for
    // removing any PID/leader records that bind_leader created before a later failure.
    process
        .exit(objects, bindings)
        .map_err(InitialLeaderPublishError::Process)?;
    identities
        .retire_process(process)
        .map_err(InitialLeaderPublishError::Identity)?;

    // SAFETY: all external authority referring to `staged` is now gone; canonical cancellation owns
    // the exact scheduler generation and returns its exact stack metadata before pool reuse.
    let stack = unsafe { scheduler.bootstrap_cancel_staged(staged) }
        .map_err(InitialLeaderPublishError::Scheduler)?;
    // SAFETY: `stack` is the exact allocation returned by generation-safe scheduler cancellation.
    unsafe { reclaim_initial_user_core_stack(stack) }.map_err(InitialLeaderPublishError::Reclaim)
}

fn scheduler_creation_error_releases_stack(error: &SchedulerError) -> bool {
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

fn scheduler_publish_error_allows_rollback(error: &SchedulerError) -> bool {
    matches!(
        error,
        SchedulerError::Scheduler(_) | SchedulerError::Context(_)
    )
}
