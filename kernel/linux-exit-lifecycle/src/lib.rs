// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]

use core::num::NonZeroU32;
use kernal_capability::{CapHandle, ObjectId};
use kernal_linux_bootstrap::{ExitRequest, ExitScope};
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{
    Error as ProcessError, Personality, Process, ProcessState, ThreadObjectBindings,
};
use kernal_scheduler::RunQueue;
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitCause {
    Exited(u8),
    Signaled { signal: u8, core_dumped: bool },
}

impl ExitCause {
    pub const fn exited(status: u8) -> Self {
        Self::Exited(status)
    }

    pub fn signaled(signal: u8, core_dumped: bool) -> Result<Self, Error> {
        if signal == 0 || signal > 127 {
            return Err(Error::InvalidSignal);
        }
        Ok(Self::Signaled {
            signal,
            core_dumped,
        })
    }

    const fn legacy_status(self) -> u8 {
        match self {
            Self::Exited(status) => status,
            Self::Signaled { signal, .. } => signal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GroupExitState {
    process: ObjectId,
    cause: ExitCause,
}

/// Generation-bound exit intent which runtime code must retain outside the exiting thread context.
///
/// Tickets are created only by [`ExitCoordinator::begin_exit`] or
/// [`ExitCoordinator::group_ticket`]. For `exit_group`, the authoritative status lives in the
/// coordinator and is keyed by the exact generation-safe Process [`ObjectId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitTicket {
    process: ObjectId,
    scope: ExitScope,
    status: u8,
    cause: ExitCause,
}

impl ExitTicket {
    pub const fn process(self) -> ObjectId {
        self.process
    }

    pub const fn scope(self) -> ExitScope {
        self.scope
    }

    pub const fn status(self) -> u8 {
        self.status
    }

    pub const fn cause(self) -> ExitCause {
        self.cause
    }
}

/// Fixed-capacity Step-14 lifecycle owner state.
///
/// `exit_group` must become persistent before the calling thread performs its non-returning
/// scheduler exit. This table keeps that state outside any thread stack and keys it by the exact
/// Process generation. Step-14 runtime code must route Linux thread publication through
/// [`attach_thread`](Self::attach_thread), which rejects new authority once group exit begins.
pub struct ExitCoordinator<const N: usize> {
    groups: [Option<GroupExitState>; N],
}

impl<const N: usize> ExitCoordinator<N> {
    pub const fn new() -> Self {
        Self { groups: [None; N] }
    }

    /// Persists one exit intent before the caller leaves its current thread context.
    ///
    /// A normal thread exit does not create process-wide state. A group exit records the first
    /// status for this exact Process generation; retries with the same status are idempotent, while
    /// later attempts to substitute a different status fail closed.
    pub fn begin_exit<const CAPS: usize>(
        &mut self,
        request: ExitRequest,
        process: &Process<CAPS>,
    ) -> Result<ExitTicket, Error> {
        self.begin_cause(request.scope, ExitCause::Exited(request.status), process)
    }

    /// Persists a fatal Linux signal as a process-wide exit cause before the current thread leaves
    /// its scheduler context. Signal termination is group-wide: any older in-flight Thread ticket is
    /// promoted to this exact persisted cause during finalization.
    pub fn begin_signal_termination<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        signal: u8,
        core_dumped: bool,
    ) -> Result<ExitTicket, Error> {
        let cause = ExitCause::signaled(signal, core_dumped)?;
        self.begin_cause(ExitScope::ThreadGroup, cause, process)
    }

    fn begin_cause<const CAPS: usize>(
        &mut self,
        scope: ExitScope,
        cause: ExitCause,
        process: &Process<CAPS>,
    ) -> Result<ExitTicket, Error> {
        self.validate_process(process)?;
        match scope {
            ExitScope::Thread => {
                if self.group_state(process.id()).is_some() {
                    return Err(Error::GroupExitDraining);
                }
                Ok(ExitTicket {
                    process: process.id(),
                    scope,
                    status: cause.legacy_status(),
                    cause,
                })
            }
            ExitScope::ThreadGroup => {
                if let Some(existing) = self.group_state(process.id()) {
                    if existing.cause != cause {
                        return Err(Error::ExitRequestMismatch);
                    }
                    return Ok(ExitTicket {
                        process: existing.process,
                        scope,
                        status: existing.cause.legacy_status(),
                        cause: existing.cause,
                    });
                }
                let slot = self
                    .groups
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::GroupStateCapacity)?;
                self.groups[slot] = Some(GroupExitState {
                    process: process.id(),
                    cause,
                });
                Ok(ExitTicket {
                    process: process.id(),
                    scope,
                    status: cause.legacy_status(),
                    cause,
                })
            }
        }
    }

    /// Returns the already-persisted group-exit ticket used to drain another surviving member.
    pub fn group_ticket<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
    ) -> Result<ExitTicket, Error> {
        self.validate_process(process)?;
        let state = self
            .group_state(process.id())
            .ok_or(Error::GroupExitNotStarted)?;
        Ok(ExitTicket {
            process: state.process,
            scope: ExitScope::ThreadGroup,
            status: state.cause.legacy_status(),
            cause: state.cause,
        })
    }

    /// Step-14 thread publication path. Once this exact Process generation enters `exit_group`, no
    /// new Thread object/capability may be published into it.
    pub fn attach_thread<
        const CAPS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
        const THREADS: usize,
    >(
        &self,
        process: &mut Process<CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        scheduler_thread: GlobalThreadId,
    ) -> Result<CapHandle, Error> {
        self.validate_process(process)?;
        if self.group_state(process.id()).is_some() {
            return Err(Error::GroupExitDraining);
        }
        Ok(process.attach_thread(
            objects,
            bindings,
            scheduler,
            scheduler_owner,
            scheduler_thread,
        )?)
    }

    pub fn is_group_draining<const CAPS: usize>(&self, process: &Process<CAPS>) -> bool {
        self.group_state(process.id()).is_some()
    }

    fn validate_process<const CAPS: usize>(&self, process: &Process<CAPS>) -> Result<(), Error> {
        if process.personality() != Personality::Linux {
            return Err(Error::WrongPersonality);
        }
        if process.state() != ProcessState::Live {
            return Err(Error::Process(ProcessError::Exited));
        }
        Ok(())
    }

    /// Resolves the lifecycle intent which is authoritative at finalization time.
    ///
    /// A normal thread-exit ticket can legitimately predate a later process-wide `exit_group`.
    /// Once the group transition is persistent, that group state dominates cleanup of every member,
    /// including a thread that has already completed scheduler reap but has not yet released its
    /// Process-owned authority. Promoting the old same-generation Thread ticket here prevents the
    /// finalizer from rejecting that legitimate in-flight cleanup and stranding its one-shot reap
    /// attestation. A ThreadGroup ticket must still carry the persisted group status exactly.
    fn resolve_ticket<const CAPS: usize>(
        &self,
        ticket: ExitTicket,
        process: &Process<CAPS>,
    ) -> Result<ExitTicket, Error> {
        self.validate_process(process)?;
        if ticket.process != process.id() {
            return Err(Error::StaleProcess);
        }

        match self.group_state(process.id()) {
            Some(state) => match ticket.scope {
                ExitScope::Thread => Ok(ExitTicket {
                    process: state.process,
                    scope: ExitScope::ThreadGroup,
                    status: state.cause.legacy_status(),
                    cause: state.cause,
                }),
                ExitScope::ThreadGroup if ticket.cause == state.cause => Ok(ExitTicket {
                    process: state.process,
                    scope: ExitScope::ThreadGroup,
                    status: state.cause.legacy_status(),
                    cause: state.cause,
                }),
                ExitScope::ThreadGroup => Err(Error::ExitRequestMismatch),
            },
            None if ticket.scope == ExitScope::ThreadGroup => Err(Error::GroupExitNotStarted),
            None => Ok(ticket),
        }
    }

    fn group_state(&self, process: ObjectId) -> Option<GroupExitState> {
        self.groups
            .iter()
            .flatten()
            .copied()
            .find(|state| state.process == process)
    }

    fn clear_group(&mut self, process: ObjectId) {
        if let Some(index) = self
            .groups
            .iter()
            .position(|state| state.is_some_and(|state| state.process == process))
        {
            self.groups[index] = None;
        }
    }
}

impl<const N: usize> Default for ExitCoordinator<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Completion state after one exact scheduler generation has already completed
/// `exit -> teardown -> reap` and its process-owned Thread authority is released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    ThreadExited {
        thread: GlobalThreadId,
        status: u8,
    },
    ThreadGroupDraining {
        thread: GlobalThreadId,
        status: u8,
    },
    ProcessExited {
        thread: GlobalThreadId,
        scope: ExitScope,
        status: u8,
    },
}

impl Completion {
    pub const fn thread(self) -> GlobalThreadId {
        match self {
            Self::ThreadExited { thread, .. }
            | Self::ThreadGroupDraining { thread, .. }
            | Self::ProcessExited { thread, .. } => thread,
        }
    }
}

/// Identity-neutral lifecycle completion produced by the same ticket-resolution linearization that
/// releases the exact process-owned Thread authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleCompletion {
    completion: Completion,
    cause: ExitCause,
}

impl LifecycleCompletion {
    pub const fn completion(self) -> Completion {
        self.completion
    }

    pub const fn cause(self) -> ExitCause {
        self.cause
    }
}

/// Completion metadata for one non-leader Linux thread whose bounded TID slot was also retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadIdentityCompletion {
    completion: Completion,
    linux_tid: NonZeroU32,
    cause: ExitCause,
}

impl ThreadIdentityCompletion {
    pub const fn completion(self) -> Completion {
        self.completion
    }

    pub const fn linux_tid(self) -> NonZeroU32 {
        self.linux_tid
    }

    pub const fn cause(self) -> ExitCause {
        self.cause
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    WrongPersonality,
    GroupStateCapacity,
    GroupExitDraining,
    GroupExitNotStarted,
    ExitRequestMismatch,
    InvalidSignal,
    StaleProcess,
    Process(ProcessError),
    Identity(IdentityError),
}

impl From<ProcessError> for Error {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}

impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

/// Finalizes one Linux thread after scheduler-owner code has produced an exact reap proof and returns
/// the lifecycle-resolved exit cause from the same owner linearization.
pub fn finalize_reaped_thread_with_cause<
    const GROUPS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
>(
    ticket: ExitTicket,
    coordinator: &mut ExitCoordinator<GROUPS>,
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    proof: ReapedThreadProof,
    thread_handle: CapHandle,
) -> Result<LifecycleCompletion, Error> {
    let ticket = coordinator.resolve_ticket(ticket, process)?;
    let cause = ticket.cause();
    let released = process.release_reaped_thread(objects, bindings, proof, thread_handle)?;
    let completion =
        complete_released_thread(ticket, coordinator, process, objects, bindings, released)?;
    Ok(LifecycleCompletion { completion, cause })
}

/// Finalizes one Linux thread after scheduler-owner code has produced an exact reap proof.
///
/// Runtime code must call [`ExitCoordinator::begin_exit`] before the accepted non-returning current
/// thread switch, retain the returned ticket outside that thread context, then obtain the exact
/// [`ReapedThreadProof`] from the Step-11 owner path. This finalizer never manipulates a RunQueue,
/// switches contexts, tears down stacks, or manufactures a reap proof.
///
/// An in-flight normal Thread ticket is promoted to the persisted group state if `exit_group`
/// became active after that thread began exiting. This ensures group exit dominates the remaining
/// cleanup without rejecting an already-reaped generation. ThreadGroup tickets still have to match
/// the persisted status exactly. Every survivor uses [`ExitCoordinator::group_ticket`] and traverses
/// the same owner-checked exit -> teardown -> reap path. Group state is removed only after normal
/// [`Process::exit`] succeeds for the final member.
pub fn finalize_reaped_thread<
    const GROUPS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
>(
    ticket: ExitTicket,
    coordinator: &mut ExitCoordinator<GROUPS>,
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    proof: ReapedThreadProof,
    thread_handle: CapHandle,
) -> Result<Completion, Error> {
    Ok(finalize_reaped_thread_with_cause(
        ticket,
        coordinator,
        process,
        objects,
        bindings,
        proof,
        thread_handle,
    )?
    .completion())
}

/// Finalizes one reaped non-leader pthread and retires its bounded Linux TID record in the same
/// proof-carrying owner chain.
///
/// The caller supplies no scalar TID and no process-local thread handle. The Linux identity owner
/// borrows the exact [`ReapedThreadProof`] to resolve the canonical stored root, then consumes that
/// same proof through Process/CSpace teardown before removing the exact TID record. Only after this
/// function succeeds may a caller return the scheduler-provided kernel stack to a reusable pool.
///
/// Process-leader PID/TID state is intentionally outside this function. A leader is finalized through
/// [`finalize_reaped_thread`], and the whole identity registry is retired only after Process exit.
pub fn finalize_reaped_thread_with_identity<
    const GROUPS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
    const PROCESSES: usize,
    const IDS: usize,
>(
    ticket: ExitTicket,
    coordinator: &mut ExitCoordinator<GROUPS>,
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &mut ThreadObjectBindings<BINDINGS>,
    identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
    proof: ReapedThreadProof,
) -> Result<ThreadIdentityCompletion, Error> {
    let ticket = coordinator.resolve_ticket(ticket, process)?;
    let cause = ticket.cause();
    let retired = identities.release_reaped_thread_identity(process, objects, bindings, proof)?;
    let linux_tid = retired.linux_tid();
    let completion = complete_released_thread(
        ticket,
        coordinator,
        process,
        objects,
        bindings,
        retired.scheduler_thread(),
    )?;

    Ok(ThreadIdentityCompletion {
        completion,
        linux_tid,
        cause,
    })
}

fn complete_released_thread<
    const GROUPS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const BINDINGS: usize,
>(
    ticket: ExitTicket,
    coordinator: &mut ExitCoordinator<GROUPS>,
    process: &mut Process<CAPS>,
    objects: &mut ObjectTable<OBJECTS>,
    bindings: &ThreadObjectBindings<BINDINGS>,
    released: GlobalThreadId,
) -> Result<Completion, Error> {
    match process.exit(objects, bindings) {
        Ok(()) => {
            if ticket.scope == ExitScope::ThreadGroup {
                coordinator.clear_group(ticket.process);
            }
            Ok(Completion::ProcessExited {
                thread: released,
                scope: ticket.scope,
                status: ticket.status,
            })
        }
        Err(ProcessError::ThreadsRemain) => match ticket.scope {
            ExitScope::Thread => Ok(Completion::ThreadExited {
                thread: released,
                status: ticket.status,
            }),
            ExitScope::ThreadGroup => Ok(Completion::ThreadGroupDraining {
                thread: released,
                status: ticket.status,
            }),
        },
        Err(error) => Err(Error::Process(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_process::{ProcessState, ThreadBindingError};
    use kernal_scheduler::ThreadId;

    const CPU0: CpuIndex = CpuIndex(0);

    fn global(local: ThreadId) -> GlobalThreadId {
        GlobalThreadId::new(CPU0, local)
    }

    unsafe fn reaped(local: ThreadId) -> ReapedThreadProof {
        // SAFETY: callers invoke this helper only immediately after the test RunQueue reaps `local`.
        unsafe { ReapedThreadProof::new_unchecked(global(local)) }
    }

    fn attach<
        const CAPS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
        const THREADS: usize,
    >(
        process: &mut Process<CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        scheduler: &mut RunQueue<THREADS>,
    ) -> (ThreadId, CapHandle) {
        let local = scheduler.create(10).unwrap();
        let handle = process
            .attach_thread(objects, bindings, scheduler, CPU0, global(local))
            .unwrap();
        scheduler.make_ready(local).unwrap();
        (local, handle)
    }

    #[test]
    fn signal_termination_is_validated_and_persisted_as_group_cause() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut exits = ExitCoordinator::<2>::new();
        assert_eq!(
            exits.begin_signal_termination(&process, 0, false),
            Err(Error::InvalidSignal)
        );
        let ticket = exits.begin_signal_termination(&process, 11, true).unwrap();
        assert_eq!(ticket.scope(), ExitScope::ThreadGroup);
        assert_eq!(ticket.status(), 11);
        assert_eq!(
            ticket.cause(),
            ExitCause::Signaled {
                signal: 11,
                core_dumped: true,
            }
        );
        assert_eq!(
            exits.group_ticket(&process).unwrap().cause(),
            ticket.cause()
        );
    }

    #[test]
    fn persisted_signal_group_cause_promotes_older_thread_ticket() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut exits = ExitCoordinator::<2>::new();
        let ordinary = exits
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 7,
                },
                &process,
            )
            .unwrap();
        exits.begin_signal_termination(&process, 15, false).unwrap();
        let promoted = exits.resolve_ticket(ordinary, &process).unwrap();
        assert_eq!(promoted.scope(), ExitScope::ThreadGroup);
        assert_eq!(
            promoted.cause(),
            ExitCause::Signaled {
                signal: 15,
                core_dumped: false,
            }
        );
    }

    #[test]
    fn conflicting_group_exit_causes_fail_closed() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut exits = ExitCoordinator::<2>::new();
        exits.begin_signal_termination(&process, 9, false).unwrap();
        assert_eq!(
            exits.begin_signal_termination(&process, 15, false),
            Err(Error::ExitRequestMismatch)
        );
    }

    #[test]
    fn single_thread_exit_reaches_normal_process_teardown() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (thread, handle) = attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 37,
                },
                &process,
            )
            .unwrap();

        assert_eq!(scheduler.schedule().unwrap(), Some(thread));
        scheduler.exit(thread).unwrap();
        scheduler.reap(thread).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let proof = unsafe { reaped(thread) };

        assert_eq!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                proof,
                handle,
            )
            .unwrap(),
            Completion::ProcessExited {
                thread: global(thread),
                scope: ExitScope::Thread,
                status: 37,
            }
        );
        assert_eq!(process.state(), ProcessState::Exited);
    }

    #[test]
    fn thread_exit_keeps_process_live_while_another_thread_remains() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (first, first_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (_second, _second_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 9,
                },
                &process,
            )
            .unwrap();

        assert_eq!(scheduler.schedule().unwrap(), Some(first));
        scheduler.exit(first).unwrap();
        scheduler.reap(first).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let proof = unsafe { reaped(first) };

        assert_eq!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                proof,
                first_handle,
            )
            .unwrap(),
            Completion::ThreadExited {
                thread: global(first),
                status: 9,
            }
        );
        assert_eq!(process.state(), ProcessState::Live);
        assert_eq!(
            process.exit(&mut objects, &bindings),
            Err(ProcessError::ThreadsRemain)
        );
    }

    #[test]
    fn reaped_worker_identity_finalizer_reclaims_capacity_without_tid_reuse() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (_leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (worker, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<2, 2>::new();
        identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();
        let worker_tid = identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            )
            .unwrap();
        let ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 17,
                },
                &process,
            )
            .unwrap();

        scheduler.exit(worker).unwrap();
        scheduler.reap(worker).unwrap();
        // SAFETY: the exact worker generation was reaped immediately above.
        let finalized = finalize_reaped_thread_with_identity(
            ticket,
            &mut coordinator,
            &mut process,
            &mut objects,
            &mut bindings,
            &mut identities,
            unsafe { reaped(worker) },
        )
        .unwrap();
        assert_eq!(
            finalized.completion(),
            Completion::ThreadExited {
                thread: global(worker),
                status: 17,
            }
        );
        assert_eq!(finalized.linux_tid(), worker_tid);
        assert_eq!(process.state(), ProcessState::Live);
        assert_eq!(bindings.len(), 1);

        let (_replacement, replacement_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let replacement_tid = identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                replacement_handle,
            )
            .unwrap();
        assert_eq!(replacement_tid.get(), 3);
        assert_ne!(replacement_tid, worker_tid);
    }

    #[test]
    fn exit_group_persists_status_blocks_new_authority_and_drains_all_members() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<6>::new();
        let mut scheduler = RunQueue::<6>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let original_process = process.id();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (first, first_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (second, second_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::ThreadGroup,
                    status: 0xa5,
                },
                &process,
            )
            .unwrap();

        let extra = scheduler.create(10).unwrap();
        assert_eq!(
            coordinator.attach_thread(
                &mut process,
                &mut objects,
                &mut bindings,
                &scheduler,
                CPU0,
                global(extra),
            ),
            Err(Error::GroupExitDraining)
        );
        assert_eq!(bindings.len(), 2);
        assert_eq!(
            coordinator.begin_exit(
                ExitRequest {
                    scope: ExitScope::ThreadGroup,
                    status: 0x11,
                },
                &process,
            ),
            Err(Error::ExitRequestMismatch)
        );
        assert_eq!(
            coordinator.begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 0x22,
                },
                &process,
            ),
            Err(Error::GroupExitDraining)
        );

        assert_eq!(scheduler.schedule().unwrap(), Some(first));
        scheduler.exit(first).unwrap();
        scheduler.reap(first).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let first_proof = unsafe { reaped(first) };
        assert_eq!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                first_proof,
                first_handle,
            )
            .unwrap(),
            Completion::ThreadGroupDraining {
                thread: global(first),
                status: 0xa5,
            }
        );
        assert_eq!(process.state(), ProcessState::Live);
        assert!(coordinator.is_group_draining(&process));

        assert_eq!(scheduler.schedule().unwrap(), Some(second));
        scheduler.exit(second).unwrap();
        scheduler.reap(second).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let second_proof = unsafe { reaped(second) };
        let substituted = ExitTicket {
            process: process.id(),
            scope: ExitScope::ThreadGroup,
            status: 1,

            cause: ExitCause::Exited(1),
        };
        assert_eq!(
            finalize_reaped_thread(
                substituted,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                second_proof,
                second_handle,
            ),
            Err(Error::ExitRequestMismatch)
        );

        // The rejected ticket did not revoke the second thread's authority. In production an invalid
        // ThreadGroup ticket cannot be constructed through the public coordinator API; the unsafe
        // test helper recreates the already-reaped proof so we can verify the canonical ticket path.
        let canonical = coordinator.group_ticket(&process).unwrap();
        // SAFETY: the exact second generation was reaped above and the rejected test-only ticket did
        // not consume its process authority.
        let second_proof = unsafe { reaped(second) };
        assert_eq!(
            finalize_reaped_thread(
                canonical,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                second_proof,
                second_handle,
            )
            .unwrap(),
            Completion::ProcessExited {
                thread: global(second),
                scope: ExitScope::ThreadGroup,
                status: 0xa5,
            }
        );
        assert_eq!(process.state(), ProcessState::Exited);
        assert!(!coordinator.is_group_draining(&process));

        let replacement = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        assert_ne!(replacement.id(), original_process);
        assert!(!coordinator.is_group_draining(&replacement));
    }

    #[test]
    fn in_flight_thread_exit_is_promoted_if_group_exit_begins_after_reap() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<6>::new();
        let mut scheduler = RunQueue::<6>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (first, first_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (second, second_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);

        let old_thread_ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 0x11,
                },
                &process,
            )
            .unwrap();
        assert_eq!(scheduler.schedule().unwrap(), Some(first));
        scheduler.exit(first).unwrap();
        scheduler.reap(first).unwrap();
        // SAFETY: the exact first generation was reaped immediately above, but its Process-owned
        // authority has intentionally not been released yet.
        let first_proof = unsafe { reaped(first) };

        let group_ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::ThreadGroup,
                    status: 0xa5,
                },
                &process,
            )
            .unwrap();

        assert_eq!(
            finalize_reaped_thread(
                old_thread_ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                first_proof,
                first_handle,
            )
            .unwrap(),
            Completion::ThreadGroupDraining {
                thread: global(first),
                status: 0xa5,
            }
        );
        assert_eq!(bindings.len(), 1);
        assert!(coordinator.is_group_draining(&process));

        assert_eq!(scheduler.schedule().unwrap(), Some(second));
        scheduler.exit(second).unwrap();
        scheduler.reap(second).unwrap();
        // SAFETY: the exact second generation was reaped immediately above.
        let second_proof = unsafe { reaped(second) };
        assert_eq!(
            finalize_reaped_thread(
                group_ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                second_proof,
                second_handle,
            )
            .unwrap(),
            Completion::ProcessExited {
                thread: global(second),
                scope: ExitScope::ThreadGroup,
                status: 0xa5,
            }
        );
        assert_eq!(process.state(), ProcessState::Exited);
    }

    #[test]
    fn wrong_reap_proof_cannot_revoke_thread_authority() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (first, first_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (second, _second_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let ticket = coordinator
            .begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 1,
                },
                &process,
            )
            .unwrap();

        assert_eq!(scheduler.schedule().unwrap(), Some(first));
        scheduler.exit(first).unwrap();
        scheduler.reap(first).unwrap();
        // SAFETY: intentionally forge a proof for a different live generation to exercise the
        // fail-closed Process binding check; production cannot construct this token directly.
        let wrong = unsafe { ReapedThreadProof::new_unchecked(global(second)) };
        assert_eq!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                wrong,
                first_handle,
            ),
            Err(Error::Process(ProcessError::ThreadBinding(
                ThreadBindingError::WrongReapProof,
            )))
        );

        // SAFETY: the exact first generation was reaped above and the failed proof consumed nothing.
        let correct = unsafe { reaped(first) };
        assert!(matches!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                correct,
                first_handle,
            ),
            Ok(Completion::ThreadExited { .. })
        ));
    }

    #[test]
    fn native_and_stale_processes_cannot_enter_linux_exit_owner() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut coordinator = ExitCoordinator::<4>::new();
        let (thread, handle) = attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        assert_eq!(
            coordinator.begin_exit(
                ExitRequest {
                    scope: ExitScope::Thread,
                    status: 0,
                },
                &process,
            ),
            Err(Error::WrongPersonality)
        );

        assert_eq!(scheduler.schedule().unwrap(), Some(thread));
        scheduler.exit(thread).unwrap();
        scheduler.reap(thread).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let proof = unsafe { reaped(thread) };
        let ticket = ExitTicket {
            process: process.id(),
            scope: ExitScope::Thread,
            status: 0,

            cause: ExitCause::Exited(0),
        };
        assert_eq!(
            finalize_reaped_thread(
                ticket,
                &mut coordinator,
                &mut process,
                &mut objects,
                &mut bindings,
                proof,
                handle,
            ),
            Err(Error::WrongPersonality)
        );
        assert_eq!(process.state(), ProcessState::Live);
    }
}
