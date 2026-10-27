// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_linux_bootstrap::{ExitRequest, ExitScope};
use kernal_linux_credentials::{CredentialTable, Error as CredentialError, LinuxCredentials};
use kernal_linux_exit_lifecycle::{ExitCoordinator, ExitTicket};
use kernal_linux_identity::{Error as LinuxIdentityError, LinuxIdentityTable};
use kernal_linux_signal::{Error as SignalError, SignalSet, SignalTable};
use kernal_linux_vm::LinuxVmRuntime;
use kernal_linux_wait::{
    ChildExitPublication, WaitCommitOutcome, WaitObservation, WaitOptions, WaitOutcome,
    WaitPrepareOutcome, WaitSelector, WaitSleepReceipt, WaitStatus, WaitTable, WaitWakeBatch,
};
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::{Personality, Process, ProcessState, ThreadObjectBindings};
use kernal_process_aarch64::BoundProcessAddressSpace;
#[cfg(test)]
use kernal_scheduler::ThreadId;
use kernal_scheduler_smp::GlobalThreadId;

pub const STEP15_RUNTIME_CAPS: usize = 32;
pub const STEP15_RUNTIME_OBJECTS: usize = 32;
pub const STEP15_RUNTIME_VMAS: usize = 64;
pub const STEP15_RUNTIME_THREADS: usize = 16;
/// Fixed process capacity for the Step-30 shell lifecycle. Four concurrent Process generations keep
/// the 32-object budget below saturation even when all sixteen thread-object slots are populated.
pub const STEP15_RUNTIME_PROCESSES: usize = 4;
const STEP15_RUNTIME_ADDITIONAL_PROCESSES: usize = STEP15_RUNTIME_PROCESSES - 1;
pub const STEP15_RUNTIME_GROUPS: usize = STEP15_RUNTIME_PROCESSES;
pub const STEP15_RUNTIME_SIGNAL_PENDING: usize = 64;
pub const STEP15_RUNTIME_VM_BREAKS: usize = STEP15_RUNTIME_PROCESSES;
pub const STEP15_RUNTIME_VM_TX_PAGES: usize = STEP15_RUNTIME_VMAS;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;
const BORROWED: u8 = 3;
const POISONED: u8 = 4;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Process(kernal_process::Error),
    AddressSpace(kernal_process_aarch64::Error),
    Credentials(kernal_linux_credentials::Error),
    Signal(kernal_linux_signal::Error),
    Wait(kernal_linux_wait::Error),
    Exit(kernal_linux_exit_lifecycle::Error),
    AlreadyInitialized,
    Unavailable,
    Busy,
    Poisoned,
    InvalidState,
    ProcessSlotsFull,
}

/// One additional Linux Process together with the exact architecture-specific AddressSpace owner.
///
/// The slot owns both values. An ObjectId may select a slot only after the canonical Linux identity
/// owner observed that exact Process generation; ObjectId itself never becomes Process authority.
struct RuntimeProcessSlot {
    process: Process<STEP15_RUNTIME_CAPS>,
    address_space: BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    /// Linear Wait publication authority retained only after the fork transaction has transferred
    /// it into this exact Process generation. None means the slot is still unpublished/rollbackable.
    wait_publication: Option<ChildExitPublication>,
}

impl RuntimeProcessSlot {
    fn validate(
        process: &Process<STEP15_RUNTIME_CAPS>,
        address_space: &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    ) -> Result<(), Error> {
        if process.personality() != Personality::Linux
            || address_space.owner_process() != process.id()
            || address_space.address_space_object() != process.address_space()
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }
}

/// Persistent owner for the initial Step-15 Linux process plus bounded Step-30 child processes.
///
/// Slot 0 remains the exact initial Process/AddressSpace pair so accepted Step-15 loader/VM callers
/// remain source-compatible. Additional slots own real Process and BoundProcessAddressSpace values;
/// no PID/TID/ObjectId-only pseudo-owner is introduced. The canonical LinuxIdentityTable remains the
/// sole scheduler-generation -> Process relationship owner.
pub struct Step15LinuxRuntime {
    objects: ObjectTable<STEP15_RUNTIME_OBJECTS>,
    process: Process<STEP15_RUNTIME_CAPS>,
    address_space: BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    additional_processes: [Option<RuntimeProcessSlot>; STEP15_RUNTIME_ADDITIONAL_PROCESSES],
    bindings: ThreadObjectBindings<STEP15_RUNTIME_THREADS>,
    identities: LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
    credentials: CredentialTable<STEP15_RUNTIME_PROCESSES>,
    signals: SignalTable<
        STEP15_RUNTIME_PROCESSES,
        STEP15_RUNTIME_SIGNAL_PENDING,
        STEP15_RUNTIME_THREADS,
    >,
    wait: WaitTable<STEP15_RUNTIME_PROCESSES>,
    exits: ExitCoordinator<STEP15_RUNTIME_GROUPS>,
    pending_exits: [Option<(GlobalThreadId, ExitTicket)>; STEP15_RUNTIME_THREADS],
    vm: LinuxVmRuntime<STEP15_RUNTIME_VM_BREAKS, STEP15_RUNTIME_VM_TX_PAGES>,
}

impl Step15LinuxRuntime {
    fn create<B: Backend>(backend: &mut B) -> Result<Self, Error> {
        let mut objects = ObjectTable::<STEP15_RUNTIME_OBJECTS>::new();
        let process = Process::<STEP15_RUNTIME_CAPS>::create(&mut objects, Personality::Linux)
            .map_err(Error::Process)?;
        let mut credentials = CredentialTable::new();
        credentials
            .bind_process(&process, LinuxCredentials::root())
            .map_err(Error::Credentials)?;
        let mut signals = SignalTable::new();
        signals.bind_process(&process).map_err(Error::Signal)?;
        let address_space =
            BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(&process, &objects, backend)
                .map_err(Error::AddressSpace)?;

        Ok(Self {
            objects,
            process,
            address_space,
            additional_processes: core::array::from_fn(|_| None),
            bindings: ThreadObjectBindings::new(),
            identities: LinuxIdentityTable::new(),
            credentials,
            signals,
            wait: WaitTable::new(),
            exits: ExitCoordinator::new(),
            pending_exits: [None; STEP15_RUNTIME_THREADS],
            vm: LinuxVmRuntime::new(),
        })
    }

    pub fn loader_parts(
        &mut self,
    ) -> (
        &Process<STEP15_RUNTIME_CAPS>,
        &ObjectTable<STEP15_RUNTIME_OBJECTS>,
        &mut BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    ) {
        let Self {
            objects,
            process,
            address_space,
            ..
        } = self;
        (&*process, &*objects, address_space)
    }

    #[allow(clippy::type_complexity)]
    pub fn initial_leader_parts(
        &mut self,
    ) -> (
        &mut Process<STEP15_RUNTIME_CAPS>,
        &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
        &mut ObjectTable<STEP15_RUNTIME_OBJECTS>,
        &mut ThreadObjectBindings<STEP15_RUNTIME_THREADS>,
        &mut LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
        &ExitCoordinator<STEP15_RUNTIME_GROUPS>,
    ) {
        let Self {
            objects,
            process,
            address_space,
            bindings,
            identities,
            exits,
            ..
        } = self;
        (
            process,
            &*address_space,
            objects,
            bindings,
            identities,
            &*exits,
        )
    }

    fn prepare_exit(
        &mut self,
        scheduler_thread: GlobalThreadId,
        status: u8,
        scope: ExitScope,
    ) -> Result<(), Error> {
        if self
            .pending_exits
            .iter()
            .flatten()
            .any(|(thread, _)| *thread == scheduler_thread)
        {
            return Err(Error::InvalidState);
        }
        let pending_slot = self
            .pending_exits
            .iter()
            .position(Option::is_none)
            .ok_or(Error::InvalidState)?;
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;

        let ticket = {
            let Self {
                process,
                address_space,
                additional_processes,
                identities,
                exits,
                ..
            } = self;
            let selected = if process.id() == process_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == process_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
                &slot.process
            };
            if selected.id() != process_id {
                return Err(Error::InvalidState);
            }
            identities
                .bound_tid_for_scheduler_thread(selected, scheduler_thread)
                .map_err(|_| Error::InvalidState)?;
            exits
                .begin_exit(ExitRequest { scope, status }, selected)
                .map_err(Error::Exit)?
        };
        if ticket.process() != process_id {
            return Err(Error::InvalidState);
        }
        self.pending_exits[pending_slot] = Some((scheduler_thread, ticket));
        Ok(())
    }

    /// Persists the lifecycle ticket for one exact current pthread generation before its
    /// non-returning scheduler exit. CPU ownership is part of the retained identity so a same-local
    /// slot on another PE can never alias this pending exit.
    pub fn prepare_thread_exit(
        &mut self,
        scheduler_thread: GlobalThreadId,
        status: u8,
    ) -> Result<(), Error> {
        self.prepare_exit(scheduler_thread, status, ExitScope::Thread)
    }

    /// Persists the process-wide exit ticket for the exact current Linux leader generation.
    pub fn prepare_group_exit(
        &mut self,
        scheduler_thread: GlobalThreadId,
        status: u8,
    ) -> Result<(), Error> {
        self.prepare_exit(scheduler_thread, status, ExitScope::ThreadGroup)
    }

    /// Returns the oldest retained exact global scheduler generation awaiting proof-carrying
    /// finalization on `scheduler_owner` only.
    ///
    /// CPU ownership is part of the scheduler generation. Filtering here prevents an older pending
    /// exit on another PE from masking work owned by the current CPU merely because both local run
    /// queues may contain the same slot/generation pair.
    pub fn pending_thread_exit(
        &self,
        scheduler_owner: kernal_percpu::CpuIndex,
    ) -> Option<GlobalThreadId> {
        self.pending_exits
            .iter()
            .flatten()
            .find_map(|(thread, _)| (thread.cpu == scheduler_owner).then_some(*thread))
    }

    /// Returns the exact Process generation retained by one pending exit ticket.
    ///
    /// The ObjectId is observation only and is useful only as a generation check against the
    /// runtime-owned Process/AddressSpace slot after the canonical lifecycle finalizer has retired
    /// Linux PID/TID identity. No caller-supplied scalar is accepted here.
    pub(super) fn pending_exit_process(
        &self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<ObjectId, Error> {
        self.pending_exits
            .iter()
            .flatten()
            .find(|(thread, _)| *thread == scheduler_thread)
            .map(|(_, ticket)| ticket.process())
            .ok_or(Error::InvalidState)
    }

    /// Consumes one retained lifecycle ticket only after selecting and revalidating the exact
    /// Process/AddressSpace owner named by that ticket and scheduler generation.
    #[allow(clippy::type_complexity)]
    pub fn finalize_pending_thread_exit<R>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        finalize: impl FnOnce(
            ExitTicket,
            &mut ExitCoordinator<STEP15_RUNTIME_GROUPS>,
            &mut Process<STEP15_RUNTIME_CAPS>,
            &mut ObjectTable<STEP15_RUNTIME_OBJECTS>,
            &mut ThreadObjectBindings<STEP15_RUNTIME_THREADS>,
            &mut LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
        ) -> Result<R, kernal_linux_exit_lifecycle::Error>,
    ) -> Result<R, Error> {
        let pending_slot = self
            .pending_exits
            .iter()
            .position(|pending| {
                pending
                    .as_ref()
                    .is_some_and(|(thread, _)| *thread == scheduler_thread)
            })
            .ok_or(Error::InvalidState)?;
        let ticket = self.pending_exits[pending_slot]
            .as_ref()
            .map(|(_, ticket)| *ticket)
            .ok_or(Error::InvalidState)?;
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        if ticket.process() != process_id {
            return Err(Error::InvalidState);
        }

        let result = {
            let Self {
                process,
                address_space,
                additional_processes,
                exits,
                objects,
                bindings,
                identities,
                ..
            } = self;
            let selected = if process.id() == process_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &mut *process
            } else {
                let slot = additional_processes
                    .iter_mut()
                    .flatten()
                    .find(|slot| slot.process.id() == process_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
                &mut slot.process
            };
            if selected.id() != process_id {
                return Err(Error::InvalidState);
            }
            identities
                .bound_tid_for_scheduler_thread(&*selected, scheduler_thread)
                .map_err(|_| Error::InvalidState)?;
            finalize(ticket, exits, selected, objects, bindings, identities).map_err(Error::Exit)?
        };
        self.pending_exits[pending_slot] = None;
        Ok(result)
    }

    pub fn register_initial_break(
        &mut self,
        initial_break: u64,
    ) -> Result<(), kernal_linux_vm::Error> {
        self.vm
            .register_process_break(self.process.id(), initial_break)
    }

    #[allow(clippy::type_complexity)]
    pub fn minimum_vm_parts(
        &mut self,
    ) -> (
        &mut LinuxVmRuntime<STEP15_RUNTIME_VM_BREAKS, STEP15_RUNTIME_VM_TX_PAGES>,
        &mut Process<STEP15_RUNTIME_CAPS>,
        &mut ObjectTable<STEP15_RUNTIME_OBJECTS>,
        &mut BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    ) {
        let Self {
            vm,
            process,
            objects,
            address_space,
            ..
        } = self;
        (vm, process, objects, address_space)
    }

    /// Number of Process/AddressSpace owner pairs retained by this runtime.
    pub fn process_slot_count(&self) -> usize {
        1 + self
            .additional_processes
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Creates one real, still-unpublished fork child from the exact current scheduler generation.
    ///
    /// Parent selection starts at the canonical Linux identity relation and is revalidated against
    /// exactly one retained Process/AddressSpace owner pair before any child object is allocated.
    /// The child receives a fresh Process generation and the architecture owner's distinct empty
    /// fork-staging AddressSpace. No PID/TID, runtime slot, scheduler generation or Ready visibility
    /// is created here. On address-space staging failure the still-threadless child Process is exited
    /// synchronously so partially created Process/ObjectTable authority does not escape.
    pub(super) fn create_unpublished_fork_child_for_scheduler_thread<B: Backend>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        backend: &mut B,
    ) -> Result<
        (
            Process<STEP15_RUNTIME_CAPS>,
            BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
        ),
        Error,
    > {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };

        let Self {
            objects,
            process,
            address_space,
            additional_processes,
            bindings,
            ..
        } = self;
        let (parent, parent_space) = if process.id() == parent_id {
            (&*process, &*address_space)
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            (&slot.process, &slot.address_space)
        };
        RuntimeProcessSlot::validate(parent, parent_space)?;
        if parent.id() != parent_id || parent_space.owner_process() != parent_id {
            return Err(Error::InvalidState);
        }

        let mut child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(parent, objects)
            .map_err(Error::Process)?;
        let child_space =
            match BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create_fork_child_staging(
                parent_space,
                parent,
                &child,
                &*objects,
                backend,
            ) {
                Ok(space) => space,
                Err(error) => {
                    child.exit(objects, &*bindings).map_err(Error::Process)?;
                    return Err(Error::AddressSpace(error));
                }
            };
        if let Err(error) = RuntimeProcessSlot::validate(&child, &child_space) {
            child.exit(objects, &*bindings).map_err(Error::Process)?;
            return Err(error);
        }
        Ok((child, child_space))
    }

    /// Binds canonical Linux child-process identity plus inherited credential and signal policy while
    /// the fork child is still unpublished.
    ///
    /// The parent is selected only from the exact current scheduler generation through the canonical
    /// identity relation and retained Process owner. `child` is the real Process owner returned by
    /// `create_unpublished_fork_child_for_scheduler_thread`; no scalar PID/ObjectId can select a child.
    /// The sole Linux identity owner allocates the child PID and atomically inherits PPID/PGID/SID;
    /// the accepted CredentialTable and SignalTable then inherit only their Linux policy metadata for
    /// that exact proven child relation. No leader TID or scheduler generation is created here.
    pub(super) fn bind_unpublished_fork_child_identity(
        &mut self,
        scheduler_thread: GlobalThreadId,
        child: &Process<STEP15_RUNTIME_CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            credentials,
            signals,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id {
            return Err(Error::InvalidState);
        }
        let child_pid = identities
            .bind_child(parent, child)
            .map_err(|_| Error::InvalidState)?;
        credentials
            .inherit_child(&*identities, parent, child)
            .map_err(Error::Credentials)?;
        signals
            .inherit_child(&*identities, parent, child)
            .map_err(Error::Signal)?;
        Ok(child_pid)
    }

    /// Tracks one exact still-unpublished fork child in the canonical bounded Wait owner.
    ///
    /// Parent selection starts from the exact current scheduler generation. The existing Linux
    /// identity relation is then handed to `WaitTable::track_child`, which snapshots the canonical
    /// parent/child ObjectIds and Linux PIDs. The returned token is linear observation state only; it
    /// grants no Process/PID authority and must remain owned by the fork transaction until publication
    /// or rollback.
    pub(super) fn track_unpublished_fork_child_wait(
        &mut self,
        scheduler_thread: GlobalThreadId,
        child: &Process<STEP15_RUNTIME_CAPS>,
    ) -> Result<ChildExitPublication, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id {
            return Err(Error::InvalidState);
        }
        wait.track_child(identities, parent, child)
            .map_err(Error::Wait)
    }

    /// Cancels one exact never-published Wait observation during synchronous fork rollback.
    ///
    /// The linear token came directly from `track_unpublished_fork_child_wait`; no PID/ObjectId
    /// lookup is performed here. A cancellation failure is an internal rollback failure and callers
    /// must quarantine the remaining fork transaction rather than retire identity underneath it.
    pub(super) fn cancel_unpublished_fork_child_wait(
        &mut self,
        publication: ChildExitPublication,
    ) -> Result<(), Error> {
        self.wait.cancel_tracking(publication).map_err(Error::Wait)
    }

    /// Retires one still-unpublished fork child after all copied user mappings have already been
    /// rolled back and before any scheduler generation exists.
    ///
    /// The exact live `Process` owner is required. Process teardown happens first; only the resulting
    /// Exited generation authorizes signal, credential and Linux identity owners to release their
    /// bounded records. Missing policy records are accepted only while rolling back a child whose
    /// corresponding inheritance step itself failed. Numeric task IDs remain monotonically consumed.
    pub(super) fn retire_unpublished_fork_child_identity(
        &mut self,
        child: &mut Process<STEP15_RUNTIME_CAPS>,
    ) -> Result<(), Error> {
        child
            .exit(&mut self.objects, &self.bindings)
            .map_err(Error::Process)?;
        match self.signals.retire_process(child) {
            Ok(()) | Err(SignalError::ProcessNotBound) => {}
            Err(error) => return Err(Error::Signal(error)),
        }
        match self.credentials.retire_process(child) {
            Ok(_) | Err(CredentialError::ProcessNotBound) => {}
            Err(error) => return Err(Error::Credentials(error)),
        }
        self.identities
            .retire_process(child)
            .map_err(|_| Error::InvalidState)
    }

    /// Installs an already-created exact Linux Process/AddressSpace owner pair into a free bounded
    /// Step-30 slot. On every failure ownership is returned to the caller for canonical rollback.
    #[allow(clippy::result_large_err)]
    pub fn install_additional_process(
        &mut self,
        process: Process<STEP15_RUNTIME_CAPS>,
        address_space: BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    ) -> Result<
        usize,
        (
            Error,
            Process<STEP15_RUNTIME_CAPS>,
            BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
        ),
    > {
        if let Err(error) = RuntimeProcessSlot::validate(&process, &address_space) {
            return Err((error, process, address_space));
        }
        let process_id = process.id();
        if self.process.id() == process_id
            || self
                .additional_processes
                .iter()
                .flatten()
                .any(|slot| slot.process.id() == process_id)
        {
            return Err((Error::InvalidState, process, address_space));
        }
        let Some(index) = self.additional_processes.iter().position(Option::is_none) else {
            return Err((Error::ProcessSlotsFull, process, address_space));
        };
        self.additional_processes[index] = Some(RuntimeProcessSlot {
            process,
            address_space,
            wait_publication: None,
        });
        Ok(index + 1)
    }

    /// Transfers one linear Wait publication token into the exact retained child Process slot.
    ///
    /// `slot` is the installation receipt returned by `install_additional_process`; it cannot select
    /// another Process. The real Process/AddressSpace pair is revalidated and the canonical identity
    /// owner must still bind that Process to the token's observed child PID. The token is returned to
    /// the caller on every failure so ownership is never silently lost.
    #[allow(clippy::result_large_err)]
    pub(super) fn adopt_additional_process_wait_publication(
        &mut self,
        slot: usize,
        expected_process: ObjectId,
        publication: ChildExitPublication,
    ) -> Result<(), (Error, ChildExitPublication)> {
        let index = match slot.checked_sub(1) {
            Some(index) => index,
            None => return Err((Error::InvalidState, publication)),
        };
        let candidate = match self
            .additional_processes
            .get(index)
            .and_then(Option::as_ref)
        {
            Some(candidate) => candidate,
            None => return Err((Error::InvalidState, publication)),
        };
        if RuntimeProcessSlot::validate(&candidate.process, &candidate.address_space).is_err()
            || candidate.process.id() != expected_process
            || candidate.wait_publication.is_some()
        {
            return Err((Error::InvalidState, publication));
        }
        let child_pid = match self.identities.pid_for(&candidate.process) {
            Ok(pid) => pid,
            Err(_) => return Err((Error::InvalidState, publication)),
        };
        if child_pid != publication.child_pid() {
            return Err((Error::InvalidState, publication));
        }

        let selected = match self
            .additional_processes
            .get_mut(index)
            .and_then(Option::as_mut)
        {
            Some(selected) => selected,
            None => return Err((Error::InvalidState, publication)),
        };
        if selected.process.id() != expected_process
            || selected.address_space.owner_process() != expected_process
            || selected.wait_publication.is_some()
        {
            return Err((Error::InvalidState, publication));
        }
        selected.wait_publication = Some(publication);
        Ok(())
    }

    /// Takes back the exact slot-owned Wait token while the scheduler publication edge is still
    /// rollbackable. No PID/ObjectId search is performed: the linear slot receipt and exact Process
    /// generation must both still match.
    pub(super) fn take_additional_process_wait_publication(
        &mut self,
        slot: usize,
        expected_process: ObjectId,
    ) -> Result<ChildExitPublication, Error> {
        let index = slot.checked_sub(1).ok_or(Error::InvalidState)?;
        let selected = self
            .additional_processes
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&selected.process, &selected.address_space)?;
        if selected.process.id() != expected_process {
            return Err(Error::InvalidState);
        }
        selected.wait_publication.take().ok_or(Error::InvalidState)
    }

    /// Publishes one normal Linux process exit into the canonical Wait owner for an exact retained
    /// child Process generation.
    ///
    /// The Process ObjectId came from the generation-bound pending exit ticket before Linux identity
    /// retirement. It is used only to select and then revalidate the retained Process/AddressSpace
    /// owner. The slot-owned linear ChildExitPublication remains retained after zombie publication so
    /// no Process/AddressSpace owner can be removed before a later destructive wait-reap transaction.
    /// The initial bootstrap Process has no parent-owned Wait token and therefore needs no publication.
    pub(super) fn publish_normal_process_exit_wait(
        &mut self,
        process_id: ObjectId,
        status: u8,
    ) -> Result<(), Error> {
        if self.process.id() == process_id {
            return Ok(());
        }

        let Self {
            additional_processes,
            wait,
            ..
        } = self;
        let slot = additional_processes
            .iter()
            .flatten()
            .find(|slot| slot.process.id() == process_id)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
        if slot.process.id() != process_id
            || slot.address_space.owner_process() != process_id
            || slot.address_space.address_space_object() != slot.process.address_space()
        {
            return Err(Error::InvalidState);
        }
        let publication = slot.wait_publication.as_ref().ok_or(Error::InvalidState)?;
        wait.publish_exit(publication, &slot.process, WaitStatus::exited(status))
            .map_err(Error::Wait)
    }

    /// Observes one child status for the exact current scheduler generation without consuming a
    /// zombie. This is phase 1 of the wait transaction: even when the eventual syscall is destructive,
    /// userspace status/siginfo/rusage writeback must complete before phase 2 is allowed to reap.
    pub(super) fn observe_wait_for_scheduler_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
        selector: WaitSelector,
        nohang: bool,
    ) -> Result<WaitOutcome, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id || parent.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        wait.wait(parent, selector, WaitOptions::new(nohang, true))
            .map_err(Error::Wait)
    }

    /// Prepares one exact-generation blocking wait against the sole canonical WaitTable.
    ///
    /// The current scheduler generation selects and revalidates the retained parent Process; no PID,
    /// ObjectId or Core-local waiter registry becomes mutation authority. The returned linear receipt
    /// may cross the runtime borrow solely so Core can compose the scheduler block transaction.
    pub(super) fn prepare_wait_sleep_for_scheduler_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
        selector: WaitSelector,
    ) -> Result<WaitPrepareOutcome, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id || parent.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        wait.prepare_sleep(parent, selector, scheduler_thread)
            .map_err(Error::Wait)
    }

    /// Commits only the exact prepared receipt immediately before the scheduler block edge.
    pub(super) fn commit_wait_sleep(
        &mut self,
        receipt: &WaitSleepReceipt,
    ) -> Result<WaitCommitOutcome, Error> {
        self.wait.commit_sleep(receipt).map_err(Error::Wait)
    }

    /// Cancels one exact retained receipt if the scheduler block did not consume the sleep window.
    pub(super) fn cancel_wait_sleep(&mut self, receipt: WaitSleepReceipt) -> Result<bool, Error> {
        self.wait.cancel_sleep(receipt).map_err(Error::Wait)
    }

    /// Notifies the sole Wait owner after an exact retained child scheduler generation becomes Exited.
    ///
    /// This is only the early lossless wake edge; zombie publication remains a later proof-carrying
    /// lifecycle transaction after scheduler reap. Initial bootstrap Process exits have no parent Wait
    /// publication and therefore return None.
    pub(super) fn notify_wait_exit_transition_for_scheduler_thread(
        &mut self,
        exiting: GlobalThreadId,
    ) -> Result<Option<WaitWakeBatch<STEP15_RUNTIME_PROCESSES>>, Error> {
        let process_id = {
            let (process, _, _) = self.process_parts_for_scheduler_thread(exiting)?;
            process.id()
        };
        if self.process.id() == process_id {
            RuntimeProcessSlot::validate(&self.process, &self.address_space)?;
            return Ok(None);
        }
        let Self {
            additional_processes,
            wait,
            ..
        } = self;
        let slot = additional_processes
            .iter()
            .flatten()
            .find(|slot| slot.process.id() == process_id)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
        if slot.process.id() != process_id {
            return Err(Error::InvalidState);
        }
        let publication = slot.wait_publication.as_ref().ok_or(Error::InvalidState)?;
        wait.notify_exit_transition(publication)
            .map(Some)
            .map_err(Error::Wait)
    }

    /// Commits a previously observed zombie reap after all fallible userspace writeback has already
    /// succeeded. The opaque WaitObservation is produced only by the canonical WaitTable; its exact
    /// historical ObjectId selects the retained exited Process/AddressSpace slot and cannot recreate
    /// authority. The method re-observes the same PID/status with WNOWAIT before any cleanup, retires
    /// exited-only credential/signal metadata idempotently, performs the one destructive WaitTable
    /// reap, and only then releases the exact runtime slot and its linear publication token.
    pub(super) fn commit_wait_reap_for_scheduler_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
        expected: WaitObservation,
    ) -> Result<(), Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let child_index = self
            .additional_processes
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.process.id() == expected.child())
            })
            .ok_or(Error::InvalidState)?;
        {
            let child = self.additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            if child.process.id() != expected.child()
                || child.process.state() != ProcessState::Exited
                || child
                    .wait_publication
                    .as_ref()
                    .is_none_or(|publication| publication.child_pid() != expected.pid())
            {
                return Err(Error::InvalidState);
            }
        }

        // Re-observe immediately before commit. No state is consumed here.
        let reobserved = {
            let Self {
                process,
                address_space,
                additional_processes,
                wait,
                ..
            } = self;
            let parent = if process.id() == parent_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == parent_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
                &slot.process
            };
            wait.wait(
                parent,
                WaitSelector::Pid(expected.pid()),
                WaitOptions::new(false, true),
            )
            .map_err(Error::Wait)?
        };
        if reobserved != WaitOutcome::Ready(expected) {
            return Err(Error::InvalidState);
        }

        // Exited metadata cannot grant authority. Treat already-retired metadata as idempotent so a
        // fail-closed retry cannot be trapped by a partial cleanup from an earlier attempt.
        {
            let Self {
                additional_processes,
                credentials,
                signals,
                ..
            } = self;
            let child = &additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?
                .process;
            match credentials.retire_process(child) {
                Ok(_) | Err(CredentialError::ProcessNotBound) => {}
                Err(error) => return Err(Error::Credentials(error)),
            }
            match signals.retire_process(child) {
                Ok(()) | Err(SignalError::ProcessNotBound) => {}
                Err(error) => return Err(Error::Signal(error)),
            }
        }

        let reaped = {
            let Self {
                process,
                address_space,
                additional_processes,
                wait,
                ..
            } = self;
            let parent = if process.id() == parent_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == parent_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
                &slot.process
            };
            wait.wait(
                parent,
                WaitSelector::Pid(expected.pid()),
                WaitOptions::BLOCKING,
            )
            .map_err(Error::Wait)?
        };
        if reaped != WaitOutcome::Ready(expected) {
            return Err(Error::InvalidState);
        }

        // The exact child record is now gone from WaitTable, so this is the first point at which the
        // retained Process/AddressSpace owners and their publication token may be released.
        let slot = self.additional_processes[child_index]
            .take()
            .ok_or(Error::InvalidState)?;
        debug_assert_eq!(slot.process.id(), expected.child());
        debug_assert_eq!(
            slot.wait_publication
                .as_ref()
                .map(ChildExitPublication::child_pid),
            Some(expected.pid())
        );
        Ok(())
    }

    /// Runs one synchronous authority operation against the exact unpublished additional Process slot.
    ///
    /// `slot` is the linear receipt returned by `install_additional_process`; `expected_process` is
    /// only a generation check for that exact slot and cannot search/select any other Process. The
    /// AddressSpace pairing is revalidated before mutable Process/Object/Binding/Identity authority is
    /// exposed to the closure. No supplied reference may escape or survive a scheduler context switch.
    #[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
    pub(super) fn with_unpublished_additional_process_authority<R>(
        &mut self,
        slot: usize,
        expected_process: ObjectId,
        operation: impl FnOnce(
            &mut Process<STEP15_RUNTIME_CAPS>,
            &mut ObjectTable<STEP15_RUNTIME_OBJECTS>,
            &mut ThreadObjectBindings<STEP15_RUNTIME_THREADS>,
            &mut LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
            &ExitCoordinator<STEP15_RUNTIME_GROUPS>,
        ) -> R,
    ) -> Result<R, Error> {
        let index = slot.checked_sub(1).ok_or(Error::InvalidState)?;
        let candidate = self
            .additional_processes
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&candidate.process, &candidate.address_space)?;
        if candidate.process.id() != expected_process {
            return Err(Error::InvalidState);
        }

        let Self {
            objects,
            additional_processes,
            bindings,
            identities,
            exits,
            ..
        } = self;
        let selected = additional_processes
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Error::InvalidState)?;
        if selected.process.id() != expected_process
            || selected.address_space.owner_process() != expected_process
        {
            return Err(Error::InvalidState);
        }
        Ok(operation(
            &mut selected.process,
            objects,
            bindings,
            identities,
            &*exits,
        ))
    }

    /// Takes back one exact additional Process/AddressSpace owner pair from the bounded runtime
    /// during the same synchronous never-published fork transaction that installed it.
    ///
    /// `slot` is the linear install receipt returned by `install_additional_process`; it is not a
    /// Linux-visible identifier. `expected_process` is used only as a generation check against that
    /// exact slot and cannot search/select another slot. The pair is validated read-only before the
    /// Option is consumed, so a stale/wrong receipt leaves every retained owner unchanged.
    pub(super) fn take_unpublished_additional_process(
        &mut self,
        slot: usize,
        expected_process: ObjectId,
    ) -> Result<
        (
            Process<STEP15_RUNTIME_CAPS>,
            BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
        ),
        Error,
    > {
        let index = slot.checked_sub(1).ok_or(Error::InvalidState)?;
        let candidate = self
            .additional_processes
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&candidate.process, &candidate.address_space)?;
        if candidate.process.id() != expected_process || candidate.wait_publication.is_some() {
            return Err(Error::InvalidState);
        }

        let removed = self
            .additional_processes
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(Error::InvalidState)?;
        debug_assert_eq!(removed.process.id(), expected_process);
        Ok((removed.process, removed.address_space))
    }

    /// Selects one retained Process/AddressSpace pair from an already generation-safe Process
    /// ObjectId observation. This helper is private because ObjectId itself is never live authority;
    /// runtime callers must enter through [`Self::process_parts_for_scheduler_thread`].
    fn process_parts_for_object_id(
        &self,
        process_id: ObjectId,
    ) -> Result<
        (
            &Process<STEP15_RUNTIME_CAPS>,
            &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
        ),
        Error,
    > {
        if self.process.id() == process_id {
            return Ok((&self.process, &self.address_space));
        }
        self.additional_processes
            .iter()
            .flatten()
            .find(|slot| slot.process.id() == process_id)
            .map(|slot| (&slot.process, &slot.address_space))
            .ok_or(Error::InvalidState)
    }

    /// Resolves one exact scheduler generation to its canonical retained Process owner and Linux TID.
    ///
    /// The identity table supplies only a generation-safe Process ObjectId observation. This method
    /// then selects the retained owner pair, revalidates the Process/AddressSpace pairing, and asks the
    /// same canonical identity owner to prove the exact thread belongs to that selected Process. No
    /// scalar PID/TID or ObjectId is accepted as mutation authority.
    pub fn process_parts_for_scheduler_thread(
        &self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<
        (
            &Process<STEP15_RUNTIME_CAPS>,
            &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
            NonZeroU32,
        ),
        Error,
    > {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let (process, address_space) = self.process_parts_for_object_id(process_id)?;
        RuntimeProcessSlot::validate(process, address_space)?;
        if process.id() != process_id || address_space.owner_process() != process_id {
            return Err(Error::InvalidState);
        }
        let tid = self
            .identities
            .bound_tid_for_scheduler_thread(process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        Ok((process, address_space, tid))
    }

    /// Replaces the Linux program break for the exact current scheduler generation after exec commit.
    ///
    /// Selection first passes through the canonical scheduler-generation -> LinuxIdentity relation
    /// and retained Process/AddressSpace validation. The resulting Process ObjectId is only an
    /// observation used to enter the sole LinuxVmRuntime BreakTable owner; no slot-0 shortcut or
    /// remove/register capacity edge is introduced.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(super) fn replace_process_break_for_exec(
        &mut self,
        scheduler_thread: GlobalThreadId,
        initial_break: u64,
    ) -> Result<(), Error> {
        let process_id = {
            let (process, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            process.id()
        };
        self.vm
            .replace_process_break_for_exec(process_id, initial_break)
            .map_err(|_| Error::InvalidState)
    }

    /// Runs one synchronous post-commit exec operation against the exact current retained owners.
    ///
    /// This bridge is deliberately separate from the historical fork-staging selector. The exact
    /// scheduler generation selects and revalidates the retained Process/AddressSpace pair, requires
    /// the exact Exec binding for the current phase to be current, and scopes ObjectTable authority
    /// to this callback only. Before the root swap that is the old binding; after replacement it is
    /// the freshly committed binding.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(super) fn with_exec_current_owner<R>(
        &self,
        scheduler_thread: GlobalThreadId,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
            &ObjectTable<STEP15_RUNTIME_OBJECTS>,
        ) -> R,
    ) -> Result<R, Error> {
        let (process, address_space, _) =
            self.process_parts_for_scheduler_thread(scheduler_thread)?;
        address_space
            .current_owner(process)
            .map_err(Error::AddressSpace)?;
        Ok(operation(process, address_space, &self.objects))
    }

    /// Runs one synchronous Linux-identity operation against the exact Process owner selected by
    /// the current scheduler generation.
    ///
    /// The scheduler generation is first resolved through the canonical LinuxIdentityTable, then the
    /// retained Process/AddressSpace pair is revalidated, and finally the same identity owner proves
    /// the exact TID still belongs to that Process. The callback receives real Process authority plus
    /// the sole mutable identity owner; no PID/TID/ObjectId scalar can select mutation authority.
    pub(super) fn with_current_process_identity<R>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &mut LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
        ) -> R,
    ) -> Result<R, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            ..
        } = self;
        let process = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if process.id() != process_id {
            return Err(Error::InvalidState);
        }
        identities
            .bound_tid_for_scheduler_thread(process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        Ok(operation(process, identities))
    }

    /// Runs one synchronous Linux-credential operation against the exact Process owner selected by
    /// the current scheduler generation.
    ///
    /// Selection is identical to the identity bridge: the sole LinuxIdentityTable resolves and
    /// revalidates the exact scheduler generation before the callback receives the retained Process
    /// plus the sole persistent CredentialTable. Numeric PID/TID values never select credential
    /// mutation authority.
    pub(super) fn with_current_process_credentials<R>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &mut CredentialTable<STEP15_RUNTIME_PROCESSES>,
        ) -> R,
    ) -> Result<R, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            credentials,
            ..
        } = self;
        let process = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if process.id() != process_id {
            return Err(Error::InvalidState);
        }
        identities
            .bound_tid_for_scheduler_thread(process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        Ok(operation(process, credentials))
    }

    /// Runs one synchronous Linux signal-policy operation against the exact Process owner selected
    /// by the current scheduler generation.
    ///
    /// The canonical Linux identity table first resolves and revalidates the exact scheduler
    /// generation. The callback then receives only that retained Process, the read-only identity
    /// owner needed by thread-aware signal operations, and the sole persistent SignalTable. Scalar
    /// PID/TID values and ObjectIds never become signal mutation authority.
    #[allow(clippy::type_complexity)]
    pub(super) fn with_current_process_signals<R>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
            &mut SignalTable<
                STEP15_RUNTIME_PROCESSES,
                STEP15_RUNTIME_SIGNAL_PENDING,
                STEP15_RUNTIME_THREADS,
            >,
        ) -> R,
    ) -> Result<R, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            signals,
            ..
        } = self;
        let process = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if process.id() != process_id {
            return Err(Error::InvalidState);
        }
        identities
            .bound_tid_for_scheduler_thread(process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        Ok(operation(process, &*identities, signals))
    }

    /// Runs one synchronous pending-signal delivery operation against the exact current Process and
    /// AddressSpace owner observed by the trapping scheduler generation.
    ///
    /// The current AddressSpace binding and exception-entry switch generation are revalidated before
    /// exposing the sole SignalTable. The callback is synchronous and no Process/AddressSpace
    /// reference may escape or survive a scheduler switch.
    #[allow(clippy::type_complexity)]
    pub(super) fn with_current_signal_delivery<R>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        entry_switch_generation: u64,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
            &ObjectTable<STEP15_RUNTIME_OBJECTS>,
            &LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
            &mut SignalTable<
                STEP15_RUNTIME_PROCESSES,
                STEP15_RUNTIME_SIGNAL_PENDING,
                STEP15_RUNTIME_THREADS,
            >,
        ) -> R,
    ) -> Result<R, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let Self {
            objects,
            process,
            address_space,
            additional_processes,
            identities,
            signals,
            ..
        } = self;
        let (process, address_space) = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            (&*process, &*address_space)
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            (&slot.process, &slot.address_space)
        };
        identities
            .bound_tid_for_scheduler_thread(process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        address_space
            .current_owner(process)
            .map_err(Error::AddressSpace)?
            .validate_entry_switch_generation(entry_switch_generation)
            .map_err(Error::AddressSpace)?;
        Ok(operation(
            process,
            address_space,
            &*objects,
            &*identities,
            signals,
        ))
    }

    /// Runs one synchronous signal-target operation against an exact retained Process selected by
    /// Linux PID. Numeric PID/ObjectId values are observation only; the retained Process/AddressSpace
    /// pair and canonical bound PID are revalidated before policy owners are exposed.
    #[allow(clippy::type_complexity)]
    pub(super) fn with_process_signal_target_for_pid<R>(
        &mut self,
        pid: NonZeroU32,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            LinuxCredentials,
            &LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
            &mut SignalTable<
                STEP15_RUNTIME_PROCESSES,
                STEP15_RUNTIME_SIGNAL_PENDING,
                STEP15_RUNTIME_THREADS,
            >,
        ) -> R,
    ) -> Result<Option<R>, Error> {
        let process_id = match self.identities.process_object_for_pid(pid) {
            Ok(process_id) => process_id,
            Err(LinuxIdentityError::ProcessNotBound) => return Ok(None),
            Err(_) => return Err(Error::InvalidState),
        };
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            credentials,
            signals,
            ..
        } = self;
        let process = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if process.id() != process_id
            || identities
                .bound_pid(process)
                .map_err(|_| Error::InvalidState)?
                != pid
        {
            return Err(Error::InvalidState);
        }
        let target_credentials = credentials
            .credentials(process)
            .map_err(Error::Credentials)?;
        Ok(Some(operation(
            process,
            target_credentials,
            &*identities,
            signals,
        )))
    }

    /// Binds the exact first Linux scheduler generation into the sole persistent SignalTable.
    ///
    /// Initial process signal state is created with the Process itself, but per-thread signal state is
    /// published only after LinuxIdentity has bound the exact leader generation. The empty initial
    /// mask matches Linux process start. Any identity mismatch fails before SignalTable mutation.
    pub(super) fn bind_initial_signal_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<(), Error> {
        let Self {
            process,
            address_space,
            identities,
            signals,
            ..
        } = self;
        RuntimeProcessSlot::validate(&*process, &*address_space)?;
        identities
            .bound_tid_for_scheduler_thread(&*process, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        signals
            .bind_thread(
                &*identities,
                &*process,
                scheduler_thread,
                SignalSet::empty(),
            )
            .map_err(Error::Signal)
    }

    /// Binds one already-published same-Process pthread generation with its exact parent's mask.
    ///
    /// The clone owner returns a Linux TID only after Process/CSpace and LinuxIdentity publication.
    /// That scalar is resolved back through the canonical identity owner to the exact GlobalThreadId,
    /// then SignalTable independently revalidates both generations before accepting the inherited
    /// mask. This function is called while the parent still owns the synchronous SVC window, before
    /// the Ready child can be selected.
    pub(super) fn inherit_same_process_thread_signal_mask(
        &mut self,
        parent_thread: GlobalThreadId,
        child_tid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        let Self {
            process,
            address_space,
            identities,
            signals,
            ..
        } = self;
        RuntimeProcessSlot::validate(&*process, &*address_space)?;
        identities
            .bound_tid_for_scheduler_thread(&*process, parent_thread)
            .map_err(|_| Error::InvalidState)?;
        let child_thread = identities
            .scheduler_thread_for_tid(&*process, child_tid)
            .map_err(|_| Error::InvalidState)?;
        if child_thread == parent_thread {
            return Err(Error::InvalidState);
        }
        let parent_mask = signals
            .thread_mask(&*identities, &*process, parent_thread)
            .map_err(Error::Signal)?;
        signals
            .bind_thread(&*identities, &*process, child_thread, parent_mask)
            .map_err(Error::Signal)?;
        Ok(child_thread)
    }

    /// Inherits the exact fork caller's SignalTable mask into one staged child leader generation.
    ///
    /// `slot` and `expected_process` are the existing linear unpublished-runtime receipt checks. The
    /// parent and child scheduler generations are both revalidated through LinuxIdentity before the
    /// canonical SignalTable observes the child relation and copies only the parent's thread mask.
    /// No scalar PID/TID or ObjectId becomes signal authority.
    #[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
    pub(super) fn inherit_unpublished_fork_child_signal_mask(
        &mut self,
        parent_thread: GlobalThreadId,
        slot: usize,
        expected_process: ObjectId,
        child_thread: GlobalThreadId,
    ) -> Result<(), Error> {
        let parent_process = self
            .identities
            .process_object_for_scheduler_thread(parent_thread)
            .map_err(|_| Error::InvalidState)?;
        let index = slot.checked_sub(1).ok_or(Error::InvalidState)?;
        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            signals,
            ..
        } = self;
        let child_slot = additional_processes
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&child_slot.process, &child_slot.address_space)?;
        if child_slot.process.id() != expected_process {
            return Err(Error::InvalidState);
        }
        let parent = if process.id() == parent_process {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_process)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        identities
            .bound_tid_for_scheduler_thread(parent, parent_thread)
            .map_err(|_| Error::InvalidState)?;
        identities
            .bound_tid_for_scheduler_thread(&child_slot.process, child_thread)
            .map_err(|_| Error::InvalidState)?;
        signals
            .inherit_thread_mask(
                &*identities,
                parent,
                parent_thread,
                &child_slot.process,
                child_thread,
            )
            .map_err(Error::Signal)
    }

    /// Removes the staged fork leader's per-thread signal state before its unpublished identity and
    /// Process/CSpace Thread authority are rolled back. Identity is intentionally still live here so
    /// SignalTable can revalidate the exact child generation before consuming its record.
    #[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
    pub(super) fn retire_unpublished_fork_child_signal_thread(
        &mut self,
        slot: usize,
        expected_process: ObjectId,
        child_thread: GlobalThreadId,
    ) -> Result<(), Error> {
        let index = slot.checked_sub(1).ok_or(Error::InvalidState)?;
        let Self {
            additional_processes,
            identities,
            signals,
            ..
        } = self;
        let child_slot = additional_processes
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&child_slot.process, &child_slot.address_space)?;
        if child_slot.process.id() != expected_process {
            return Err(Error::InvalidState);
        }
        identities
            .bound_tid_for_scheduler_thread(&child_slot.process, child_thread)
            .map_err(|_| Error::InvalidState)?;
        signals
            .retire_thread(&*identities, &child_slot.process, child_thread)
            .map_err(Error::Signal)
    }

    /// Runs one synchronous read-only Linux-identity observation against a retained Process selected
    /// from a Linux PID that has already been resolved by the canonical identity owner.
    ///
    /// The scalar PID is never Process authority. `process_object_for_pid` supplies only an ObjectId
    /// observation; the bounded runtime owner pair is then selected and its exact Process/AddressSpace
    /// relationship is revalidated before the callback receives short-lived references. A retired or
    /// unknown PID returns `Ok(None)`. Any retained-owner mismatch fails closed as an internal error.
    pub(super) fn with_process_identity_for_pid<R>(
        &self,
        pid: NonZeroU32,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &LinuxIdentityTable<STEP15_RUNTIME_PROCESSES, STEP15_RUNTIME_THREADS>,
        ) -> R,
    ) -> Result<Option<R>, Error> {
        let process_id = match self.identities.process_object_for_pid(pid) {
            Ok(process_id) => process_id,
            Err(LinuxIdentityError::ProcessNotBound) => return Ok(None),
            Err(_) => return Err(Error::InvalidState),
        };
        let (process, address_space) = self.process_parts_for_object_id(process_id)?;
        RuntimeProcessSlot::validate(process, address_space)?;
        if process.id() != process_id
            || address_space.owner_process() != process_id
            || address_space.address_space_object() != process.address_space()
        {
            return Err(Error::InvalidState);
        }
        Ok(Some(operation(process, &self.identities)))
    }

    /// Applies Linux setpgid to an exact retained target selected by a canonical PID observation.
    ///
    /// The current scheduler generation resolves the caller Process; the scalar target PID is used
    /// only by LinuxIdentityTable to observe the target ObjectId. Both retained Process/AddressSpace
    /// pairs are revalidated before the sole mutable identity owner receives real Process authority.
    /// Missing/retired PIDs return Ok(None); callers map that observation to Linux ESRCH.
    pub(super) fn setpgid_for_scheduler_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
        target_pid: NonZeroU32,
        requested_pgid: i32,
    ) -> Result<Option<Result<NonZeroU32, LinuxIdentityError>>, Error> {
        let caller_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let target_id = match self.identities.process_object_for_pid(target_pid) {
            Ok(process_id) => process_id,
            Err(LinuxIdentityError::ProcessNotBound) => return Ok(None),
            Err(_) => return Err(Error::InvalidState),
        };

        let Self {
            process,
            address_space,
            additional_processes,
            identities,
            ..
        } = self;
        let select = |wanted: ObjectId| -> Result<&Process<STEP15_RUNTIME_CAPS>, Error> {
            if process.id() == wanted {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                return Ok(&*process);
            }
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == wanted)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            if slot.process.id() != wanted
                || slot.address_space.owner_process() != wanted
                || slot.address_space.address_space_object() != slot.process.address_space()
            {
                return Err(Error::InvalidState);
            }
            Ok(&slot.process)
        };
        let caller = select(caller_id)?;
        let target = select(target_id)?;
        identities
            .bound_tid_for_scheduler_thread(caller, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        Ok(Some(identities.setpgid(caller, target, requested_pgid)))
    }

    /// Activates the exact retained AArch64 user address space selected by one canonical scheduler
    /// generation at a scheduler-owned destination switch boundary.
    ///
    /// `expected_address_space` is only a generation-bound observation copied from the scheduler's
    /// private ContextTable. It never selects Process authority by itself: LinuxIdentity first maps
    /// `scheduler_thread` to the exact retained Process generation, the Process/BoundAddressSpace
    /// pair is revalidated, and only then must its canonical AddressSpace ObjectId equal the token.
    /// The existing Process CSpace CONTROL check in `activate_owner` remains the final authority.
    ///
    /// # Safety
    /// Caller must own the current PE's scheduler/address-space switch window with user access
    /// quiesced. This function must run only after scheduler table borrows for the selected
    /// generation have ended and before that generation's user stack is resumed. Any returned error
    /// must be handled fail-closed; returning to EL0 after a failed destination activation is invalid.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(super) unsafe fn activate_scheduler_destination_address_space(
        &self,
        scheduler_thread: GlobalThreadId,
        expected_address_space: u64,
    ) -> Result<(), Error> {
        if expected_address_space == 0 {
            return Err(Error::InvalidState);
        }
        let (process, address_space, _) =
            self.process_parts_for_scheduler_thread(scheduler_thread)?;
        if process.address_space().0 != expected_address_space
            || address_space.address_space_object().0 != expected_address_space
        {
            return Err(Error::InvalidState);
        }
        // SAFETY: delegated caller contract owns the PE switch window; exact Process/CSpace and
        // BoundProcessAddressSpace authority were revalidated above before architectural mutation.
        unsafe { address_space.activate_owner(process, &self.objects) }.map_err(Error::AddressSpace)
    }

    /// Runs one private fork-snapshot operation against the exact Process owner selected by the
    /// canonical scheduler-generation -> Linux identity relation.
    ///
    /// The ObjectTable reference is scoped to the callback and cannot escape as a second authority.
    /// The callback must remain synchronous and must not publish, block, switch address spaces, or
    /// retain any supplied reference. This bridge exists only for the AArch64 Step-30 fork staging
    /// transaction; scalar PID/TID/ObjectId inputs never select the parent.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(super) fn with_fork_snapshot_parent<R>(
        &self,
        scheduler_thread: GlobalThreadId,
        operation: impl FnOnce(
            &Process<STEP15_RUNTIME_CAPS>,
            &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
            &ObjectTable<STEP15_RUNTIME_OBJECTS>,
        ) -> R,
    ) -> Result<R, Error> {
        let (process, address_space, _) =
            self.process_parts_for_scheduler_thread(scheduler_thread)?;
        Ok(operation(process, address_space, &self.objects))
    }

    pub const fn process(&self) -> &Process<STEP15_RUNTIME_CAPS> {
        &self.process
    }

    pub const fn address_space(&self) -> &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS> {
        &self.address_space
    }
}

struct RuntimeCell {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<Step15LinuxRuntime>>,
}

// SAFETY: installation is one-shot and READY -> BORROWED is the only state exposing mutable runtime
// access. Every reference is scoped to one synchronous closure and READY is republished afterwards.
unsafe impl Sync for RuntimeCell {}

impl RuntimeCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn initialize<B: Backend>(&self, backend: &mut B) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | READY) => return Err(Error::AlreadyInitialized),
            Err(BORROWED) => return Err(Error::Busy),
            Err(POISONED) => return Err(Error::Poisoned),
            Err(_) => return Err(Error::InvalidState),
        }

        match Step15LinuxRuntime::create(backend) {
            Ok(runtime) => {
                // SAFETY: successful EMPTY -> INSTALLING gives this path unique initialization.
                unsafe { (*self.value.get()).write(runtime) };
                self.state.store(READY, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                // Root construction may already have consumed monotonic object/page-table state.
                // Never retry with a second partially overlapping owner.
                self.state.store(POISONED, Ordering::Release);
                Err(error)
            }
        }
    }

    fn with_runtime<R>(
        &self,
        operation: impl FnOnce(&mut Step15LinuxRuntime) -> R,
    ) -> Result<R, Error> {
        match self
            .state
            .compare_exchange(READY, BORROWED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(EMPTY | INSTALLING) => return Err(Error::Unavailable),
            Err(BORROWED) => return Err(Error::Busy),
            Err(POISONED) => return Err(Error::Poisoned),
            Err(_) => return Err(Error::InvalidState),
        }

        // SAFETY: BORROWED proves exclusive mutable access and READY proved completed initialization.
        let runtime = unsafe { (&mut *self.value.get()).assume_init_mut() };
        let result = operation(runtime);
        self.state.store(READY, Ordering::Release);
        Ok(result)
    }
}

static STEP15_LINUX_RUNTIME: RuntimeCell = RuntimeCell::new();

pub fn initialize_linux_runtime<B: Backend>(backend: &mut B) -> Result<(), Error> {
    STEP15_LINUX_RUNTIME.initialize(backend)
}

pub fn with_linux_runtime<R>(
    operation: impl FnOnce(&mut Step15LinuxRuntime) -> R,
) -> Result<R, Error> {
    STEP15_LINUX_RUNTIME.with_runtime(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_signal::{Disposition, Signal};
    use kernal_percpu::CpuIndex;
    use kernal_scheduler::RunQueue;
    use kernal_vm::USER_MIN;

    const CPU0: CpuIndex = CpuIndex(0);

    struct TestBackend {
        next: u64,
        end: u64,
    }

    impl TestBackend {
        fn new(pages: u64) -> Self {
            Self {
                next: 0x10_0000,
                end: 0x10_0000 + pages * 4096,
            }
        }
    }

    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            let current = self.next;
            let next = current.checked_add(4096)?;
            if next > self.end {
                return None;
            }
            self.next = next;
            Some(current)
        }

        fn read_entry(&self, _table_phys: u64, _index: usize) -> Option<u64> {
            Some(0)
        }

        fn write_entry(&mut self, _table_phys: u64, _index: usize, _value: u64) -> bool {
            true
        }
    }

    #[test]
    fn runtime_creation_binds_one_linux_process_to_its_address_space() {
        let mut backend = TestBackend::new(4);
        let runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        assert_eq!(runtime.process().personality(), Personality::Linux);
        assert_eq!(
            runtime.address_space().owner_process(),
            runtime.process().id()
        );
        assert_eq!(
            runtime.address_space().address_space_object(),
            runtime.process().address_space()
        );
        assert_eq!(
            runtime.credentials.credentials(runtime.process()).unwrap(),
            LinuxCredentials::root()
        );
        assert_eq!(
            runtime
                .signals
                .disposition(runtime.process(), Signal::new(2).unwrap())
                .unwrap(),
            Disposition::Default
        );
    }

    fn bind_test_initial_generation(
        runtime: &mut Step15LinuxRuntime,
        scheduler: &mut RunQueue<STEP15_RUNTIME_THREADS>,
    ) -> GlobalThreadId {
        let local = scheduler.create(10).unwrap();
        let global = GlobalThreadId::new(CPU0, local);
        let handle = runtime
            .process
            .attach_thread(
                &mut runtime.objects,
                &mut runtime.bindings,
                &*scheduler,
                CPU0,
                global,
            )
            .unwrap();
        runtime
            .identities
            .bind_leader(
                &runtime.process,
                &runtime.objects,
                &runtime.bindings,
                &*scheduler,
                CPU0,
                handle,
            )
            .unwrap();
        global
    }

    #[test]
    fn signal_thread_state_binds_initial_and_inherits_to_pthread_generation() {
        use kernal_linux_signal::MaskHow;

        let mut backend = TestBackend::new(8);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let parent = bind_test_initial_generation(&mut runtime, &mut scheduler);
        runtime.bind_initial_signal_thread(parent).unwrap();

        let blocked = SignalSet::empty().with(Signal::new(2).unwrap());
        runtime
            .signals
            .update_thread_mask(
                &runtime.identities,
                &runtime.process,
                parent,
                MaskHow::Set,
                blocked,
            )
            .unwrap();

        let child_local = scheduler.create(10).unwrap();
        let child = GlobalThreadId::new(CPU0, child_local);
        let child_handle = runtime
            .process
            .attach_thread(
                &mut runtime.objects,
                &mut runtime.bindings,
                &scheduler,
                CPU0,
                child,
            )
            .unwrap();
        let child_tid = runtime
            .identities
            .tid_for(
                &runtime.process,
                &runtime.objects,
                &runtime.bindings,
                &scheduler,
                CPU0,
                child_handle,
            )
            .unwrap();

        assert_eq!(
            runtime
                .inherit_same_process_thread_signal_mask(parent, child_tid)
                .unwrap(),
            child
        );
        assert_eq!(
            runtime
                .signals
                .thread_mask(&runtime.identities, &runtime.process, child),
            Ok(blocked)
        );
    }

    #[test]
    fn exact_current_generation_routes_process_signal_disposition() {
        let mut backend = TestBackend::new(8);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let signal = Signal::new(2).unwrap();

        let previous = runtime
            .with_current_process_signals(current, |process, _identities, signals| {
                signals.set_disposition(process, signal, Disposition::Ignore)
            })
            .unwrap()
            .unwrap();
        assert_eq!(previous, Disposition::Default);
        assert_eq!(
            runtime
                .signals
                .disposition(&runtime.process, signal)
                .unwrap(),
            Disposition::Ignore
        );

        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: current.local.slot,
                generation: current.local.generation.wrapping_add(1),
            },
        );
        assert!(matches!(
            runtime.with_current_process_signals(stale, |_process, _identities, _signals| ()),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn exact_current_generation_creates_fresh_empty_unpublished_fork_child() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let parent_id = runtime.process.id();
        let parent_space_id = runtime.address_space.address_space_object();
        let retained_before = runtime.process_slot_count();

        let (child, child_space) = runtime
            .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
            .unwrap();

        assert_eq!(runtime.process_slot_count(), retained_before);
        assert_eq!(runtime.process.id(), parent_id);
        assert_eq!(
            runtime.address_space.address_space_object(),
            parent_space_id
        );
        assert_eq!(child.personality(), Personality::Linux);
        assert_ne!(child.id(), parent_id);
        assert_ne!(child.address_space(), parent_space_id);
        assert_eq!(child_space.owner_process(), child.id());
        assert_eq!(child_space.address_space_object(), child.address_space());
        assert_eq!(
            child_space
                .user_vma_at(&child, &runtime.objects, child.address_space_handle(), 0)
                .unwrap(),
            None
        );
        assert!(runtime.identities.bound_pid(&child).is_err());
        assert!(runtime.credentials.credentials(&child).is_err());
        assert!(
            runtime
                .signals
                .disposition(&child, Signal::new(2).unwrap())
                .is_err()
        );
    }

    #[test]
    fn stale_current_generation_fails_before_fork_child_allocation() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: current.local.slot,
                generation: current.local.generation.wrapping_add(1),
            },
        );
        let table_cursor_before = backend.next;
        let retained_before = runtime.process_slot_count();

        assert!(matches!(
            runtime.create_unpublished_fork_child_for_scheduler_thread(stale, &mut backend),
            Err(Error::InvalidState)
        ));
        assert_eq!(backend.next, table_cursor_before);
        assert_eq!(runtime.process_slot_count(), retained_before);

        assert!(
            runtime
                .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
                .is_ok()
        );
    }

    #[test]
    fn unpublished_fork_identity_inherits_parent_family_and_retires_exact_child() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let parent_pid = runtime.identities.bound_pid(&runtime.process).unwrap();
        let parent_pgid = runtime.identities.getpgid(&runtime.process).unwrap();
        let parent_sid = runtime.identities.getsid(&runtime.process).unwrap();
        let parent_credentials = runtime.credentials.credentials(&runtime.process).unwrap();
        let signal = Signal::new(2).unwrap();
        let parent_disposition = runtime
            .signals
            .disposition(&runtime.process, signal)
            .unwrap();
        let (mut child, _child_space) = runtime
            .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
            .unwrap();

        let child_pid = runtime
            .bind_unpublished_fork_child_identity(current, &child)
            .unwrap();
        assert_eq!(runtime.identities.pid_for(&child).unwrap(), child_pid);
        assert_eq!(
            runtime.identities.parent_pid_for(&child).unwrap(),
            parent_pid
        );
        assert_eq!(runtime.identities.getpgid(&child).unwrap(), parent_pgid);
        assert_eq!(runtime.identities.getsid(&child).unwrap(), parent_sid);
        assert_eq!(
            runtime.credentials.credentials(&child).unwrap(),
            parent_credentials
        );
        assert_eq!(
            runtime.signals.disposition(&child, signal).unwrap(),
            parent_disposition
        );
        assert!(
            runtime
                .identities
                .is_child_of(&runtime.process, &child)
                .unwrap()
        );

        runtime
            .retire_unpublished_fork_child_identity(&mut child)
            .unwrap();
        assert_eq!(child.state(), kernal_process::ProcessState::Exited);
        assert!(runtime.identities.pid_for(&child).is_err());
        assert!(runtime.credentials.credentials(&child).is_err());
        assert!(runtime.signals.disposition(&child, signal).is_err());
        assert_eq!(
            runtime.identities.bound_pid(&runtime.process).unwrap(),
            parent_pid
        );
    }

    #[test]
    fn unpublished_fork_wait_tracking_is_linear_and_cancellable() {
        use kernal_linux_wait::{WaitOptions, WaitOutcome, WaitSelector};

        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let (mut child, _child_space) = runtime
            .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
            .unwrap();
        let child_pid = runtime
            .bind_unpublished_fork_child_identity(current, &child)
            .unwrap();
        let publication = runtime
            .track_unpublished_fork_child_wait(current, &child)
            .unwrap();
        assert_eq!(publication.child_pid(), child_pid);
        assert_eq!(
            runtime
                .wait
                .wait(
                    &runtime.process,
                    WaitSelector::Pid(child_pid),
                    WaitOptions::WNOHANG,
                )
                .unwrap(),
            WaitOutcome::NoHang
        );

        runtime
            .cancel_unpublished_fork_child_wait(publication)
            .unwrap();
        assert!(matches!(
            runtime.wait.wait(
                &runtime.process,
                WaitSelector::Pid(child_pid),
                WaitOptions::WNOHANG,
            ),
            Err(kernal_linux_wait::Error::NoChild)
        ));

        runtime
            .retire_unpublished_fork_child_identity(&mut child)
            .unwrap();
    }

    #[test]
    fn stale_parent_generation_cannot_bind_child_identity() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let (mut child, _child_space) = runtime
            .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
            .unwrap();
        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: current.local.slot,
                generation: current.local.generation.wrapping_add(1),
            },
        );

        assert!(matches!(
            runtime.bind_unpublished_fork_child_identity(stale, &child),
            Err(Error::InvalidState)
        ));
        assert!(runtime.identities.pid_for(&child).is_ok());
        assert!(runtime.identities.parent_pid_for(&child).is_err());
        assert!(runtime.credentials.credentials(&child).is_err());
        assert!(
            runtime
                .signals
                .disposition(&child, Signal::new(2).unwrap())
                .is_err()
        );

        runtime
            .retire_unpublished_fork_child_identity(&mut child)
            .unwrap();
        assert_eq!(child.state(), kernal_process::ProcessState::Exited);
    }

    #[test]
    fn runtime_retains_bounded_additional_process_owners() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let child =
            Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let child_space_object = child_space.address_space_object();

        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid child owner pair must fit"),
        };
        assert_eq!(slot, 1);
        assert_eq!(runtime.process_slot_count(), 2);
        let (observed_process, observed_space) =
            runtime.process_parts_for_object_id(child_id).unwrap();
        assert_eq!(observed_process.id(), child_id);
        assert_eq!(observed_space.owner_process(), child_id);
        assert_eq!(observed_space.address_space_object(), child_space_object);
    }

    #[test]
    fn wait_publication_token_is_linear_and_bound_to_exact_runtime_slot() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let (child, child_space) = runtime
            .create_unpublished_fork_child_for_scheduler_thread(current, &mut backend)
            .unwrap();
        let child_id = child.id();
        runtime
            .bind_unpublished_fork_child_identity(current, &child)
            .unwrap();
        let publication = runtime
            .track_unpublished_fork_child_wait(current, &child)
            .unwrap();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid exact child owner pair must fit bounded runtime"),
        };

        runtime
            .adopt_additional_process_wait_publication(slot, child_id, publication)
            .unwrap();
        assert!(matches!(
            runtime.take_unpublished_additional_process(slot, child_id),
            Err(Error::InvalidState)
        ));

        let publication = runtime
            .take_additional_process_wait_publication(slot, child_id)
            .unwrap();
        assert!(matches!(
            runtime.take_additional_process_wait_publication(slot, child_id),
            Err(Error::InvalidState)
        ));
        runtime
            .cancel_unpublished_fork_child_wait(publication)
            .unwrap();

        let (mut child, _child_space) = runtime
            .take_unpublished_additional_process(slot, child_id)
            .unwrap();
        runtime
            .retire_unpublished_fork_child_identity(&mut child)
            .unwrap();
    }

    #[test]
    fn unpublished_runtime_authority_receipt_cannot_select_another_process() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let initial_id = runtime.process.id();
        let child =
            Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid unpublished child owner pair must fit"),
        };

        assert!(matches!(
            runtime.with_unpublished_additional_process_authority(
                slot,
                initial_id,
                |_process, _objects, _bindings, _identities, _exits| (),
            ),
            Err(Error::InvalidState)
        ));
        let observed = runtime
            .with_unpublished_additional_process_authority(
                slot,
                child_id,
                |process, _objects, _bindings, _identities, _exits| process.id(),
            )
            .unwrap();
        assert_eq!(observed, child_id);
        assert_eq!(runtime.process_slot_count(), 2);
    }

    #[test]
    fn unpublished_runtime_slot_take_is_exact_and_preserves_other_owners() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let initial_id = runtime.process.id();
        let child =
            Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let child_space_id = child_space.address_space_object();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid unpublished child owner pair must fit"),
        };
        assert_eq!(runtime.process_slot_count(), 2);

        assert!(matches!(
            runtime.take_unpublished_additional_process(slot, initial_id),
            Err(Error::InvalidState)
        ));
        assert_eq!(runtime.process_slot_count(), 2);
        assert_eq!(runtime.process.id(), initial_id);
        assert_eq!(
            runtime
                .process_parts_for_object_id(child_id)
                .unwrap()
                .1
                .address_space_object(),
            child_space_id
        );

        let (returned_child, returned_space) = runtime
            .take_unpublished_additional_process(slot, child_id)
            .unwrap();
        assert_eq!(returned_child.id(), child_id);
        assert_eq!(returned_space.owner_process(), child_id);
        assert_eq!(returned_space.address_space_object(), child_space_id);
        assert_eq!(runtime.process_slot_count(), 1);
        assert_eq!(runtime.process.id(), initial_id);
        assert!(matches!(
            runtime.take_unpublished_additional_process(slot, child_id),
            Err(Error::InvalidState)
        ));
        assert!(matches!(
            runtime.process_parts_for_object_id(child_id),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn scheduler_generation_selects_exact_retained_process_owner() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();

        let initial_local = scheduler.create(10).unwrap();
        let initial_global = GlobalThreadId::new(CPU0, initial_local);
        let initial_handle = runtime
            .process
            .attach_thread(
                &mut runtime.objects,
                &mut runtime.bindings,
                &scheduler,
                CPU0,
                initial_global,
            )
            .unwrap();
        let initial_tid = runtime
            .identities
            .bind_leader(
                &runtime.process,
                &runtime.objects,
                &runtime.bindings,
                &scheduler,
                CPU0,
                initial_handle,
            )
            .unwrap();

        let mut child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        runtime
            .identities
            .bind_child(&runtime.process, &child)
            .unwrap();
        runtime
            .credentials
            .inherit_child(&runtime.identities, &runtime.process, &child)
            .unwrap();
        runtime
            .signals
            .inherit_child(&runtime.identities, &runtime.process, &child)
            .unwrap();
        let child_local = scheduler.create(10).unwrap();
        let child_global = GlobalThreadId::new(CPU0, child_local);
        let child_handle = child
            .attach_thread(
                &mut runtime.objects,
                &mut runtime.bindings,
                &scheduler,
                CPU0,
                child_global,
            )
            .unwrap();
        let child_tid = runtime
            .identities
            .bind_leader(
                &child,
                &runtime.objects,
                &runtime.bindings,
                &scheduler,
                CPU0,
                child_handle,
            )
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        assert!(
            runtime
                .install_additional_process(child, child_space)
                .is_ok()
        );
        let Ok((selected_initial, selected_initial_space, observed_initial_tid)) =
            runtime.process_parts_for_scheduler_thread(initial_global)
        else {
            panic!("initial scheduler generation must resolve to its retained Process owner");
        };
        assert_eq!(selected_initial.id(), runtime.process.id());
        assert_eq!(selected_initial_space.owner_process(), runtime.process.id());
        assert_eq!(observed_initial_tid, initial_tid);

        let Ok((selected_child, selected_child_space, observed_child_tid)) =
            runtime.process_parts_for_scheduler_thread(child_global)
        else {
            panic!("child scheduler generation must resolve to its retained Process owner");
        };
        assert_eq!(selected_child.id(), child_id);
        assert_eq!(selected_child_space.owner_process(), child_id);
        assert_eq!(observed_child_tid, child_tid);

        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: child_local.slot,
                generation: child_local.generation.wrapping_add(1),
            },
        );
        assert!(matches!(
            runtime.process_parts_for_scheduler_thread(stale),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn exited_child_publishes_normal_wait_status_without_releasing_runtime_slot() {
        let mut backend = TestBackend::new(16);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        let child_pid = runtime
            .identities
            .bind_child(&runtime.process, &child)
            .unwrap();
        let publication = runtime
            .wait
            .track_child(&mut runtime.identities, &runtime.process, &child)
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid child owner pair must fit"),
        };
        assert!(
            runtime
                .adopt_additional_process_wait_publication(slot, child_id, publication)
                .is_ok()
        );

        runtime
            .with_unpublished_additional_process_authority(
                slot,
                child_id,
                |process, objects, bindings, identities, _exits| {
                    process.exit(objects, bindings).unwrap();
                    identities.retire_process(process).unwrap();
                },
            )
            .unwrap();
        runtime
            .publish_normal_process_exit_wait(child_id, 7)
            .unwrap();

        // Zombie publication must not consume the linear slot token or release Process/AddressSpace
        // ownership. WNOWAIT proves the status while keeping destructive reap for the later syscall
        // transaction.
        assert!(
            runtime
                .take_unpublished_additional_process(slot, child_id)
                .is_err()
        );
        let observed = runtime
            .wait
            .wait(
                &runtime.process,
                kernal_linux_wait::WaitSelector::Pid(child_pid),
                kernal_linux_wait::WaitOptions::new(false, true),
            )
            .unwrap();
        let kernal_linux_wait::WaitOutcome::Ready(observation) = observed else {
            panic!("expected retained zombie observation");
        };
        assert_eq!(observation.pid(), child_pid);
        assert_eq!(observation.status().raw(), 7 << 8);
        assert_eq!(runtime.process_slot_count(), 2);
    }

    #[test]
    fn two_phase_wait_observation_reaps_only_after_explicit_commit() {
        let mut backend = TestBackend::new(16);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        let child_pid = runtime
            .bind_unpublished_fork_child_identity(current, &child)
            .unwrap();
        let publication = runtime
            .track_unpublished_fork_child_wait(current, &child)
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid child owner pair must fit"),
        };
        assert!(
            runtime
                .adopt_additional_process_wait_publication(slot, child_id, publication)
                .is_ok()
        );
        runtime
            .with_unpublished_additional_process_authority(
                slot,
                child_id,
                |process, objects, bindings, identities, _exits| {
                    process.exit(objects, bindings).unwrap();
                    identities.retire_process(process).unwrap();
                },
            )
            .unwrap();
        runtime
            .publish_normal_process_exit_wait(child_id, 9)
            .unwrap();

        let first = runtime
            .observe_wait_for_scheduler_thread(current, WaitSelector::Pid(child_pid), false)
            .unwrap();
        let WaitOutcome::Ready(observation) = first else {
            panic!("expected zombie observation");
        };
        assert_eq!(observation.child(), child_id);
        assert_eq!(observation.status().raw(), 9 << 8);
        assert_eq!(runtime.process_slot_count(), 2);

        // A second phase-1 observation proves the first did not reap or release the child.
        assert_eq!(
            runtime
                .observe_wait_for_scheduler_thread(current, WaitSelector::Pid(child_pid), false)
                .unwrap(),
            WaitOutcome::Ready(observation)
        );
        assert_eq!(runtime.process_slot_count(), 2);

        runtime
            .commit_wait_reap_for_scheduler_thread(current, observation)
            .unwrap();
        assert_eq!(runtime.process_slot_count(), 1);
        assert_eq!(
            runtime.observe_wait_for_scheduler_thread(current, WaitSelector::Pid(child_pid), true,),
            Err(Error::Wait(kernal_linux_wait::Error::NoChild))
        );
    }

    #[test]
    fn wait_wnohang_observation_keeps_running_child_and_runtime_slot() {
        let mut backend = TestBackend::new(16);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        let child_pid = runtime
            .bind_unpublished_fork_child_identity(current, &child)
            .unwrap();
        let publication = runtime
            .track_unpublished_fork_child_wait(current, &child)
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let slot = match runtime.install_additional_process(child, child_space) {
            Ok(slot) => slot,
            Err(_) => panic!("valid child owner pair must fit"),
        };
        assert!(
            runtime
                .adopt_additional_process_wait_publication(slot, child_id, publication)
                .is_ok()
        );

        assert_eq!(
            runtime
                .observe_wait_for_scheduler_thread(current, WaitSelector::Pid(child_pid), true)
                .unwrap(),
            WaitOutcome::NoHang
        );
        assert_eq!(runtime.process_slot_count(), 2);
    }

    #[test]
    fn exact_child_generation_owns_its_exit_ticket_and_finalizer_process() {
        let mut backend = TestBackend::new(32);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let initial = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let initial_id = runtime.process.id();

        let mut child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        runtime
            .identities
            .bind_child(&runtime.process, &child)
            .unwrap();
        runtime
            .credentials
            .inherit_child(&runtime.identities, &runtime.process, &child)
            .unwrap();
        runtime
            .signals
            .inherit_child(&runtime.identities, &runtime.process, &child)
            .unwrap();
        let child_local = scheduler.create(10).unwrap();
        let child_global = GlobalThreadId::new(CPU0, child_local);
        let child_handle = child
            .attach_thread(
                &mut runtime.objects,
                &mut runtime.bindings,
                &scheduler,
                CPU0,
                child_global,
            )
            .unwrap();
        runtime
            .identities
            .bind_leader(
                &child,
                &runtime.objects,
                &runtime.bindings,
                &scheduler,
                CPU0,
                child_handle,
            )
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        match runtime.install_additional_process(child, child_space) {
            Ok(_) => {}
            Err(_) => panic!("valid child owner pair must fit"),
        }

        runtime.prepare_thread_exit(child_global, 23).unwrap();
        assert_eq!(runtime.pending_thread_exit(CPU0), Some(child_global));
        assert_eq!(runtime.pending_thread_exit(CpuIndex(1)), None);
        let (pending, ticket) = runtime
            .pending_exits
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap();
        assert_eq!(pending, child_global);
        assert_eq!(ticket.process(), child_id);
        assert_ne!(ticket.process(), initial_id);
        assert_eq!(runtime.process.id(), initial_id);
        assert_eq!(runtime.process.state(), kernal_process::ProcessState::Live);

        let selected = runtime
            .finalize_pending_thread_exit(
                child_global,
                |ticket, _exits, process, _objects, _bindings, _identities| {
                    assert_eq!(ticket.process(), child_id);
                    assert_eq!(process.id(), child_id);
                    Ok(process.id())
                },
            )
            .unwrap();
        assert_eq!(selected, child_id);
        assert_eq!(runtime.process.id(), initial_id);
        assert_eq!(runtime.process.state(), kernal_process::ProcessState::Live);
        assert!(runtime.pending_thread_exit(CPU0).is_none());
        assert_eq!(
            runtime
                .process_parts_for_scheduler_thread(initial)
                .unwrap()
                .0
                .id(),
            initial_id
        );
    }

    #[test]
    fn stale_or_wrong_cpu_generation_cannot_prepare_an_exit_ticket() {
        let mut backend = TestBackend::new(8);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: current.local.slot,
                generation: current.local.generation.wrapping_add(1),
            },
        );
        let wrong_cpu = GlobalThreadId::new(CpuIndex(1), current.local);

        assert_eq!(
            runtime.prepare_thread_exit(stale, 1),
            Err(Error::InvalidState)
        );
        assert_eq!(
            runtime.prepare_thread_exit(wrong_cpu, 1),
            Err(Error::InvalidState)
        );
        assert!(runtime.pending_thread_exit(CPU0).is_none());
    }

    #[test]
    fn setpgid_adapter_resolves_exact_child_and_preserves_exec_barrier() {
        let mut backend = TestBackend::new(16);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let mut scheduler = RunQueue::<STEP15_RUNTIME_THREADS>::new();
        let current = bind_test_initial_generation(&mut runtime, &mut scheduler);
        let parent_pid = runtime.identities.bound_pid(&runtime.process).unwrap();
        let child = Process::<STEP15_RUNTIME_CAPS>::create_fork_child(
            &runtime.process,
            &mut runtime.objects,
        )
        .unwrap();
        let child_pid = runtime
            .identities
            .bind_child(&runtime.process, &child)
            .unwrap();
        let child_id = child.id();
        let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &child,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        match runtime.install_additional_process(child, child_space) {
            Ok(_) => {}
            Err(_) => panic!("valid child owner pair must fit"),
        }

        assert_eq!(
            runtime
                .setpgid_for_scheduler_thread(current, child_pid, 0)
                .unwrap(),
            Some(Ok(child_pid))
        );
        {
            let Step15LinuxRuntime {
                additional_processes,
                identities,
                ..
            } = &mut runtime;
            let child_process = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == child_id)
                .map(|slot| &slot.process)
                .unwrap();
            identities.mark_execed(child_process).unwrap();
        }
        assert_eq!(
            runtime
                .setpgid_for_scheduler_thread(current, child_pid, parent_pid.get() as i32)
                .unwrap(),
            Some(Err(LinuxIdentityError::ChildExeced))
        );
        assert_eq!(
            runtime.setpgid_for_scheduler_thread(
                current,
                NonZeroU32::new(i32::MAX as u32).unwrap(),
                0,
            ),
            Ok(None)
        );
    }

    #[test]
    fn full_process_slots_return_unconsumed_owners() {
        let mut backend = TestBackend::new(64);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        for expected in 1..STEP15_RUNTIME_PROCESSES {
            let child =
                Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                    .unwrap();
            let child_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
                &child,
                &runtime.objects,
                &mut backend,
            )
            .unwrap();
            let slot = match runtime.install_additional_process(child, child_space) {
                Ok(slot) => slot,
                Err(_) => panic!("bounded child slot must fit"),
            };
            assert_eq!(slot, expected);
        }
        assert_eq!(runtime.process_slot_count(), STEP15_RUNTIME_PROCESSES);

        let overflow =
            Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                .unwrap();
        let overflow_id = overflow.id();
        let overflow_space = BoundProcessAddressSpace::<STEP15_RUNTIME_VMAS>::create(
            &overflow,
            &runtime.objects,
            &mut backend,
        )
        .unwrap();
        let overflow_space_object = overflow_space.address_space_object();
        let (error, returned_process, returned_space) =
            match runtime.install_additional_process(overflow, overflow_space) {
                Ok(_) => panic!("full bounded runtime must reject another Process"),
                Err(failure) => failure,
            };
        assert_eq!(error, Error::ProcessSlotsFull);
        assert_eq!(returned_process.id(), overflow_id);
        assert_eq!(returned_space.owner_process(), overflow_id);
        assert_eq!(returned_space.address_space_object(), overflow_space_object);
        assert_eq!(runtime.process_slot_count(), STEP15_RUNTIME_PROCESSES);
    }

    #[test]
    fn process_slot_lookup_is_exact_object_generation_only() {
        let mut backend = TestBackend::new(16);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let initial_id = runtime.process().id();
        let unrelated =
            Process::<STEP15_RUNTIME_CAPS>::create(&mut runtime.objects, Personality::Linux)
                .unwrap();
        let unrelated_id = unrelated.id();
        assert_eq!(
            runtime
                .process_parts_for_object_id(initial_id)
                .unwrap()
                .0
                .id(),
            initial_id
        );
        assert!(matches!(
            runtime.process_parts_for_object_id(unrelated_id),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn runtime_owns_one_generation_safe_linux_break_table() {
        let mut backend = TestBackend::new(4);
        let mut runtime = Step15LinuxRuntime::create(&mut backend).unwrap();
        let initial_break = USER_MIN + 0x1234;
        runtime.register_initial_break(initial_break).unwrap();
        assert_eq!(
            runtime.vm.current_break(runtime.process().id()).unwrap(),
            initial_break
        );
        assert!(runtime.register_initial_break(initial_break).is_err());
    }

    #[test]
    fn cell_initializes_once_and_serializes_runtime_borrows() {
        let cell = RuntimeCell::new();
        let mut backend = TestBackend::new(4);
        cell.initialize(&mut backend).unwrap();
        assert_eq!(
            cell.initialize(&mut backend),
            Err(Error::AlreadyInitialized)
        );

        cell.with_runtime(|runtime| {
            assert_eq!(cell.state.load(Ordering::Acquire), BORROWED);
            assert!(matches!(cell.with_runtime(|_| ()), Err(Error::Busy)));
            assert_eq!(runtime.process().personality(), Personality::Linux);
        })
        .unwrap();
        assert_eq!(cell.state.load(Ordering::Acquire), READY);
    }

    #[test]
    fn failed_root_construction_poison_prevents_retry() {
        let cell = RuntimeCell::new();
        let mut empty = TestBackend::new(0);
        assert!(matches!(
            cell.initialize(&mut empty),
            Err(Error::AddressSpace(_))
        ));
        let mut replacement = TestBackend::new(4);
        assert_eq!(cell.initialize(&mut replacement), Err(Error::Poisoned));
        assert!(matches!(cell.with_runtime(|_| ()), Err(Error::Poisoned)));
    }
}
