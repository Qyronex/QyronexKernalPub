// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::num::NonZeroU32;
use kernal_capability::{CapHandle, CapRights, ObjectId};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{
    Error as ProcessError, Personality, Process, ProcessState, StagedThreadRollbackProof,
    ThreadObjectBindings,
};
use kernal_scheduler::RunQueue;
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof};

/// Linux task IDs are positive signed 32-bit values at the ABI boundary.
pub const MAX_LINUX_TASK_ID: u32 = i32::MAX as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Exhausted,
    ProcessCapacity,
    ThreadCapacity,
    ThreadNotBound,
    LeaderCannotRetire,
    NotLinuxProcess,
    ProcessExited,
    ProcessStillLive,
    LeaderNotBound,
    LeaderAlreadyBound,
    ProcessNotBound,
    InvalidParent,
    AlreadyParented,
    ParentNotBound,
    InvalidProcessGroup,
    InvalidProcessGroupTarget,
    ChildExeced,
    DifferentSession,
    SessionLeader,
    ProcessGroupLeader,
    ProcessGroupNotFound,
    Process(ProcessError),
}

impl From<ProcessError> for Error {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}

/// Result of releasing one exact non-leader Linux thread after scheduler reap.
///
/// The scheduler identity, canonical process-local root handle and Linux TID are returned only after
/// the Process/CSpace Thread authority and the matching bounded Linux identity record are gone. This
/// value is diagnostic/finalization metadata; it cannot recreate any of the consumed authorities.
#[derive(Debug, Eq, PartialEq)]
pub struct RetiredThreadIdentity {
    scheduler_thread: GlobalThreadId,
    thread_handle: CapHandle,
    linux_tid: NonZeroU32,
}

impl RetiredThreadIdentity {
    pub const fn scheduler_thread(&self) -> GlobalThreadId {
        self.scheduler_thread
    }

    pub const fn thread_handle(&self) -> CapHandle {
        self.thread_handle
    }

    pub const fn linux_tid(&self) -> NonZeroU32 {
        self.linux_tid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadKey {
    object: ObjectId,
    scheduler_thread: GlobalThreadId,
}

/// Exact live parent binding retained alongside Linux-visible scalar identity.
///
/// `ObjectId` is generation-safe but not authority. Keeping it beside the parent's PID prevents a
/// recycled object-table slot or a caller-supplied scalar PID from manufacturing a parent relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParentLink {
    process: ObjectId,
    pid: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessRecord {
    process: ObjectId,
    pid: NonZeroU32,
    leader: Option<ThreadKey>,
    parent: Option<ParentLink>,
    did_exec: bool,
    process_group: NonZeroU32,
    session: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadRecord {
    process: ObjectId,
    key: ThreadKey,
    tid: NonZeroU32,
}

/// Monotonic allocator shared by the PID/TID namespace.
///
/// IDs never encode ObjectIds, capability handles, CPU numbers or scheduler slots. Exhaustion fails
/// closed instead of wrapping and accidentally reviving a stale userspace identifier.
struct LinuxIdAllocator {
    next: u32,
}

impl LinuxIdAllocator {
    const fn new() -> Self {
        Self { next: 1 }
    }

    fn allocate(&mut self) -> Result<NonZeroU32, Error> {
        if self.next == 0 || self.next > MAX_LINUX_TASK_ID {
            return Err(Error::Exhausted);
        }
        let value = NonZeroU32::new(self.next).ok_or(Error::Exhausted)?;
        self.next = self.next.checked_add(1).unwrap_or(0);
        Ok(value)
    }
}

/// Fixed-capacity, architecture-neutral Linux PID/TID registry.
///
/// The registry is the sole Linux task-identity owner. Repeating a lookup for the same exact
/// generation-safe Process or Thread returns the same Linux-visible scalar instead of allocating a
/// second identity. Step 30 extends the same owner with exact parent, process-group and session
/// identity; it does not create a second PID/PGID/SID registry or accept scalar PIDs as Process
/// authority. Thread calls never accept a caller-constructed `ResolvedThread`; they resolve
/// process-local CONTROL authority through [`Process::resolve_thread`] on every bind/lookup.
///
/// A process leader is bound once explicitly and has Linux `TID == PID`. Additional threads draw
/// monotonically from the same namespace. A standalone Process begins as its own process-group and
/// session leader; [`Self::bind_child`] replaces those bootstrap values with the exact parent's group
/// and session before child publication. Retiring an exited process frees bounded registry slots,
/// but numeric IDs are never reused.
pub struct LinuxIdentityTable<const PROCESSES: usize, const THREADS: usize> {
    allocator: LinuxIdAllocator,
    processes: [Option<ProcessRecord>; PROCESSES],
    threads: [Option<ThreadRecord>; THREADS],
}

impl<const PROCESSES: usize, const THREADS: usize> LinuxIdentityTable<PROCESSES, THREADS> {
    pub const fn new() -> Self {
        Self {
            allocator: LinuxIdAllocator::new(),
            processes: [None; PROCESSES],
            threads: [None; THREADS],
        }
    }

    /// Returns the stable Linux PID for one exact live Linux Process generation.
    pub fn pid_for<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        if let Some(record) = self.process_record(process_id) {
            return Ok(record.pid);
        }

        let slot = self
            .processes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ProcessCapacity)?;
        let pid = self.allocator.allocate()?;
        self.processes[slot] = Some(ProcessRecord {
            process: process_id,
            pid,
            leader: None,
            parent: None,
            did_exec: false,
            process_group: pid,
            session: pid,
        });
        Ok(pid)
    }

    /// Binds one exact live child Process generation to one exact live parent Process generation.
    ///
    /// Parent and child PIDs are allocated by this same table. Repeating the identical generation-safe
    /// relation is idempotent. Self-parenting and attempts to replace an already-published parent fail
    /// closed. A newly bound child inherits the parent's exact current process group and session in
    /// the same transaction. The relation carries no Process, scheduler, AddressSpace or capability
    /// authority.
    pub fn bind_child<const PARENT_CAPS: usize, const CHILD_CAPS: usize>(
        &mut self,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let parent_id = live_linux_process(parent)?;
        let child_id = live_linux_process(child)?;
        if parent_id == child_id {
            return Err(Error::InvalidParent);
        }

        let parent_pid = self.pid_for(parent)?;
        let parent_record = self
            .process_record(parent_id)
            .ok_or(Error::ParentNotBound)?;
        let child_pid = self.pid_for(child)?;
        let child_index = self
            .process_record_index(child_id)
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.processes[child_index].ok_or(Error::ProcessNotBound)?;
        let link = ParentLink {
            process: parent_id,
            pid: parent_pid,
        };
        match record.parent {
            None => {
                record.parent = Some(link);
                record.process_group = parent_record.process_group;
                record.session = parent_record.session;
            }
            Some(existing) if existing == link => return Ok(child_pid),
            Some(_) => return Err(Error::AlreadyParented),
        }
        self.processes[child_index] = Some(record);
        Ok(child_pid)
    }

    /// Returns the Linux-visible parent PID for one exact live child Process generation.
    ///
    /// The lookup first validates the child's generation-safe Process identity, then reads the parent
    /// link already established by [`Self::bind_child`]. The returned PID is observation only and is
    /// never accepted back as relationship authority.
    pub fn parent_pid_for<const CAPS: usize>(
        &self,
        child: &Process<CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let child_id = live_linux_process(child)?;
        self.process_record(child_id)
            .ok_or(Error::ProcessNotBound)?
            .parent
            .map(|parent| parent.pid)
            .ok_or(Error::ParentNotBound)
    }

    /// Returns whether the exact live child is already bound to this exact live parent generation.
    ///
    /// This is a read-only generation check used by later publication/rollback owners. Equal numeric
    /// PIDs are insufficient: both Process ObjectIds must match the stored relation.
    pub fn is_child_of<const PARENT_CAPS: usize, const CHILD_CAPS: usize>(
        &self,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
    ) -> Result<bool, Error> {
        let parent_id = live_linux_process(parent)?;
        let child_id = live_linux_process(child)?;
        let record = self
            .process_record(child_id)
            .ok_or(Error::ProcessNotBound)?;
        Ok(record.parent.is_some_and(|link| link.process == parent_id))
    }

    /// Returns the exact Process ObjectId already bound to one live Linux PID.
    ///
    /// This is a bounded read-only observation over the canonical ProcessRecord table. The returned
    /// ObjectId is observation only: callers must select and revalidate the retained Process owner
    /// before any operation. No PID is allocated and no identity relationship is mutated.
    pub fn process_object_for_pid(&self, pid: NonZeroU32) -> Result<ObjectId, Error> {
        self.processes
            .iter()
            .flatten()
            .find(|record| record.pid == pid)
            .map(|record| record.process)
            .ok_or(Error::ProcessNotBound)
    }

    /// Marks one exact live Process generation as having completed a successful exec transaction.
    ///
    /// This bit lives in the canonical ProcessRecord owner rather than a second exec registry. The
    /// caller must hold the exact Process authority and may publish the marker only after image
    /// replacement has committed. Repeating the same exact-generation marker is idempotent.
    pub fn mark_execed<const CAPS: usize>(&mut self, process: &Process<CAPS>) -> Result<(), Error> {
        let process_id = live_linux_process(process)?;
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let record = self.processes[index].ok_or(Error::ProcessNotBound)?;
        if record.did_exec {
            return Ok(());
        }
        self.processes[index] = Some(ProcessRecord {
            did_exec: true,
            ..record
        });
        Ok(())
    }

    /// Returns the Linux process-group ID for one exact live Process generation.
    ///
    /// The returned scalar is Linux observation metadata only. Callers must resolve any target PID to
    /// a canonical Process before reaching this owner.
    pub fn getpgid<const CAPS: usize>(&self, process: &Process<CAPS>) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        self.process_record(process_id)
            .map(|record| record.process_group)
            .ok_or(Error::ProcessNotBound)
    }

    /// Returns the Linux session ID for one exact live Process generation.
    pub fn getsid<const CAPS: usize>(&self, process: &Process<CAPS>) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        self.process_record(process_id)
            .map(|record| record.session)
            .ok_or(Error::ProcessNotBound)
    }

    /// Applies Linux `setpgid` policy to an already-resolved exact target Process.
    ///
    /// `target` must be `caller` or one exact child generation already published by this identity
    /// owner. A parent cannot move a child that has entered another session. Session leaders are
    /// immutable. `requested_pgid == 0` means the target's own PID; otherwise the requested group must
    /// already have a live member in the target session unless the target is creating its own group.
    /// This bounded scan deliberately reuses `ProcessRecord` instead of creating a second group
    /// registry.
    pub fn setpgid<const CALLER_CAPS: usize, const TARGET_CAPS: usize>(
        &mut self,
        caller: &Process<CALLER_CAPS>,
        target: &Process<TARGET_CAPS>,
        requested_pgid: i32,
    ) -> Result<NonZeroU32, Error> {
        let caller_id = live_linux_process(caller)?;
        let target_id = live_linux_process(target)?;
        let caller_record = self
            .process_record(caller_id)
            .ok_or(Error::ProcessNotBound)?;
        let target_index = self
            .process_record_index(target_id)
            .ok_or(Error::ProcessNotBound)?;
        let target_record = self.processes[target_index].ok_or(Error::ProcessNotBound)?;

        if target_id != caller_id
            && !target_record
                .parent
                .is_some_and(|parent| parent.process == caller_id)
        {
            return Err(Error::InvalidProcessGroupTarget);
        }
        // Linux forbids a parent from changing an exact child generation's process group after that
        // child has successfully exec'd. Relationship validation deliberately comes first so an
        // unrelated target cannot be laundered into an EACCES-style child-exec result. A process may
        // still change its own otherwise-valid PGID after exec.
        if target_id != caller_id && target_record.did_exec {
            return Err(Error::ChildExeced);
        }
        if target_record.session != caller_record.session {
            return Err(Error::DifferentSession);
        }
        if target_record.session == target_record.pid {
            return Err(Error::SessionLeader);
        }
        if requested_pgid < 0 {
            return Err(Error::InvalidProcessGroup);
        }

        let process_group = if requested_pgid == 0 {
            target_record.pid
        } else {
            NonZeroU32::new(requested_pgid as u32).ok_or(Error::InvalidProcessGroup)?
        };

        if process_group != target_record.pid
            && !self.process_group_exists(target_record.session, process_group)
        {
            return Err(Error::ProcessGroupNotFound);
        }

        self.processes[target_index] = Some(ProcessRecord {
            process_group,
            ..target_record
        });
        Ok(process_group)
    }

    /// Creates a new Linux session for one exact live Process generation.
    ///
    /// Linux forbids `setsid` whenever any live process group already has the caller's PID as its
    /// process-group ID. The caller need not currently be a member of that group: another live member
    /// can keep PGID == caller PID alive after the caller has moved elsewhere. Success makes the
    /// caller both session leader and process-group leader using its already-allocated PID; no new
    /// scalar identity is allocated.
    pub fn setsid<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let record = self.processes[index].ok_or(Error::ProcessNotBound)?;
        if self
            .processes
            .iter()
            .flatten()
            .any(|candidate| candidate.process_group == record.pid)
        {
            return Err(Error::ProcessGroupLeader);
        }
        self.processes[index] = Some(ProcessRecord {
            process_group: record.pid,
            session: record.pid,
            ..record
        });
        Ok(record.pid)
    }

    /// Returns the already-bound Linux PID for one exact live Linux Process generation.
    ///
    /// This read-only trap/runtime lookup never allocates an ID and grants no Process, capability or
    /// scheduler authority. The leader must already have been bound through [`Self::bind_leader`].
    pub fn bound_pid<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        let record = self
            .process_record(process_id)
            .ok_or(Error::LeaderNotBound)?;
        if record.leader.is_none() {
            return Err(Error::LeaderNotBound);
        }
        Ok(record.pid)
    }

    /// Binds the process leader after freshly validating its process-local Thread authority.
    ///
    /// Repeating this call for the same exact Thread object/scheduler generation is idempotent.
    /// Attempting to replace the leader with a different generation fails closed.
    pub fn bind_leader<
        const CAPS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
        const SCHED_THREADS: usize,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        bindings: &ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<SCHED_THREADS>,
        scheduler_owner: CpuIndex,
        handle: CapHandle,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        let pid = self.pid_for(process)?;
        let resolved =
            process.resolve_thread(objects, bindings, scheduler, scheduler_owner, handle)?;
        let key = ThreadKey {
            object: resolved.object,
            scheduler_thread: resolved.scheduler_thread,
        };
        let process_index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessCapacity)?;
        let process_record = self.processes[process_index].ok_or(Error::ProcessCapacity)?;

        if let Some(leader) = process_record.leader {
            return if leader == key {
                Ok(pid)
            } else {
                Err(Error::LeaderAlreadyBound)
            };
        }

        if let Some(existing) = self.thread_record(process_id, key) {
            if existing.tid != pid {
                return Err(Error::LeaderAlreadyBound);
            }
        } else {
            let thread_slot = self
                .threads
                .iter()
                .position(Option::is_none)
                .ok_or(Error::ThreadCapacity)?;
            self.threads[thread_slot] = Some(ThreadRecord {
                process: process_id,
                key,
                tid: pid,
            });
        }

        let mut updated = process_record;
        updated.leader = Some(key);
        self.processes[process_index] = Some(updated);
        Ok(pid)
    }

    /// Returns the stable Linux TID after freshly resolving the supplied process-local Thread handle.
    ///
    /// The leader must have been bound before the process enters Linux EL0. Additional exact Thread
    /// generations are allocated once and repeated calls are idempotent.
    pub fn tid_for<
        const CAPS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
        const SCHED_THREADS: usize,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        bindings: &ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<SCHED_THREADS>,
        scheduler_owner: CpuIndex,
        handle: CapHandle,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        let _ = self.pid_for(process)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessCapacity)?;
        if process_record.leader.is_none() {
            return Err(Error::LeaderNotBound);
        }

        let resolved =
            process.resolve_thread(objects, bindings, scheduler, scheduler_owner, handle)?;
        let key = ThreadKey {
            object: resolved.object,
            scheduler_thread: resolved.scheduler_thread,
        };
        if let Some(record) = self.thread_record(process_id, key) {
            return Ok(record.tid);
        }

        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ThreadCapacity)?;
        let tid = self.allocator.allocate()?;
        self.threads[slot] = Some(ThreadRecord {
            process: process_id,
            key,
            tid,
        });
        Ok(tid)
    }

    /// Returns the already-bound Linux TID for one exact global scheduler generation.
    ///
    /// The caller must independently obtain `scheduler_thread` from the scheduler owner. The exact
    /// generation-safe identity is matched only against this process's existing registry record; no
    /// capability is resolved and no Linux ID is allocated. The returned scalar is not authority.
    pub fn bound_tid_for_scheduler_thread<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
        scheduler_thread: GlobalThreadId,
    ) -> Result<NonZeroU32, Error> {
        let process_id = live_linux_process(process)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::LeaderNotBound)?;
        if process_record.leader.is_none() {
            return Err(Error::LeaderNotBound);
        }

        self.threads
            .iter()
            .flatten()
            .find(|record| {
                record.process == process_id && record.key.scheduler_thread == scheduler_thread
            })
            .map(|record| record.tid)
            .ok_or(Error::ThreadNotBound)
    }

    /// Returns the exact scheduler generation already bound to one Linux TID in this exact Process.
    ///
    /// The scalar TID is lookup input only. This read-only observation allocates nothing and grants no
    /// scheduler or Process authority; callers must pass the returned GlobalThreadId back through the
    /// canonical owners before mutation. Monotonic TID allocation plus exact Process generation
    /// matching prevents stale numeric reuse from selecting another thread.
    pub fn scheduler_thread_for_tid<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
        tid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        let process_id = live_linux_process(process)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::LeaderNotBound)?;
        if process_record.leader.is_none() {
            return Err(Error::LeaderNotBound);
        }
        self.threads
            .iter()
            .flatten()
            .find(|record| record.process == process_id && record.tid == tid)
            .map(|record| record.key.scheduler_thread)
            .ok_or(Error::ThreadNotBound)
    }

    /// Returns one exact scheduler generation already bound to this exact live Process by bounded
    /// ordinal. This is a read-only observation over the canonical ThreadRecord table: it allocates
    /// no Linux ID, exposes no table reference and grants no scheduler or Process authority. `None`
    /// marks the end of the process-local bounded sequence. Callers must re-enter canonical owners
    /// before any mutation or notification.
    pub fn bound_scheduler_thread_at<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
        ordinal: usize,
    ) -> Result<Option<GlobalThreadId>, Error> {
        let process_id = live_linux_process(process)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::LeaderNotBound)?;
        if process_record.leader.is_none() {
            return Err(Error::LeaderNotBound);
        }
        Ok(self
            .threads
            .iter()
            .flatten()
            .filter(|record| record.process == process_id)
            .nth(ordinal)
            .map(|record| record.key.scheduler_thread))
    }

    /// Returns the canonical Process ObjectId already bound to one exact scheduler generation.
    ///
    /// This is a read-only integration resolver. It allocates no Linux ID, mutates no registry state
    /// and accepts no scalar PID/TID authority. Stale or unbound scheduler generations fail closed.
    pub fn process_object_for_scheduler_thread(
        &self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<ObjectId, Error> {
        self.threads
            .iter()
            .flatten()
            .find(|record| record.key.scheduler_thread == scheduler_thread)
            .map(|record| record.process)
            .ok_or(Error::ThreadNotBound)
    }

    /// Releases one exact non-leader Linux thread after scheduler-owner reap.
    ///
    /// The only scheduler authority accepted here is the non-Copy/non-Clone [`ReapedThreadProof`].
    /// The existing Process binding owner first resolves that proof to the canonical process-local
    /// CONTROL root. The Process then consumes the same proof to revoke the capability tree and
    /// destroy the Thread object/binding. Only after that infallible owner handoff succeeds is the
    /// exact Linux TID record removed. The monotonic numeric allocator is never rewound.
    ///
    /// Process leaders are deliberately rejected: their PID/TID record remains process-scoped and is
    /// released by [`Self::retire_process`] only after the whole Process reaches Exited.
    pub fn release_reaped_thread_identity<
        const CAPS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
    >(
        &mut self,
        process: &mut Process<CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        proof: ReapedThreadProof,
    ) -> Result<RetiredThreadIdentity, Error> {
        let process_id = live_linux_process(process)?;
        let scheduler_thread = proof.thread();
        let thread_handle = bindings
            .authority_for_reaped_proof(objects, process_id, &proof)
            .map_err(ProcessError::ThreadBinding)?;
        let resolved = process.resolve_object(objects, thread_handle, CapRights::CONTROL)?;
        let key = ThreadKey {
            object: resolved.object,
            scheduler_thread,
        };
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessCapacity)?;
        let index = self
            .threads
            .iter()
            .position(|entry| {
                entry.is_some_and(|record| record.process == process_id && record.key == key)
            })
            .ok_or(Error::ThreadNotBound)?;
        let record = self.threads[index].ok_or(Error::ThreadNotBound)?;
        if process_record.leader == Some(record.key) {
            return Err(Error::LeaderCannotRetire);
        }

        let released = process.release_reaped_thread(objects, bindings, proof, thread_handle)?;
        debug_assert_eq!(released, scheduler_thread);
        self.threads[index] = None;
        Ok(RetiredThreadIdentity {
            scheduler_thread: released,
            thread_handle,
            linux_tid: record.tid,
        })
    }

    /// Reclaims the bounded Linux identity slot for one exact never-published clone child.
    ///
    /// The only authority accepted here is the linear [`StagedThreadRollbackProof`] produced by the
    /// Process owner after it has already revoked the process-local capability tree and destroyed the
    /// matching Thread object/binding. The proof binds the Process ObjectId, destroyed Thread ObjectId
    /// and exact GlobalThreadId; callers cannot authorize this safe API with reconstructed scheduler
    /// scalars. Numeric TIDs remain permanently consumed because the monotonic allocator is never
    /// rewound.
    ///
    /// On success the exact GlobalThreadId is returned only after the identity record is gone. The
    /// clone owner must immediately use that generation for canonical scheduler staged cancellation
    /// under the same owner-quiescent transaction.
    pub fn rollback_unpublished_thread_tid<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        proof: StagedThreadRollbackProof,
        tid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        let process_id = live_linux_process(process)?;
        self.rollback_unpublished_thread_tid_parts(
            process_id,
            proof.process(),
            proof.thread_object(),
            proof.scheduler_thread(),
            tid,
        )
    }

    fn rollback_unpublished_thread_tid_parts(
        &mut self,
        process_id: ObjectId,
        proof_process: ObjectId,
        thread_object: ObjectId,
        scheduler_thread: GlobalThreadId,
        tid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        if proof_process != process_id {
            return Err(Error::ThreadNotBound);
        }
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessCapacity)?;
        let index = self
            .threads
            .iter()
            .position(|entry| {
                entry.is_some_and(|record| {
                    record.process == process_id
                        && record.key.object == thread_object
                        && record.key.scheduler_thread == scheduler_thread
                        && record.tid == tid
                })
            })
            .ok_or(Error::ThreadNotBound)?;
        let record = self.threads[index].ok_or(Error::ThreadNotBound)?;
        if process_record.leader == Some(record.key) {
            return Err(Error::LeaderCannotRetire);
        }
        self.threads[index] = None;
        Ok(scheduler_thread)
    }

    /// Reclaims the Linux leader identity for one exact never-published fork child.
    ///
    /// Normal leader teardown remains process-scoped and is intentionally rejected by
    /// [`Self::rollback_unpublished_thread_tid`]. This narrower rollback exists only for a fork
    /// leader which never crossed scheduler Ready/Published: Process/CSpace Thread authority must
    /// already have been destroyed by [`Process::rollback_staged_thread`], yielding the consumed
    /// linear [`StagedThreadRollbackProof`]. The proof is matched against the exact Process,
    /// Thread-object and scheduler generations plus the already-bound PID/TID. Success removes only
    /// the leader ThreadRecord and clears `ProcessRecord::leader`; the child's PID/PPID/PGID/SID
    /// record remains until the exact Process reaches Exited and [`Self::retire_process`] consumes it.
    /// Numeric task IDs are never rewound.
    pub fn rollback_unpublished_leader_identity<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        proof: StagedThreadRollbackProof,
        pid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        let process_id = live_linux_process(process)?;
        self.rollback_unpublished_leader_identity_parts(
            process_id,
            proof.process(),
            proof.thread_object(),
            proof.scheduler_thread(),
            pid,
        )
    }

    fn rollback_unpublished_leader_identity_parts(
        &mut self,
        process_id: ObjectId,
        proof_process: ObjectId,
        thread_object: ObjectId,
        scheduler_thread: GlobalThreadId,
        pid: NonZeroU32,
    ) -> Result<GlobalThreadId, Error> {
        if proof_process != process_id {
            return Err(Error::ThreadNotBound);
        }
        let process_index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let process_record = self.processes[process_index].ok_or(Error::ProcessNotBound)?;
        let leader = process_record.leader.ok_or(Error::LeaderNotBound)?;
        if leader.object != thread_object
            || leader.scheduler_thread != scheduler_thread
            || process_record.pid != pid
        {
            return Err(Error::ThreadNotBound);
        }

        let thread_index = self
            .threads
            .iter()
            .position(|entry| {
                entry.is_some_and(|record| {
                    record.process == process_id && record.key == leader && record.tid == pid
                })
            })
            .ok_or(Error::ThreadNotBound)?;
        let record = self.threads[thread_index].ok_or(Error::ThreadNotBound)?;
        if record.key != leader || record.tid != process_record.pid {
            return Err(Error::ThreadNotBound);
        }

        self.threads[thread_index] = None;
        self.processes[process_index] = Some(ProcessRecord {
            leader: None,
            ..process_record
        });
        Ok(scheduler_thread)
    }

    /// Releases bounded registry slots only after normal Process teardown has completed.
    ///
    /// Linux-visible numeric IDs remain consumed forever, so stale userspace IDs cannot alias a
    /// recreated Process generation even when internal registry capacity is reclaimed.
    pub fn retire_process<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<(), Error> {
        if process.personality() != Personality::Linux {
            return Err(Error::NotLinuxProcess);
        }
        if process.state() != ProcessState::Exited {
            return Err(Error::ProcessStillLive);
        }
        let process_id = process.id();
        for record in &mut self.processes {
            if record.is_some_and(|record| record.process == process_id) {
                *record = None;
            }
        }
        for record in &mut self.threads {
            if record.is_some_and(|record| record.process == process_id) {
                *record = None;
            }
        }
        Ok(())
    }

    fn process_group_exists(&self, session: NonZeroU32, process_group: NonZeroU32) -> bool {
        self.processes
            .iter()
            .flatten()
            .any(|record| record.session == session && record.process_group == process_group)
    }

    fn process_record(&self, process: ObjectId) -> Option<ProcessRecord> {
        self.processes
            .iter()
            .flatten()
            .copied()
            .find(|record| record.process == process)
    }

    fn process_record_index(&self, process: ObjectId) -> Option<usize> {
        self.processes
            .iter()
            .position(|record| record.is_some_and(|record| record.process == process))
    }

    fn thread_record(&self, process: ObjectId, key: ThreadKey) -> Option<ThreadRecord> {
        self.threads
            .iter()
            .flatten()
            .copied()
            .find(|record| record.process == process && record.key == key)
    }
}

impl<const PROCESSES: usize, const THREADS: usize> Default
    for LinuxIdentityTable<PROCESSES, THREADS>
{
    fn default() -> Self {
        Self::new()
    }
}

fn live_linux_process<const CAPS: usize>(process: &Process<CAPS>) -> Result<ObjectId, Error> {
    if process.personality() != Personality::Linux {
        return Err(Error::NotLinuxProcess);
    }
    if process.state() != ProcessState::Live {
        return Err(Error::ProcessExited);
    }
    Ok(process.id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_process::ThreadObjectBindings;
    use kernal_scheduler::ThreadId;

    const CPU0: CpuIndex = CpuIndex(0);

    fn global(local: ThreadId) -> GlobalThreadId {
        GlobalThreadId::new(CPU0, local)
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
        (local, handle)
    }

    #[test]
    fn unpublished_leader_rollback_clears_only_leader_and_preserves_child_relation() {
        let mut objects = ObjectTable::<16>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (_parent_thread, parent_handle) =
            attach(&mut parent, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();
        let parent_pid = identities
            .bind_leader(
                &parent,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                parent_handle,
            )
            .unwrap();

        let mut child = Process::<8>::create_fork_child(&parent, &mut objects).unwrap();
        let (child_thread, child_handle) =
            attach(&mut child, &mut objects, &mut bindings, &mut scheduler);
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        assert_eq!(
            identities
                .bind_leader(&child, &objects, &bindings, &scheduler, CPU0, child_handle,)
                .unwrap(),
            child_pid
        );
        assert_eq!(identities.parent_pid_for(&child), Ok(parent_pid));

        let process_record = identities.process_record(child.id()).unwrap();
        let leader = process_record.leader.unwrap();
        assert_eq!(leader.scheduler_thread, global(child_thread));
        assert_eq!(process_record.pid, child_pid);

        assert_eq!(
            identities.rollback_unpublished_leader_identity_parts(
                child.id(),
                child.id(),
                leader.object,
                leader.scheduler_thread,
                child_pid,
            ),
            Ok(global(child_thread))
        );
        assert_eq!(identities.bound_pid(&child), Err(Error::LeaderNotBound));
        assert_eq!(identities.parent_pid_for(&child), Ok(parent_pid));
        assert!(identities.process_record(child.id()).is_some());
        assert!(
            identities
                .threads
                .iter()
                .flatten()
                .all(|record| record.process != child.id())
        );
    }

    #[test]
    fn unpublished_leader_rollback_rejects_stale_proof_without_mutation() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (leader_thread, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<2, 4>::new();
        let pid = identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();
        let leader = identities
            .process_record(process.id())
            .unwrap()
            .leader
            .unwrap();
        let stale = GlobalThreadId::new(
            CPU0,
            ThreadId {
                slot: leader_thread.slot,
                generation: leader_thread.generation.wrapping_add(1),
            },
        );

        assert_eq!(
            identities.rollback_unpublished_leader_identity_parts(
                process.id(),
                process.id(),
                leader.object,
                stale,
                pid,
            ),
            Err(Error::ThreadNotBound)
        );
        assert_eq!(identities.bound_pid(&process), Ok(pid));
        assert_eq!(
            identities.bound_tid_for_scheduler_thread(&process, global(leader_thread)),
            Ok(pid)
        );
    }

    #[test]
    fn tid_reverse_observation_returns_exact_scheduler_generation() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (leader_thread, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<2, 4>::new();
        let pid = identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();

        let (worker_thread, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
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
        assert_ne!(worker_tid, pid);
        assert_eq!(
            identities.scheduler_thread_for_tid(&process, pid),
            Ok(global(leader_thread))
        );
        assert_eq!(
            identities.scheduler_thread_for_tid(&process, worker_tid),
            Ok(global(worker_thread))
        );
        assert_eq!(
            identities.bound_scheduler_thread_at(&process, 0),
            Ok(Some(global(leader_thread)))
        );
        assert_eq!(
            identities.bound_scheduler_thread_at(&process, 1),
            Ok(Some(global(worker_thread)))
        );
        assert_eq!(identities.bound_scheduler_thread_at(&process, 2), Ok(None));
        let unknown = NonZeroU32::new(worker_tid.get().checked_add(1000).unwrap()).unwrap();
        assert_eq!(
            identities.scheduler_thread_for_tid(&process, unknown),
            Err(Error::ThreadNotBound)
        );
    }

    #[test]
    fn process_and_leader_bindings_are_idempotent_and_share_pid_tid() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (_leader, handle) = attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();

        let pid = identities.pid_for(&process).unwrap();
        assert_eq!(identities.pid_for(&process).unwrap(), pid);
        assert_eq!(
            identities
                .bind_leader(&process, &objects, &bindings, &scheduler, CPU0, handle)
                .unwrap(),
            pid
        );
        assert_eq!(
            identities
                .bind_leader(&process, &objects, &bindings, &scheduler, CPU0, handle)
                .unwrap(),
            pid
        );
        assert_eq!(
            identities
                .tid_for(&process, &objects, &bindings, &scheduler, CPU0, handle)
                .unwrap(),
            pid
        );
        assert_eq!(pid.get(), 1);
    }

    #[test]
    fn additional_thread_gets_one_stable_id_after_fresh_authority_resolution() {
        let mut objects = ObjectTable::<10>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (_leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (_worker, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();
        let pid = identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();

        let first = identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            )
            .unwrap();
        let second = identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_ne!(first, pid);
        assert_eq!(first.get(), 2);
    }

    #[test]
    fn bound_scalar_lookups_require_existing_generation_and_never_allocate() {
        let mut objects = ObjectTable::<12>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (worker, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<2, 4>::new();

        assert_eq!(identities.bound_pid(&process), Err(Error::LeaderNotBound));
        assert_eq!(
            identities.bound_tid_for_scheduler_thread(&process, global(leader)),
            Err(Error::LeaderNotBound)
        );
        assert_eq!(
            identities.process_object_for_scheduler_thread(global(leader)),
            Err(Error::ThreadNotBound)
        );

        let pid = identities
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
        let next_before = identities.allocator.next;

        assert_eq!(identities.bound_pid(&process), Ok(pid));
        assert_eq!(
            identities.bound_tid_for_scheduler_thread(&process, global(leader)),
            Ok(pid)
        );
        assert_eq!(
            identities.bound_tid_for_scheduler_thread(&process, global(worker)),
            Ok(worker_tid)
        );
        assert_eq!(
            identities.process_object_for_scheduler_thread(global(leader)),
            Ok(process.id())
        );
        assert_eq!(
            identities.process_object_for_scheduler_thread(global(worker)),
            Ok(process.id())
        );
        assert_eq!(
            identities.bound_tid_for_scheduler_thread(
                &process,
                GlobalThreadId::new(
                    CPU0,
                    ThreadId {
                        slot: worker.slot,
                        generation: worker.generation.wrapping_add(1),
                    },
                ),
            ),
            Err(Error::ThreadNotBound)
        );
        assert_eq!(
            identities.process_object_for_scheduler_thread(GlobalThreadId::new(
                CPU0,
                ThreadId {
                    slot: worker.slot,
                    generation: worker.generation.wrapping_add(1),
                },
            )),
            Err(Error::ThreadNotBound)
        );
        assert_eq!(identities.allocator.next, next_before);
    }

    #[test]
    fn unpublished_tid_parts_reclaim_slot_without_reusing_numeric_tid() {
        let mut objects = ObjectTable::<14>::new();
        let mut bindings = ThreadObjectBindings::<6>::new();
        let mut scheduler = RunQueue::<6>::new();
        let mut process = Process::<12>::create(&mut objects, Personality::Linux).unwrap();
        let (_leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (worker, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 4>::new();
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
        let abandoned = identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            )
            .unwrap();
        let worker_object = process
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, worker_handle)
            .unwrap()
            .object;

        assert_eq!(
            identities
                .rollback_unpublished_thread_tid_parts(
                    process.id(),
                    process.id(),
                    worker_object,
                    global(worker),
                    abandoned,
                )
                .unwrap(),
            global(worker)
        );
        assert_eq!(identities.allocator.next, 3);

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
        assert_ne!(replacement_tid, abandoned);
    }

    #[test]
    fn unpublished_tid_parts_reject_leader_and_mismatched_process() {
        let mut objects = ObjectTable::<10>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 4>::new();
        let pid = identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();
        let leader_object = process
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, leader_handle)
            .unwrap()
            .object;

        assert_eq!(
            identities.rollback_unpublished_thread_tid_parts(
                process.id(),
                process.id(),
                leader_object,
                global(leader),
                pid,
            ),
            Err(Error::LeaderCannotRetire)
        );

        let other = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        assert_eq!(
            identities.rollback_unpublished_thread_tid_parts(
                process.id(),
                other.id(),
                leader_object,
                global(leader),
                pid,
            ),
            Err(Error::ThreadNotBound)
        );
    }

    #[test]
    fn leader_cannot_be_replaced_by_another_thread_generation() {
        let mut objects = ObjectTable::<10>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (_leader, leader_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let (_worker, worker_handle) =
            attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();
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

        assert_eq!(
            identities.bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            ),
            Err(Error::LeaderAlreadyBound)
        );
    }

    #[test]
    fn tid_requires_leader_binding_before_linux_runtime_use() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (_thread, handle) = attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();

        assert_eq!(
            identities.tid_for(&process, &objects, &bindings, &scheduler, CPU0, handle),
            Err(Error::LeaderNotBound)
        );
    }

    #[test]
    fn stale_scheduler_generation_fails_fresh_resolution_instead_of_reusing_tid() {
        let mut objects = ObjectTable::<8>::new();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let (thread, handle) = attach(&mut process, &mut objects, &mut bindings, &mut scheduler);
        let mut identities = LinuxIdentityTable::<4, 8>::new();
        identities
            .bind_leader(&process, &objects, &bindings, &scheduler, CPU0, handle)
            .unwrap();

        scheduler.make_ready(thread).unwrap();
        assert_eq!(scheduler.schedule().unwrap(), Some(thread));
        scheduler.exit(thread).unwrap();
        scheduler.reap(thread).unwrap();

        assert!(matches!(
            identities.tid_for(&process, &objects, &bindings, &scheduler, CPU0, handle),
            Err(Error::Process(_))
        ));
    }

    #[test]
    fn native_and_exited_processes_fail_closed() {
        let mut objects = ObjectTable::<8>::new();
        let native = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let mut identities = LinuxIdentityTable::<4, 8>::new();
        assert_eq!(identities.pid_for(&native), Err(Error::NotLinuxProcess));

        let mut linux = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let bindings = ThreadObjectBindings::<1>::new();
        let _ = identities.pid_for(&linux).unwrap();
        linux.exit(&mut objects, &bindings).unwrap();
        assert_eq!(identities.pid_for(&linux), Err(Error::ProcessExited));
    }

    #[test]
    fn retired_process_reclaims_registry_slots_without_reusing_numeric_ids() {
        let mut objects = ObjectTable::<8>::new();
        let bindings = ThreadObjectBindings::<1>::new();
        let mut first = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut identities = LinuxIdentityTable::<1, 1>::new();
        let first_pid = identities.pid_for(&first).unwrap();
        assert_eq!(
            identities.retire_process(&first),
            Err(Error::ProcessStillLive)
        );
        first.exit(&mut objects, &bindings).unwrap();
        identities.retire_process(&first).unwrap();

        let second = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let second_pid = identities.pid_for(&second).unwrap();
        assert_ne!(first_pid, second_pid);
        assert_eq!(first_pid.get(), 1);
        assert_eq!(second_pid.get(), 2);
    }

    #[test]
    fn allocator_and_registry_capacity_fail_closed() {
        let mut identities = LinuxIdentityTable::<1, 1>::new();
        identities.allocator.next = MAX_LINUX_TASK_ID;
        let mut objects = ObjectTable::<8>::new();
        let first = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let second = Process::<4>::create(&mut objects, Personality::Linux).unwrap();

        assert_eq!(identities.pid_for(&first).unwrap().get(), MAX_LINUX_TASK_ID);
        assert_eq!(identities.pid_for(&second), Err(Error::ProcessCapacity));

        let mut another = LinuxIdentityTable::<2, 1>::new();
        another.allocator.next = 0;
        assert_eq!(another.pid_for(&second), Err(Error::Exhausted));
    }
}
