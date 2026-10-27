// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapHandle, ObjectId};
use kernal_object::{Error as ObjectError, ObjectKind, ObjectMeta, ObjectTable};
use kernal_percpu::CpuIndex;
use kernal_scheduler::{Error as SchedulerError, RunQueue, ThreadState};
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Object(ObjectError),
    Scheduler(SchedulerError),
    Capacity,
    AlreadyBound,
    NotBound,
    WrongOwner,
    WrongSchedulerOwner,
    StaleSchedulerThread,
    ThreadStillLive,
    WrongReapProof,
    AuthorityAlreadyPublished,
    AuthorityNotPublished,
}

impl From<ObjectError> for Error {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<SchedulerError> for Error {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

/// Exact Step-11 binding between one process-owned kernel object and one global scheduler identity.
///
/// [`GlobalThreadId`] remains the sole scheduler identity: it combines the owning CPU with the
/// existing local slot+generation [`kernal_scheduler::ThreadId`]. `ObjectId` remains the sole
/// kernel-object identity. Once the owning Process publishes the Thread object in its private CSpace,
/// `authority` records that exact root handle so teardown can revoke the entire derived capability
/// tree rather than trusting a caller-supplied descendant handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadObjectBinding {
    owner: ObjectId,
    object: ObjectId,
    scheduler_thread: GlobalThreadId,
    authority: Option<CapHandle>,
}

impl ThreadObjectBinding {
    pub const fn owner(self) -> ObjectId {
        self.owner
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn scheduler_thread(self) -> GlobalThreadId {
        self.scheduler_thread
    }

    pub const fn authority(self) -> Option<CapHandle> {
        self.authority
    }
}

#[derive(Clone, Copy)]
struct Slot {
    occupied: bool,
    binding: ThreadObjectBinding,
}

impl Slot {
    const EMPTY: Self = Self {
        occupied: false,
        binding: ThreadObjectBinding {
            owner: ObjectId(0),
            object: ObjectId(0),
            scheduler_thread: GlobalThreadId {
                cpu: CpuIndex(0),
                local: kernal_scheduler::ThreadId {
                    slot: 0,
                    generation: 0,
                },
            },
            authority: None,
        },
    };
}

/// Fixed-capacity process/thread ownership bindings for Step 11.
///
/// A binding is created only for a live `Process` object and an already-created scheduler thread on
/// the stated owner CPU. The owning Process then publishes a CONTROL root capability in its private
/// CSpace and records that root with [`publish_authority`](Self::publish_authority). The table never
/// controls scheduler lifetime itself. The owner must still perform scheduler
/// `exit -> teardown -> reap`; only then may the Process revoke the stored root and release the
/// Thread object/binding using an exact [`ReapedThreadProof`].
pub struct ThreadObjectBindings<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> ThreadObjectBindings<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reports whether this exact process generation still owns any thread binding.
    pub fn has_owner(&self, owner: ObjectId) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.occupied && slot.binding.owner == owner)
    }

    /// Creates one process-owned Thread object bound to an exact global scheduler identity.
    ///
    /// `scheduler_owner` must be the CPU that owns `scheduler`; this explicit check prevents an
    /// identically numbered local ThreadId on another CPU from satisfying the binding.
    pub fn bind<const OBJECTS: usize, const THREADS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        owner: ObjectId,
        scheduler_thread: GlobalThreadId,
    ) -> Result<ThreadObjectBinding, Error> {
        objects.resolve_kind(owner, ObjectKind::Process)?;
        self.validate_scheduler_owner(scheduler_owner, scheduler_thread)?;
        scheduler.state(scheduler_thread.local)?;

        if self
            .slots
            .iter()
            .any(|slot| slot.occupied && slot.binding.scheduler_thread == scheduler_thread)
        {
            return Err(Error::AlreadyBound);
        }

        let index = self
            .slots
            .iter()
            .position(|slot| !slot.occupied)
            .ok_or(Error::Capacity)?;

        let object = objects.create(ObjectMeta {
            kind: ObjectKind::Thread,
            owner_domain: 0,
            flags: 0,
        })?;
        let binding = ThreadObjectBinding {
            owner,
            object,
            scheduler_thread,
            authority: None,
        };
        self.slots[index] = Slot {
            occupied: true,
            binding,
        };
        self.len += 1;
        Ok(binding)
    }

    /// Records the exact process-local root capability after successful CSpace publication.
    pub(crate) fn publish_authority(
        &mut self,
        owner: ObjectId,
        object: ObjectId,
        authority: CapHandle,
    ) -> Result<ThreadObjectBinding, Error> {
        let index = self.slot_for_object(object)?;
        let mut binding = self.slots[index].binding;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        if binding.authority.is_some() {
            return Err(Error::AuthorityAlreadyPublished);
        }
        binding.authority = Some(authority);
        self.slots[index].binding = binding;
        Ok(binding)
    }

    /// Cancels a newly-created binding before any capability for it has been published.
    ///
    /// This is intentionally crate-private and exists only for `Process::attach_thread()` rollback.
    pub(crate) fn cancel_unpublished<const OBJECTS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        owner: ObjectId,
        object: ObjectId,
    ) -> Result<ThreadObjectBinding, Error> {
        let index = self.slot_for_object(object)?;
        let binding = self.slots[index].binding;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        if binding.authority.is_some() {
            return Err(Error::AuthorityAlreadyPublished);
        }
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;
        objects.destroy(binding.object)?;
        self.slots[index] = Slot::EMPTY;
        self.len -= 1;
        Ok(binding)
    }

    /// Removes an already CSpace-published binding for a scheduler generation that the caller has
    /// independently proven is still clone-Staged and therefore never runnable.
    ///
    /// The ordinary teardown path deliberately requires a [`ReapedThreadProof`]. Clone creation is
    /// different: external Process/TID authority must be rolled back *before* the scheduler owner may
    /// call its staged cancellation/reap primitive. This narrow helper closes that transaction without
    /// treating a normal published FUTEX-blocked thread as cancellable merely because it is Blocked.
    ///
    /// # Safety
    /// The caller must hold the scheduler owner's quiescence window and must have verified through the
    /// generation-owned ContextTable owner that `binding.scheduler_thread()` is still Staged. The
    /// scheduler generation must still be Blocked and must never have been Ready/Running/Published.
    pub(crate) unsafe fn release_published_staged<const OBJECTS: usize, const THREADS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        owner: ObjectId,
        object: ObjectId,
    ) -> Result<ThreadObjectBinding, Error> {
        let index = self.slot_for_object(object)?;
        let binding = self.slots[index].binding;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        if binding.authority.is_none() {
            return Err(Error::AuthorityNotPublished);
        }
        self.validate_scheduler_owner(scheduler_owner, binding.scheduler_thread)?;
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;
        match scheduler.state(binding.scheduler_thread.local) {
            Ok(ThreadState::Blocked) => {}
            Ok(_) => return Err(Error::ThreadStillLive),
            Err(SchedulerError::InvalidThread) => return Err(Error::StaleSchedulerThread),
            Err(error) => return Err(Error::Scheduler(error)),
        }
        objects.destroy(binding.object)?;
        self.slots[index] = Slot::EMPTY;
        self.len -= 1;
        Ok(binding)
    }

    /// Resolves a thread object only for its exact process owner, CPU owner and scheduler generation.
    pub fn resolve<const OBJECTS: usize, const THREADS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        owner: ObjectId,
        object: ObjectId,
    ) -> Result<ThreadObjectBinding, Error> {
        let binding = self.binding_for_object(object)?;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        self.validate_scheduler_owner(scheduler_owner, binding.scheduler_thread)?;
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;
        match scheduler.state(binding.scheduler_thread.local) {
            Ok(_) => Ok(binding),
            Err(SchedulerError::InvalidThread) => Err(Error::StaleSchedulerThread),
            Err(error) => Err(Error::Scheduler(error)),
        }
    }

    #[cfg(test)]
    fn validate_reaped<const OBJECTS: usize, const THREADS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        owner: ObjectId,
        object: ObjectId,
    ) -> Result<ThreadObjectBinding, Error> {
        let binding = self.binding_for_object(object)?;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        self.validate_scheduler_owner(scheduler_owner, binding.scheduler_thread)?;
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;

        match scheduler.state(binding.scheduler_thread.local) {
            Err(SchedulerError::InvalidThread) => Ok(binding),
            Ok(_) => Err(Error::ThreadStillLive),
            Err(error) => Err(Error::Scheduler(error)),
        }
    }

    /// Validates an explicit scheduler-owner reap attestation against this exact binding.
    pub(crate) fn validate_reaped_proof<const OBJECTS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        owner: ObjectId,
        object: ObjectId,
        proof: &ReapedThreadProof,
    ) -> Result<ThreadObjectBinding, Error> {
        let binding = self.binding_for_object(object)?;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;
        if proof.thread() != binding.scheduler_thread {
            return Err(Error::WrongReapProof);
        }
        Ok(binding)
    }

    /// Returns the canonical process-local root authority for one exact reaped scheduler generation.
    ///
    /// The caller supplies only the generation-safe Process ObjectId and the scheduler-owner-issued
    /// [`ReapedThreadProof`]. The binding table remains the sole owner of the Process/Thread mapping
    /// and stored root handle, so clone/runtime code never needs a second CapHandle registry. A stale
    /// scheduler generation cannot alias a replacement binding, and a proof for another Process is
    /// rejected even if its local scheduler slot number happens to match.
    pub fn authority_for_reaped_proof<const OBJECTS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        owner: ObjectId,
        proof: &ReapedThreadProof,
    ) -> Result<CapHandle, Error> {
        let binding = self
            .slots
            .iter()
            .find(|slot| slot.occupied && slot.binding.scheduler_thread == proof.thread())
            .map(|slot| slot.binding)
            .ok_or(Error::NotBound)?;
        if binding.owner != owner {
            return Err(Error::WrongOwner);
        }
        objects.resolve_kind(binding.owner, ObjectKind::Process)?;
        objects.resolve_kind(binding.object, ObjectKind::Thread)?;
        binding.authority.ok_or(Error::AuthorityNotPublished)
    }

    #[cfg(test)]
    fn release_reaped<const OBJECTS: usize, const THREADS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        owner: ObjectId,
        object: ObjectId,
    ) -> Result<ThreadObjectBinding, Error> {
        let binding = self.validate_reaped(objects, scheduler, scheduler_owner, owner, object)?;
        let index = self.slot_for_object(object)?;
        objects.destroy(binding.object)?;
        self.slots[index] = Slot::EMPTY;
        self.len -= 1;
        Ok(binding)
    }

    /// Destroys the Thread object/binding only for a matching owner-attested scheduler reap proof.
    pub(crate) fn release_reaped_proof<const OBJECTS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        owner: ObjectId,
        object: ObjectId,
        proof: &ReapedThreadProof,
    ) -> Result<ThreadObjectBinding, Error> {
        let binding = self.validate_reaped_proof(objects, owner, object, proof)?;
        let index = self.slot_for_object(object)?;
        objects.destroy(binding.object)?;
        self.slots[index] = Slot::EMPTY;
        self.len -= 1;
        Ok(binding)
    }

    fn validate_scheduler_owner(
        &self,
        scheduler_owner: CpuIndex,
        scheduler_thread: GlobalThreadId,
    ) -> Result<(), Error> {
        if scheduler_thread.cpu == scheduler_owner {
            Ok(())
        } else {
            Err(Error::WrongSchedulerOwner)
        }
    }

    fn binding_for_object(&self, object: ObjectId) -> Result<ThreadObjectBinding, Error> {
        Ok(self.slots[self.slot_for_object(object)?].binding)
    }

    fn slot_for_object(&self, object: ObjectId) -> Result<usize, Error> {
        self.slots
            .iter()
            .position(|slot| slot.occupied && slot.binding.object == object)
            .ok_or(Error::NotBound)
    }
}

impl<const N: usize> Default for ThreadObjectBindings<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU0: CpuIndex = CpuIndex(0);
    const CPU1: CpuIndex = CpuIndex(1);

    fn create_process<const N: usize>(objects: &mut ObjectTable<N>) -> ObjectId {
        objects
            .create(ObjectMeta {
                kind: ObjectKind::Process,
                owner_domain: 0,
                flags: 0,
            })
            .unwrap()
    }

    fn global(cpu: CpuIndex, local: kernal_scheduler::ThreadId) -> GlobalThreadId {
        GlobalThreadId::new(cpu, local)
    }

    #[test]
    fn binding_tracks_the_exact_scheduler_generation() {
        let mut objects = ObjectTable::<4>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(10).unwrap();
        let thread = global(CPU0, local);
        let mut bindings = ThreadObjectBindings::<2>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();

        assert_eq!(
            bindings
                .resolve(&objects, &scheduler, CPU0, owner, binding.object())
                .unwrap(),
            binding
        );

        scheduler.make_ready(local).unwrap();
        let running = scheduler.schedule().unwrap().unwrap();
        scheduler.exit(running).unwrap();
        assert_eq!(scheduler.state(local), Ok(ThreadState::Exited));
        assert!(
            bindings
                .resolve(&objects, &scheduler, CPU0, owner, binding.object())
                .is_ok()
        );

        scheduler.reap(local).unwrap();
        assert_eq!(
            bindings.resolve(&objects, &scheduler, CPU0, owner, binding.object()),
            Err(Error::StaleSchedulerThread)
        );

        let replacement = scheduler.create(10).unwrap();
        assert_eq!(replacement.slot, local.slot);
        assert_ne!(replacement.generation, local.generation);
        assert_eq!(
            bindings.resolve(&objects, &scheduler, CPU0, owner, binding.object()),
            Err(Error::StaleSchedulerThread)
        );
    }

    #[test]
    fn cpu_identity_is_part_of_the_scheduler_binding() {
        let mut objects = ObjectTable::<4>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(3).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();

        assert_eq!(
            bindings.bind(&mut objects, &scheduler, CPU0, owner, global(CPU1, local),),
            Err(Error::WrongSchedulerOwner)
        );

        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, global(CPU0, local))
            .unwrap();
        assert_eq!(
            bindings.resolve(&objects, &scheduler, CPU1, owner, binding.object()),
            Err(Error::WrongSchedulerOwner)
        );
    }

    #[test]
    fn equal_local_ids_on_different_cpus_can_coexist() {
        let mut objects = ObjectTable::<5>::new();
        let owner = create_process(&mut objects);
        let mut cpu0_queue = RunQueue::<1>::new();
        let mut cpu1_queue = RunQueue::<1>::new();
        let cpu0_local = cpu0_queue.create(3).unwrap();
        let cpu1_local = cpu1_queue.create(3).unwrap();
        assert_eq!(cpu0_local, cpu1_local);

        let mut bindings = ThreadObjectBindings::<2>::new();
        let cpu0_binding = bindings
            .bind(
                &mut objects,
                &cpu0_queue,
                CPU0,
                owner,
                global(CPU0, cpu0_local),
            )
            .unwrap();
        let cpu1_binding = bindings
            .bind(
                &mut objects,
                &cpu1_queue,
                CPU1,
                owner,
                global(CPU1, cpu1_local),
            )
            .unwrap();

        assert_ne!(
            cpu0_binding.scheduler_thread(),
            cpu1_binding.scheduler_thread()
        );
        assert_eq!(
            bindings.resolve(&objects, &cpu1_queue, CPU1, owner, cpu0_binding.object(),),
            Err(Error::WrongSchedulerOwner)
        );
        assert!(
            bindings
                .resolve(&objects, &cpu1_queue, CPU1, owner, cpu1_binding.object(),)
                .is_ok()
        );
    }

    #[test]
    fn one_global_scheduler_generation_cannot_be_bound_twice() {
        let mut objects = ObjectTable::<5>::new();
        let left = create_process(&mut objects);
        let right = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let thread = global(CPU0, scheduler.create(4).unwrap());
        let mut bindings = ThreadObjectBindings::<2>::new();
        bindings
            .bind(&mut objects, &scheduler, CPU0, left, thread)
            .unwrap();
        assert_eq!(
            bindings.bind(&mut objects, &scheduler, CPU0, right, thread),
            Err(Error::AlreadyBound)
        );
    }

    #[test]
    fn cross_process_resolution_is_denied() {
        let mut objects = ObjectTable::<5>::new();
        let owner = create_process(&mut objects);
        let stranger = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let thread = global(CPU0, scheduler.create(5).unwrap());
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();

        assert_eq!(
            bindings.resolve(&objects, &scheduler, CPU0, stranger, binding.object()),
            Err(Error::WrongOwner)
        );
    }

    #[test]
    fn reaped_proof_recovers_only_the_stored_root_authority() {
        let mut objects = ObjectTable::<5>::new();
        let owner = create_process(&mut objects);
        let stranger = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(6).unwrap();
        let thread = global(CPU0, local);
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();
        let root = CapHandle {
            slot: 7,
            generation: 11,
        };
        bindings
            .publish_authority(owner, binding.object(), root)
            .unwrap();
        scheduler.exit(local).unwrap();
        scheduler.reap(local).unwrap();
        // SAFETY: the exact CPU0 generation was reaped immediately above.
        let proof = unsafe { ReapedThreadProof::new_unchecked(thread) };

        assert_eq!(
            bindings.authority_for_reaped_proof(&objects, owner, &proof),
            Ok(root)
        );
        assert_eq!(
            bindings.authority_for_reaped_proof(&objects, stranger, &proof),
            Err(Error::WrongOwner)
        );

        // SAFETY: deliberately forge a later generation to prove stale scheduler identities cannot
        // recover authority from the still-bound old generation.
        let stale = unsafe {
            ReapedThreadProof::new_unchecked(GlobalThreadId::new(
                CPU0,
                kernal_scheduler::ThreadId {
                    slot: local.slot,
                    generation: local.generation.wrapping_add(1),
                },
            ))
        };
        assert_eq!(
            bindings.authority_for_reaped_proof(&objects, owner, &stale),
            Err(Error::NotBound)
        );
    }

    #[test]
    fn release_requires_scheduler_reap_and_then_invalidates_object_generation() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(6).unwrap();
        let thread = global(CPU0, local);
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();

        assert_eq!(
            bindings.release_reaped(&mut objects, &scheduler, CPU0, owner, binding.object()),
            Err(Error::ThreadStillLive)
        );
        objects
            .resolve_kind(binding.object(), ObjectKind::Thread)
            .unwrap();

        scheduler.exit(local).unwrap();
        scheduler.reap(local).unwrap();
        // SAFETY: this test has just reaped the exact CPU0 scheduler generation above.
        let proof = unsafe { ReapedThreadProof::new_unchecked(thread) };
        assert_eq!(
            bindings
                .release_reaped_proof(&mut objects, owner, binding.object(), &proof)
                .unwrap(),
            binding
        );
        assert!(bindings.is_empty());
        assert_eq!(
            objects.resolve(binding.object()),
            Err(ObjectError::InvalidObject)
        );

        let replacement_thread = global(CPU0, scheduler.create(6).unwrap());
        let replacement = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, replacement_thread)
            .unwrap();
        assert_ne!(replacement.object(), binding.object());
        assert_eq!(
            objects.resolve(binding.object()),
            Err(ObjectError::StaleObject)
        );
    }

    #[test]
    fn mismatched_reap_proof_cannot_release_thread_object() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(6).unwrap();
        let thread = global(CPU0, local);
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();
        scheduler.exit(local).unwrap();
        scheduler.reap(local).unwrap();

        // SAFETY: intentionally forge the wrong identity to verify fail-closed matching.
        let wrong = unsafe {
            ReapedThreadProof::new_unchecked(GlobalThreadId::new(
                CPU1,
                kernal_scheduler::ThreadId {
                    slot: local.slot,
                    generation: local.generation,
                },
            ))
        };
        assert_eq!(
            bindings.release_reaped_proof(&mut objects, owner, binding.object(), &wrong),
            Err(Error::WrongReapProof)
        );
        objects
            .resolve_kind(binding.object(), ObjectKind::Thread)
            .unwrap();
    }

    #[test]
    fn unpublished_binding_can_be_rolled_back_without_reaping_scheduler_thread() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(8).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, global(CPU0, local))
            .unwrap();

        assert_eq!(
            bindings
                .cancel_unpublished(&mut objects, owner, binding.object())
                .unwrap(),
            binding
        );
        assert!(bindings.is_empty());
        assert!(scheduler.state(local).is_ok());
        assert_eq!(
            objects.resolve(binding.object()),
            Err(ObjectError::InvalidObject)
        );
    }

    #[test]
    fn published_staged_binding_can_be_rolled_back_while_scheduler_stays_blocked() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(8).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, global(CPU0, local))
            .unwrap();
        let root = CapHandle {
            slot: 2,
            generation: 4,
        };
        bindings
            .publish_authority(owner, binding.object(), root)
            .unwrap();

        // SAFETY: the test generation has never left its initial Blocked creation state and stands in
        // for the external ContextTable::Staged proof required by the crate-private owner API.
        let released = unsafe {
            bindings.release_published_staged(
                &mut objects,
                &scheduler,
                CPU0,
                owner,
                binding.object(),
            )
        }
        .unwrap();
        assert_eq!(released.scheduler_thread(), global(CPU0, local));
        assert!(bindings.is_empty());
        assert_eq!(scheduler.state(local), Ok(ThreadState::Blocked));
        assert_eq!(
            objects.resolve(binding.object()),
            Err(ObjectError::InvalidObject)
        );
    }

    #[test]
    fn published_staged_rollback_rejects_ready_thread() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(8).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, global(CPU0, local))
            .unwrap();
        bindings
            .publish_authority(
                owner,
                binding.object(),
                CapHandle {
                    slot: 2,
                    generation: 4,
                },
            )
            .unwrap();
        scheduler.make_ready(local).unwrap();

        // SAFETY: deliberately violates the required Staged+Blocked precondition to verify fail-closed
        // scheduler-state validation before object destruction.
        assert_eq!(
            unsafe {
                bindings.release_published_staged(
                    &mut objects,
                    &scheduler,
                    CPU0,
                    owner,
                    binding.object(),
                )
            },
            Err(Error::ThreadStillLive)
        );
        objects
            .resolve_kind(binding.object(), ObjectKind::Thread)
            .unwrap();
    }

    #[test]
    fn published_root_is_recorded_exactly_once() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(9).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, global(CPU0, local))
            .unwrap();
        let root = CapHandle {
            slot: 2,
            generation: 4,
        };
        let published = bindings
            .publish_authority(owner, binding.object(), root)
            .unwrap();
        assert_eq!(published.authority(), Some(root));
        assert_eq!(
            bindings.publish_authority(owner, binding.object(), root),
            Err(Error::AuthorityAlreadyPublished)
        );
        assert_eq!(
            bindings.cancel_unpublished(&mut objects, owner, binding.object()),
            Err(Error::AuthorityAlreadyPublished)
        );
    }

    #[test]
    fn stale_process_generation_cannot_own_a_live_thread_binding() {
        let mut objects = ObjectTable::<3>::new();
        let owner = create_process(&mut objects);
        let mut scheduler = RunQueue::<1>::new();
        let thread = global(CPU0, scheduler.create(7).unwrap());
        let mut bindings = ThreadObjectBindings::<1>::new();
        let binding = bindings
            .bind(&mut objects, &scheduler, CPU0, owner, thread)
            .unwrap();

        objects.destroy(owner).unwrap();
        let replacement = create_process(&mut objects);
        assert_ne!(replacement, owner);
        assert_eq!(
            bindings.resolve(&objects, &scheduler, CPU0, owner, binding.object()),
            Err(Error::Object(ObjectError::StaleObject))
        );
    }
}
