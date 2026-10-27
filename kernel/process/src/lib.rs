// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_capability::{CapError, CapHandle, CapRights, CapabilityTable, ObjectId};
use kernal_object::{Error as ObjectError, ObjectKind, ObjectMeta, ObjectTable};
use kernal_percpu::CpuIndex;
use kernal_scheduler::{RunQueue, ThreadState};
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof, StagedThreadProof};

mod thread_binding;
pub use thread_binding::{Error as ThreadBindingError, ThreadObjectBinding, ThreadObjectBindings};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Personality {
    Native,
    Linux,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Live,
    Exited,
}

/// Lifetime contract of the mandatory address-space object held by one Process.
///
/// Normal/fork children own a private address-space ObjectId and destroy it on Process exit. A vfork
/// child temporarily borrows the exact parent's object and therefore revokes only its local CSpace
/// root on exit. The enum grants no page-table authority; architecture owners must still bind the
/// appropriate root and keep the vfork parent suspended until the later exec/exit handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceOwnership {
    Owned,
    BorrowedVfork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedObject {
    pub object: ObjectId,
    pub meta: ObjectMeta,
    pub rights: CapRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedThread {
    pub object: ObjectId,
    pub scheduler_thread: GlobalThreadId,
    pub rights: CapRights,
}

/// Linear evidence that Process/CSpace authority for one exact never-published clone child has been
/// destroyed while scheduler staging authority is still held by the caller.
///
/// This proof is intentionally neither `Copy` nor `Clone`. Its fields are private and it is minted
/// only by a successful [`Process::rollback_staged_thread`], after the process-local capability tree,
/// Thread object and binding are gone. The Linux identity owner consumes it by value before the same
/// exact scheduler generation may be cancelled/reaped.
#[derive(Debug, Eq, PartialEq)]
pub struct StagedThreadRollbackProof {
    process: ObjectId,
    thread_object: ObjectId,
    scheduler_thread: GlobalThreadId,
}

impl StagedThreadRollbackProof {
    pub const fn process(&self) -> ObjectId {
        self.process
    }

    pub const fn thread_object(&self) -> ObjectId {
        self.thread_object
    }

    pub const fn scheduler_thread(&self) -> GlobalThreadId {
        self.scheduler_thread
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Object(ObjectError),
    Capability(CapError),
    ThreadBinding(ThreadBindingError),
    Exited,
    ThreadsRemain,
}

impl From<ObjectError> for Error {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<CapError> for Error {
    fn from(value: CapError) -> Self {
        Self::Capability(value)
    }
}

impl From<ThreadBindingError> for Error {
    fn from(value: ThreadBindingError) -> Self {
        Self::ThreadBinding(value)
    }
}

/// Architecture-neutral Step-11 process ownership core.
///
/// A process owns one generation-safe process object identity, references one generation-safe
/// address-space object identity and holds one private capability namespace. Normal/fork processes own
/// their AddressSpace object; a staged vfork child may temporarily borrow its parent's exact object.
/// The actual architecture-specific address-space root is deliberately not stored here; AArch64 binds
/// the accepted Step-7 root to the returned address-space object in its adapter layer.
///
/// `CapHandle` values are meaningful only inside this process's CSpace. Cross-process authority is
/// created only through [`Process::delegate_to`], which requires `GRANT` and cannot increase rights.
/// Thread authority is likewise process-local: a scheduler generation is not usable through this
/// model until [`Process::attach_thread`] publishes its Thread object in this CSpace.
pub struct Process<const CAPS: usize> {
    id: ObjectId,
    address_space: ObjectId,
    address_space_ownership: AddressSpaceOwnership,
    personality: Personality,
    state: ProcessState,
    cspace: CapabilityTable<CAPS>,
    self_root: CapHandle,
    address_space_root: CapHandle,
    attached_threads: usize,
}

impl<const CAPS: usize> Process<CAPS> {
    /// Creates one process identity and one private address-space identity, then installs their root
    /// capabilities into a new per-process CSpace.
    ///
    /// Object-table allocation is rolled back if the CSpace cannot hold both mandatory roots.
    pub fn create<const OBJECTS: usize>(
        objects: &mut ObjectTable<OBJECTS>,
        personality: Personality,
    ) -> Result<Self, Error> {
        let id = objects.create(ObjectMeta {
            kind: ObjectKind::Process,
            owner_domain: 0,
            flags: 0,
        })?;

        let address_space = match objects.create(ObjectMeta {
            kind: ObjectKind::AddressSpace,
            owner_domain: 0,
            flags: 0,
        }) {
            Ok(id) => id,
            Err(error) => {
                let _ = objects.destroy(id);
                return Err(error.into());
            }
        };

        let mut cspace = CapabilityTable::<CAPS>::new();
        let process_rights = CapRights::CONTROL.union(CapRights::GRANT);
        let self_root = match cspace.insert_root(id, process_rights) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = objects.destroy(address_space);
                let _ = objects.destroy(id);
                return Err(error.into());
            }
        };

        let address_space_rights = CapRights::MAP
            .union(CapRights::CONTROL)
            .union(CapRights::GRANT);
        let address_space_root = match cspace.insert_root(address_space, address_space_rights) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = cspace.revoke(self_root);
                let _ = objects.destroy(address_space);
                let _ = objects.destroy(id);
                return Err(error.into());
            }
        };

        Ok(Self {
            id,
            address_space,
            address_space_ownership: AddressSpaceOwnership::Owned,
            personality,
            state: ProcessState::Live,
            cspace,
            self_root,
            address_space_root,
            attached_threads: 0,
        })
    }

    /// Creates the Process/CSpace half of one fork child without inheriting ambient capabilities.
    ///
    /// The child receives a fresh Process ObjectId, fresh address-space ObjectId and only the normal
    /// mandatory roots owned by [`Self::create`]. No parent CSpace entry is copied. This is the
    /// architecture-neutral staging hook; the AArch64 owner must populate the fresh address space and
    /// scheduler state before publishing the child.
    pub fn create_fork_child<const PARENT_CAPS: usize, const OBJECTS: usize>(
        parent: &Process<PARENT_CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
    ) -> Result<Self, Error> {
        parent.ensure_live()?;
        Self::create(objects, parent.personality())
    }

    /// Creates the Process/CSpace half of one vfork child with the minimum shared-address-space root.
    ///
    /// A new Process ObjectId is allocated, but the child temporarily names the exact parent's live
    /// AddressSpace ObjectId. The child receives `MAP|CONTROL` only; `GRANT` is deliberately omitted,
    /// so vfork cannot amplify or delegate the parent's address-space authority. No other parent
    /// capability is inherited. If either mandatory CSpace insertion fails, the new Process ObjectId
    /// is destroyed and the parent's address space is untouched.
    ///
    /// This function does not schedule the child. The higher-level clone owner must keep the parent
    /// suspended until the child exec/exit handoff and must bind the architecture root consistently.
    pub fn create_vfork_child<const PARENT_CAPS: usize, const OBJECTS: usize>(
        parent: &Process<PARENT_CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
    ) -> Result<Self, Error> {
        parent.ensure_live()?;
        let parent_space = parent.resolve_object(
            objects,
            parent.address_space_handle(),
            CapRights::MAP.union(CapRights::CONTROL),
        )?;
        if parent_space.meta.kind != ObjectKind::AddressSpace {
            return Err(ObjectError::KindMismatch.into());
        }

        let id = objects.create(ObjectMeta {
            kind: ObjectKind::Process,
            owner_domain: 0,
            flags: 0,
        })?;
        let mut cspace = CapabilityTable::<CAPS>::new();
        let self_root = match cspace.insert_root(id, CapRights::CONTROL.union(CapRights::GRANT)) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = objects.destroy(id);
                return Err(error.into());
            }
        };
        let address_space_root = match cspace.insert_root(
            parent_space.object,
            CapRights::MAP.union(CapRights::CONTROL),
        ) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = cspace.revoke(self_root);
                let _ = objects.destroy(id);
                return Err(error.into());
            }
        };

        Ok(Self {
            id,
            address_space: parent_space.object,
            address_space_ownership: AddressSpaceOwnership::BorrowedVfork,
            personality: parent.personality(),
            state: ProcessState::Live,
            cspace,
            self_root,
            address_space_root,
            attached_threads: 0,
        })
    }

    pub const fn id(&self) -> ObjectId {
        self.id
    }

    pub const fn address_space(&self) -> ObjectId {
        self.address_space
    }

    pub const fn address_space_ownership(&self) -> AddressSpaceOwnership {
        self.address_space_ownership
    }

    pub const fn personality(&self) -> Personality {
        self.personality
    }

    pub const fn state(&self) -> ProcessState {
        self.state
    }

    pub const fn self_handle(&self) -> CapHandle {
        self.self_root
    }

    pub const fn address_space_handle(&self) -> CapHandle {
        self.address_space_root
    }

    /// Resolves one local CSpace handle and validates the referenced generation-safe object ID.
    pub fn resolve_object<const OBJECTS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        required: CapRights,
    ) -> Result<ResolvedObject, Error> {
        self.ensure_live()?;
        let capability = self.cspace.resolve(handle)?;
        if !capability.rights.contains(required) {
            return Err(CapError::InsufficientRights.into());
        }
        let meta = objects.resolve(capability.object)?;
        Ok(ResolvedObject {
            object: capability.object,
            meta,
            rights: capability.rights,
        })
    }

    /// Derives a weaker capability inside this process's own CSpace.
    pub fn derive_cap(
        &mut self,
        parent: CapHandle,
        requested: CapRights,
    ) -> Result<CapHandle, Error> {
        self.ensure_live()?;
        Ok(self.cspace.derive(parent, requested)?)
    }

    /// Explicitly delegates authority into another process's CSpace.
    ///
    /// The source capability must contain `GRANT`, the delegated rights must be a subset of the
    /// source rights and the underlying object generation must still be live.
    pub fn delegate_to<const TARGET_CAPS: usize, const OBJECTS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        source: CapHandle,
        requested: CapRights,
        target: &mut Process<TARGET_CAPS>,
    ) -> Result<CapHandle, Error> {
        self.ensure_live()?;
        target.ensure_live()?;

        let capability = self.cspace.resolve(source)?;
        if !capability.rights.contains(CapRights::GRANT) || !capability.rights.contains(requested) {
            return Err(CapError::InsufficientRights.into());
        }
        objects.resolve(capability.object)?;
        Ok(target.cspace.insert_root(capability.object, requested)?)
    }

    /// Publishes an existing scheduler thread as process-local CONTROL authority.
    ///
    /// The Thread ObjectId is created only after the exact `GlobalThreadId`/CPU owner is validated.
    /// If the private CSpace is full, the new object/binding is rolled back while the scheduler thread
    /// remains untouched. No raw ObjectId becomes process authority.
    pub fn attach_thread<const OBJECTS: usize, const BINDINGS: usize, const THREADS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        scheduler_thread: GlobalThreadId,
    ) -> Result<CapHandle, Error> {
        self.ensure_live()?;
        let binding = bindings.bind(
            objects,
            scheduler,
            scheduler_owner,
            self.id,
            scheduler_thread,
        )?;

        let root = match self
            .cspace
            .insert_root(binding.object(), CapRights::CONTROL)
        {
            Ok(handle) => handle,
            Err(error) => {
                if let Err(rollback) =
                    bindings.cancel_unpublished(objects, self.id, binding.object())
                {
                    return Err(Error::ThreadBinding(rollback));
                }
                return Err(Error::Capability(error));
            }
        };

        if let Err(error) = bindings.publish_authority(self.id, binding.object(), root) {
            let revoke_result = self.cspace.revoke(root);
            let rollback_result = bindings.cancel_unpublished(objects, self.id, binding.object());
            if let Err(rollback) = rollback_result {
                return Err(Error::ThreadBinding(rollback));
            }
            if let Err(revoke) = revoke_result {
                return Err(Error::Capability(revoke));
            }
            return Err(Error::ThreadBinding(error));
        }

        self.attached_threads += 1;
        Ok(root)
    }

    /// Resolves thread authority through this process's CSpace, then validates object, CPU owner and
    /// exact scheduler generation.
    pub fn resolve_thread<const OBJECTS: usize, const BINDINGS: usize, const THREADS: usize>(
        &self,
        objects: &ObjectTable<OBJECTS>,
        bindings: &ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        handle: CapHandle,
    ) -> Result<ResolvedThread, Error> {
        self.ensure_live()?;
        let capability = self.cspace.resolve(handle)?;
        if !capability.rights.contains(CapRights::CONTROL) {
            return Err(CapError::InsufficientRights.into());
        }
        objects.resolve_kind(capability.object, ObjectKind::Thread)?;
        let binding = bindings.resolve(
            objects,
            scheduler,
            scheduler_owner,
            self.id,
            capability.object,
        )?;
        if binding.authority().is_none() {
            return Err(ThreadBindingError::AuthorityNotPublished.into());
        }
        Ok(ResolvedThread {
            object: binding.object(),
            scheduler_thread: binding.scheduler_thread(),
            rights: capability.rights,
        })
    }

    /// Rolls back Process/CSpace authority for one clone child that is still scheduler-Staged.
    ///
    /// The scheduler owner hands this method a one-shot [`StagedThreadProof`] for the exact
    /// `ContextTable::Staged + RunQueue::Blocked` generation. The proof is consumed by value. This
    /// method still rechecks the binding and RunQueue state as defense in depth, then revokes the
    /// process-local capability tree and destroys the Thread object/binding. Only successful teardown
    /// advances authority into [`StagedThreadRollbackProof`].
    ///
    /// # Safety
    /// The caller must retain the same scheduler-owner quiescence window under which `proof` was
    /// minted, and must not publish, run, migrate or otherwise advance the exact generation while
    /// this transaction executes. `scheduler` must be the canonical owner RunQueue for `proof`.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
    pub unsafe fn rollback_staged_thread<
        const OBJECTS: usize,
        const BINDINGS: usize,
        const THREADS: usize,
    >(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        scheduler: &RunQueue<THREADS>,
        scheduler_owner: CpuIndex,
        proof: StagedThreadProof,
        handle: CapHandle,
    ) -> Result<StagedThreadRollbackProof, Error> {
        self.ensure_live()?;
        let capability = self.cspace.resolve(handle)?;
        if !capability.rights.contains(CapRights::CONTROL) {
            return Err(CapError::InsufficientRights.into());
        }
        objects.resolve_kind(capability.object, ObjectKind::Thread)?;
        let binding = bindings.resolve(
            objects,
            scheduler,
            scheduler_owner,
            self.id,
            capability.object,
        )?;
        if proof.thread() != binding.scheduler_thread() {
            return Err(ThreadBindingError::StaleSchedulerThread.into());
        }
        if scheduler
            .state(binding.scheduler_thread().local)
            .map_err(ThreadBindingError::Scheduler)?
            != ThreadState::Blocked
        {
            return Err(ThreadBindingError::ThreadStillLive.into());
        }
        let root = binding
            .authority()
            .ok_or(ThreadBindingError::AuthorityNotPublished)?;
        let root_capability = self.cspace.resolve(root)?;
        if root_capability.object != binding.object()
            || !root_capability.rights.contains(CapRights::CONTROL)
        {
            return Err(CapError::InsufficientRights.into());
        }
        let remaining_threads = self
            .attached_threads
            .checked_sub(1)
            .ok_or(ThreadBindingError::NotBound)?;
        let destroyed_thread_object = binding.object();

        self.cspace.revoke(root)?;
        // SAFETY: delegated caller contract plus the consumed StagedThreadProof identify this exact
        // generation as the never-published clone child; the checks above prove it is still Blocked.
        let released = unsafe {
            bindings.release_published_staged(
                objects,
                scheduler,
                scheduler_owner,
                self.id,
                binding.object(),
            )
        }?;
        debug_assert_eq!(released.scheduler_thread(), binding.scheduler_thread());
        debug_assert_eq!(released.object(), destroyed_thread_object);
        self.attached_threads = remaining_threads;
        Ok(StagedThreadRollbackProof {
            process: self.id,
            thread_object: destroyed_thread_object,
            scheduler_thread: released.scheduler_thread(),
        })
    }

    /// Releases a process-owned Thread object/capability only after scheduler-owner code provides an
    /// exact [`ReapedThreadProof`].
    ///
    /// The proof must match the binding's `{CPU, slot, generation}` exactly. Safe Process code never
    /// infers reaping from `RunQueue::state()`, so a foreign/fresh RunQueue returning `InvalidThread`
    /// cannot authorize teardown. The stored root capability is revoked before the Thread ObjectId
    /// and binding are destroyed, invalidating every derived process-local handle first.
    pub fn release_reaped_thread<const OBJECTS: usize, const BINDINGS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        proof: ReapedThreadProof,
        handle: CapHandle,
    ) -> Result<GlobalThreadId, Error> {
        self.ensure_live()?;
        let capability = self.cspace.resolve(handle)?;
        if !capability.rights.contains(CapRights::CONTROL) {
            return Err(CapError::InsufficientRights.into());
        }
        objects.resolve_kind(capability.object, ObjectKind::Thread)?;

        let binding =
            bindings.validate_reaped_proof(objects, self.id, capability.object, &proof)?;
        let root = binding
            .authority()
            .ok_or(ThreadBindingError::AuthorityNotPublished)?;
        let root_capability = self.cspace.resolve(root)?;
        if root_capability.object != binding.object()
            || !root_capability.rights.contains(CapRights::CONTROL)
        {
            return Err(CapError::InsufficientRights.into());
        }
        let remaining_threads = self
            .attached_threads
            .checked_sub(1)
            .ok_or(ThreadBindingError::NotBound)?;

        self.cspace.revoke(root)?;
        let released = bindings.release_reaped_proof(objects, self.id, binding.object(), &proof)?;
        debug_assert_eq!(released.scheduler_thread(), binding.scheduler_thread());
        self.attached_threads = remaining_threads;
        Ok(released.scheduler_thread())
    }

    /// Explicitly exits the process ownership domain.
    ///
    /// Scheduler resources must already have completed `exit -> teardown -> reap`, and all process
    /// thread capabilities/bindings must have been released. The process-owned count makes this
    /// precondition unskippable even if a caller accidentally supplies the wrong binding table.
    /// A borrowed vfork AddressSpace root is revoked locally but never destroys the parent's object.
    pub fn exit<const OBJECTS: usize, const BINDINGS: usize>(
        &mut self,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &ThreadObjectBindings<BINDINGS>,
    ) -> Result<(), Error> {
        self.ensure_live()?;
        if self.attached_threads != 0 || bindings.has_owner(self.id) {
            return Err(Error::ThreadsRemain);
        }

        objects.resolve_kind(self.id, ObjectKind::Process)?;
        objects.resolve_kind(self.address_space, ObjectKind::AddressSpace)?;

        self.cspace.revoke(self.address_space_root)?;
        self.cspace.revoke(self.self_root)?;
        if self.address_space_ownership == AddressSpaceOwnership::Owned {
            objects.destroy(self.address_space)?;
        }
        objects.destroy(self.id)?;
        self.state = ProcessState::Exited;
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), Error> {
        if self.state == ProcessState::Live {
            Ok(())
        } else {
            Err(Error::Exited)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU0: CpuIndex = CpuIndex(0);

    fn global(local: kernal_scheduler::ThreadId) -> GlobalThreadId {
        GlobalThreadId::new(CPU0, local)
    }

    unsafe fn reaped(local: kernal_scheduler::ThreadId) -> ReapedThreadProof {
        // SAFETY: callers use this helper only immediately after reaping `local` from the CPU0 test queue.
        unsafe { ReapedThreadProof::new_unchecked(global(local)) }
    }

    unsafe fn staged(local: kernal_scheduler::ThreadId) -> StagedThreadProof {
        // SAFETY: callers use this helper only while the exact CPU0 test generation is still Blocked
        // and represents generation-owned Staged clone state.
        unsafe { StagedThreadProof::new_unchecked(global(local)) }
    }

    #[test]
    fn process_gets_private_cspace_and_address_space_authority() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<8>::create(&mut objects, Personality::Native).unwrap();

        let self_object = process
            .resolve_object(&objects, process.self_handle(), CapRights::CONTROL)
            .unwrap();
        assert_eq!(self_object.object, process.id());
        assert_eq!(self_object.meta.kind, ObjectKind::Process);

        let address_space = process
            .resolve_object(&objects, process.address_space_handle(), CapRights::MAP)
            .unwrap();
        assert_eq!(address_space.object, process.address_space());
        assert_eq!(address_space.meta.kind, ObjectKind::AddressSpace);
        assert_eq!(
            process.address_space_ownership(),
            AddressSpaceOwnership::Owned
        );
    }

    #[test]
    fn linux_personality_is_retained_by_the_existing_process_model() {
        let mut objects = ObjectTable::<2>::new();
        let process = Process::<2>::create(&mut objects, Personality::Linux).unwrap();
        assert_eq!(process.personality(), Personality::Linux);
    }

    #[test]
    fn fork_child_gets_fresh_process_and_address_space_without_parent_capability_copy() {
        let mut objects = ObjectTable::<4>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();

        assert_eq!(child.personality(), Personality::Linux);
        assert_ne!(child.id(), parent.id());
        assert_ne!(child.address_space(), parent.address_space());
        assert_eq!(
            child.address_space_ownership(),
            AddressSpaceOwnership::Owned
        );

        // Equal mandatory handle numbers stay CSpace-local and resolve only the child's fresh object.
        assert_eq!(child.address_space_handle(), parent.address_space_handle());
        assert_eq!(
            child
                .resolve_object(&objects, parent.address_space_handle(), CapRights::MAP)
                .unwrap()
                .object,
            child.address_space()
        );
    }

    #[test]
    fn vfork_child_borrows_exact_parent_address_space_without_grant_or_destruction() {
        let mut objects = ObjectTable::<3>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_vfork_child(&parent, &mut objects).unwrap();

        assert_ne!(child.id(), parent.id());
        assert_eq!(child.address_space(), parent.address_space());
        assert_eq!(
            child.address_space_ownership(),
            AddressSpaceOwnership::BorrowedVfork
        );
        let borrowed = child
            .resolve_object(
                &objects,
                child.address_space_handle(),
                CapRights::MAP.union(CapRights::CONTROL),
            )
            .unwrap();
        assert_eq!(borrowed.object, parent.address_space());
        assert!(!borrowed.rights.contains(CapRights::GRANT));
        assert_eq!(
            child.resolve_object(&objects, child.address_space_handle(), CapRights::GRANT),
            Err(Error::Capability(CapError::InsufficientRights))
        );

        let bindings = ThreadObjectBindings::<0>::new();
        child.exit(&mut objects, &bindings).unwrap();
        assert_eq!(child.state(), ProcessState::Exited);
        assert!(
            parent
                .resolve_object(&objects, parent.address_space_handle(), CapRights::MAP)
                .is_ok()
        );
    }

    #[test]
    fn vfork_child_cspace_failure_rolls_back_only_new_process_object() {
        let mut objects = ObjectTable::<3>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let parent_space = parent.address_space();

        let failed = Process::<1>::create_vfork_child(&parent, &mut objects);
        assert!(matches!(
            failed,
            Err(Error::Capability(CapError::TableFull))
        ));
        assert!(
            parent
                .resolve_object(&objects, parent.address_space_handle(), CapRights::MAP)
                .is_ok()
        );
        assert_eq!(parent.address_space(), parent_space);
        assert!(
            objects
                .create(ObjectMeta {
                    kind: ObjectKind::Process,
                    owner_domain: 0,
                    flags: 0,
                })
                .is_ok()
        );
    }

    #[test]
    fn raw_handles_are_local_names_not_cross_process_authority() {
        let mut objects = ObjectTable::<4>::new();
        let left = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let right = Process::<8>::create(&mut objects, Personality::Native).unwrap();

        assert_eq!(left.self_handle(), right.self_handle());
        let through_right = right
            .resolve_object(&objects, left.self_handle(), CapRights::CONTROL)
            .unwrap();
        assert_eq!(through_right.object, right.id());
        assert_ne!(through_right.object, left.id());
    }

    #[test]
    fn delegation_is_explicit_requires_grant_and_cannot_grow_rights() {
        let mut objects = ObjectTable::<4>::new();
        let mut source = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut target = Process::<8>::create(&mut objects, Personality::Native).unwrap();

        let delegated = source
            .delegate_to(
                &objects,
                source.address_space_handle(),
                CapRights::MAP,
                &mut target,
            )
            .unwrap();
        assert_eq!(
            target
                .resolve_object(&objects, delegated, CapRights::MAP)
                .unwrap()
                .object,
            source.address_space()
        );

        let no_grant = source
            .derive_cap(source.address_space_handle(), CapRights::MAP)
            .unwrap();
        assert_eq!(
            source.delegate_to(&objects, no_grant, CapRights::MAP, &mut target),
            Err(Error::Capability(CapError::InsufficientRights))
        );
    }

    #[test]
    fn thread_authority_is_published_in_the_owning_process_cspace() {
        let mut objects = ObjectTable::<6>::new();
        let mut process = Process::<6>::create(&mut objects, Personality::Native).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(4).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();

        let root = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local))
            .unwrap();
        let resolved = process
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, root)
            .unwrap();
        assert_eq!(resolved.scheduler_thread, global(local));
        assert_eq!(resolved.rights, CapRights::CONTROL);
        objects
            .resolve_kind(resolved.object, ObjectKind::Thread)
            .unwrap();

        let derived = process.derive_cap(root, CapRights::CONTROL).unwrap();
        assert_eq!(
            process
                .resolve_thread(&objects, &bindings, &scheduler, CPU0, derived)
                .unwrap()
                .object,
            resolved.object
        );

        scheduler.exit(local).unwrap();
        assert_eq!(scheduler.state(local), Ok(ThreadState::Exited));
        scheduler.reap(local).unwrap();
        // SAFETY: the exact CPU0 test generation was reaped immediately above.
        let proof = unsafe { reaped(local) };
        assert_eq!(
            process
                .release_reaped_thread(&mut objects, &mut bindings, proof, derived)
                .unwrap(),
            global(local)
        );
        assert_eq!(
            process.resolve_thread(&objects, &bindings, &scheduler, CPU0, root),
            Err(Error::Capability(CapError::StaleHandle))
        );
        assert_eq!(
            process.resolve_thread(&objects, &bindings, &scheduler, CPU0, derived),
            Err(Error::Capability(CapError::StaleHandle))
        );
        assert_eq!(
            objects.resolve(resolved.object),
            Err(ObjectError::InvalidObject)
        );
    }

    #[test]
    fn staged_thread_rollback_revokes_root_and_derived_authority_without_reaping_scheduler() {
        let mut objects = ObjectTable::<6>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(4).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let root = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local))
            .unwrap();
        let derived = process.derive_cap(root, CapRights::CONTROL).unwrap();
        let object = process
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, root)
            .unwrap()
            .object;
        // SAFETY: this exact test generation is still Blocked and models ContextTable::Staged.
        let staged = unsafe { staged(local) };

        // SAFETY: owner quiescence and Staged+Blocked continuity are modeled by this single-threaded test.
        let rollback = unsafe {
            process.rollback_staged_thread(
                &mut objects,
                &mut bindings,
                &scheduler,
                CPU0,
                staged,
                derived,
            )
        }
        .unwrap();
        assert_eq!(rollback.process(), process.id());
        assert_eq!(rollback.thread_object(), object);
        assert_eq!(rollback.scheduler_thread(), global(local));
        assert!(bindings.is_empty());
        assert_eq!(scheduler.state(local), Ok(ThreadState::Blocked));
        assert_eq!(objects.resolve(object), Err(ObjectError::InvalidObject));
        assert_eq!(
            process.resolve_thread(&objects, &bindings, &scheduler, CPU0, root),
            Err(Error::Capability(CapError::StaleHandle))
        );
        assert_eq!(
            process.resolve_thread(&objects, &bindings, &scheduler, CPU0, derived),
            Err(Error::Capability(CapError::StaleHandle))
        );
    }

    #[test]
    fn staged_thread_rollback_rejects_state_advance_after_proof_mint() {
        let mut objects = ObjectTable::<6>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(4).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let root = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local))
            .unwrap();
        // SAFETY: proof is minted while the generation is still Blocked/Staged in the modeled test.
        let staged = unsafe { staged(local) };
        // Deliberately advance scheduler state after attestation. Production owner code must not do
        // this; the defense-in-depth RunQueue check must still reject before revoking authority.
        scheduler.make_ready(local).unwrap();

        assert_eq!(
            unsafe {
                process.rollback_staged_thread(
                    &mut objects,
                    &mut bindings,
                    &scheduler,
                    CPU0,
                    staged,
                    root,
                )
            },
            Err(Error::ThreadBinding(ThreadBindingError::ThreadStillLive))
        );
        assert!(
            process
                .resolve_thread(&objects, &bindings, &scheduler, CPU0, root)
                .is_ok()
        );
    }

    #[test]
    fn numerically_equal_thread_handles_remain_process_local() {
        let mut objects = ObjectTable::<8>::new();
        let mut left = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let mut right = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let mut scheduler = RunQueue::<2>::new();
        let left_local = scheduler.create(3).unwrap();
        let right_local = scheduler.create(3).unwrap();
        let mut bindings = ThreadObjectBindings::<2>::new();

        let left_handle = left
            .attach_thread(
                &mut objects,
                &mut bindings,
                &scheduler,
                CPU0,
                global(left_local),
            )
            .unwrap();
        let right_handle = right
            .attach_thread(
                &mut objects,
                &mut bindings,
                &scheduler,
                CPU0,
                global(right_local),
            )
            .unwrap();
        assert_eq!(left_handle, right_handle);

        let left_thread = left
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, left_handle)
            .unwrap();
        let through_right = right
            .resolve_thread(&objects, &bindings, &scheduler, CPU0, left_handle)
            .unwrap();
        assert_eq!(left_thread.scheduler_thread, global(left_local));
        assert_eq!(through_right.scheduler_thread, global(right_local));
        assert_ne!(left_thread.object, through_right.object);
    }

    #[test]
    fn full_cspace_rolls_back_unpublished_thread_object_and_binding() {
        let mut objects = ObjectTable::<3>::new();
        let mut process = Process::<2>::create(&mut objects, Personality::Native).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(2).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();

        assert_eq!(
            process.attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local),),
            Err(Error::Capability(CapError::TableFull))
        );
        assert!(bindings.is_empty());
        assert!(scheduler.state(local).is_ok());
        assert!(
            objects
                .create(ObjectMeta {
                    kind: ObjectKind::Thread,
                    owner_domain: 0,
                    flags: 0,
                })
                .is_ok()
        );
    }

    #[test]
    fn process_exit_is_blocked_until_owned_threads_are_reaped_and_released() {
        let mut objects = ObjectTable::<4>::new();
        let mut process = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(1).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let thread = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local))
            .unwrap();

        assert_eq!(
            process.exit(&mut objects, &bindings),
            Err(Error::ThreadsRemain)
        );
        scheduler.exit(local).unwrap();
        scheduler.reap(local).unwrap();
        // SAFETY: the exact CPU0 test generation was reaped immediately above.
        let proof = unsafe { reaped(local) };
        process
            .release_reaped_thread(&mut objects, &mut bindings, proof, thread)
            .unwrap();
        process.exit(&mut objects, &bindings).unwrap();
        assert_eq!(process.state(), ProcessState::Exited);
    }

    #[test]
    fn alternate_empty_binding_view_cannot_bypass_process_exit_guard() {
        let mut objects = ObjectTable::<4>::new();
        let mut process = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let mut scheduler = RunQueue::<1>::new();
        let local = scheduler.create(1).unwrap();
        let mut bindings = ThreadObjectBindings::<1>::new();
        let thread = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global(local))
            .unwrap();
        let empty_bindings = ThreadObjectBindings::<0>::new();

        assert_eq!(
            process.exit(&mut objects, &empty_bindings),
            Err(Error::ThreadsRemain)
        );
        assert_eq!(process.state(), ProcessState::Live);

        scheduler.exit(local).unwrap();
        scheduler.reap(local).unwrap();
        // SAFETY: the exact CPU0 test generation was reaped immediately above.
        let proof = unsafe { reaped(local) };
        process
            .release_reaped_thread(&mut objects, &mut bindings, proof, thread)
            .unwrap();
        process.exit(&mut objects, &empty_bindings).unwrap();
        assert_eq!(process.state(), ProcessState::Exited);
    }

    #[test]
    fn owner_exit_invalidates_delegated_authority_across_slot_reuse() {
        let mut objects = ObjectTable::<4>::new();
        let mut owner = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut peer = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let old_address_space = owner.address_space();

        let delegated = owner
            .delegate_to(
                &objects,
                owner.address_space_handle(),
                CapRights::MAP,
                &mut peer,
            )
            .unwrap();
        let empty_bindings = ThreadObjectBindings::<0>::new();
        owner.exit(&mut objects, &empty_bindings).unwrap();
        assert_eq!(owner.state(), ProcessState::Exited);
        assert_eq!(
            peer.resolve_object(&objects, delegated, CapRights::MAP),
            Err(Error::Object(ObjectError::InvalidObject))
        );

        let replacement = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        assert_ne!(replacement.address_space(), old_address_space);
        assert_eq!(
            peer.resolve_object(&objects, delegated, CapRights::MAP),
            Err(Error::Object(ObjectError::StaleObject))
        );
    }

    #[test]
    fn failed_cspace_construction_rolls_back_object_identities() {
        let mut objects = ObjectTable::<2>::new();
        let failed = Process::<1>::create(&mut objects, Personality::Native);
        assert!(matches!(
            failed,
            Err(Error::Capability(CapError::TableFull))
        ));

        let process = Process::<2>::create(&mut objects, Personality::Native).unwrap();
        assert_eq!(
            objects
                .resolve_kind(process.id(), ObjectKind::Process)
                .unwrap()
                .kind,
            ObjectKind::Process
        );
    }
}
