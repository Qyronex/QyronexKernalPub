// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(
    not(all(target_arch = "aarch64", target_os = "none")),
    allow(dead_code)
)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernal_address_space_aarch64::Aarch64AddressSpaceExt;
use kernal_capability::CapRights;
use kernal_object::{ObjectKind, ObjectTable};
use kernal_page_table_aarch64::Backend;
use kernal_process::{AddressSpaceOwnership, Process};

use super::{BoundProcessAddressSpace, Error};

const MAX_TRACKED_PES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BindingId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ActivationIdentity {
    process: u64,
    address_space: u64,
    binding: u64,
    root: u64,
    switch_generation: u64,
}

impl ActivationIdentity {
    pub(super) const fn new(
        process: u64,
        address_space: u64,
        binding: BindingId,
        root: u64,
        switch_generation: u64,
    ) -> Self {
        Self {
            process,
            address_space,
            binding: binding.0,
            root,
            switch_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegistryError {
    Full,
    Busy,
    #[cfg_attr(all(target_arch = "aarch64", target_os = "none"), allow(dead_code))]
    Unavailable,
}

static NEXT_BINDING_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn allocate_binding_id() -> Option<BindingId> {
    NEXT_BINDING_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
        .map(BindingId)
}

struct ActivationSlot {
    affinity_key: AtomicU64,
    locked: AtomicBool,
    process: AtomicU64,
    address_space: AtomicU64,
    binding: AtomicU64,
    root: AtomicU64,
    activation_generation: AtomicU64,
    switch_generation: AtomicU64,
    generation_exhausted: AtomicBool,
}

impl ActivationSlot {
    const fn new() -> Self {
        Self {
            affinity_key: AtomicU64::new(0),
            locked: AtomicBool::new(false),
            process: AtomicU64::new(0),
            address_space: AtomicU64::new(0),
            binding: AtomicU64::new(0),
            root: AtomicU64::new(0),
            activation_generation: AtomicU64::new(0),
            switch_generation: AtomicU64::new(0),
            generation_exhausted: AtomicBool::new(false),
        }
    }

    fn try_lock(&self) -> Result<(), RegistryError> {
        self.locked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| RegistryError::Busy)
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    fn begin_update(&self) -> Result<ActivationUpdate<'_>, RegistryError> {
        self.try_lock()?;
        Ok(ActivationUpdate {
            slot: self,
            finished: false,
        })
    }

    fn read(&self) -> Result<ActivationRead<'_>, RegistryError> {
        self.try_lock()?;
        let identity = ActivationIdentity {
            process: self.process.load(Ordering::Relaxed),
            address_space: self.address_space.load(Ordering::Relaxed),
            binding: self.binding.load(Ordering::Relaxed),
            root: self.root.load(Ordering::Relaxed),
            switch_generation: self.activation_generation.load(Ordering::Relaxed),
        };
        Ok(ActivationRead {
            slot: self,
            identity: (identity.binding != 0 && identity.switch_generation != 0)
                .then_some(identity),
        })
    }

    #[cfg(test)]
    fn observe(&self) -> Option<ActivationIdentity> {
        let read = self.read().ok()?;
        read.identity()
    }

    fn write_identity(&self, identity: Option<ActivationIdentity>) {
        let identity = identity.unwrap_or(ActivationIdentity {
            process: 0,
            address_space: 0,
            binding: 0,
            root: 0,
            switch_generation: 0,
        });
        self.process.store(identity.process, Ordering::Relaxed);
        self.address_space
            .store(identity.address_space, Ordering::Relaxed);
        self.binding.store(identity.binding, Ordering::Relaxed);
        self.root.store(identity.root, Ordering::Relaxed);
        self.activation_generation
            .store(identity.switch_generation, Ordering::Relaxed);
    }

    fn record_switch(&self) -> Option<u64> {
        if self.generation_exhausted.load(Ordering::Acquire) {
            return None;
        }
        match self.switch_generation.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |generation| generation.checked_add(1),
        ) {
            Ok(previous) => Some(previous + 1),
            Err(_) => {
                self.generation_exhausted.store(true, Ordering::Release);
                self.switch_generation.store(0, Ordering::Release);
                None
            }
        }
    }

    fn current_switch_generation(&self) -> Option<u64> {
        if self.generation_exhausted.load(Ordering::Acquire) {
            return None;
        }
        let generation = self.switch_generation.load(Ordering::Acquire);
        (generation != 0).then_some(generation)
    }
}

pub(super) struct ActivationRead<'a> {
    slot: &'a ActivationSlot,
    identity: Option<ActivationIdentity>,
}

impl ActivationRead<'_> {
    pub(super) const fn identity(&self) -> Option<ActivationIdentity> {
        self.identity
    }
}

impl Drop for ActivationRead<'_> {
    fn drop(&mut self) {
        self.slot.unlock();
    }
}

pub(super) struct ActivationUpdate<'a> {
    slot: &'a ActivationSlot,
    finished: bool,
}

impl ActivationUpdate<'_> {
    pub(super) fn finish(mut self, identity: Option<ActivationIdentity>) {
        self.slot.write_identity(identity);
        self.slot.unlock();
        self.finished = true;
    }
}

impl Drop for ActivationUpdate<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.slot.write_identity(None);
        self.slot.unlock();
    }
}

struct ActivationRegistry<const N: usize> {
    slots: [ActivationSlot; N],
}

impl<const N: usize> ActivationRegistry<N> {
    const fn new() -> Self {
        Self {
            slots: [const { ActivationSlot::new() }; N],
        }
    }

    const fn affinity_key(affinity: u32) -> u64 {
        affinity as u64 + 1
    }

    fn find(&self, affinity: u32) -> Option<&ActivationSlot> {
        let key = Self::affinity_key(affinity);
        self.slots
            .iter()
            .find(|slot| slot.affinity_key.load(Ordering::Acquire) == key)
    }

    fn find_or_register(&self, affinity: u32) -> Result<&ActivationSlot, RegistryError> {
        let key = Self::affinity_key(affinity);
        for slot in &self.slots {
            let observed = slot.affinity_key.load(Ordering::Acquire);
            if observed == key {
                return Ok(slot);
            }
            if observed != 0 {
                continue;
            }
            match slot
                .affinity_key
                .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(slot),
                Err(actual) if actual == key => return Ok(slot),
                Err(_) => {}
            }
        }
        Err(RegistryError::Full)
    }

    fn begin_update(&self, affinity: u32) -> Result<ActivationUpdate<'_>, RegistryError> {
        self.find_or_register(affinity)?.begin_update()
    }

    fn read(&self, affinity: u32) -> Option<ActivationRead<'_>> {
        self.find(affinity)?.read().ok()
    }

    #[cfg(test)]
    fn observe(&self, affinity: u32) -> Option<ActivationIdentity> {
        self.read(affinity)?.identity()
    }

    fn record_switch(&self, affinity: u32) -> Option<u64> {
        self.find_or_register(affinity).ok()?.record_switch()
    }

    fn current_switch_generation(&self, affinity: u32) -> Option<u64> {
        self.find(affinity)?.current_switch_generation()
    }
}

static ACTIVATIONS: ActivationRegistry<MAX_TRACKED_PES> = ActivationRegistry::new();

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_affinity_key() -> u32 {
    kernal_arch_aarch64::current_affinity().packed()
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn begin_current_update() -> Result<ActivationUpdate<'static>, RegistryError> {
    ACTIVATIONS.begin_update(current_affinity_key())
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(super) fn begin_current_update() -> Result<ActivationUpdate<'static>, RegistryError> {
    Err(RegistryError::Unavailable)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn current_read() -> Option<ActivationRead<'static>> {
    ACTIVATIONS.read(current_affinity_key())
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(super) fn current_read() -> Option<ActivationRead<'static>> {
    None
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn record_current_switch() {
    let _ = ACTIVATIONS.record_switch(current_affinity_key());
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(super) fn record_current_switch() {}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn current_switch_generation() -> Option<u64> {
    ACTIVATIONS.current_switch_generation(current_affinity_key())
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(super) fn current_switch_generation() -> Option<u64> {
    None
}

impl<const VMAS: usize> BoundProcessAddressSpace<VMAS> {
    /// Creates the AArch64 address-space staging target for one already-created fork child.
    ///
    /// The parent binding must still belong to the exact live parent Process. The child must be a
    /// distinct live Process with an independently owned AddressSpace ObjectId. A fresh, empty TTBR0
    /// root is allocated for that exact child object. Mapping population is intentionally not inferred
    /// here: the VM owner exposes no snapshot/iteration authority, so later fork integration must copy
    /// accepted mappings through explicit mapping owners before the child is schedulable.
    pub fn create_fork_child_staging<
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
        const OBJECTS: usize,
        B: Backend,
    >(
        parent_space: &Self,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
        objects: &ObjectTable<OBJECTS>,
        backend: &mut B,
    ) -> Result<Self, Error> {
        parent_space.authorize_owner(parent, objects)?;
        if child.id() == parent.id() || child.personality() != parent.personality() {
            return Err(Error::WrongProcess);
        }
        if child.address_space_ownership() != AddressSpaceOwnership::Owned
            || child.address_space() == parent.address_space()
        {
            return Err(Error::WrongAddressSpace);
        }
        Self::create(child, objects, backend)
    }

    /// Validates the address-space half of one vfork transition without creating another root owner.
    ///
    /// The existing parent binding remains the sole page-table/TTBR0 owner. The candidate child must
    /// be a distinct live Process created with `BorrowedVfork`, and its mandatory local AddressSpace
    /// capability must resolve `MAP|CONTROL` to the exact same generation-safe object while omitting
    /// `GRANT`. This method performs no hardware switch and no scheduler publication; later owner code
    /// must suspend the parent before the child may execute and must use the existing binding.
    pub fn validate_vfork_child_borrow<
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
        const OBJECTS: usize,
    >(
        &self,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
        objects: &ObjectTable<OBJECTS>,
    ) -> Result<(), Error> {
        self.authorize_owner(parent, objects)?;
        if child.id() == parent.id() || child.personality() != parent.personality() {
            return Err(Error::WrongProcess);
        }
        if child.address_space_ownership() != AddressSpaceOwnership::BorrowedVfork
            || child.address_space() != self.address_space_object
        {
            return Err(Error::WrongAddressSpace);
        }
        let resolved = child.resolve_object(
            objects,
            child.address_space_handle(),
            CapRights::MAP.union(CapRights::CONTROL),
        )?;
        if resolved.meta.kind != ObjectKind::AddressSpace {
            return Err(Error::WrongObjectKind);
        }
        if resolved.object != self.address_space_object
            || resolved.rights.contains(CapRights::GRANT)
        {
            return Err(Error::WrongAddressSpace);
        }
        Ok(())
    }

    /// Destructively drains anonymous leaves from one exact superseded live-Process binding after
    /// exec has already activated a distinct replacement binding for that same Process generation.
    ///
    /// This remains inside the canonical process-aarch64 owner. Both bindings must resolve the same
    /// Process/AddressSpace capability with CONTROL authority, but their logical BindingIds must be
    /// distinct. The replacement must prove current ownership; the superseded binding must fail that
    /// same current-owner proof. Numeric root equality is deliberately irrelevant because safe backend
    /// instances may allocate aliased root addresses while BindingId + switch generation remain the
    /// authoritative identity.
    ///
    /// Unsupported backing, page-table removal failure, frame-release failure or accounting overflow
    /// monotonically poisons the superseded binding. The replacement binding is never mutated here.
    ///
    /// # Safety
    /// Caller must own the local PE address-space/page-table mutation window with IRQ/preemption/
    /// migration and context switching suppressed for the complete call. `active_space` must be the
    /// already-committed exec replacement for `process`; `self` must be the exact prior binding and
    /// must be unreachable by every scheduler generation. No user access or context switch may race
    /// the drain, and `release` may retire only frames returned by this exact canonical unmap path.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn reclaim_superseded_anonymous_user_frames<
        const CAPS: usize,
        const OBJECTS: usize,
        B: Backend,
        F: FnMut(kernal_memory::PhysFrame) -> bool,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        active_space: &Self,
        backend: &mut B,
        mut release: F,
    ) -> Result<usize, Error> {
        if self.is_poisoned() {
            return Err(Error::Poisoned);
        }
        if process.state() != kernal_process::ProcessState::Live {
            return Err(Error::InactiveProcess);
        }
        if core::ptr::eq(
            core::ptr::from_ref(&*self),
            core::ptr::from_ref(active_space),
        ) {
            return Err(Error::NotCurrentAddressSpace);
        }

        self.authorize_owner(process, objects)?;
        active_space.authorize_owner(process, objects)?;
        if self.owner_process != active_space.owner_process {
            return Err(Error::WrongProcess);
        }
        if self.address_space_object != active_space.address_space_object {
            return Err(Error::WrongAddressSpace);
        }
        if self.binding_id == active_space.binding_id {
            return Err(Error::NotCurrentAddressSpace);
        }

        active_space.current_owner(process)?;
        match self.current_owner(process) {
            Ok(_) => return Err(Error::NotCurrentAddressSpace),
            Err(Error::NotCurrentProcess | Error::NotCurrentAddressSpace) => {}
            Err(error) => return Err(error),
        }

        let handle = process.address_space_handle();
        let mut released = 0usize;
        while let Some(vma) = self.user_vma_at(process, objects, handle, 0)? {
            if !matches!(vma.backing, kernal_vm::Backing::Anonymous) {
                self.poison();
                return Err(Error::UnsupportedExitBacking);
            }

            let frame = match self
                .unmap_user_page_coalescing_anonymous(process, objects, handle, backend, vma.start)
            {
                Ok(frame) => frame,
                Err(_) => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
            if !release(frame) {
                self.poison();
                return Err(Error::ExitCleanupFailed);
            }
            released = match released.checked_add(1) {
                Some(next) => next,
                None => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
        }

        // Every old-image user leaf and returned data frame is gone before the terminal table-tree
        // release begins. Poison first so no process-aarch64 API can ever reuse the superseded
        // BindingId/root while its now-empty hierarchy is returned to the unique live backend owner.
        self.poison();
        if unsafe { self.space.reclaim_empty_page_table_tree(backend) }.is_err() {
            return Err(Error::ExitCleanupFailed);
        }
        Ok(released)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use kernal_paging::PAGE_SIZE;
    use kernal_process::Personality;

    const TEST_TABLES: usize = 8;
    const TEST_TABLE_BASE: u64 = 0x20_0000;

    struct TestBackend {
        tables: [[u64; 512]; TEST_TABLES],
        used: usize,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TEST_TABLES],
                used: 0,
            }
        }

        fn index(physical: u64) -> Option<usize> {
            if physical < TEST_TABLE_BASE || !(physical - TEST_TABLE_BASE).is_multiple_of(PAGE_SIZE)
            {
                return None;
            }
            let index = ((physical - TEST_TABLE_BASE) / PAGE_SIZE) as usize;
            (index < TEST_TABLES).then_some(index)
        }
    }

    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == TEST_TABLES {
                return None;
            }
            let index = self.used;
            self.used += 1;
            self.tables[index] = [0; 512];
            Some(TEST_TABLE_BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let table = Self::index(table_phys).and_then(|index| self.tables.get_mut(index));
            let Some(table) = table else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    fn identity(binding: u64, root: u64, switch_generation: u64) -> ActivationIdentity {
        ActivationIdentity {
            process: 0x100,
            address_space: 0x200,
            binding,
            root,
            switch_generation,
        }
    }

    #[test]
    fn fork_staging_allocates_distinct_root_for_exact_child_process() {
        let mut objects = ObjectTable::<6>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut backend = TestBackend::new();
        let parent_space =
            BoundProcessAddressSpace::<2>::create(&parent, &objects, &mut backend).unwrap();
        let child_space = BoundProcessAddressSpace::<2>::create_fork_child_staging(
            &parent_space,
            &parent,
            &child,
            &objects,
            &mut backend,
        )
        .unwrap();

        assert_eq!(child_space.owner_process(), child.id());
        assert_eq!(child_space.address_space_object(), child.address_space());
        assert_ne!(
            child_space.address_space_object(),
            parent_space.address_space_object()
        );
        assert_ne!(child_space.root_phys(), parent_space.root_phys());
    }

    #[test]
    fn vfork_borrow_requires_exact_parent_root_and_borrowed_child_generation() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let vfork_child = Process::<4>::create_vfork_child(&parent, &mut objects).unwrap();
        let fork_child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let foreign_parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let parent_space =
            BoundProcessAddressSpace::<2>::create(&parent, &objects, &mut backend).unwrap();

        assert_eq!(
            parent_space.validate_vfork_child_borrow(&parent, &vfork_child, &objects),
            Ok(())
        );
        assert_eq!(
            parent_space.validate_vfork_child_borrow(&parent, &fork_child, &objects),
            Err(Error::WrongAddressSpace)
        );
        assert_eq!(
            parent_space.validate_vfork_child_borrow(&foreign_parent, &vfork_child, &objects),
            Err(Error::WrongProcess)
        );
    }

    #[test]
    fn registry_keeps_distinct_pe_activation_state() {
        let registry = ActivationRegistry::<2>::new();
        assert_eq!(registry.record_switch(0x10), Some(1));
        assert_eq!(registry.record_switch(0x20), Some(1));
        registry
            .begin_update(0x10)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));
        registry
            .begin_update(0x20)
            .unwrap()
            .finish(Some(identity(2, 0x2000, 1)));

        assert_eq!(registry.observe(0x10), Some(identity(1, 0x1000, 1)));
        assert_eq!(registry.observe(0x20), Some(identity(2, 0x2000, 1)));
        assert_eq!(registry.current_switch_generation(0x10), Some(1));
        assert_eq!(registry.current_switch_generation(0x20), Some(1));
    }

    #[test]
    fn switching_binding_identity_replaces_same_root_owner() {
        let registry = ActivationRegistry::<1>::new();
        assert_eq!(registry.record_switch(7), Some(1));
        registry
            .begin_update(7)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));
        assert_eq!(registry.record_switch(7), Some(2));
        registry
            .begin_update(7)
            .unwrap()
            .finish(Some(identity(2, 0x1000, 2)));

        assert_eq!(registry.observe(7), Some(identity(2, 0x1000, 2)));
        assert_ne!(registry.observe(7), Some(identity(1, 0x1000, 1)));
    }

    #[test]
    fn raw_switch_generation_invalidates_published_identity_without_rewriting_it() {
        let registry = ActivationRegistry::<1>::new();
        assert_eq!(registry.record_switch(4), Some(1));
        registry
            .begin_update(4)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));
        assert_eq!(registry.observe(4), Some(identity(1, 0x1000, 1)));
        assert_eq!(registry.record_switch(4), Some(2));
        assert_eq!(registry.current_switch_generation(4), Some(2));
        assert_eq!(registry.observe(4), Some(identity(1, 0x1000, 1)));
    }

    #[test]
    fn aborted_update_clears_previous_activation() {
        let registry = ActivationRegistry::<1>::new();
        assert_eq!(registry.record_switch(9), Some(1));
        registry
            .begin_update(9)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));
        drop(registry.begin_update(9).unwrap());
        assert_eq!(registry.observe(9), None);
    }

    #[test]
    fn repeated_same_affinity_registration_uses_one_slot() {
        let registry = ActivationRegistry::<2>::new();
        registry.find_or_register(0xffff_ffff).unwrap();
        registry.find_or_register(0xffff_ffff).unwrap();
        let key = ActivationRegistry::<2>::affinity_key(0xffff_ffff);
        let matches = registry
            .slots
            .iter()
            .filter(|slot| slot.affinity_key.load(Ordering::Relaxed) == key)
            .count();
        assert_eq!(matches, 1);
    }

    #[test]
    fn reader_fails_closed_while_switch_writer_owns_slot() {
        let registry = ActivationRegistry::<1>::new();
        let update = registry.begin_update(3).unwrap();
        assert_eq!(registry.observe(3), None);
        assert_eq!(registry.record_switch(3), Some(1));
        update.finish(Some(identity(1, 0x1000, 1)));
        assert_eq!(registry.observe(3), Some(identity(1, 0x1000, 1)));
    }

    #[test]
    fn read_guard_blocks_process_switch_until_identity_and_root_checks_finish() {
        let registry = ActivationRegistry::<1>::new();
        assert_eq!(registry.record_switch(5), Some(1));
        registry
            .begin_update(5)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));

        let read = registry.read(5).unwrap();
        assert_eq!(read.identity(), Some(identity(1, 0x1000, 1)));
        assert!(matches!(registry.begin_update(5), Err(RegistryError::Busy)));
        drop(read);

        assert_eq!(registry.record_switch(5), Some(2));
        registry
            .begin_update(5)
            .unwrap()
            .finish(Some(identity(2, 0x1000, 2)));
        assert_eq!(registry.observe(5), Some(identity(2, 0x1000, 2)));
    }

    #[test]
    fn busy_deactivation_gate_does_not_reach_hardware_mutation() {
        let registry = ActivationRegistry::<1>::new();
        assert_eq!(registry.record_switch(6), Some(1));
        registry
            .begin_update(6)
            .unwrap()
            .finish(Some(identity(1, 0x1000, 1)));

        let read = registry.read(6).unwrap();
        let hardware_mutated = Cell::new(false);
        let attempt = (|| -> Result<(), RegistryError> {
            let update = registry.begin_update(6)?;
            hardware_mutated.set(true);
            update.finish(None);
            Ok(())
        })();

        assert_eq!(attempt, Err(RegistryError::Busy));
        assert!(!hardware_mutated.get());
        assert_eq!(read.identity(), Some(identity(1, 0x1000, 1)));
        drop(read);
    }
}
