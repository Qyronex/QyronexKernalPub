// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod activation;
mod exec_discard;

use activation::{ActivationIdentity, BindingId, RegistryError};
use kernal_address_space_aarch64::{
    Aarch64AddressSpaceExt, Aarch64Root, Error as AddressSpaceError,
};
use kernal_capability::{CapHandle, CapRights, ObjectId};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::{ObjectKind, ObjectTable};
use kernal_page_table_aarch64::{Backend, current_user_ttbr0, install_user_ttbr0_switch_observer};
use kernal_process::{Error as ProcessError, Personality, Process, ProcessState};
use kernal_vm::{AddressSpace, Backing, Vma};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Process(ProcessError),
    AddressSpace(AddressSpaceError),
    InactiveProcess,
    WrongProcess,
    WrongAddressSpace,
    WrongObjectKind,
    NotCurrentProcess,
    NotCurrentAddressSpace,
    BindingIdExhausted,
    ActivationRegistryFull,
    ActivationBusy,
    ActivationUnavailable,
    ProcessStillLive,
    UnsupportedExitBacking,
    ExitCleanupFailed,
    Poisoned,
}

impl From<ProcessError> for Error {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}

impl From<AddressSpaceError> for Error {
    fn from(value: AddressSpaceError) -> Self {
        Self::AddressSpace(value)
    }
}

fn map_registry_error(error: RegistryError) -> Error {
    match error {
        RegistryError::Full => Error::ActivationRegistryFull,
        RegistryError::Busy => Error::ActivationBusy,
        RegistryError::Unavailable => Error::ActivationUnavailable,
    }
}

fn observe_user_ttbr0_switch() {
    activation::record_current_switch();
}

fn ensure_user_ttbr0_switch_observer() -> Result<(), Error> {
    if install_user_ttbr0_switch_observer(observe_user_ttbr0_switch) {
        Ok(())
    } else {
        Err(Error::ActivationUnavailable)
    }
}

/// Returns the current PE's canonical user-TTBR0 switch generation.
///
/// This value is diagnostic input for the accepted exception-frame path. It is not an authority
/// token: Linux policy still requires an opaque [`ActiveProcess`] whose logical activation identity,
/// process ownership, root and generation all revalidate together.
pub fn current_user_switch_generation() -> Option<u64> {
    activation::current_switch_generation()
}

/// Opaque proof that one live process owns the exact logical user address-space binding active now.
///
/// The witness can only be created through [`BoundProcessAddressSpace::current_owner`]. It borrows
/// both the process and its bound address space, so safe code cannot exit that process or poison the
/// binding while the witness exists. Every policy query revalidates the architectural TTBR0 state,
/// the per-PE logical activation identity and the canonical TTBR0 switch generation. Therefore raw
/// root switches and numerically aliased roots cannot preserve or manufacture Linux authority.
pub struct ActiveProcess<'a, const CAPS: usize, const VMAS: usize> {
    process: &'a Process<CAPS>,
    space: &'a BoundProcessAddressSpace<VMAS>,
}

impl<'a, const CAPS: usize, const VMAS: usize> ActiveProcess<'a, CAPS, VMAS> {
    /// Returns the personality only while this exact process/address-space binding remains current.
    pub fn personality(&self) -> Result<Personality, Error> {
        self.validate_current()?;
        Ok(self.process.personality())
    }

    /// Returns the personality only if the current binding still has the exact switch generation
    /// captured when the supplied exception frame entered EL1.
    pub fn personality_at_switch_generation(
        &self,
        entry_switch_generation: u64,
    ) -> Result<Personality, Error> {
        self.validate_entry_switch_generation(entry_switch_generation)?;
        Ok(self.process.personality())
    }

    /// Revalidates process liveness, ownership, logical activation identity, switch generation and
    /// current TTBR0.
    pub fn validate_current(&self) -> Result<(), Error> {
        self.validate_current_generation().map(|_| ())
    }

    /// Proves that this current process is also the process generation that trapped into the saved
    /// exception frame. A zero/unavailable entry generation always fails closed.
    pub fn validate_entry_switch_generation(
        &self,
        entry_switch_generation: u64,
    ) -> Result<(), Error> {
        if entry_switch_generation == 0 {
            return Err(Error::NotCurrentProcess);
        }
        let current_generation = self.validate_current_generation()?;
        if current_generation != entry_switch_generation {
            return Err(Error::NotCurrentProcess);
        }
        Ok(())
    }

    fn validate_current_generation(&self) -> Result<u64, Error> {
        let activation = activation::current_read().ok_or(Error::NotCurrentProcess)?;
        let generation_before =
            activation::current_switch_generation().ok_or(Error::NotCurrentProcess)?;
        let observed_root = current_user_ttbr0();
        let generation_after =
            activation::current_switch_generation().ok_or(Error::NotCurrentProcess)?;
        if generation_before != generation_after {
            return Err(Error::NotCurrentAddressSpace);
        }
        self.validate_current_with_observation(
            observed_root,
            activation.identity(),
            Some(generation_after),
        )?;
        Ok(generation_after)
    }

    fn validate_current_with_observation(
        &self,
        observed_root: Option<u64>,
        observed_activation: Option<ActivationIdentity>,
        observed_switch_generation: Option<u64>,
    ) -> Result<(), Error> {
        if self.process.state() != ProcessState::Live {
            return Err(Error::InactiveProcess);
        }
        if self.space.poisoned {
            return Err(Error::Poisoned);
        }
        if self.process.id() != self.space.owner_process {
            return Err(Error::WrongProcess);
        }
        if self.process.address_space() != self.space.address_space_object {
            return Err(Error::WrongAddressSpace);
        }
        let generation = observed_switch_generation.ok_or(Error::NotCurrentProcess)?;
        if observed_activation != Some(self.space.activation_identity(generation)) {
            return Err(Error::NotCurrentProcess);
        }
        if observed_root != Some(self.space.root_phys()) {
            return Err(Error::NotCurrentAddressSpace);
        }
        Ok(())
    }
}

/// A Step-11 AArch64 address-space root bound to one generation-safe process/address-space pair.
///
/// The binding stores object identities only for comparison; they are never accepted as authority.
/// Every mapping/translation operation first resolves a [`CapHandle`] through the caller's current
/// process CSpace with `MAP` rights. TTBR0 activation is stricter: only the process that owns this
/// binding may activate it, and its mandatory address-space root capability must still resolve with
/// `CONTROL` rights.
///
/// Each instance additionally owns a monotonic `BindingId`. `activate_owner` publishes that ID with
/// the generation-safe Process and AddressSpace ObjectIds plus the canonical TTBR0 switch generation
/// into a per-PE registry. Current-process policy requires that logical identity, generation and the
/// hardware root, so safe Backend root aliasing or raw canonical TTBR0 switches cannot widen policy.
///
/// The page-table and VMA implementation is the already accepted Step-7
/// `AddressSpace<Aarch64Root, _>` stack. This adapter adds process/CSpace ownership only.
pub struct BoundProcessAddressSpace<const VMAS: usize> {
    owner_process: ObjectId,
    address_space_object: ObjectId,
    binding_id: BindingId,
    space: AddressSpace<Aarch64Root, VMAS>,
    poisoned: bool,
}

impl<const VMAS: usize> BoundProcessAddressSpace<VMAS> {
    /// Allocates an empty AArch64 TTBR0 root and binds it to the process's mandatory address-space
    /// capability. The capability and unique logical BindingId are established before root use.
    pub fn create<const CAPS: usize, const OBJECTS: usize, B: Backend>(
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        backend: &mut B,
    ) -> Result<Self, Error> {
        let resolved =
            process.resolve_object(objects, process.address_space_handle(), CapRights::MAP)?;
        if resolved.meta.kind != ObjectKind::AddressSpace {
            return Err(Error::WrongObjectKind);
        }

        let binding_id = activation::allocate_binding_id().ok_or(Error::BindingIdExhausted)?;
        let root = Aarch64Root::new(backend)?;
        Ok(Self {
            owner_process: process.id(),
            address_space_object: resolved.object,
            binding_id,
            space: AddressSpace::new(root),
            poisoned: false,
        })
    }

    /// Returns the stored process identity for diagnostics/tests only. It is not an authority token.
    pub const fn owner_process(&self) -> ObjectId {
        self.owner_process
    }

    /// Returns the stored address-space identity for diagnostics/tests only. It is not authority.
    pub const fn address_space_object(&self) -> ObjectId {
        self.address_space_object
    }

    /// Returns whether this binding has been quarantined after an unrecoverable mapping cleanup
    /// failure. A poisoned binding rejects all future user mapping, translation and activation.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Quarantines this address-space binding after cleanup can no longer prove transactional state.
    ///
    /// Poisoning is monotonic. The root may still contain residual mappings, but no future operation
    /// through this accepted process/CSpace adapter can map, unmap, translate or activate it.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Drains every anonymous user leaf from an exact already-exited Process generation.
    ///
    /// Normal user mapping mutation requires a live Process and MAP authority. Process exit deliberately
    /// revokes that authority before wait/zombie observation, so final resource reclamation needs a
    /// separate, narrower owner edge. This method accepts only the retained Process object whose exact
    /// generation and AddressSpace identity match this binding, requires `ProcessState::Exited`, and
    /// exposes no mapping/translation capability to callers.
    ///
    /// Every leaf is removed through the existing AArch64 AddressSpace owner. Only after a successful
    /// unmap is its exact PhysFrame offered to `release`. A release or unmap failure monotonically
    /// poisons the binding and fails closed; already-removed frames are never remapped or silently
    /// recycled. Fork/ELF Step-30 mappings are Anonymous; any other backing is rejected before that
    /// leaf is touched rather than guessing file/shared-memory teardown semantics.
    pub fn reclaim_exited_anonymous_user_frames<
        const CAPS: usize,
        B: Backend,
        F: FnMut(PhysFrame) -> bool,
    >(
        &mut self,
        process: &Process<CAPS>,
        backend: &mut B,
        mut release: F,
    ) -> Result<usize, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if process.state() != ProcessState::Exited {
            return Err(Error::ProcessStillLive);
        }
        if process.id() != self.owner_process {
            return Err(Error::WrongProcess);
        }
        if process.address_space() != self.address_space_object {
            return Err(Error::WrongAddressSpace);
        }

        let mut released = 0usize;
        loop {
            let Some(vma) = self.space.vmas().get(0) else {
                return Ok(released);
            };
            if !matches!(vma.backing, Backing::Anonymous) {
                self.poisoned = true;
                return Err(Error::UnsupportedExitBacking);
            }

            let frame = match self
                .space
                .unmap_user_page_coalescing_anonymous(backend, vma.start)
            {
                Ok(frame) => frame,
                Err(_) => {
                    self.poisoned = true;
                    return Err(Error::ExitCleanupFailed);
                }
            };
            if !release(frame) {
                self.poisoned = true;
                return Err(Error::ExitCleanupFailed);
            }
            released = released.checked_add(1).ok_or_else(|| {
                self.poisoned = true;
                Error::ExitCleanupFailed
            })?;
        }
    }

    /// Creates a non-forgeable witness for the logical binding active on this PE right now.
    ///
    /// Unlike a plain `&Process`, this succeeds only when Process/AddressSpace ownership matches,
    /// the per-PE activation registry names this exact BindingId and current switch generation, and
    /// enabled TTBR0 equals this root. Numeric root equality alone is deliberately insufficient.
    pub fn current_owner<'a, const CAPS: usize>(
        &'a self,
        process: &'a Process<CAPS>,
    ) -> Result<ActiveProcess<'a, CAPS, VMAS>, Error> {
        let active = ActiveProcess {
            process,
            space: self,
        };
        active.validate_current()?;
        Ok(active)
    }

    /// Validates one candidate user range against the existing VMA policy only after resolving
    /// `handle` through the caller's CSpace with `MAP` rights.
    ///
    /// This is a read-only placement query. A successful `true` result grants no mapping authority
    /// beyond the already-resolved capability and is not a reservation: callers must re-enter the
    /// normal process-bound mapping transaction before mutating page tables.
    pub fn user_range_is_free<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        start: u64,
        len: u64,
    ) -> Result<bool, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .range_is_free(start, len)
            .map_err(|error| Error::AddressSpace(AddressSpaceError::Vm(error)))
    }

    /// Finds one top-down candidate gap through the same private VMA table after resolving the
    /// caller's `MAP` authority. The VMA table remains encapsulated; Linux address-selection policy
    /// receives only the candidate address and must still perform normal mapping/rollback later.
    pub fn find_user_gap_top_down<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        len: u64,
        ceiling: u64,
    ) -> Result<u64, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .find_gap_top_down(len, ceiling)
            .map_err(|error| Error::AddressSpace(AddressSpaceError::Vm(error)))
    }

    /// Returns one copied VMA in canonical sorted order after exact MAP authorization.
    ///
    /// This is a bounded read-only capability boundary for cross-owner operations such as Linux
    /// `fork`. The private AddressSpace and VmaTable never escape; `None` means `index` is outside
    /// the currently populated canonical VMA range.
    pub fn user_vma_at<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        index: usize,
    ) -> Result<Option<Vma>, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        Ok(self.space.vmas().get(index))
    }

    /// Maps one user page after resolving `handle` in the caller process with `MAP` rights.
    /// Explicitly delegated authority is therefore usable; a coincidentally equal numeric handle in
    /// another CSpace is not.
    ///
    /// The security boundary intentionally keeps process/CSpace authority, backend, mapping,
    /// physical frame and reservation inputs explicit rather than hiding them in an opaque request.
    #[allow(clippy::too_many_arguments)]
    pub fn map_user_page<
        const CAPS: usize,
        const OBJECTS: usize,
        const RESERVED: usize,
        B: Backend,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        backend: &mut B,
        vma: Vma,
        frame: PhysFrame,
        reserved: &ReservationSet<RESERVED>,
    ) -> Result<(), Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .map_user_page(backend, vma, frame, reserved)
            .map_err(Error::from)
    }

    /// Maps one anonymous Linux-VM leaf through the same authority boundary while allowing the
    /// lower AArch64 owner to compact adjacent anonymous VMA policy. Existing loader callers stay on
    /// [`Self::map_user_page`] and retain exact VMA-capacity semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn map_user_page_coalescing_anonymous<
        const CAPS: usize,
        const OBJECTS: usize,
        const RESERVED: usize,
        B: Backend,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        backend: &mut B,
        vma: Vma,
        frame: PhysFrame,
        reserved: &ReservationSet<RESERVED>,
    ) -> Result<(), Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .map_user_page_coalescing_anonymous(backend, vma, frame, reserved)
            .map_err(Error::from)
    }

    /// Unmaps one user page after resolving `handle` through the caller's CSpace.
    pub fn unmap_user_page<const CAPS: usize, const OBJECTS: usize, B: Backend>(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<PhysFrame, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .unmap_user_page(backend, virtual_address)
            .map_err(Error::from)
    }

    /// Unmaps one leaf from the compact anonymous Linux-VM policy through the same CSpace check.
    pub fn unmap_user_page_coalescing_anonymous<
        const CAPS: usize,
        const OBJECTS: usize,
        B: Backend,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<PhysFrame, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .unmap_user_page_coalescing_anonymous(backend, virtual_address)
            .map_err(Error::from)
    }

    /// Translates one user address only after the caller proves `MAP` authority via its CSpace.
    pub fn translate_user<const CAPS: usize, const OBJECTS: usize, B: Backend>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<u64, Error> {
        self.authorize_handle(process, objects, handle, CapRights::MAP)?;
        self.space
            .translate_user(backend, virtual_address)
            .map_err(Error::from)
    }

    /// Activates this process's own root as TTBR0 and publishes the same logical binding per PE.
    ///
    /// Explicitly delegated `MAP` authority does not grant the ability to become this root's owner.
    /// The canonical lower-level TTBR0 observer advances the switch generation before hardware
    /// mutation; this process-aware path publishes the matching generation only after activation.
    ///
    /// # Safety
    /// After authorization succeeds, the caller must satisfy the existing
    /// `Aarch64Root::activate` contract: EL1 execution, quiesced user access, and scheduler ownership
    /// of the current PE/address-space switch window. The same ownership guarantees one activation
    /// writer per PE while the registry update is in progress.
    pub unsafe fn activate_owner<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
    ) -> Result<(), Error> {
        self.authorize_owner(process, objects)?;
        ensure_user_ttbr0_switch_observer()?;
        let update = activation::begin_current_update().map_err(map_registry_error)?;
        let root = *self.space.root();
        // SAFETY: delegated to the caller after owner/CSpace validation and registry writer claim.
        unsafe { root.activate() }.map_err(Error::from)?;
        let generation =
            activation::current_switch_generation().ok_or(Error::ActivationUnavailable)?;
        if current_user_ttbr0() != Some(self.root_phys()) {
            return Err(Error::NotCurrentAddressSpace);
        }
        update.finish(Some(self.activation_identity(generation)));
        Ok(())
    }

    /// Leaves the current PE in the kernel-only TTBR1 regime and removes logical activation.
    ///
    /// If the activation-registry switch window is busy, this returns `ActivationBusy` without
    /// touching TCR_EL1/TTBR0_EL1. Hardware and logical state therefore remain one serialized switch
    /// transaction instead of allowing a reader to succeed against stale identity after hardware
    /// deactivation.
    ///
    /// # Safety
    /// Caller must satisfy the accepted `Aarch64Root::deactivate` contract and own the same PE switch
    /// window used by `activate_owner`.
    pub unsafe fn deactivate() -> Result<(), Error> {
        ensure_user_ttbr0_switch_observer()?;
        let update = activation::begin_current_update().map_err(map_registry_error)?;
        // SAFETY: delegated caller contract after the logical switch writer was acquired.
        unsafe { Aarch64Root::deactivate() };
        update.finish(None);
        Ok(())
    }

    fn root_phys(&self) -> u64 {
        self.space.root().root_phys()
    }

    fn activation_identity(&self, switch_generation: u64) -> ActivationIdentity {
        ActivationIdentity::new(
            self.owner_process.0,
            self.address_space_object.0,
            self.binding_id,
            self.root_phys(),
            switch_generation,
        )
    }

    fn authorize_handle<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        handle: CapHandle,
        required: CapRights,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let resolved = process.resolve_object(objects, handle, required)?;
        if resolved.meta.kind != ObjectKind::AddressSpace {
            return Err(Error::WrongObjectKind);
        }
        if resolved.object != self.address_space_object {
            return Err(Error::WrongAddressSpace);
        }
        Ok(())
    }

    fn authorize_owner<const CAPS: usize, const OBJECTS: usize>(
        &self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
    ) -> Result<(), Error> {
        if process.id() != self.owner_process {
            return Err(Error::WrongProcess);
        }
        self.authorize_handle(
            process,
            objects,
            process.address_space_handle(),
            CapRights::CONTROL,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_object::{Error as ObjectError, ObjectTable};
    use kernal_page_table_aarch64::Backend;
    use kernal_paging::PAGE_SIZE;
    use kernal_process::{Personality, ThreadObjectBindings};
    use kernal_vm::{Backing, USER_MIN, VmPerms};

    const TABLES: usize = 64;
    const TABLE_BASE: u64 = 0x10_0000;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TABLES],
                used: 0,
            }
        }

        fn index(physical: u64) -> Option<usize> {
            if physical < TABLE_BASE || !(physical - TABLE_BASE).is_multiple_of(PAGE_SIZE) {
                return None;
            }
            let index = ((physical - TABLE_BASE) / PAGE_SIZE) as usize;
            (index < TABLES).then_some(index)
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
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = Self::index(table_phys).and_then(|index| self.tables.get_mut(index))
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

    fn vma(address: u64) -> Vma {
        Vma::new(address, PAGE_SIZE, VmPerms::READ, Backing::Anonymous).unwrap()
    }

    #[test]
    fn two_processes_map_same_va_to_distinct_frames_under_own_caps() {
        let mut objects = ObjectTable::<8>::new();
        let left = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let right = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut left_space =
            BoundProcessAddressSpace::<4>::create(&left, &objects, &mut backend).unwrap();
        let mut right_space =
            BoundProcessAddressSpace::<4>::create(&right, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let address = USER_MIN + 0x20_000;
        let left_frame = PhysFrame::from_start_address(0x40_0000).unwrap();
        let right_frame = PhysFrame::from_start_address(0x80_0000).unwrap();

        left_space
            .map_user_page(
                &left,
                &objects,
                left.address_space_handle(),
                &mut backend,
                vma(address),
                left_frame,
                &reserved,
            )
            .unwrap();
        right_space
            .map_user_page(
                &right,
                &objects,
                right.address_space_handle(),
                &mut backend,
                vma(address),
                right_frame,
                &reserved,
            )
            .unwrap();

        assert_eq!(
            left_space
                .translate_user(
                    &left,
                    &objects,
                    left.address_space_handle(),
                    &mut backend,
                    address,
                )
                .unwrap(),
            left_frame.start_address()
        );
        assert_eq!(
            right_space
                .translate_user(
                    &right,
                    &objects,
                    right.address_space_handle(),
                    &mut backend,
                    address,
                )
                .unwrap(),
            right_frame.start_address()
        );
        assert_ne!(
            left_space.address_space_object(),
            right_space.address_space_object()
        );
    }

    #[test]
    fn exited_owner_drain_returns_exact_anonymous_frames_after_capability_revoke() {
        let mut objects = ObjectTable::<8>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<4>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let base = USER_MIN + 0x18_000;
        let first = PhysFrame::from_start_address(0x40_0000).unwrap();
        let second = PhysFrame::from_start_address(0x41_0000).unwrap();
        for (address, frame) in [(base, first), (base + PAGE_SIZE, second)] {
            space
                .map_user_page_coalescing_anonymous(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    Vma::new(address, PAGE_SIZE, VmPerms::READ, Backing::Anonymous).unwrap(),
                    frame,
                    &reserved,
                )
                .unwrap();
        }

        let bindings = ThreadObjectBindings::<0>::new();
        process.exit(&mut objects, &bindings).unwrap();
        let mut observed = [None; 2];
        let mut count = 0usize;
        let released = space
            .reclaim_exited_anonymous_user_frames(&process, &mut backend, |frame| {
                if count >= observed.len() {
                    return false;
                }
                observed[count] = Some(frame);
                count += 1;
                true
            })
            .unwrap();

        assert_eq!(released, 2);
        assert_eq!(observed, [Some(first), Some(second)]);
        assert_eq!(space.space.vmas().get(0), None);
        assert!(!space.is_poisoned());
    }

    #[test]
    fn exited_owner_drain_rejects_live_process_before_mapping_mutation() {
        let mut objects = ObjectTable::<8>::new();
        let process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<2>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let address = USER_MIN + 0x28_000;
        let frame = PhysFrame::from_start_address(0x50_0000).unwrap();
        space
            .map_user_page_coalescing_anonymous(
                &process,
                &objects,
                process.address_space_handle(),
                &mut backend,
                vma(address),
                frame,
                &reserved,
            )
            .unwrap();

        let mut release_called = false;
        assert_eq!(
            space.reclaim_exited_anonymous_user_frames(&process, &mut backend, |_| {
                release_called = true;
                true
            }),
            Err(Error::ProcessStillLive)
        );
        assert!(!release_called);
        assert_eq!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    address,
                )
                .unwrap(),
            frame.start_address()
        );
        assert!(!space.is_poisoned());
    }

    #[test]
    fn exited_owner_drain_poison_fails_closed_when_frame_release_fails() {
        let mut objects = ObjectTable::<8>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<2>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let address = USER_MIN + 0x38_000;
        let frame = PhysFrame::from_start_address(0x60_0000).unwrap();
        space
            .map_user_page_coalescing_anonymous(
                &process,
                &objects,
                process.address_space_handle(),
                &mut backend,
                vma(address),
                frame,
                &reserved,
            )
            .unwrap();
        let bindings = ThreadObjectBindings::<0>::new();
        process.exit(&mut objects, &bindings).unwrap();

        assert_eq!(
            space.reclaim_exited_anonymous_user_frames(&process, &mut backend, |_| false),
            Err(Error::ExitCleanupFailed)
        );
        assert!(space.is_poisoned());
        assert_eq!(
            space.reclaim_exited_anonymous_user_frames(&process, &mut backend, |_| true),
            Err(Error::Poisoned)
        );
    }

    #[test]
    fn placement_queries_require_exact_map_authority_and_do_not_reserve() {
        let mut objects = ObjectTable::<8>::new();
        let owner = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut peer = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<4>::create(&owner, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let mapped = USER_MIN + 0x20_000;
        let frame = PhysFrame::from_start_address(0x40_0000).unwrap();
        space
            .map_user_page(
                &owner,
                &objects,
                owner.address_space_handle(),
                &mut backend,
                vma(mapped),
                frame,
                &reserved,
            )
            .unwrap();

        assert_eq!(
            space.user_range_is_free(
                &owner,
                &objects,
                owner.address_space_handle(),
                mapped,
                PAGE_SIZE,
            ),
            Ok(false)
        );
        let candidate = space
            .find_user_gap_top_down(
                &owner,
                &objects,
                owner.address_space_handle(),
                PAGE_SIZE,
                mapped + 4 * PAGE_SIZE,
            )
            .unwrap();
        assert_eq!(candidate, mapped + 3 * PAGE_SIZE);
        assert_eq!(
            space.user_vma_at(&owner, &objects, owner.address_space_handle(), 0),
            Ok(Some(vma(mapped)))
        );
        assert_eq!(
            space.user_vma_at(&owner, &objects, owner.address_space_handle(), 1),
            Ok(None)
        );
        assert_eq!(
            space.user_range_is_free(
                &owner,
                &objects,
                owner.address_space_handle(),
                candidate,
                PAGE_SIZE,
            ),
            Ok(true)
        );
        assert_eq!(
            space.translate_user(
                &owner,
                &objects,
                owner.address_space_handle(),
                &mut backend,
                candidate,
            ),
            Err(Error::AddressSpace(AddressSpaceError::PageTable(
                kernal_page_table_aarch64::Error::NotMapped
            )))
        );

        // The same numeric mandatory handle in another private CSpace cannot query this space.
        assert_eq!(owner.address_space_handle(), peer.address_space_handle());
        assert_eq!(
            space.user_range_is_free(
                &peer,
                &objects,
                peer.address_space_handle(),
                candidate,
                PAGE_SIZE,
            ),
            Err(Error::WrongAddressSpace)
        );

        assert_eq!(
            space.user_vma_at(&peer, &objects, peer.address_space_handle(), 0),
            Err(Error::WrongAddressSpace)
        );

        // Explicit MAP delegation grants read-only placement authority, but still no reservation.
        let delegated = owner
            .delegate_to(
                &objects,
                owner.address_space_handle(),
                CapRights::MAP,
                &mut peer,
            )
            .unwrap();
        assert_eq!(
            space.user_range_is_free(&peer, &objects, delegated, candidate, PAGE_SIZE),
            Ok(true)
        );
        assert_eq!(
            space.find_user_gap_top_down(
                &peer,
                &objects,
                delegated,
                PAGE_SIZE,
                mapped + 4 * PAGE_SIZE,
            ),
            Ok(candidate)
        );
        assert_eq!(
            space.user_vma_at(&peer, &objects, delegated, 0),
            Ok(Some(vma(mapped)))
        );
    }

    #[test]
    fn equal_numeric_handles_in_private_cspaces_do_not_cross_authorize() {
        let mut objects = ObjectTable::<8>::new();
        let left = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let right = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        assert_eq!(left.address_space_handle(), right.address_space_handle());

        let mut backend = TestBackend::new();
        let mut left_space =
            BoundProcessAddressSpace::<2>::create(&left, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let frame = PhysFrame::from_start_address(0x40_0000).unwrap();
        assert_eq!(
            left_space.map_user_page(
                &right,
                &objects,
                right.address_space_handle(),
                &mut backend,
                vma(USER_MIN + 0x30_000),
                frame,
                &reserved,
            ),
            Err(Error::WrongAddressSpace)
        );
    }

    #[test]
    fn explicit_delegation_is_required_for_cross_process_mapping_authority() {
        let mut objects = ObjectTable::<8>::new();
        let left = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut right = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut left_space =
            BoundProcessAddressSpace::<2>::create(&left, &objects, &mut backend).unwrap();
        let delegated = left
            .delegate_to(
                &objects,
                left.address_space_handle(),
                CapRights::MAP,
                &mut right,
            )
            .unwrap();
        let reserved = ReservationSet::<1>::new();
        let address = USER_MIN + 0x40_000;
        let frame = PhysFrame::from_start_address(0x50_0000).unwrap();

        left_space
            .map_user_page(
                &right,
                &objects,
                delegated,
                &mut backend,
                vma(address),
                frame,
                &reserved,
            )
            .unwrap();
        assert_eq!(
            left_space
                .translate_user(&right, &objects, delegated, &mut backend, address)
                .unwrap(),
            frame.start_address()
        );

        // Delegated MAP authority is not process ownership and cannot activate this root as right's
        // own TTBR0 root. This check fails before the host-only activation registry is reached.
        assert_eq!(
            unsafe { left_space.activate_owner(&right, &objects) },
            Err(Error::WrongProcess)
        );
    }

    #[test]
    fn owner_exit_invalidates_delegated_address_space_authority() {
        let mut objects = ObjectTable::<8>::new();
        let mut owner = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut peer = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<2>::create(&owner, &objects, &mut backend).unwrap();
        let delegated = owner
            .delegate_to(
                &objects,
                owner.address_space_handle(),
                CapRights::MAP,
                &mut peer,
            )
            .unwrap();
        let bindings = ThreadObjectBindings::<1>::new();
        owner.exit(&mut objects, &bindings).unwrap();

        let reserved = ReservationSet::<1>::new();
        let frame = PhysFrame::from_start_address(0x60_0000).unwrap();
        assert_eq!(
            space.map_user_page(
                &peer,
                &objects,
                delegated,
                &mut backend,
                vma(USER_MIN + 0x50_000),
                frame,
                &reserved,
            ),
            Err(Error::Process(ProcessError::Object(
                ObjectError::InvalidObject
            )))
        );
    }

    #[test]
    fn poisoned_binding_rejects_all_future_user_authority() {
        let mut objects = ObjectTable::<8>::new();
        let owner = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<2>::create(&owner, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();
        let address = USER_MIN + 0x60_000;
        let frame = PhysFrame::from_start_address(0x70_0000).unwrap();

        space.poison();
        assert!(space.is_poisoned());
        assert_eq!(
            space.user_range_is_free(
                &owner,
                &objects,
                owner.address_space_handle(),
                address,
                PAGE_SIZE,
            ),
            Err(Error::Poisoned)
        );
        assert_eq!(
            space.find_user_gap_top_down(
                &owner,
                &objects,
                owner.address_space_handle(),
                PAGE_SIZE,
                address + 4 * PAGE_SIZE,
            ),
            Err(Error::Poisoned)
        );
        assert_eq!(
            space.map_user_page(
                &owner,
                &objects,
                owner.address_space_handle(),
                &mut backend,
                vma(address),
                frame,
                &reserved,
            ),
            Err(Error::Poisoned)
        );
        assert_eq!(
            space.unmap_user_page(
                &owner,
                &objects,
                owner.address_space_handle(),
                &mut backend,
                address,
            ),
            Err(Error::Poisoned)
        );
        assert_eq!(
            space.translate_user(
                &owner,
                &objects,
                owner.address_space_handle(),
                &mut backend,
                address,
            ),
            Err(Error::Poisoned)
        );
        assert_eq!(
            unsafe { space.activate_owner(&owner, &objects) },
            Err(Error::Poisoned)
        );
    }

    #[test]
    fn active_process_witness_binds_owner_root_activation_and_switch_generation() {
        let mut objects = ObjectTable::<8>::new();
        let native = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let linux = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let native_space =
            BoundProcessAddressSpace::<2>::create(&native, &objects, &mut backend).unwrap();
        let root = native_space.root_phys();
        let generation = 7;
        let identity = native_space.activation_identity(generation);

        let native_active = ActiveProcess {
            process: &native,
            space: &native_space,
        };
        assert_eq!(
            native_active.validate_current_with_observation(
                Some(root),
                Some(identity),
                Some(generation),
            ),
            Ok(())
        );
        assert_eq!(
            native_active.validate_current_with_observation(None, Some(identity), Some(generation)),
            Err(Error::NotCurrentAddressSpace)
        );
        assert_eq!(
            native_active.validate_current_with_observation(Some(root), None, Some(generation)),
            Err(Error::NotCurrentProcess)
        );
        assert_eq!(
            native_active.validate_current_with_observation(
                Some(root),
                Some(identity),
                Some(generation + 1),
            ),
            Err(Error::NotCurrentProcess)
        );

        let substituted_linux = ActiveProcess {
            process: &linux,
            space: &native_space,
        };
        assert_eq!(
            substituted_linux.validate_current_with_observation(
                Some(root),
                Some(identity),
                Some(generation),
            ),
            Err(Error::WrongProcess)
        );
    }

    #[test]
    fn aliased_backend_root_cannot_impersonate_another_logical_binding_or_raw_switch() {
        let mut objects = ObjectTable::<8>::new();
        let native = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let linux = Process::<8>::create(&mut objects, Personality::Linux).unwrap();

        // Separate safe Backend instances both allocate their first root at TABLE_BASE. Numeric
        // TTBR0 equality therefore cannot identify which logical binding was activated.
        let mut native_backend = TestBackend::new();
        let mut linux_backend = TestBackend::new();
        let native_space =
            BoundProcessAddressSpace::<2>::create(&native, &objects, &mut native_backend).unwrap();
        let linux_space =
            BoundProcessAddressSpace::<2>::create(&linux, &objects, &mut linux_backend).unwrap();
        assert_eq!(native_space.root_phys(), linux_space.root_phys());
        assert_ne!(
            native_space.activation_identity(11),
            linux_space.activation_identity(11)
        );

        let linux_active = ActiveProcess {
            process: &linux,
            space: &linux_space,
        };
        assert_eq!(
            linux_active.validate_current_with_observation(
                Some(native_space.root_phys()),
                Some(native_space.activation_identity(11)),
                Some(11),
            ),
            Err(Error::NotCurrentProcess)
        );

        // Model a raw serialized switch from Linux to an aliased root. The old Linux identity still
        // names generation 11, while the canonical TTBR0 observer has advanced the PE to 12.
        assert_eq!(
            linux_active.validate_current_with_observation(
                Some(native_space.root_phys()),
                Some(linux_space.activation_identity(11)),
                Some(12),
            ),
            Err(Error::NotCurrentProcess)
        );
    }

    #[test]
    fn exited_process_cannot_form_a_current_witness_even_for_matching_activation() {
        let mut objects = ObjectTable::<4>::new();
        let mut process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut backend = TestBackend::new();
        let space =
            BoundProcessAddressSpace::<1>::create(&process, &objects, &mut backend).unwrap();
        let root = space.root_phys();
        let generation = 9;
        let identity = space.activation_identity(generation);
        let bindings = ThreadObjectBindings::<1>::new();
        process.exit(&mut objects, &bindings).unwrap();

        let stale = ActiveProcess {
            process: &process,
            space: &space,
        };
        assert_eq!(
            stale.validate_current_with_observation(Some(root), Some(identity), Some(generation),),
            Err(Error::InactiveProcess)
        );
    }
}
