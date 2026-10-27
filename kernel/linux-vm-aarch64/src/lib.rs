// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_address_space_aarch64::Error as AddressSpaceError;
use kernal_frame_allocator::{Error as FrameError, ExtentAllocator, FrameRange};
use kernal_kmap_aarch64::{Error as KmapError, KmapController};
use kernal_linux_abi::MinimumRuntimeCall;
use kernal_linux_vm::{BackendFailure, Error, LinuxVmRuntime, PageBackend};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressError};
use kernal_vm::{Backing, PAGE_SIZE, VmPerms, Vma};

/// Failure classification for preparing one anonymous physical page before user exposure.
///
/// `ReclaimSafe` proves that no writable temporary alias can remain and the still-unexposed frame
/// may therefore be returned to the existing reclaimable allocator. `Quarantine` means cleanup did
/// not prove that property; the frame must remain allocated and the address-space runtime is
/// poisoned so it cannot be exposed to EL0 or recycled through this owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnonymousPageZeroFailure {
    ReclaimSafe(BackendFailure),
    Quarantine,
}

/// Existing architecture/runtime owner that can scrub one reclaimable physical page before it is
/// exposed through a new anonymous user mapping.
///
/// The exact page-table backend is passed into the zeroer instead of being stored behind a second
/// mutable handle. This makes the KMap temporary alias and the later user mapping operate through the
/// same canonical hierarchy owner.
pub trait AnonymousPageZeroer<B: Backend> {
    /// Zeroes one still-unexposed physical frame through the supplied canonical backend.
    ///
    /// # Safety
    /// The caller must hold the zeroer's documented global hierarchy-mutation authority for this
    /// exact `backend`, with local IRQ/preemption/migration quiesced as required by the concrete
    /// architecture owner. That authority must remain held until the zeroer returns and must also
    /// cover the subsequent mapping transaction performed by the enclosing [`Aarch64VmBackend`].
    unsafe fn zero_page(
        &mut self,
        backend: &mut B,
        physical_address: u64,
    ) -> Result<(), AnonymousPageZeroFailure>;
}

/// The integrated AArch64 KMap controller is the concrete Step-15 anonymous-page zeroing owner.
///
/// Cleanup failure or a pre-poisoned controller is a quarantine boundary: a writable temporary
/// alias may still exist, so the physical frame must not return to the general allocator. All other
/// KMap failures happen before this call can leave an unproven live alias and are reclaim-safe.
impl<B: Backend> AnonymousPageZeroer<B> for KmapController {
    unsafe fn zero_page(
        &mut self,
        backend: &mut B,
        physical_address: u64,
    ) -> Result<(), AnonymousPageZeroFailure> {
        // SAFETY: delegated trait contract is the same global TTBR1 hierarchy-mutation contract
        // required by KmapController::zero_frame for this exact backend.
        unsafe { self.zero_frame(backend, physical_address) }.map_err(classify_kmap_zero_error)
    }
}

/// Thin AArch64 execution adapter for the architecture-neutral Linux VM transaction owner.
///
/// All policy, Linux errno decisions and rollback ordering remain in `kernal-linux-vm`. This adapter
/// only supplies the already accepted process/CSpace-authorized AArch64 mapping operations and the
/// reclaimable ExtentAllocator. Newly allocated anonymous frames are scrubbed before this adapter
/// can return them to the common transaction owner.
pub struct Aarch64VmBackend<
    'a,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    B: Backend,
    Z: AnonymousPageZeroer<B>,
> {
    process: &'a Process<CAPS>,
    objects: &'a ObjectTable<OBJECTS>,
    space: &'a mut BoundProcessAddressSpace<VMAS>,
    page_tables: &'a mut B,
    reserved: &'a ReservationSet<RESERVED>,
    frames: &'a mut ExtentAllocator<EXTENTS>,
    zeroer: &'a mut Z,
}

impl<
    'a,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    B: Backend,
    Z: AnonymousPageZeroer<B>,
> Aarch64VmBackend<'a, CAPS, OBJECTS, VMAS, RESERVED, EXTENTS, B, Z>
{
    /// Creates one VM transaction adapter over an already-exclusive AArch64 hierarchy owner window.
    ///
    /// # Safety
    /// `page_tables` must be the single canonical mutable backend for the active hierarchy used by
    /// `space` and `zeroer`. The caller must hold globally exclusive mutation authority for that
    /// hierarchy, keep local IRQ/preemption/migration quiesced according to the concrete zeroer's
    /// contract, and retain that authority for the full lifetime of the returned adapter. No second
    /// mutable backend or competing page-table/KMap mutation may overlap this value.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        process: &'a Process<CAPS>,
        objects: &'a ObjectTable<OBJECTS>,
        space: &'a mut BoundProcessAddressSpace<VMAS>,
        page_tables: &'a mut B,
        reserved: &'a ReservationSet<RESERVED>,
        frames: &'a mut ExtentAllocator<EXTENTS>,
        zeroer: &'a mut Z,
    ) -> Self {
        Self {
            process,
            objects,
            space,
            page_tables,
            reserved,
            frames,
            zeroer,
        }
    }

    fn validate_current(&self) -> Result<(), BackendFailure> {
        self.space
            .current_owner(self.process)
            .map(|_| ())
            .map_err(classify_process_error)
    }
}

impl<
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    B: Backend,
    Z: AnonymousPageZeroer<B>,
> PageBackend for Aarch64VmBackend<'_, CAPS, OBJECTS, VMAS, RESERVED, EXTENTS, B, Z>
{
    fn range_is_free(&mut self, start: u64, len: u64) -> Result<bool, BackendFailure> {
        self.validate_current()?;
        self.space
            .user_range_is_free(
                self.process,
                self.objects,
                self.process.address_space_handle(),
                start,
                len,
            )
            .map_err(classify_process_error)
    }

    fn find_gap_top_down(&mut self, len: u64, ceiling: u64) -> Result<u64, BackendFailure> {
        self.validate_current()?;
        self.space
            .find_user_gap_top_down(
                self.process,
                self.objects,
                self.process.address_space_handle(),
                len,
                ceiling,
            )
            .map_err(classify_process_error)
    }

    fn page_is_mapped(&mut self, virtual_address: u64) -> Result<bool, BackendFailure> {
        self.validate_current()?;
        match self.space.translate_user(
            self.process,
            self.objects,
            self.process.address_space_handle(),
            self.page_tables,
            virtual_address,
        ) {
            Ok(_) => Ok(true),
            Err(error) => match classify_process_error(error) {
                BackendFailure::NotMapped => Ok(false),
                other => Err(other),
            },
        }
    }

    fn allocate_page(&mut self) -> Result<u64, BackendFailure> {
        let frame = self.frames.allocate_page().map_err(classify_frame_error)?;
        // SAFETY: construction of this adapter requires one exclusive hierarchy owner window for
        // this exact `page_tables` backend and keeps that authority live for the adapter lifetime.
        if let Err(failure) = unsafe { self.zeroer.zero_page(self.page_tables, frame) } {
            let frames = &mut self.frames;
            let space = &mut self.space;
            let error =
                resolve_zero_failure(failure, || reclaim_frame(frames, frame), || space.poison());
            return Err(error);
        }
        Ok(frame)
    }

    fn map_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        perms: VmPerms,
    ) -> Result<(), BackendFailure> {
        self.validate_current()?;
        let frame =
            PhysFrame::from_start_address(physical_address).ok_or(BackendFailure::Invariant)?;
        let vma = Vma::new(virtual_address, PAGE_SIZE, perms, Backing::Anonymous)
            .map_err(|_| BackendFailure::Invariant)?;
        let result = self.space.map_user_page_coalescing_anonymous(
            self.process,
            self.objects,
            self.process.address_space_handle(),
            self.page_tables,
            vma,
            frame,
            self.reserved,
        );
        result.map_err(|error| classify_mapping_error(error, || self.space.poison()))
    }

    fn protect_page(&mut self, virtual_address: u64, perms: VmPerms) -> Result<(), BackendFailure> {
        self.validate_current()?;
        let physical = self
            .space
            .translate_user(
                self.process,
                self.objects,
                self.process.address_space_handle(),
                self.page_tables,
                virtual_address,
            )
            .map_err(classify_process_error)?;
        let expected = PhysFrame::from_start_address(physical).ok_or(BackendFailure::Invariant)?;

        let removed = self
            .space
            .unmap_user_page_coalescing_anonymous(
                self.process,
                self.objects,
                self.process.address_space_handle(),
                self.page_tables,
                virtual_address,
            )
            .map_err(|error| classify_mapping_error(error, || self.space.poison()))?;
        if removed != expected {
            self.space.poison();
            return Err(BackendFailure::Invariant);
        }

        let vma = Vma::new(virtual_address, PAGE_SIZE, perms, Backing::Anonymous)
            .map_err(|_| BackendFailure::Invariant)?;
        if self
            .space
            .map_user_page_coalescing_anonymous(
                self.process,
                self.objects,
                self.process.address_space_handle(),
                self.page_tables,
                vma,
                removed,
                self.reserved,
            )
            .is_err()
        {
            // The old mapping has already been removed and the exact frame is deliberately retained
            // rather than reclaimed. Quarantine the Process binding instead of returning to EL0 with
            // an unprovable partially protected address space.
            self.space.poison();
            return Err(BackendFailure::Invariant);
        }
        Ok(())
    }

    fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, BackendFailure> {
        self.validate_current()?;
        let result = self.space.unmap_user_page_coalescing_anonymous(
            self.process,
            self.objects,
            self.process.address_space_handle(),
            self.page_tables,
            virtual_address,
        );
        result
            .map(PhysFrame::start_address)
            .map_err(|error| classify_mapping_error(error, || self.space.poison()))
    }

    fn free_page(&mut self, physical_address: u64) -> Result<(), BackendFailure> {
        reclaim_frame(self.frames, physical_address)
    }

    fn poison(&mut self) {
        self.space.poison();
    }
}

/// Executes one canonical Step-15 VM call for the current process through the existing AArch64
/// address-space, frame and anonymous-page-zeroing owners.
///
/// # Safety
/// `page_tables` must be the exact canonical backend accepted by `zeroer`; the caller must hold the
/// concrete zeroer's global hierarchy-mutation authority with local IRQ/preemption/migration
/// quiesced for the complete call. No competing page-table/KMap mutation or second mutable backend
/// may overlap this transaction.
#[allow(clippy::too_many_arguments)]
pub unsafe fn handle_current<
    const BREAKS: usize,
    const TX_PAGES: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    B: Backend,
    Z: AnonymousPageZeroer<B>,
>(
    runtime: &mut LinuxVmRuntime<BREAKS, TX_PAGES>,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    page_tables: &mut B,
    reserved: &ReservationSet<RESERVED>,
    frames: &mut ExtentAllocator<EXTENTS>,
    zeroer: &mut Z,
    call: MinimumRuntimeCall,
) -> Result<u64, Error> {
    // SAFETY: delegated caller contract establishes the exclusive hierarchy owner window for the
    // exact backend/zeroer pair for the full lifetime of the transaction adapter.
    let mut backend = unsafe {
        Aarch64VmBackend::new(
            process,
            objects,
            space,
            page_tables,
            reserved,
            frames,
            zeroer,
        )
    };
    runtime.handle(process.id(), call, &mut backend)
}

fn resolve_zero_failure(
    failure: AnonymousPageZeroFailure,
    reclaim: impl FnOnce() -> Result<(), BackendFailure>,
    poison: impl FnOnce(),
) -> BackendFailure {
    match failure {
        AnonymousPageZeroFailure::ReclaimSafe(original) => {
            if reclaim().is_err() {
                poison();
                BackendFailure::Invariant
            } else {
                original
            }
        }
        AnonymousPageZeroFailure::Quarantine => {
            poison();
            BackendFailure::Invariant
        }
    }
}

fn classify_kmap_zero_error(error: KmapError) -> AnonymousPageZeroFailure {
    match error {
        KmapError::CleanupFailed | KmapError::Poisoned => AnonymousPageZeroFailure::Quarantine,
        KmapError::Window(kernal_kmap::Error::Exhausted) => {
            AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::NoMemory)
        }
        _ => AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::Invariant),
    }
}

fn reclaim_frame<const EXTENTS: usize>(
    frames: &mut ExtentAllocator<EXTENTS>,
    physical_address: u64,
) -> Result<(), BackendFailure> {
    let range = FrameRange::new(physical_address, 1).map_err(classify_frame_error)?;
    frames.free(range).map_err(classify_frame_error)
}

fn classify_frame_error(error: FrameError) -> BackendFailure {
    match error {
        FrameError::NoMemory | FrameError::Capacity => BackendFailure::NoMemory,
        _ => BackendFailure::Invariant,
    }
}

fn classify_mapping_error(error: ProcessAddressError, poison: impl FnOnce()) -> BackendFailure {
    match error {
        ProcessAddressError::AddressSpace(AddressSpaceError::RollbackFailed) => {
            poison();
            BackendFailure::Invariant
        }
        other => classify_process_error(other),
    }
}

fn classify_process_error(error: ProcessAddressError) -> BackendFailure {
    match error {
        ProcessAddressError::AddressSpace(AddressSpaceError::Vm(kernal_vm::Error::NotFound)) => {
            BackendFailure::NotMapped
        }
        ProcessAddressError::AddressSpace(AddressSpaceError::PageTable(
            kernal_page_table_aarch64::Error::NotMapped,
        )) => BackendFailure::NotMapped,
        ProcessAddressError::AddressSpace(AddressSpaceError::Vm(kernal_vm::Error::Capacity))
        | ProcessAddressError::AddressSpace(AddressSpaceError::Vm(
            kernal_vm::Error::GapUnavailable,
        )) => BackendFailure::NoMemory,
        _ => BackendFailure::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    #[test]
    fn quarantine_zero_failure_never_reclaims_frame() {
        let reclaim_calls = Cell::new(0usize);
        let poisoned = Cell::new(false);

        let error = resolve_zero_failure(
            AnonymousPageZeroFailure::Quarantine,
            || {
                reclaim_calls.set(reclaim_calls.get() + 1);
                Ok(())
            },
            || poisoned.set(true),
        );

        assert_eq!(error, BackendFailure::Invariant);
        assert_eq!(reclaim_calls.get(), 0);
        assert!(poisoned.get());
    }

    #[test]
    fn reclaim_safe_zero_failure_reclaims_once_and_preserves_error() {
        let reclaim_calls = Cell::new(0usize);
        let poisoned = Cell::new(false);

        let error = resolve_zero_failure(
            AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::NoMemory),
            || {
                reclaim_calls.set(reclaim_calls.get() + 1);
                Ok(())
            },
            || poisoned.set(true),
        );

        assert_eq!(error, BackendFailure::NoMemory);
        assert_eq!(reclaim_calls.get(), 1);
        assert!(!poisoned.get());
    }

    #[test]
    fn reclaim_failure_poison_fails_closed() {
        let reclaim_calls = Cell::new(0usize);
        let poisoned = Cell::new(false);

        let error = resolve_zero_failure(
            AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::NoMemory),
            || {
                reclaim_calls.set(reclaim_calls.get() + 1);
                Err(BackendFailure::Invariant)
            },
            || poisoned.set(true),
        );

        assert_eq!(error, BackendFailure::Invariant);
        assert_eq!(reclaim_calls.get(), 1);
        assert!(poisoned.get());
    }

    #[test]
    fn kmap_cleanup_or_poison_requires_frame_quarantine() {
        assert_eq!(
            classify_kmap_zero_error(KmapError::CleanupFailed),
            AnonymousPageZeroFailure::Quarantine
        );
        assert_eq!(
            classify_kmap_zero_error(KmapError::Poisoned),
            AnonymousPageZeroFailure::Quarantine
        );
    }

    #[test]
    fn kmap_window_exhaustion_is_reclaim_safe_enomem() {
        assert_eq!(
            classify_kmap_zero_error(KmapError::Window(kernal_kmap::Error::Exhausted)),
            AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::NoMemory)
        );
    }

    #[test]
    fn kmap_pre_alias_failure_remains_reclaim_safe() {
        assert_eq!(
            classify_kmap_zero_error(KmapError::UnsupportedHostArchitecture),
            AnonymousPageZeroFailure::ReclaimSafe(BackendFailure::Invariant)
        );
    }

    #[test]
    fn map_owner_rollback_failure_poisons_before_return() {
        let poison_calls = Cell::new(0usize);

        let error = classify_mapping_error(
            ProcessAddressError::AddressSpace(AddressSpaceError::RollbackFailed),
            || poison_calls.set(poison_calls.get() + 1),
        );

        assert_eq!(error, BackendFailure::Invariant);
        assert_eq!(poison_calls.get(), 1);
    }

    #[test]
    fn first_unmap_owner_rollback_failure_poisons_before_return() {
        let poison_calls = Cell::new(0usize);

        let error = classify_mapping_error(
            ProcessAddressError::AddressSpace(AddressSpaceError::RollbackFailed),
            || poison_calls.set(poison_calls.get() + 1),
        );

        assert_eq!(error, BackendFailure::Invariant);
        assert_eq!(poison_calls.get(), 1);
    }
}
