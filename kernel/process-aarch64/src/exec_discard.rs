// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Destructive cleanup owner for never-committed exec staging and terminal exited bindings.
//!
//! Normal mapping APIs reject a poisoned [`BoundProcessAddressSpace`]. That is correct for usable
//! bindings, but terminal Step-30 cleanup needs narrower proof-carrying edges that can permanently
//! quarantine an unreachable binding and return its empty page-table hierarchy to the canonical
//! Backend owner.

use super::{BoundProcessAddressSpace, Error};
use kernal_address_space_aarch64::Aarch64AddressSpaceExt;
use kernal_capability::CapRights;
use kernal_memory::PhysFrame;
use kernal_object::{ObjectKind, ObjectTable};
use kernal_page_table_aarch64::Backend;
use kernal_process::{Process, ProcessState};
use kernal_vm::Backing;

impl<const VMAS: usize> BoundProcessAddressSpace<VMAS> {
    /// Permanently discards one fresh same-Process exec staging binding.
    ///
    /// This is intentionally different from `reclaim_superseded_anonymous_user_frames`: staging has
    /// never become current and may already be poisoned by an opaque lower-loader rollback failure.
    /// The old image must therefore prove exact current ownership first. CSpace CONTROL authority is
    /// revalidated directly rather than through `authorize_handle`, because that normal usable-binding
    /// path rejects the already-poisoned staging state this terminal cleanup is specifically for.
    ///
    /// The method poisons `self` before any destructive mutation and never clears that bit. Therefore
    /// even a completely successful drain cannot turn discarded staging back into activation/mapping
    /// authority. Unsupported backing, page-table removal failure, release failure or accounting
    /// overflow fail closed with the staging binding still poisoned.
    ///
    /// # Safety
    /// Caller must own the local PE page-table/address-space mutation window with IRQ/preemption,
    /// migration and context switching suppressed for the complete call. `active_space` must be the
    /// exact old image that remains current for `process`; `self` must be an unreachable fresh exec
    /// staging binding for the same exact Process and AddressSpace object. `release` may retire only
    /// frames returned by this exact canonical unmap path.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn discard_exec_staging_anonymous_user_frames<
        const CAPS: usize,
        const OBJECTS: usize,
        B: Backend,
        F: FnMut(PhysFrame) -> bool,
    >(
        &mut self,
        process: &Process<CAPS>,
        objects: &ObjectTable<OBJECTS>,
        active_space: &Self,
        backend: &mut B,
        mut release: F,
    ) -> Result<usize, Error> {
        if process.state() != ProcessState::Live {
            return Err(Error::InactiveProcess);
        }
        if core::ptr::eq(
            core::ptr::from_ref(&*self),
            core::ptr::from_ref(active_space),
        ) {
            return Err(Error::NotCurrentAddressSpace);
        }
        if self.owner_process != process.id() || active_space.owner_process != process.id() {
            return Err(Error::WrongProcess);
        }
        if self.address_space_object != active_space.address_space_object
            || process.address_space() != self.address_space_object
        {
            return Err(Error::WrongAddressSpace);
        }
        if self.binding_id == active_space.binding_id {
            return Err(Error::NotCurrentAddressSpace);
        }

        // Revalidate the mandatory same-Process AddressSpace CONTROL capability without entering the
        // normal staging binding authorization path, which intentionally rejects `self.poisoned`.
        let resolved =
            process.resolve_object(objects, process.address_space_handle(), CapRights::CONTROL)?;
        if resolved.meta.kind != ObjectKind::AddressSpace {
            return Err(Error::WrongObjectKind);
        }
        if resolved.object != self.address_space_object {
            return Err(Error::WrongAddressSpace);
        }

        // The old image must still be the exact logical current binding on this PE. Distinct BindingId
        // then proves the staging binding is not that current owner even if a safe backend happens to
        // allocate a numerically aliased root address.
        active_space.current_owner(process)?;

        // Terminal authority is monotonic. A lower loader may have set this already; that is accepted.
        self.poisoned = true;

        let mut released = 0usize;
        while let Some(vma) = self.space.vmas().get(0) {
            if !matches!(vma.backing, Backing::Anonymous) {
                return Err(Error::UnsupportedExitBacking);
            }

            let frame = self
                .space
                .unmap_user_page_coalescing_anonymous(backend, vma.start)
                .map_err(|_| Error::ExitCleanupFailed)?;
            if !release(frame) {
                return Err(Error::ExitCleanupFailed);
            }
            released = released.checked_add(1).ok_or(Error::ExitCleanupFailed)?;
        }

        unsafe { self.space.reclaim_empty_page_table_tree(backend) }
            .map_err(|_| Error::ExitCleanupFailed)?;
        Ok(released)
    }

    /// Returns the complete empty TTBR0 hierarchy for one exact already-exited Process generation.
    ///
    /// Data frames must have been drained first through `reclaim_exited_anonymous_user_frames`.
    /// This terminal edge then validates the exact retained Process/AddressSpace pair, requires an
    /// empty VMA owner, monotonically poisons the binding, and delegates the detached table hierarchy
    /// to the canonical AArch64 page-table owner. The binding must never be activated or reused after
    /// this call, even when reclamation succeeds.
    ///
    /// # Safety
    /// The caller must prove that the Process has no schedulable generation on any PE and that no
    /// current or future translation can reach this TTBR0 root. The caller must also hold the unique
    /// live Backend mutation window for the complete operation.
    pub unsafe fn reclaim_exited_empty_page_table_tree<const CAPS: usize, B: Backend>(
        &mut self,
        process: &Process<CAPS>,
        backend: &mut B,
    ) -> Result<(), Error> {
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
        if self.space.vmas().get(0).is_some() {
            self.poisoned = true;
            return Err(Error::ExitCleanupFailed);
        }

        // From this point onward the logical binding is permanently terminal. Poison before the
        // physical table pages enter the backend free list so no later safe mapping API can observe a
        // recycled root as usable authority if a downstream operation fails.
        self.poisoned = true;
        unsafe { self.space.reclaim_empty_page_table_tree(backend) }
            .map_err(|_| Error::ExitCleanupFailed)
    }
}
