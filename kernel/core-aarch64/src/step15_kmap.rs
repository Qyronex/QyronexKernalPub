// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_kmap_aarch64::KmapController;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;
const BORROWED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Kmap(kernal_kmap_aarch64::Error),
    AlreadyInitialized,
    Busy,
    Unavailable,
    InvalidState,
}

struct KmapOwnerCell {
    state: AtomicU8,
    controller: UnsafeCell<MaybeUninit<KmapController>>,
}

// SAFETY: installation is one-shot and READY -> BORROWED is the only transition that exposes the
// controller. The caller-side contract keeps the controller CPU-local and closes IRQ/preemption/
// migration and competing TTBR1 mutation for every scoped borrow.
unsafe impl Sync for KmapOwnerCell {}

impl KmapOwnerCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            controller: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    unsafe fn install(&self, cpu_index: usize, root_table: u64) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | BORROWED) => return Err(Error::Busy),
            Err(READY) => return Err(Error::AlreadyInitialized),
            Err(_) => return Err(Error::InvalidState),
        }

        // SAFETY: delegated caller contract proves that `root_table` is the already-active TTBR1
        // hierarchy for this CPU-local owner. Construction itself creates no mapping or table alias.
        let controller = match unsafe { KmapController::assume_active(cpu_index, root_table) } {
            Ok(controller) => controller,
            Err(error) => {
                self.state.store(EMPTY, Ordering::Release);
                return Err(Error::Kmap(error));
            }
        };

        // SAFETY: successful EMPTY -> INSTALLING gives this path unique initialization ownership.
        unsafe { (*self.controller.get()).write(controller) };
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    unsafe fn with_controller<R>(
        &self,
        operation: impl for<'a> FnOnce(&'a mut KmapController) -> R,
    ) -> Result<R, Error> {
        match self
            .state
            .compare_exchange(READY, BORROWED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(EMPTY | INSTALLING) => return Err(Error::Unavailable),
            Err(BORROWED) => return Err(Error::Busy),
            Err(_) => return Err(Error::InvalidState),
        }

        // SAFETY: BORROWED is exclusive mutable ownership and READY proved initialization.
        let controller = unsafe { (&mut *self.controller.get()).assume_init_mut() };
        let result = operation(controller);
        self.state.store(READY, Ordering::Release);
        Ok(result)
    }
}

static STEP15_KMAP: KmapOwnerCell = KmapOwnerCell::new();

/// Installs the single persistent Step-15 CPU-local KMap controller.
///
/// The controller is never reconstructed for later VM calls. In particular, its poison bit survives
/// every syscall so a failed temporary-alias cleanup cannot be forgotten and a quarantined frame can
/// never become reusable through a fresh controller.
///
/// # Safety
/// `root_table` must be the active protected TTBR1 root for `cpu_index`. The caller must be that CPU's
/// owner with local IRQs masked and migration/preemption closed, and no competing KMap owner may use
/// this CPU window. Initialization must happen before any Step-15 anonymous-page VM transaction.
pub unsafe fn initialize(cpu_index: usize, root_table: u64) -> Result<(), Error> {
    // SAFETY: delegated caller contract is exactly the cell/KmapController construction contract.
    unsafe { STEP15_KMAP.install(cpu_index, root_table) }
}

/// Executes one short VM/KMap operation through the persistent Step-15 controller.
///
/// # Safety
/// The caller must own the local scheduler/address-space mutation window with IRQ/preemption/migration
/// reentrancy closed and must also own the exact canonical TTBR1 page-table backend for the full
/// callback. `operation` must not block, context-switch, retain the controller, or expose references
/// derived from it after returning.
pub unsafe fn with_kmap<R>(
    operation: impl for<'a> FnOnce(&'a mut KmapController) -> R,
) -> Result<R, Error> {
    // SAFETY: delegated caller contract supplies the CPU-local/quiescent hierarchy owner window.
    unsafe { STEP15_KMAP.with_controller(operation) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_root_leaves_owner_retryable() {
        let cell = KmapOwnerCell::new();
        // SAFETY: invalid-root validation rejects before any privileged mapping operation.
        assert_eq!(
            unsafe { cell.install(0, 3) },
            Err(Error::Kmap(kernal_kmap_aarch64::Error::InvalidRoot))
        );
        assert_eq!(cell.state.load(Ordering::Acquire), EMPTY);

        // SAFETY: host construction only validates metadata; no privileged mapping is performed.
        unsafe { cell.install(0, 0x4000) }.unwrap();
        assert_eq!(cell.state.load(Ordering::Acquire), READY);
    }

    #[test]
    fn controller_is_one_shot_and_stable_across_borrows() {
        let cell = KmapOwnerCell::new();
        // SAFETY: host construction only validates metadata; no privileged mapping is performed.
        unsafe { cell.install(1, 0x8000) }.unwrap();

        // SAFETY: the test is single-threaded and performs no mapping or context switch.
        let first = unsafe {
            cell.with_controller(|controller| {
                (core::ptr::from_ref(controller) as usize, controller.base())
            })
        }
        .unwrap();
        // SAFETY: same single-threaded scoped-borrow contract as above.
        let second = unsafe {
            cell.with_controller(|controller| {
                (core::ptr::from_ref(controller) as usize, controller.base())
            })
        }
        .unwrap();

        assert_eq!(first, second);
        // SAFETY: duplicate initialization is rejected before constructing a replacement controller.
        assert_eq!(
            unsafe { cell.install(0, 0x4000) },
            Err(Error::AlreadyInitialized)
        );
    }

    #[test]
    fn nested_borrow_fails_closed_and_outer_owner_recovers() {
        let cell = KmapOwnerCell::new();
        // SAFETY: host construction only validates metadata; no privileged mapping is performed.
        unsafe { cell.install(0, 0x4000) }.unwrap();

        // SAFETY: the outer borrow is single-threaded; the nested attempt must be rejected by state.
        let nested = unsafe {
            cell.with_controller(|_| {
                // The nested attempt exposes no controller reference and is rejected by state.
                cell.with_controller(|_| ())
            })
        }
        .unwrap();
        assert_eq!(nested, Err(Error::Busy));
        assert_eq!(cell.state.load(Ordering::Acquire), READY);
    }
}
