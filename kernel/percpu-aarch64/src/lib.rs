// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use kernal_arch_aarch64::CpuAffinity;
use kernal_percpu::CpuIndex;

#[repr(C, align(64))]
pub struct CpuLocal {
    // Offset zero remains a self pointer just like x86_64 CpuLocal. TPIDR_EL1 directly holds this
    // address, while keeping the field makes layout/debugging and tiny future assembly paths simple.
    self_ptr: u64,
    index: CpuIndex,
    _index_padding: u16,
    affinity: u32,
    mpidr: u64,
    preempt_count: AtomicU32,
    irq_depth: AtomicU32,
    need_reschedule: AtomicBool,
    _padding0: [u8; 7],
    current_thread: AtomicU64,
}

impl CpuLocal {
    fn new(index: CpuIndex, mpidr: u64, self_ptr: u64) -> Self {
        let affinity = CpuAffinity::from_mpidr(mpidr).packed();
        Self {
            self_ptr,
            index,
            _index_padding: 0,
            affinity,
            mpidr,
            preempt_count: AtomicU32::new(0),
            irq_depth: AtomicU32::new(0),
            need_reschedule: AtomicBool::new(false),
            _padding0: [0; 7],
            current_thread: AtomicU64::new(0),
        }
    }

    pub const fn index(&self) -> CpuIndex {
        self.index
    }

    pub const fn mpidr(&self) -> u64 {
        self.mpidr
    }

    pub const fn affinity(&self) -> u32 {
        self.affinity
    }

    pub fn preempt_count(&self) -> u32 {
        self.preempt_count.load(Ordering::Relaxed)
    }

    pub fn irq_depth(&self) -> u32 {
        self.irq_depth.load(Ordering::Relaxed)
    }

    pub fn need_reschedule(&self) -> bool {
        self.need_reschedule.load(Ordering::Acquire)
    }

    pub fn current_thread(&self) -> u64 {
        self.current_thread.load(Ordering::Acquire)
    }

    pub fn preempt_disable(&self) {
        self.preempt_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn preempt_enable(&self) -> Result<(), Error> {
        self.preempt_count
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .map(|_| ())
            .map_err(|_| Error::PreemptUnderflow)
    }

    pub fn enter_irq(&self) {
        self.irq_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn exit_irq(&self) -> Result<(), Error> {
        self.irq_depth
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .map(|_| ())
            .map_err(|_| Error::IrqDepthUnderflow)
    }

    pub fn request_reschedule(&self) {
        self.need_reschedule.store(true, Ordering::Release);
    }

    pub fn clear_reschedule(&self) {
        self.need_reschedule.store(false, Ordering::Release);
    }

    pub fn set_current_thread(&self, thread_id: u64) {
        self.current_thread.store(thread_id, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
    PreemptUnderflow,
    IrqDepthUnderflow,
    TpidrMismatch,
}

pub struct CpuLocalCell {
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<CpuLocal>>,
}

// SAFETY: one-shot state machine grants exclusive initialization; afterwards CpuLocal contains
// immutable identity fields plus atomics for concurrent state.
unsafe impl Sync for CpuLocalCell {}

impl CpuLocalCell {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const READY: u8 = 2;

    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            storage: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn prepare(&'static self, index: CpuIndex, mpidr: u64) -> Result<&'static CpuLocal, Error> {
        match self.state.compare_exchange(
            Self::EMPTY,
            Self::INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(Self::INITIALIZING) => return Err(Error::InitializationInProgress),
            Err(_) => return Err(Error::AlreadyInitialized),
        }

        let address = self.storage.get() as *mut CpuLocal as u64;
        // SAFETY: successful CAS makes this invocation the only writer and storage is static.
        unsafe { (*self.storage.get()).write(CpuLocal::new(index, mpidr, address)) };
        self.state.store(Self::READY, Ordering::Release);
        // SAFETY: READY publishes fully initialized static storage that never moves.
        Ok(unsafe { (&*self.storage.get()).assume_init_ref() })
    }

    pub fn get(&'static self) -> Option<&'static CpuLocal> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return None;
        }
        // SAFETY: acquire observes initialization before READY.
        Some(unsafe { (&*self.storage.get()).assume_init_ref() })
    }
}

impl Default for CpuLocalCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Installs kernel CpuLocal into TPIDR_EL1. TPIDR_EL0 remains reserved for future user TLS.
///
/// # Safety
/// Must execute at EL1 on the PE represented by `local` while migration is impossible.
#[cfg(target_arch = "aarch64")]
pub unsafe fn install_bootstrap_tpidr_el1(local: &'static CpuLocal) -> Result<(), Error> {
    let address = local as *const CpuLocal as u64;
    // SAFETY: caller guarantees EL1 ownership; ISB makes the system-register update visible before
    // any subsequent fast-path read relies on it.
    unsafe {
        asm!("msr TPIDR_EL1, {address}", address = in(reg) address, options(nomem, nostack));
        asm!("isb", options(nostack));
    }
    let observed = unsafe { current_ptr() };
    if observed != address {
        return Err(Error::TpidrMismatch);
    }
    Ok(())
}

/// # Safety
/// TPIDR_EL1 must already contain a published static CpuLocal pointer for this PE.
#[cfg(target_arch = "aarch64")]
pub unsafe fn current_ptr() -> u64 {
    let pointer: u64;
    // SAFETY: delegated to caller; TPIDR_EL1 is kernel-owned per-PE state.
    unsafe {
        asm!("mrs {pointer}, TPIDR_EL1", pointer = out(reg) pointer, options(nomem, nostack))
    };
    pointer
}

/// # Safety
/// TPIDR_EL1 must already contain a published static CpuLocal pointer for this PE.
#[cfg(target_arch = "aarch64")]
pub unsafe fn current() -> &'static CpuLocal {
    let pointer = unsafe { current_ptr() };
    // SAFETY: bootstrap installation stores a static CpuLocal pointer and verifies the readback.
    unsafe { &*(pointer as *const CpuLocal) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_identity_tracks_mpidr_affinity_and_atomic_state() {
        let mpidr = (4u64 << 32) | (3u64 << 16) | (2u64 << 8) | 1;
        let local = CpuLocal::new(CpuIndex(7), mpidr, 0xffff_0000_0000_1000);
        assert_eq!(local.index(), CpuIndex(7));
        assert_eq!(local.mpidr(), mpidr);
        assert_eq!(local.affinity(), 0x0403_0201);
        local.preempt_disable();
        assert_eq!(local.preempt_count(), 1);
        local.preempt_enable().unwrap();
        assert_eq!(local.preempt_enable(), Err(Error::PreemptUnderflow));
        local.enter_irq();
        assert_eq!(local.irq_depth(), 1);
        local.exit_irq().unwrap();
        assert_eq!(local.irq_depth(), 0);
    }

    #[test]
    fn cpu_local_is_cacheline_aligned_and_self_pointer_leads_layout() {
        assert_eq!(core::mem::align_of::<CpuLocal>(), 64);
        assert_eq!(core::mem::offset_of!(CpuLocal, self_ptr), 0);
    }

    #[test]
    fn cell_initializes_once() {
        static CELL: CpuLocalCell = CpuLocalCell::new();
        let local = CELL.prepare(CpuIndex(1), 9).unwrap();
        assert_eq!(local.index(), CpuIndex(1));
        assert!(matches!(
            CELL.prepare(CpuIndex(1), 9),
            Err(Error::AlreadyInitialized)
        ));
        assert_eq!(CELL.get().unwrap().mpidr(), 9);
    }
}
