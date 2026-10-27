// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
#[cfg(target_arch = "x86_64")]
use kernal_arch_x86_64::{rdmsr, wrmsr};
use kernal_percpu::CpuIndex;

pub const IA32_GS_BASE: u32 = 0xc000_0101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

#[repr(C, align(64))]
pub struct CpuLocal {
    // Offset 0 is intentionally a self pointer so tiny assembly fastpaths can recover the full
    // CpuLocal address with one `mov reg, gs:[0]` without a global lookup.
    self_ptr: u64,
    index: CpuIndex,
    _index_padding: u16,
    apic_id: u32,
    preempt_count: AtomicU32,
    irq_depth: AtomicU32,
    need_reschedule: AtomicBool,
    _padding0: [u8; 7],
    current_thread: AtomicU64,
}

impl CpuLocal {
    fn new(index: CpuIndex, apic_id: u32, self_ptr: u64) -> Self {
        Self {
            self_ptr,
            index,
            _index_padding: 0,
            apic_id,
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
    pub const fn apic_id(&self) -> u32 {
        self.apic_id
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
    NonCanonicalAddress,
    PreemptUnderflow,
    IrqDepthUnderflow,
    GsMismatch,
}

pub struct CpuLocalCell {
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<CpuLocal>>,
}

// SAFETY: one-shot state machine grants exclusive initialization; afterwards CpuLocal contains
// only immutable identity fields plus atomics for concurrent state.
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

    pub fn prepare(
        &'static self,
        index: CpuIndex,
        apic_id: u32,
    ) -> Result<&'static CpuLocal, Error> {
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
        let address = self.storage.get().cast::<CpuLocal>() as u64;
        if !is_canonical_48(address) {
            self.state.store(Self::EMPTY, Ordering::Release);
            return Err(Error::NonCanonicalAddress);
        }
        // SAFETY: successful CAS makes this invocation the only writer and storage is static.
        unsafe { (*self.storage.get()).write(CpuLocal::new(index, apic_id, address)) };
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

/// Installs kernel CpuLocal into both GS MSRs during bootstrap. Keeping both equal makes an
/// accidental early SWAPGS harmless; the future user-entry layer will establish asymmetric
/// user/kernel GS bases immediately before first Ring-3 entry.
///
/// # Safety
/// Must execute at CPL0 on the CPU represented by `local` while migration is impossible.
#[cfg(target_arch = "x86_64")]
pub unsafe fn install_bootstrap_gs(local: &'static CpuLocal) -> Result<(), Error> {
    let address = local as *const CpuLocal as u64;
    if !is_canonical_48(address) {
        return Err(Error::NonCanonicalAddress);
    }
    // SAFETY: caller guarantees CPL0 and CPU ownership.
    unsafe {
        wrmsr(IA32_GS_BASE, address);
        wrmsr(IA32_KERNEL_GS_BASE, address);
    }
    // SAFETY: GS base was just installed and offset zero is the self pointer.
    let observed = unsafe { current_ptr() };
    if observed != address {
        return Err(Error::GsMismatch);
    }
    Ok(())
}

/// # Safety
/// GS must already refer to an initialized CpuLocal for the current CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_ptr() -> u64 {
    let pointer: u64;
    // SAFETY: delegated to caller; offset zero is CpuLocal::self_ptr.
    unsafe {
        asm!("mov {}, gs:[0]", out(reg) pointer, options(nostack, readonly, preserves_flags))
    };
    pointer
}

/// # Safety
/// GS must already refer to an initialized CpuLocal for the current CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current() -> &'static CpuLocal {
    // SAFETY: caller guarantees the pointer contract.
    let pointer = unsafe { current_ptr() };
    // SAFETY: bootstrap initialization stores a static CpuLocal self pointer at GS:0.
    unsafe { &*(pointer as *const CpuLocal) }
}

/// Reads MSRs for diagnostics without dereferencing GS.
///
/// # Safety
/// Must run at CPL0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn gs_bases() -> (u64, u64) {
    // SAFETY: caller guarantees CPL0.
    unsafe { (rdmsr(IA32_GS_BASE), rdmsr(IA32_KERNEL_GS_BASE)) }
}

const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_identity_and_atomic_state_are_independent() {
        let local = CpuLocal::new(CpuIndex(7), 42, 0xffff_ffff_8000_1000);
        assert_eq!(local.index(), CpuIndex(7));
        assert_eq!(local.apic_id(), 42);
        local.preempt_disable();
        assert_eq!(local.preempt_count(), 1);
        local.preempt_enable().unwrap();
        assert_eq!(local.preempt_count(), 0);
        assert_eq!(local.preempt_enable(), Err(Error::PreemptUnderflow));
        local.enter_irq();
        assert_eq!(local.irq_depth(), 1);
        local.exit_irq().unwrap();
        assert_eq!(local.irq_depth(), 0);
    }

    #[test]
    fn cpu_local_is_cacheline_aligned() {
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
        assert_eq!(CELL.get().unwrap().apic_id(), 9);
    }
}
