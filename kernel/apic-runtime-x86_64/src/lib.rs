// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_apic_x86_64::RuntimeApicHandle;
use kernal_percpu::CpuIndex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
    NotInitialized,
    WrongCpu,
}

pub struct RuntimeApicCell {
    state: AtomicU8,
    cpu: UnsafeCell<CpuIndex>,
    handle: UnsafeCell<MaybeUninit<RuntimeApicHandle>>,
}

// SAFETY: one-shot publication freezes cpu+handle. RuntimeApicHandle contains only immutable mode
// metadata/raw MMIO base whose backing kmap lease must outlive the cell's use.
unsafe impl Sync for RuntimeApicCell {}

impl RuntimeApicCell {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const READY: u8 = 2;

    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            cpu: UnsafeCell::new(CpuIndex(0)),
            handle: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn prepare(&'static self, cpu: CpuIndex, handle: RuntimeApicHandle) -> Result<(), Error> {
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
        // SAFETY: successful CAS gives this call exclusive initialization access.
        unsafe {
            *self.cpu.get() = cpu;
            (*self.handle.get()).write(handle);
        }
        self.state.store(Self::READY, Ordering::Release);
        Ok(())
    }

    pub fn get(&'static self, expected_cpu: CpuIndex) -> Result<RuntimeApicHandle, Error> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return Err(Error::NotInitialized);
        }
        // SAFETY: READY freezes cpu forever.
        if unsafe { *self.cpu.get() } != expected_cpu {
            return Err(Error::WrongCpu);
        }
        // SAFETY: acquire observes handle initialization before READY.
        Ok(unsafe { *(&*self.handle.get()).assume_init_ref() })
    }
}

impl Default for RuntimeApicCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_once_and_checks_cpu_identity() {
        static CELL: RuntimeApicCell = RuntimeApicCell::new();
        CELL.prepare(CpuIndex(3), RuntimeApicHandle::X2Apic)
            .unwrap();
        assert_eq!(CELL.get(CpuIndex(3)), Ok(RuntimeApicHandle::X2Apic));
        assert_eq!(CELL.get(CpuIndex(2)), Err(Error::WrongCpu));
        assert_eq!(
            CELL.prepare(CpuIndex(3), RuntimeApicHandle::X2Apic),
            Err(Error::AlreadyInitialized)
        );
    }
}
