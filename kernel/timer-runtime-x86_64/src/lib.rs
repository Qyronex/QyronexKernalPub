// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::write_volatile;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use kernal_apic_timer_x86_64::Calibration;
use kernal_apic_x86_64::{HardwareLocalApic, RuntimeApicHandle};
use kernal_arch_x86_64::{CpuFeatures, read_tsc_ordered, wrmsr};
use kernal_tickless_x86_64::{DeadlinePlan, IA32_TSC_DEADLINE_MSR};
use kernal_tsc_x86_64::{FrequencyQuality, TscFrequency};

const X2APIC_TIMER_INITIAL_COUNT_MSR: u32 = 0x838;
const XAPIC_TIMER_INITIAL_COUNT_OFFSET: u64 = 0x380;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
    NotInitialized,
    NonInvariantTsc,
    UnreliableFrequency,
    InvalidVector,
    Apic,
    ApicTimer(kernal_apic_timer_x86_64::Error),
    AddressOverflow,
    Deadline,
    WrongVector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimerMode {
    TscDeadline,
    ApicOneShot {
        calibration: Calibration,
        runtime_apic: RuntimeApicHandle,
    },
}

/// One immutable timer configuration plus atomic runtime accounting for one CPU.
///
/// TSC-deadline is preferred when advertised. Otherwise the Local APIC countdown timer is
/// calibrated against the same reliable TSC timebase and used as a true one-shot fallback.
pub struct TimerCell {
    state: AtomicU8,
    vector: UnsafeCell<u8>,
    frequency: UnsafeCell<MaybeUninit<TscFrequency>>,
    mode: UnsafeCell<MaybeUninit<TimerMode>>,
    last_deadline: AtomicU64,
    interrupts: AtomicU64,
}

// SAFETY: immutable configuration fields are written once before READY. Runtime counters are
// atomic. APIC programming is restricted by the public current-CPU/CPL0 safety contract.
unsafe impl Sync for TimerCell {}

impl TimerCell {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const READY: u8 = 2;

    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            vector: UnsafeCell::new(0),
            frequency: UnsafeCell::new(MaybeUninit::uninit()),
            mode: UnsafeCell::new(MaybeUninit::uninit()),
            last_deadline: AtomicU64::new(0),
            interrupts: AtomicU64::new(0),
        }
    }

    pub fn prepare(
        &'static self,
        apic: &mut HardwareLocalApic<'_>,
        features: CpuFeatures,
        frequency: TscFrequency,
        vector: u8,
    ) -> Result<(), Error> {
        // Normal hardware paths require architectural invariant TSC. SyntheticProof is the only
        // exception and is reliable solely in the explicitly fixed-frequency QEMU proof build.
        if !features.invariant_tsc && frequency.quality != FrequencyQuality::SyntheticProof {
            return Err(Error::NonInvariantTsc);
        }
        if !frequency.reliable_for_timing() {
            return Err(Error::UnreliableFrequency);
        }
        if vector < 0x20 {
            return Err(Error::InvalidVector);
        }
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

        let mode = if features.tsc_deadline {
            if apic.configure_tsc_deadline_timer(vector).is_err() {
                self.state.store(Self::EMPTY, Ordering::Release);
                return Err(Error::Apic);
            }
            TimerMode::TscDeadline
        } else {
            // SAFETY: HardwareLocalApic can only have been initialized for the current privileged
            // CPU. prepare_cpu invokes this before STI/migration during per-CPU bootstrap.
            let calibration =
                match unsafe { kernal_apic_timer_x86_64::calibrate(apic, frequency, vector) } {
                    Ok(calibration) => calibration,
                    Err(error) => {
                        self.state.store(Self::EMPTY, Ordering::Release);
                        return Err(Error::ApicTimer(error));
                    }
                };
            TimerMode::ApicOneShot {
                calibration,
                runtime_apic: apic.runtime_handle(),
            }
        };

        // SAFETY: successful INITIALIZING transition grants exclusive publication access.
        unsafe {
            *self.vector.get() = vector;
            (*self.frequency.get()).write(frequency);
            (*self.mode.get()).write(mode);
        }
        self.last_deadline.store(0, Ordering::Relaxed);
        self.interrupts.store(0, Ordering::Relaxed);
        self.state.store(Self::READY, Ordering::Release);
        Ok(())
    }

    pub fn vector(&self) -> Result<u8, Error> {
        self.ensure_ready()?;
        // SAFETY: READY freezes vector.
        Ok(unsafe { *self.vector.get() })
    }

    pub fn frequency(&self) -> Result<TscFrequency, Error> {
        self.ensure_ready()?;
        // SAFETY: READY publishes initialized immutable frequency.
        Ok(unsafe { *(&*self.frequency.get()).assume_init_ref() })
    }

    pub fn last_deadline(&self) -> Result<u64, Error> {
        self.ensure_ready()?;
        Ok(self.last_deadline.load(Ordering::Acquire))
    }

    pub fn interrupt_count(&self) -> Result<u64, Error> {
        self.ensure_ready()?;
        Ok(self.interrupts.load(Ordering::Acquire))
    }

    /// # Safety
    /// Must execute at CPL0 on the CPU whose Local APIC timer was configured by `prepare`. The
    /// caller must prevent migration while arming.
    pub unsafe fn arm_after_ns(&self, delay_ns: u64) -> Result<DeadlinePlan, Error> {
        let frequency = self.frequency()?;
        let now = read_tsc_ordered();
        let plan = DeadlinePlan::after_ns(now, delay_ns, frequency).map_err(|_| Error::Deadline)?;
        match self.mode()? {
            TimerMode::TscDeadline => {
                // SAFETY: prepare selected TSC-deadline only after CPU feature validation.
                unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, plan.deadline_cycles) };
            }
            TimerMode::ApicOneShot {
                calibration,
                runtime_apic,
            } => {
                let count = calibration
                    .count_for_ns(delay_ns)
                    .map_err(Error::ApicTimer)?;
                // SAFETY: delegated current-CPL0 CPU contract and runtime handle is CPU-local.
                unsafe { set_apic_initial_count(runtime_apic, count) }?;
            }
        }
        self.last_deadline
            .store(plan.deadline_cycles, Ordering::Release);
        Ok(plan)
    }

    /// # Safety
    /// Same current-CPL0 CPU contract as `arm_after_ns`.
    pub unsafe fn disarm(&self) -> Result<(), Error> {
        match self.mode()? {
            TimerMode::TscDeadline => {
                // SAFETY: mode proves this CPU's deadline MSR path was configured.
                unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, 0) };
            }
            TimerMode::ApicOneShot { runtime_apic, .. } => {
                // SAFETY: delegated current-CPL0 CPU contract.
                unsafe { set_apic_initial_count(runtime_apic, 0) }?;
            }
        }
        self.last_deadline.store(0, Ordering::Release);
        Ok(())
    }

    /// Records a delivered timer vector. EOI is deliberately separate.
    pub fn record_interrupt(&self, vector: u8) -> Result<u64, Error> {
        let expected = self.vector()?;
        if vector != expected {
            return Err(Error::WrongVector);
        }
        self.last_deadline.store(0, Ordering::Release);
        Ok(self.interrupts.fetch_add(1, Ordering::AcqRel) + 1)
    }

    fn mode(&self) -> Result<TimerMode, Error> {
        self.ensure_ready()?;
        // SAFETY: READY publishes initialized immutable mode.
        Ok(unsafe { *(&*self.mode.get()).assume_init_ref() })
    }

    fn ensure_ready(&self) -> Result<(), Error> {
        if self.state.load(Ordering::Acquire) == Self::READY {
            Ok(())
        } else {
            Err(Error::NotInitialized)
        }
    }
}

impl Default for TimerCell {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
/// Must execute at CPL0 on the CPU owning `handle`; the xAPIC mapping must still be pinned.
unsafe fn set_apic_initial_count(handle: RuntimeApicHandle, count: u32) -> Result<(), Error> {
    match handle {
        RuntimeApicHandle::X2Apic => {
            // SAFETY: caller guarantees current x2APIC CPU and privileged execution.
            unsafe { wrmsr(X2APIC_TIMER_INITIAL_COUNT_MSR, count as u64) };
            Ok(())
        }
        RuntimeApicHandle::XApic { virtual_base } => {
            let address = virtual_base
                .checked_add(XAPIC_TIMER_INITIAL_COUNT_OFFSET)
                .ok_or(Error::AddressOverflow)?;
            // SAFETY: caller guarantees the pinned UC Local APIC mapping remains valid/writable.
            unsafe { write_volatile(address as *mut u32, count) };
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprepared_runtime_queries_fail_closed() {
        let timer = TimerCell::new();
        assert_eq!(timer.vector(), Err(Error::NotInitialized));
        assert_eq!(timer.interrupt_count(), Err(Error::NotInitialized));
    }

    #[test]
    fn timing_quality_policy_rejects_estimated_values() {
        let estimated = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Estimated,
        };
        let calibrated = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Calibrated,
        };
        assert!(!estimated.reliable_for_timing());
        assert!(calibrated.reliable_for_timing());
    }

    #[test]
    fn synthetic_proof_is_not_reliable_in_normal_host_build() {
        let synthetic = TscFrequency {
            hz: 2_500_000_000,
            quality: FrequencyQuality::SyntheticProof,
        };
        assert!(!synthetic.reliable_for_timing());
    }
}
