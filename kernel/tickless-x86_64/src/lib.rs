// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_apic_x86_64::HardwareLocalApic;
use kernal_arch_x86_64::{CpuFeatures, read_tsc_ordered, wrmsr};
use kernal_tsc_x86_64::TscFrequency;

pub const IA32_TSC_DEADLINE_MSR: u32 = 0x6e0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TscDeadlineUnsupported,
    NonInvariantTsc,
    InvalidVector,
    Frequency,
    DeadlineOverflow,
    Apic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlinePlan {
    pub now_cycles: u64,
    pub delta_cycles: u64,
    pub deadline_cycles: u64,
}

impl DeadlinePlan {
    pub fn after_ns(
        now_cycles: u64,
        delay_ns: u64,
        frequency: TscFrequency,
    ) -> Result<Self, Error> {
        let mut delta = frequency
            .ns_to_cycles_ceil(delay_ns)
            .map_err(|_| Error::Frequency)?;
        // A deadline equal to or before the current TSC may be treated as already expired. Ensure
        // every armed future event advances by at least one cycle, including a zero-ns request.
        if delta == 0 {
            delta = 1;
        }
        let deadline = now_cycles
            .checked_add(delta)
            .ok_or(Error::DeadlineOverflow)?;
        Ok(Self {
            now_cycles,
            delta_cycles: delta,
            deadline_cycles: deadline,
        })
    }
}

pub struct TscDeadlineTimer<'a, 'k> {
    apic: &'a mut HardwareLocalApic<'k>,
    frequency: TscFrequency,
    vector: u8,
}

impl<'a, 'k> TscDeadlineTimer<'a, 'k> {
    pub fn new(
        apic: &'a mut HardwareLocalApic<'k>,
        features: CpuFeatures,
        frequency: TscFrequency,
        vector: u8,
    ) -> Result<Self, Error> {
        if !features.tsc_deadline {
            return Err(Error::TscDeadlineUnsupported);
        }
        if !features.invariant_tsc {
            return Err(Error::NonInvariantTsc);
        }
        if vector < 0x20 {
            return Err(Error::InvalidVector);
        }
        apic.configure_tsc_deadline_timer(vector)
            .map_err(|_| Error::Apic)?;
        Ok(Self {
            apic,
            frequency,
            vector,
        })
    }

    pub const fn vector(&self) -> u8 {
        self.vector
    }
    pub const fn frequency(&self) -> TscFrequency {
        self.frequency
    }

    pub fn arm_after_ns(&mut self, delay_ns: u64) -> Result<DeadlinePlan, Error> {
        let now = read_tsc_ordered();
        let plan = DeadlinePlan::after_ns(now, delay_ns, self.frequency)?;
        self.arm_absolute_cycles(plan.deadline_cycles)?;
        Ok(plan)
    }

    pub fn arm_absolute_cycles(&mut self, deadline_cycles: u64) -> Result<(), Error> {
        // SAFETY: timer construction verified TSC-deadline support and configured the LVT mode.
        unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, deadline_cycles) };
        Ok(())
    }

    pub fn disarm(&mut self) {
        // Architectural TSC-deadline cancellation is a write of zero.
        // SAFETY: same feature/mode contract as arm.
        unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, 0) };
    }

    pub fn end_of_interrupt(&mut self) -> Result<(), Error> {
        self.apic.end_of_interrupt().map_err(|_| Error::Apic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_tsc_x86_64::FrequencyQuality;

    #[test]
    fn deadline_plan_rounds_delay_up_and_never_arms_at_now() {
        let frequency = TscFrequency {
            hz: 2_500_000_000,
            quality: FrequencyQuality::Architectural,
        };
        let plan = DeadlinePlan::after_ns(100, 1, frequency).unwrap();
        assert_eq!(plan.delta_cycles, 3);
        assert_eq!(plan.deadline_cycles, 103);
        let zero = DeadlinePlan::after_ns(100, 0, frequency).unwrap();
        assert_eq!(zero.deadline_cycles, 101);
    }

    #[test]
    fn overflow_is_rejected() {
        let frequency = TscFrequency {
            hz: 1_000_000_000,
            quality: FrequencyQuality::Architectural,
        };
        assert_eq!(
            DeadlinePlan::after_ns(u64::MAX, 1, frequency),
            Err(Error::DeadlineOverflow)
        );
    }
}
