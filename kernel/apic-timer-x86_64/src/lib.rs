// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::hint::spin_loop;
use kernal_apic_x86_64::{HardwareLocalApic, TimerDivide};
use kernal_arch_x86_64::read_tsc_ordered;
use kernal_tsc_x86_64::TscFrequency;

pub const CALIBRATION_NS: u64 = 10_000_000;
pub const CALIBRATION_DIVIDE: TimerDivide = TimerDivide::By16;
pub const MAX_CALIBRATION_POLLS: usize = 50_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnreliableTsc,
    TimeConversion,
    CalibrationTimeout,
    CounterDidNotAdvance,
    FrequencyOverflow,
    CountOverflow,
    Apic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Calibration {
    /// Effective decrement rate after the configured APIC divider.
    pub ticks_per_second: u64,
    pub divide: TimerDivide,
}

impl Calibration {
    pub fn count_for_ns(self, delay_ns: u64) -> Result<u32, Error> {
        let product = (delay_ns as u128)
            .checked_mul(self.ticks_per_second as u128)
            .ok_or(Error::CountOverflow)?;
        let ticks = product
            .checked_add(999_999_999)
            .ok_or(Error::CountOverflow)?
            / 1_000_000_000u128;
        let ticks = core::cmp::max(ticks, 1);
        u32::try_from(ticks).map_err(|_| Error::CountOverflow)
    }
}

pub fn frequency_from_deltas(
    apic_ticks: u64,
    tsc_cycles: u64,
    tsc_frequency: TscFrequency,
) -> Result<u64, Error> {
    if !tsc_frequency.reliable_for_timing() {
        return Err(Error::UnreliableTsc);
    }
    if apic_ticks == 0 || tsc_cycles == 0 {
        return Err(Error::CounterDidNotAdvance);
    }
    let numerator = (apic_ticks as u128)
        .checked_mul(tsc_frequency.hz as u128)
        .ok_or(Error::FrequencyOverflow)?;
    let hz = numerator
        .checked_add((tsc_cycles / 2) as u128)
        .ok_or(Error::FrequencyOverflow)?
        / tsc_cycles as u128;
    let hz = u64::try_from(hz).map_err(|_| Error::FrequencyOverflow)?;
    if hz == 0 {
        return Err(Error::CounterDidNotAdvance);
    }
    Ok(hz)
}

/// Configures and calibrates the current CPU's Local APIC one-shot timer against a reliable TSC.
///
/// The returned frequency is the effective timer decrement rate *after* the selected divider, so
/// later `count_for_ns` values can be written directly to the APIC Initial Count register.
///
/// # Safety
/// Must execute at CPL0 on a non-migrating CPU with this CPU's Local APIC exclusively owned by the
/// caller. Maskable interrupts should remain disabled during bootstrap calibration.
pub unsafe fn calibrate(
    apic: &mut HardwareLocalApic<'_>,
    tsc_frequency: TscFrequency,
    vector: u8,
) -> Result<Calibration, Error> {
    if !tsc_frequency.reliable_for_timing() {
        return Err(Error::UnreliableTsc);
    }
    apic.configure_one_shot_timer(vector, CALIBRATION_DIVIDE)
        .map_err(|_| Error::Apic)?;
    apic.set_timer_initial_count(u32::MAX)
        .map_err(|_| Error::Apic)?;

    let target_cycles = tsc_frequency
        .ns_to_cycles_ceil(CALIBRATION_NS)
        .map_err(|_| Error::TimeConversion)?;
    let start_tsc = read_tsc_ordered();
    let mut reached = false;
    for _ in 0..MAX_CALIBRATION_POLLS {
        let now = read_tsc_ordered();
        if now.wrapping_sub(start_tsc) >= target_cycles {
            reached = true;
            break;
        }
        spin_loop();
    }
    if !reached {
        let _ = apic.set_timer_initial_count(0);
        return Err(Error::CalibrationTimeout);
    }

    let end_tsc = read_tsc_ordered();
    let current = apic.timer_current_count().map_err(|_| Error::Apic)?;
    apic.set_timer_initial_count(0).map_err(|_| Error::Apic)?;
    let apic_ticks = u32::MAX.wrapping_sub(current) as u64;
    let tsc_cycles = end_tsc
        .checked_sub(start_tsc)
        .ok_or(Error::CounterDidNotAdvance)?;
    let ticks_per_second = frequency_from_deltas(apic_ticks, tsc_cycles, tsc_frequency)?;
    Ok(Calibration {
        ticks_per_second,
        divide: CALIBRATION_DIVIDE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_tsc_x86_64::FrequencyQuality;

    fn reliable() -> TscFrequency {
        TscFrequency {
            hz: 2_500_000_000,
            quality: FrequencyQuality::Architectural,
        }
    }

    #[test]
    fn frequency_calculation_matches_reference_ratio() {
        // 625,000 APIC ticks during 25,000,000 TSC cycles at 2.5 GHz = 62.5 MHz.
        assert_eq!(
            frequency_from_deltas(625_000, 25_000_000, reliable()).unwrap(),
            62_500_000
        );
    }

    #[test]
    fn one_shot_count_rounds_up_and_never_programs_zero() {
        let calibration = Calibration {
            ticks_per_second: 62_500_000,
            divide: TimerDivide::By16,
        };
        assert_eq!(calibration.count_for_ns(0).unwrap(), 1);
        assert_eq!(calibration.count_for_ns(1).unwrap(), 1);
        assert_eq!(calibration.count_for_ns(5_000_000).unwrap(), 312_500);
    }

    #[test]
    fn excessive_deadline_is_rejected_instead_of_wrapping() {
        let calibration = Calibration {
            ticks_per_second: u64::MAX,
            divide: TimerDivide::By16,
        };
        assert_eq!(
            calibration.count_for_ns(u64::MAX),
            Err(Error::CountOverflow)
        );
    }

    #[test]
    fn estimated_tsc_cannot_calibrate_apic_timer() {
        let estimated = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Estimated,
        };
        assert_eq!(
            frequency_from_deltas(1, 1, estimated),
            Err(Error::UnreliableTsc)
        );
    }
}
