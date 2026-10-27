// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;

pub const NANOS_PER_SECOND: u128 = 1_000_000_000;
pub const MONOTONIC_SCALE_SHIFT: u8 = 32;
const CNTV_CTL_ENABLE: u64 = 1 << 0;
const CNTV_CTL_IMASK: u64 = 1 << 1;
const CNTV_CTL_ISTATUS: u64 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ZeroFrequency,
    IntervalOverflow,
    DeadlineOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonotonicError {
    Time(kernal_time::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerState {
    pub enabled: bool,
    pub masked: bool,
    pub pending: bool,
}

impl TimerState {
    pub const fn from_ctl(value: u64) -> Self {
        Self {
            enabled: value & CNTV_CTL_ENABLE != 0,
            masked: value & CNTV_CTL_IMASK != 0,
            pending: value & CNTV_CTL_ISTATUS != 0,
        }
    }
}

/// Converts nanoseconds to generic-timer ticks, rounding up so a one-shot never expires earlier
/// solely because of integer truncation.
pub fn ticks_for_ns(frequency_hz: u64, nanoseconds: u64) -> Result<u64, Error> {
    if frequency_hz == 0 {
        return Err(Error::ZeroFrequency);
    }
    let product = (frequency_hz as u128)
        .checked_mul(nanoseconds as u128)
        .ok_or(Error::IntervalOverflow)?;
    let rounded = product
        .checked_add(NANOS_PER_SECOND - 1)
        .ok_or(Error::IntervalOverflow)?
        / NANOS_PER_SECOND;
    u64::try_from(rounded).map_err(|_| Error::IntervalOverflow)
}

pub fn deadline_after_ns(now: u64, frequency_hz: u64, nanoseconds: u64) -> Result<u64, Error> {
    let ticks = ticks_for_ns(frequency_hz, nanoseconds)?;
    now.checked_add(ticks).ok_or(Error::DeadlineOverflow)
}

/// Converts one architected generic-timer sample into the shared monotonic nanosecond domain.
///
/// Step 15 Linux time support must reuse the architecture-neutral `kernal-time` conversion rather
/// than growing a Linux-only or AArch64-only cycle-to-time formula. A zero/invalid frequency and
/// arithmetic overflow remain kernel time-source failures; callers must not silently turn them into
/// a fabricated userspace timestamp.
pub fn monotonic_ns_from_sample(
    frequency_hz: u64,
    virtual_counter: u64,
) -> Result<u64, MonotonicError> {
    let scale = kernal_time::CycleScale::from_frequency_hz(frequency_hz, MONOTONIC_SCALE_SHIFT)
        .map_err(MonotonicError::Time)?;
    kernal_time::MonotonicClock::new(scale, 0, 0)
        .now_ns(virtual_counter)
        .map_err(MonotonicError::Time)
}

/// Reads the current AArch64 generic virtual counter and converts it through the shared Kernal
/// monotonic time abstraction.
///
/// This is intentionally only a time-source bridge. Linux clock-id policy, syscall classification,
/// errno mapping and user `timespec` copying belong to their existing shared Linux/usercopy layers.
#[cfg(target_arch = "aarch64")]
pub fn monotonic_now_ns() -> Result<u64, MonotonicError> {
    monotonic_ns_from_sample(
        kernal_arch_aarch64::counter_frequency_hz(),
        kernal_arch_aarch64::read_virtual_counter(),
    )
}

/// Arms the architected virtual timer as a one-shot absolute deadline.
///
/// # Safety
/// Caller must execute where CNTV_*_EL0 system registers are accessible, with the current CPU's
/// GIC virtual-timer PPI configured before unmasking interrupts.
#[cfg(target_arch = "aarch64")]
pub unsafe fn arm_after_ns(nanoseconds: u64) -> Result<u64, Error> {
    let frequency_hz = kernal_arch_aarch64::counter_frequency_hz();
    let now = kernal_arch_aarch64::read_virtual_counter();
    let deadline = deadline_after_ns(now, frequency_hz, nanoseconds)?;
    // SAFETY: delegated to caller. CVAL is written before CTL enable and ISB makes the new timer
    // programming visible before subsequent interrupt-state changes.
    unsafe {
        asm!("msr CNTV_CVAL_EL0, {deadline}", deadline = in(reg) deadline, options(nomem, nostack));
        asm!("msr CNTV_CTL_EL0, {control}", control = in(reg) CNTV_CTL_ENABLE, options(nomem, nostack));
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
    Ok(deadline)
}

/// Masks and disables the current CPU's virtual timer.
///
/// # Safety
/// Caller must execute where CNTV_CTL_EL0 is accessible.
#[cfg(target_arch = "aarch64")]
pub unsafe fn disarm() {
    let control = CNTV_CTL_IMASK;
    // SAFETY: delegated to caller. The timer is masked and disabled before returning.
    unsafe {
        asm!("msr CNTV_CTL_EL0, {control}", control = in(reg) control, options(nomem, nostack));
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(target_arch = "aarch64")]
pub fn state() -> TimerState {
    let control: u64;
    // SAFETY: CNTV_CTL_EL0 is architecturally readable when the virtual timer is available.
    unsafe {
        asm!("mrs {control}, CNTV_CTL_EL0", control = out(reg) control, options(nomem, nostack, preserves_flags))
    };
    TimerState::from_ctl(control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanoseconds_round_up_to_next_timer_tick() {
        assert_eq!(ticks_for_ns(1_000_000_000, 1).unwrap(), 1);
        assert_eq!(ticks_for_ns(100_000_000, 1).unwrap(), 1);
        assert_eq!(ticks_for_ns(100_000_000, 10).unwrap(), 1);
        assert_eq!(ticks_for_ns(100_000_000, 11).unwrap(), 2);
    }

    #[test]
    fn deadline_math_is_checked() {
        assert_eq!(deadline_after_ns(100, 1_000_000_000, 25).unwrap(), 125);
        assert_eq!(
            deadline_after_ns(u64::MAX, 1_000_000_000, 1),
            Err(Error::DeadlineOverflow)
        );
        assert_eq!(ticks_for_ns(0, 1), Err(Error::ZeroFrequency));
    }

    #[test]
    fn shared_monotonic_scale_converts_common_arm_timer_samples() {
        assert_eq!(
            monotonic_ns_from_sample(100_000_000, 100_000_000),
            Ok(1_000_000_000)
        );
        assert_eq!(
            monotonic_ns_from_sample(62_500_000, 125_000_000),
            Ok(2_000_000_000)
        );
    }

    #[test]
    fn shared_monotonic_sample_is_non_decreasing() {
        let first = monotonic_ns_from_sample(100_000_000, 123_456).unwrap();
        let second = monotonic_ns_from_sample(100_000_000, 123_457).unwrap();
        assert!(second >= first);
    }

    #[test]
    fn invalid_counter_frequency_is_not_fabricated_into_time() {
        assert_eq!(
            monotonic_ns_from_sample(0, 1),
            Err(MonotonicError::Time(kernal_time::Error::ZeroFrequency))
        );
    }

    #[test]
    fn control_decoder_preserves_enable_mask_and_pending_bits() {
        assert_eq!(
            TimerState::from_ctl(CNTV_CTL_ENABLE | CNTV_CTL_ISTATUS),
            TimerState {
                enabled: true,
                masked: false,
                pending: true
            }
        );
        assert_eq!(
            TimerState::from_ctl(CNTV_CTL_IMASK),
            TimerState {
                enabled: false,
                masked: true,
                pending: false
            }
        );
    }
}
