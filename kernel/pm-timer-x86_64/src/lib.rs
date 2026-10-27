// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::hint::spin_loop;
#[cfg(any(target_arch = "x86_64", test))]
use kernal_acpi_fadt::AddressSpace;
use kernal_acpi_fadt::{PM_TIMER_HZ, PmTimer};
use kernal_arch_x86_64::CpuFeatures;
#[cfg(target_arch = "x86_64")]
use kernal_arch_x86_64::read_tsc_ordered;
use kernal_tsc_x86_64::TscFrequency;

pub const CALIBRATION_NS: u64 = 10_000_000;
pub const MAX_POLLS: usize = 5_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedHostArchitecture,
    UnsupportedAddressSpace,
    PortOutOfRange,
    InvalidWidth,
    ReferenceStalled,
    TscWentBackwards,
    Frequency(kernal_tsc_x86_64::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    pub tsc_cycles: u64,
    pub reference_ticks: u64,
}

pub fn reference_ticks_for_ns(ns: u64) -> Result<u64, Error> {
    let product = (ns as u128)
        .checked_mul(PM_TIMER_HZ as u128)
        .ok_or(Error::Frequency(kernal_tsc_x86_64::Error::Overflow))?;
    let ticks = product
        .checked_add(999_999_999)
        .ok_or(Error::Frequency(kernal_tsc_x86_64::Error::Overflow))?
        / 1_000_000_000u128;
    u64::try_from(ticks).map_err(|_| Error::Frequency(kernal_tsc_x86_64::Error::Overflow))
}

pub fn elapsed_reference_ticks(start: u32, end: u32, width_bits: u8) -> Result<u64, Error> {
    let mask = match width_bits {
        24 => 0x00ff_ffff,
        32 => u32::MAX,
        _ => return Err(Error::InvalidWidth),
    };
    Ok(end.wrapping_sub(start) as u64 & mask as u64)
}

pub fn frequency_from_sample(features: CpuFeatures, sample: Sample) -> Result<TscFrequency, Error> {
    TscFrequency::from_reference_delta(
        features,
        sample.tsc_cycles,
        sample.reference_ticks,
        PM_TIMER_HZ,
    )
    .map_err(Error::Frequency)
}

/// Measures the current invariant TSC against a legacy-compatible ACPI PM timer I/O register.
///
/// # Safety
/// Caller must execute at CPL0 on a non-migrating x86_64 CPU. `timer` must describe the
/// checksum-validated FADT PM timer for this machine. Port I/O is privileged and the caller must
/// ensure no concurrent firmware/OS transition can invalidate the ACPI hardware description.
#[cfg(target_arch = "x86_64")]
pub unsafe fn calibrate_io(features: CpuFeatures, timer: PmTimer) -> Result<TscFrequency, Error> {
    if timer.address_space != AddressSpace::SystemIo {
        return Err(Error::UnsupportedAddressSpace);
    }
    let port = u16::try_from(timer.address).map_err(|_| Error::PortOutOfRange)?;
    if !matches!(timer.width_bits, 24 | 32) {
        return Err(Error::InvalidWidth);
    }
    let target_ticks = reference_ticks_for_ns(CALIBRATION_NS)?;

    // Read TSC outside the reference read pair so the complete I/O measurement overhead is
    // included. At 10 ms this overhead is negligible and, importantly, cannot make the result zero.
    let start_tsc = read_tsc_ordered();
    // SAFETY: delegated CPL0/validated PM timer contract.
    let start_reference = unsafe { inl(port) } & timer.mask();

    let mut elapsed = 0u64;
    for _ in 0..MAX_POLLS {
        // SAFETY: same validated I/O-port contract as the initial sample.
        let observed = unsafe { inl(port) } & timer.mask();
        elapsed = elapsed_reference_ticks(start_reference, observed, timer.width_bits)?;
        if elapsed >= target_ticks {
            break;
        }
        spin_loop();
    }
    if elapsed < target_ticks {
        return Err(Error::ReferenceStalled);
    }

    let end_tsc = read_tsc_ordered();
    let tsc_cycles = end_tsc
        .checked_sub(start_tsc)
        .ok_or(Error::TscWentBackwards)?;
    frequency_from_sample(
        features,
        Sample {
            tsc_cycles,
            reference_ticks: elapsed,
        },
    )
}

/// Host-test fail-closed implementation. It preserves the API so x86_64 support state machines can
/// compile on Apple Silicon, but it never pretends that ARM can execute x86 port I/O.
///
/// # Safety
/// No hardware access is performed on non-x86_64 hosts.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn calibrate_io(_features: CpuFeatures, _timer: PmTimer) -> Result<TscFrequency, Error> {
    Err(Error::UnsupportedHostArchitecture)
}

#[cfg(target_arch = "x86_64")]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: caller is responsible for CPL0 and port validity.
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_tsc_x86_64::FrequencyQuality;

    fn invariant() -> CpuFeatures {
        CpuFeatures {
            invariant_tsc: true,
            ..CpuFeatures::default()
        }
    }

    #[test]
    fn ten_ms_window_is_about_35796_reference_ticks() {
        assert_eq!(reference_ticks_for_ns(CALIBRATION_NS).unwrap(), 35_796);
    }

    #[test]
    fn elapsed_ticks_handles_24_bit_wrap() {
        let start = 0x00ff_fff0;
        let end = 0x0000_0010;
        assert_eq!(elapsed_reference_ticks(start, end, 24).unwrap(), 32);
    }

    #[test]
    fn elapsed_ticks_handles_32_bit_wrap() {
        let start = 0xffff_fff0;
        let end = 0x0000_0010;
        assert_eq!(elapsed_reference_ticks(start, end, 32).unwrap(), 32);
    }

    #[test]
    fn calibrated_sample_produces_reliable_frequency() {
        let frequency = frequency_from_sample(
            invariant(),
            Sample {
                tsc_cycles: 25_000_000,
                reference_ticks: 35_795,
            },
        )
        .unwrap();
        assert_eq!(frequency.quality, FrequencyQuality::Calibrated);
        assert!(frequency.reliable_for_timing());
        assert!((2_499_000_000..=2_501_000_000).contains(&frequency.hz));
    }

    #[test]
    fn invalid_timer_width_is_rejected() {
        assert_eq!(elapsed_reference_ticks(0, 1, 16), Err(Error::InvalidWidth));
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn hardware_calibration_fails_closed_on_foreign_host() {
        let timer = PmTimer {
            address_space: AddressSpace::SystemIo,
            address: 0x408,
            width_bits: 24,
        };
        // SAFETY: non-x86 implementation performs no hardware access by contract.
        assert_eq!(
            unsafe { calibrate_io(invariant(), timer) },
            Err(Error::UnsupportedHostArchitecture)
        );
    }
}
