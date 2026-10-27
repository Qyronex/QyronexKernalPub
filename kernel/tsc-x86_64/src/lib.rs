// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::hint::spin_loop;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use kernal_arch_x86_64::CpuFeatures;
use kernal_time::{CycleScale, MonotonicClock};

/// Canonical virtual TSC frequency for the controlled QEMU proof profile.
///
/// The value is public in every build so the host-side `xtask` harness can derive its QEMU CPU
/// profile from the same source of truth. It only becomes acceptable as timing evidence when the
/// `qemu-fixed-frequency` feature is enabled; normal hardware policy remains unchanged.
pub const QEMU_PROOF_TSC_HZ: u64 = 2_500_000_000;

const PUBLISH_EMPTY: u8 = 0;
const PUBLISH_WRITING: u8 = 1;
const PUBLISH_READY: u8 = 2;
const QUALITY_ARCHITECTURAL: u8 = 1;
const QUALITY_CALIBRATED: u8 = 2;
const QUALITY_SYNTHETIC_PROOF: u8 = 3;
const PUBLISH_SPIN_LIMIT: usize = 1_000_000;

static PUBLISHED_STATE: AtomicU8 = AtomicU8::new(PUBLISH_EMPTY);
static PUBLISHED_HZ: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_QUALITY: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrequencyQuality {
    /// CPUID leaf 0x15 supplied a complete crystal/ratio description on invariant hardware.
    Architectural,
    /// Measured against a fixed-frequency hardware reference such as the ACPI PM timer.
    Calibrated,
    /// Fixed by the controlled QEMU proof profile. Never valid as normal hardware evidence.
    SyntheticProof,
    /// Firmware/CPUID nominal value only; unsuitable for precise early timing.
    Estimated,
}

impl FrequencyQuality {
    pub const fn reliable_for_timing(self) -> bool {
        match self {
            Self::Architectural | Self::Calibrated => true,
            Self::SyntheticProof => cfg!(feature = "qemu-fixed-frequency"),
            Self::Estimated => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TscFrequency {
    pub hz: u64,
    pub quality: FrequencyQuality,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NonInvariantTsc,
    FrequencyUnavailable,
    Overflow,
    TimeScale,
    InvalidCalibration,
    UnreliablePublication,
    PublicationInProgress,
    PublishedMismatch,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrequencyLeaves {
    pub denominator: u32,
    pub numerator: u32,
    pub crystal_hz: u32,
    pub base_mhz: u32,
}

impl TscFrequency {
    pub fn from_leaves(features: CpuFeatures, leaves: FrequencyLeaves) -> Result<Self, Error> {
        if !features.invariant_tsc {
            return Err(Error::NonInvariantTsc);
        }
        if leaves.denominator != 0 && leaves.numerator != 0 && leaves.crystal_hz != 0 {
            let numerator = (leaves.crystal_hz as u128)
                .checked_mul(leaves.numerator as u128)
                .ok_or(Error::Overflow)?;
            let hz = numerator / leaves.denominator as u128;
            let hz = u64::try_from(hz).map_err(|_| Error::Overflow)?;
            if hz != 0 {
                return Ok(Self {
                    hz,
                    quality: FrequencyQuality::Architectural,
                });
            }
        }
        if leaves.base_mhz != 0 {
            let hz = (leaves.base_mhz as u64)
                .checked_mul(1_000_000)
                .ok_or(Error::Overflow)?;
            return Ok(Self {
                hz,
                quality: FrequencyQuality::Estimated,
            });
        }
        Err(Error::FrequencyUnavailable)
    }

    pub fn from_reference_delta(
        features: CpuFeatures,
        tsc_cycles: u64,
        reference_ticks: u64,
        reference_hz: u64,
    ) -> Result<Self, Error> {
        if !features.invariant_tsc {
            return Err(Error::NonInvariantTsc);
        }
        if tsc_cycles == 0 || reference_ticks == 0 || reference_hz == 0 {
            return Err(Error::InvalidCalibration);
        }
        let numerator = (tsc_cycles as u128)
            .checked_mul(reference_hz as u128)
            .ok_or(Error::Overflow)?;
        let hz = numerator
            .checked_add((reference_ticks / 2) as u128)
            .ok_or(Error::Overflow)?
            / reference_ticks as u128;
        let hz = u64::try_from(hz).map_err(|_| Error::Overflow)?;
        if hz == 0 {
            return Err(Error::InvalidCalibration);
        }
        Ok(Self {
            hz,
            quality: FrequencyQuality::Calibrated,
        })
    }

    pub const fn reliable_for_timing(self) -> bool {
        self.quality.reliable_for_timing()
    }

    pub fn cycle_scale(self) -> Result<CycleScale, Error> {
        CycleScale::from_frequency_hz(self.hz, 32).map_err(|_| Error::TimeScale)
    }

    pub fn monotonic_clock(self, base_cycles: u64, base_ns: u64) -> Result<MonotonicClock, Error> {
        Ok(MonotonicClock::new(
            self.cycle_scale()?,
            base_cycles,
            base_ns,
        ))
    }

    pub fn ns_to_cycles_ceil(self, ns: u64) -> Result<u64, Error> {
        let product = (ns as u128)
            .checked_mul(self.hz as u128)
            .ok_or(Error::Overflow)?;
        let cycles = product.checked_add(999_999_999).ok_or(Error::Overflow)? / 1_000_000_000u128;
        u64::try_from(cycles).map_err(|_| Error::Overflow)
    }
}

pub fn publish_reliable(frequency: TscFrequency) -> Result<(), Error> {
    if frequency.hz == 0 || !frequency.reliable_for_timing() {
        return Err(Error::UnreliablePublication);
    }
    loop {
        match PUBLISHED_STATE.compare_exchange(
            PUBLISH_EMPTY,
            PUBLISH_WRITING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                PUBLISHED_HZ.store(frequency.hz, Ordering::Relaxed);
                PUBLISHED_QUALITY.store(encode_quality(frequency.quality)?, Ordering::Relaxed);
                PUBLISHED_STATE.store(PUBLISH_READY, Ordering::Release);
                return Ok(());
            }
            Err(PUBLISH_READY) => {
                return if published() == Some(frequency) {
                    Ok(())
                } else {
                    Err(Error::PublishedMismatch)
                };
            }
            Err(PUBLISH_WRITING) => {
                for _ in 0..PUBLISH_SPIN_LIMIT {
                    spin_loop();
                    if PUBLISHED_STATE.load(Ordering::Acquire) != PUBLISH_WRITING {
                        break;
                    }
                }
                if PUBLISHED_STATE.load(Ordering::Acquire) == PUBLISH_WRITING {
                    return Err(Error::PublicationInProgress);
                }
            }
            Err(_) => return Err(Error::PublishedMismatch),
        }
    }
}

pub fn published() -> Option<TscFrequency> {
    if PUBLISHED_STATE.load(Ordering::Acquire) != PUBLISH_READY {
        return None;
    }
    let hz = PUBLISHED_HZ.load(Ordering::Relaxed);
    let quality = decode_quality(PUBLISHED_QUALITY.load(Ordering::Relaxed))?;
    (hz != 0).then_some(TscFrequency { hz, quality })
}

fn encode_quality(quality: FrequencyQuality) -> Result<u8, Error> {
    match quality {
        FrequencyQuality::Architectural => Ok(QUALITY_ARCHITECTURAL),
        FrequencyQuality::Calibrated => Ok(QUALITY_CALIBRATED),
        FrequencyQuality::SyntheticProof if cfg!(feature = "qemu-fixed-frequency") => {
            Ok(QUALITY_SYNTHETIC_PROOF)
        }
        FrequencyQuality::SyntheticProof | FrequencyQuality::Estimated => {
            Err(Error::UnreliablePublication)
        }
    }
}

fn decode_quality(value: u8) -> Option<FrequencyQuality> {
    match value {
        QUALITY_ARCHITECTURAL => Some(FrequencyQuality::Architectural),
        QUALITY_CALIBRATED => Some(FrequencyQuality::Calibrated),
        QUALITY_SYNTHETIC_PROOF if cfg!(feature = "qemu-fixed-frequency") => {
            Some(FrequencyQuality::SyntheticProof)
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
pub fn detect(features: CpuFeatures) -> Result<TscFrequency, Error> {
    use core::arch::x86_64::__cpuid;

    if let Some(frequency) = published() {
        return Ok(frequency);
    }

    let maximum = __cpuid(0).eax;
    let leaf15 = if maximum >= 0x15 {
        __cpuid(0x15)
    } else {
        __cpuid(0)
    };
    if features.invariant_tsc
        && maximum >= 0x15
        && leaf15.eax != 0
        && leaf15.ebx != 0
        && leaf15.ecx != 0
    {
        let frequency = TscFrequency::from_leaves(
            features,
            FrequencyLeaves {
                denominator: leaf15.eax,
                numerator: leaf15.ebx,
                crystal_hz: leaf15.ecx,
                base_mhz: 0,
            },
        )?;
        publish_reliable(frequency)?;
        return Ok(published().unwrap_or(frequency));
    }

    #[cfg(feature = "qemu-fixed-frequency")]
    {
        let frequency = TscFrequency {
            hz: QEMU_PROOF_TSC_HZ,
            quality: FrequencyQuality::SyntheticProof,
        };
        publish_reliable(frequency)?;
        return Ok(published().unwrap_or(frequency));
    }

    #[cfg(not(feature = "qemu-fixed-frequency"))]
    {
        if !features.invariant_tsc {
            return Err(Error::NonInvariantTsc);
        }
        let leaf16 = if maximum >= 0x16 {
            __cpuid(0x16)
        } else {
            __cpuid(0)
        };
        TscFrequency::from_leaves(
            features,
            FrequencyLeaves {
                denominator: 0,
                numerator: 0,
                crystal_hz: 0,
                base_mhz: if maximum >= 0x16 { leaf16.eax } else { 0 },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invariant() -> CpuFeatures {
        CpuFeatures {
            invariant_tsc: true,
            ..CpuFeatures::default()
        }
    }

    #[test]
    fn architectural_ratio_is_preferred() {
        let frequency = TscFrequency::from_leaves(
            invariant(),
            FrequencyLeaves {
                denominator: 1,
                numerator: 100,
                crystal_hz: 24_000_000,
                base_mhz: 2200,
            },
        )
        .unwrap();
        assert_eq!(frequency.hz, 2_400_000_000);
        assert_eq!(frequency.quality, FrequencyQuality::Architectural);
        assert!(frequency.reliable_for_timing());
    }

    #[test]
    fn base_mhz_fallback_is_explicitly_estimated() {
        let frequency = TscFrequency::from_leaves(
            invariant(),
            FrequencyLeaves {
                base_mhz: 3200,
                ..FrequencyLeaves::default()
            },
        )
        .unwrap();
        assert_eq!(frequency.hz, 3_200_000_000);
        assert_eq!(frequency.quality, FrequencyQuality::Estimated);
        assert!(!frequency.reliable_for_timing());
    }

    #[test]
    fn reference_delta_produces_calibrated_frequency() {
        let frequency =
            TscFrequency::from_reference_delta(invariant(), 25_000_000, 35_795, 3_579_545).unwrap();
        assert!((2_499_000_000..=2_501_000_000).contains(&frequency.hz));
        assert_eq!(frequency.quality, FrequencyQuality::Calibrated);
        assert!(frequency.reliable_for_timing());
    }

    #[test]
    fn synthetic_proof_quality_is_never_implicitly_hardware_reliable() {
        assert_eq!(
            FrequencyQuality::SyntheticProof.reliable_for_timing(),
            cfg!(feature = "qemu-fixed-frequency")
        );
    }

    #[test]
    fn publication_encoding_rejects_estimated_time() {
        assert_eq!(
            encode_quality(FrequencyQuality::Estimated),
            Err(Error::UnreliablePublication)
        );
        assert_eq!(
            decode_quality(QUALITY_ARCHITECTURAL),
            Some(FrequencyQuality::Architectural)
        );
        assert_eq!(
            decode_quality(QUALITY_CALIBRATED),
            Some(FrequencyQuality::Calibrated)
        );
    }

    #[test]
    fn invalid_reference_calibration_is_rejected() {
        assert_eq!(
            TscFrequency::from_reference_delta(invariant(), 10, 0, 3_579_545),
            Err(Error::InvalidCalibration)
        );
    }

    #[test]
    fn variable_tsc_is_rejected_for_normal_hardware_frequency_sources() {
        let features = CpuFeatures::default();
        assert_eq!(
            TscFrequency::from_leaves(
                features,
                FrequencyLeaves {
                    base_mhz: 3000,
                    ..FrequencyLeaves::default()
                }
            ),
            Err(Error::NonInvariantTsc)
        );
        assert_eq!(
            TscFrequency::from_reference_delta(features, 10_000, 100, 3_579_545),
            Err(Error::NonInvariantTsc)
        );
    }

    #[test]
    fn nanoseconds_to_cycles_rounds_up() {
        let frequency = TscFrequency {
            hz: 2_500_000_000,
            quality: FrequencyQuality::Architectural,
        };
        assert_eq!(frequency.ns_to_cycles_ceil(1).unwrap(), 3);
        assert_eq!(
            frequency.ns_to_cycles_ceil(1_000_000_000).unwrap(),
            2_500_000_000
        );
    }
}
