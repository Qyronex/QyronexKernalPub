// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use kernal_acpi_fadt_physical::read_pm_timer;
#[cfg(target_arch = "x86_64")]
use kernal_acpi_physical::{find_unique_table, read_root_table, read_rsdp};
use kernal_arch_x86_64::CpuFeatures;
use kernal_physical_io::PhysicalReader;
use kernal_tsc_x86_64::TscFrequency;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Publish(kernal_tsc_x86_64::Error),
    Rsdp(kernal_acpi_physical::Error),
    Root(kernal_acpi_physical::Error),
    FadtTable(kernal_acpi_physical::Error),
    FadtTimer(kernal_acpi_fadt_physical::Error),
    Calibration(kernal_pm_timer_x86_64::Error),
    UnsupportedHostArchitecture,
}

/// Resolves and publishes one reliable TSC frequency for the entire SMP system.
///
/// `kernal_tsc_x86_64::detect` first returns an already-published value, then prefers CPUID 0x15.
/// If that path is unavailable/unreliable, the complete FADT is checksum-validated and the BSP
/// calibrates invariant TSC against the ACPI PM timer. APs subsequently obtain this exact central
/// value through ordinary `detect()` and therefore never perform independent calibration.
///
/// # Safety
/// Must execute at CPL0 on the non-migrating BSP after ACPI/kmap access is available and before AP
/// startup. The ACPI PM timer descriptor must remain firmware-valid during calibration.
#[cfg(target_arch = "x86_64")]
pub unsafe fn resolve_and_publish<R: PhysicalReader>(
    reader: &R,
    rsdp_physical: u64,
    features: CpuFeatures,
) -> Result<TscFrequency, Error> {
    if let Some(existing) = kernal_tsc_x86_64::published() {
        return Ok(existing);
    }

    if let Ok(detected) = kernal_tsc_x86_64::detect(features) {
        if detected.reliable_for_timing() {
            kernal_tsc_x86_64::publish_reliable(detected).map_err(Error::Publish)?;
            return Ok(kernal_tsc_x86_64::published().unwrap_or(detected));
        }
    }

    let rsdp = read_rsdp(reader, rsdp_physical).map_err(Error::Rsdp)?;
    let root = read_root_table(reader, rsdp).map_err(Error::Root)?;
    let fadt = find_unique_table(reader, root, *b"FACP").map_err(Error::FadtTable)?;
    let timer = read_pm_timer(reader, fadt.address).map_err(Error::FadtTimer)?;
    // SAFETY: delegated CPL0/BSP contract and timer came from checksum-validated FADT.
    let calibrated = unsafe { kernal_pm_timer_x86_64::calibrate_io(features, timer) }
        .map_err(Error::Calibration)?;
    kernal_tsc_x86_64::publish_reliable(calibrated).map_err(Error::Publish)?;
    Ok(kernal_tsc_x86_64::published().unwrap_or(calibrated))
}

/// Foreign-host compatibility entry point for host-side workspace tests.
///
/// It deliberately does not emulate CPUID, TSC, ACPI PM-timer I/O, or any other x86 bootstrap
/// mechanism. Runtime callers on a non-x86 host fail closed while pure policy crates remain
/// compilable on Apple Silicon and other developer hosts.
///
/// # Safety
/// This stub performs no privileged operation.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn resolve_and_publish<R: PhysicalReader>(
    reader: &R,
    rsdp_physical: u64,
    features: CpuFeatures,
) -> Result<TscFrequency, Error> {
    let _ = (reader, rsdp_physical, features);
    Err(Error::UnsupportedHostArchitecture)
}

pub fn published() -> Option<TscFrequency> {
    kernal_tsc_x86_64::published()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_tsc_x86_64::{FrequencyQuality, TscFrequency};

    #[test]
    fn wrapper_exposes_same_central_publication_type() {
        let value = published();
        assert!(value.is_none() || value.is_some_and(TscFrequency::reliable_for_timing));
    }

    #[test]
    fn estimated_frequency_is_not_reliable_for_bootstrap_publication() {
        let value = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Estimated,
        };
        assert!(!value.reliable_for_timing());
    }
}
