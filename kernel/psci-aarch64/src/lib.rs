// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;

pub const PSCI_VERSION: u64 = 0x8400_0000;
pub const PSCI_CPU_OFF: u64 = 0x8400_0002;
pub const PSCI_CPU_ON_64: u64 = 0xc400_0003;
pub const PSCI_AFFINITY_INFO_64: u64 = 0xc400_0004;
pub const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Conduit {
    Smc,
    Hvc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

impl Version {
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            major: (raw >> 16) as u16,
            minor: raw as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotSupported,
    InvalidParameters,
    Denied,
    AlreadyOn,
    OnPending,
    InternalFailure,
    NotPresent,
    Disabled,
    InvalidAddress,
    Unknown(i64),
    MisalignedEntry,
    UnexpectedReturn,
}

pub const fn decode_status(status: i64) -> Result<(), Error> {
    match status {
        0 => Ok(()),
        -1 => Err(Error::NotSupported),
        -2 => Err(Error::InvalidParameters),
        -3 => Err(Error::Denied),
        -4 => Err(Error::AlreadyOn),
        -5 => Err(Error::OnPending),
        -6 => Err(Error::InternalFailure),
        -7 => Err(Error::NotPresent),
        -8 => Err(Error::Disabled),
        -9 => Err(Error::InvalidAddress),
        other => Err(Error::Unknown(other)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Psci {
    conduit: Conduit,
}

impl Psci {
    pub const fn new(conduit: Conduit) -> Self {
        Self { conduit }
    }

    pub const fn conduit(self) -> Conduit {
        self.conduit
    }

    /// Returns the PSCI interface version advertised by firmware.
    ///
    /// # Safety
    /// Firmware must expose a PSCI conduit matching `self.conduit`, and the caller must execute at
    /// an exception level from which the configured SMC/HVC conduit is legal.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn version(self) -> Result<Version, Error> {
        let raw = unsafe { call(self.conduit, PSCI_VERSION, 0, 0, 0) };
        if raw < 0 {
            decode_status(raw)?;
        }
        Ok(Version::from_raw(raw as u32))
    }

    /// Starts one secondary processing element at `entry_point`, passing `context_id` in x0.
    ///
    /// During the protected Step-6 boot, the requested linker text address is validated and then
    /// replaced by the physical MMU transition trampoline. Once final-regime TTBR0 retirement has
    /// started, that physical trampoline is no longer a valid future entry and CPU_ON fails closed.
    /// Normal callers retain the exact entry they supplied.
    ///
    /// # Safety
    /// `target_mpidr` must identify a valid PSCI affinity target. `entry_point` must be a physical
    /// or protected high-alias address containing executable AArch64 bootstrap code. The selected
    /// physical entry must establish all required EL1/MMU/per-CPU state before publishing Online.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn cpu_on(
        self,
        target_mpidr: u64,
        entry_point: u64,
        context_id: u64,
    ) -> Result<(), Error> {
        if !kernal_protected_boot_aarch64::cpu_on_bootstrap_available() {
            return Err(Error::Disabled);
        }
        let effective_entry = kernal_protected_boot_aarch64::cpu_on_entry(entry_point);
        if effective_entry == 0 || effective_entry & 0x3 != 0 {
            return Err(Error::MisalignedEntry);
        }
        let status = unsafe {
            call(
                self.conduit,
                PSCI_CPU_ON_64,
                target_mpidr,
                effective_entry,
                context_id,
            )
        };
        decode_status(status)
    }

    /// Queries affinity state for a PE or affinity level.
    ///
    /// # Safety
    /// Same conduit/exception-level requirements as `version`.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn affinity_info(
        self,
        target_affinity: u64,
        lowest_level: u32,
    ) -> Result<u32, Error> {
        let raw = unsafe {
            call(
                self.conduit,
                PSCI_AFFINITY_INFO_64,
                target_affinity,
                lowest_level as u64,
                0,
            )
        };
        if raw < 0 {
            decode_status(raw)?;
        }
        Ok(raw as u32)
    }

    /// Requests that the calling PE be powered off. A successful firmware implementation does not
    /// return; returning PSCI_SUCCESS is therefore treated as a failure of the control-flow
    /// contract rather than allowing the kernel to continue on a supposedly powered-off CPU.
    ///
    /// # Safety
    /// Caller must have removed the current PE from scheduler/interrupt ownership before calling.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn cpu_off(self) -> Result<(), Error> {
        let status = unsafe { call(self.conduit, PSCI_CPU_OFF, 0, 0, 0) };
        match decode_status(status) {
            Ok(()) => Err(Error::UnexpectedReturn),
            Err(error) => Err(error),
        }
    }

    /// Requests whole-system poweroff. Success is non-returning by PSCI contract.
    ///
    /// The protected Step-6 runtime normally retires TTBR0 and completes its permission probes
    /// before the final IRQ proof. If that runtime gate has not run, the shutdown hook performs the
    /// same retirement as a fail-safe fallback. In both cases an unexpected firmware return is kept
    /// in the high-half fail-stop path.
    ///
    /// # Safety
    /// Caller must have completed any required shutdown ordering.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn system_off(self) -> Result<(), Error> {
        let protected = if kernal_protected_boot_aarch64::runtime_protected_regime_ready() {
            true
        } else {
            kernal_protected_boot_aarch64::before_system_off()
        };
        let status = unsafe { call(self.conduit, PSCI_SYSTEM_OFF, 0, 0, 0) };
        if protected {
            let _ = status;
            kernal_protected_boot_aarch64::system_off_returned();
        }
        match decode_status(status) {
            Ok(()) => Err(Error::UnexpectedReturn),
            Err(error) => Err(error),
        }
    }

    /// Requests whole-system reset. Success is non-returning by PSCI contract.
    ///
    /// # Safety
    /// Caller must have completed any required reset ordering.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn system_reset(self) -> Result<(), Error> {
        let status = unsafe { call(self.conduit, PSCI_SYSTEM_RESET, 0, 0, 0) };
        match decode_status(status) {
            Ok(()) => Err(Error::UnexpectedReturn),
            Err(error) => Err(error),
        }
    }
}

/// Executes one SMCCC-style PSCI call. x0 carries the function ID/result and x1-x3 arguments.
/// Caller-saved x0-x17 are modeled as clobbered so Rust never assumes firmware preserves them.
#[cfg(target_arch = "aarch64")]
unsafe fn call(conduit: Conduit, function: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let mut x0 = function;
    match conduit {
        Conduit::Smc => unsafe {
            asm!(
                "smc #0",
                inout("x0") x0,
                inlateout("x1") arg0 => _,
                inlateout("x2") arg1 => _,
                inlateout("x3") arg2 => _,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack)
            )
        },
        Conduit::Hvc => unsafe {
            asm!(
                "hvc #0",
                inout("x0") x0,
                inlateout("x1") arg0 => _,
                inlateout("x2") arg1 => _,
                inlateout("x3") arg2 => _,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack)
            )
        },
    }
    x0 as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_decoder_uses_psci_major_minor_layout() {
        assert_eq!(
            Version::from_raw(0x0001_0002),
            Version { major: 1, minor: 2 }
        );
        assert_eq!(
            Version::from_raw(0x0000_0002),
            Version { major: 0, minor: 2 }
        );
    }

    #[test]
    fn standard_status_codes_are_fail_closed() {
        assert_eq!(decode_status(0), Ok(()));
        assert_eq!(decode_status(-1), Err(Error::NotSupported));
        assert_eq!(decode_status(-4), Err(Error::AlreadyOn));
        assert_eq!(decode_status(-9), Err(Error::InvalidAddress));
        assert_eq!(decode_status(-77), Err(Error::Unknown(-77)));
    }

    #[test]
    fn function_ids_match_psci_64bit_call_convention() {
        assert_eq!(PSCI_VERSION, 0x8400_0000);
        assert_eq!(PSCI_CPU_ON_64, 0xc400_0003);
        assert_eq!(PSCI_AFFINITY_INFO_64, 0xc400_0004);
        assert_eq!(PSCI_SYSTEM_OFF, 0x8400_0008);
    }

    #[test]
    fn inactive_protected_boot_preserves_requested_entry_on_host() {
        assert!(kernal_protected_boot_aarch64::cpu_on_bootstrap_available());
        assert_eq!(
            kernal_protected_boot_aarch64::cpu_on_entry(0x4020_1000),
            0x4020_1000
        );
    }
}
