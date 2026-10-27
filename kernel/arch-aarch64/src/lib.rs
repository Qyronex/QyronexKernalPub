// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

pub const DAIF_IRQ_MASK: u64 = 1 << 7;
pub const MPIDR_AFF0_SHIFT: u32 = 0;
pub const MPIDR_AFF1_SHIFT: u32 = 8;
pub const MPIDR_AFF2_SHIFT: u32 = 16;
pub const MPIDR_AFF3_SHIFT: u32 = 32;
pub const MPIDR_AFFINITY_MASK: u64 = 0xff;

const PAR_FAULT: u64 = 1 << 0;
const PAR_FAULT_STATUS_SHIFT: u32 = 1;
const PAR_FAULT_STATUS_MASK: u64 = 0x3f;
const SCTLR_M: u64 = 1 << 0;
const SCTLR_WXN: u64 = 1 << 19;

#[cfg(target_arch = "aarch64")]
static WAIT_HOOK_ADDRESS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuAffinity {
    pub aff0: u8,
    pub aff1: u8,
    pub aff2: u8,
    pub aff3: u8,
}

impl CpuAffinity {
    pub const fn from_mpidr(mpidr: u64) -> Self {
        Self {
            aff0: ((mpidr >> MPIDR_AFF0_SHIFT) & MPIDR_AFFINITY_MASK) as u8,
            aff1: ((mpidr >> MPIDR_AFF1_SHIFT) & MPIDR_AFFINITY_MASK) as u8,
            aff2: ((mpidr >> MPIDR_AFF2_SHIFT) & MPIDR_AFFINITY_MASK) as u8,
            aff3: ((mpidr >> MPIDR_AFF3_SHIFT) & MPIDR_AFFINITY_MASK) as u8,
        }
    }

    /// Stable packed affinity identifier suitable for topology lookup.
    pub const fn packed(self) -> u32 {
        (self.aff0 as u32)
            | ((self.aff1 as u32) << 8)
            | ((self.aff2 as u32) << 16)
            | ((self.aff3 as u32) << 24)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranslationAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslationProbe {
    raw_par_el1: u64,
}

impl TranslationProbe {
    pub const fn from_par_el1(raw_par_el1: u64) -> Self {
        Self { raw_par_el1 }
    }

    pub const fn raw_par_el1(self) -> u64 {
        self.raw_par_el1
    }

    pub const fn faulted(self) -> bool {
        self.raw_par_el1 & PAR_FAULT != 0
    }

    pub const fn fault_status(self) -> Option<u8> {
        if self.faulted() {
            Some(((self.raw_par_el1 >> PAR_FAULT_STATUS_SHIFT) & PAR_FAULT_STATUS_MASK) as u8)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1TranslationState {
    raw_sctlr_el1: u64,
}

impl El1TranslationState {
    pub const fn from_sctlr_el1(raw_sctlr_el1: u64) -> Self {
        Self { raw_sctlr_el1 }
    }

    pub const fn raw_sctlr_el1(self) -> u64 {
        self.raw_sctlr_el1
    }

    pub const fn mmu_enabled(self) -> bool {
        self.raw_sctlr_el1 & SCTLR_M != 0
    }

    pub const fn write_xor_execute_enabled(self) -> bool {
        self.raw_sctlr_el1 & SCTLR_WXN != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitHookError {
    InvalidAddress,
    AlreadyInstalled,
}

pub const fn exception_level_from_current_el(raw: u64) -> u8 {
    ((raw >> 2) & 0x3) as u8
}

const fn valid_wait_hook_address(address: u64) -> bool {
    address != 0 && address & 3 == 0
}

/// Reads the current processor affinity from MPIDR_EL1.
#[cfg(target_arch = "aarch64")]
pub fn read_mpidr_el1() -> u64 {
    let value: u64;
    // SAFETY: MPIDR_EL1 is an architectural read-only system register available at EL1.
    unsafe {
        asm!("mrs {value}, MPIDR_EL1", value = out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

#[cfg(target_arch = "aarch64")]
pub fn current_affinity() -> CpuAffinity {
    CpuAffinity::from_mpidr(read_mpidr_el1())
}

/// Returns the current exception level encoded as 0..=3.
#[cfg(target_arch = "aarch64")]
pub fn current_exception_level() -> u8 {
    let value: u64;
    // SAFETY: CurrentEL is architectural and read-only.
    unsafe {
        asm!("mrs {value}, CurrentEL", value = out(reg) value, options(nomem, nostack, preserves_flags))
    };
    exception_level_from_current_el(value)
}

/// Reads the architected generic-timer frequency.
#[cfg(target_arch = "aarch64")]
pub fn counter_frequency_hz() -> u64 {
    let value: u64;
    // SAFETY: CNTFRQ_EL0 is architecturally readable from EL1.
    unsafe {
        asm!("mrs {value}, CNTFRQ_EL0", value = out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Reads the virtual count after an ISB so preceding control changes are observed first.
#[cfg(target_arch = "aarch64")]
pub fn read_virtual_counter() -> u64 {
    let value: u64;
    // SAFETY: CNTVCT_EL0 is architecturally readable from EL1. ISB orders the sample against
    // preceding context/system-register changes.
    unsafe {
        asm!(
            "isb",
            "mrs {value}, CNTVCT_EL0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Performs an EL1 Stage-1 translation/permission probe without dereferencing `virtual_address`.
/// `AT S1E1R/W` reports the outcome in PAR_EL1, allowing the Step-6 MMU proof to test null/guard
/// holes and read-only mappings without deliberately raising a synchronous exception.
///
/// # Safety
/// Caller must execute at EL1 with a coherent active Stage-1 translation regime. This primitive is
/// diagnostic only and does not establish pointer validity or memory ownership.
#[cfg(target_arch = "aarch64")]
pub unsafe fn probe_el1_translation(
    virtual_address: u64,
    access: TranslationAccess,
) -> TranslationProbe {
    match access {
        TranslationAccess::Read => unsafe {
            asm!(
                "at s1e1r, {address}",
                "isb",
                address = in(reg) virtual_address,
                options(nostack, preserves_flags)
            )
        },
        TranslationAccess::Write => unsafe {
            asm!(
                "at s1e1w, {address}",
                "isb",
                address = in(reg) virtual_address,
                options(nostack, preserves_flags)
            )
        },
    }
    let raw_par_el1: u64;
    unsafe {
        asm!(
            "mrs {value}, PAR_EL1",
            value = out(reg) raw_par_el1,
            options(nomem, nostack, preserves_flags)
        )
    };
    TranslationProbe::from_par_el1(raw_par_el1)
}

/// Reads the active EL1 translation/protection control state for post-transition proof.
#[cfg(target_arch = "aarch64")]
pub fn el1_translation_state() -> El1TranslationState {
    let raw_sctlr_el1: u64;
    // SAFETY: SCTLR_EL1 is readable at EL1; this function does not mutate control state.
    unsafe {
        asm!(
            "mrs {value}, SCTLR_EL1",
            value = out(reg) raw_sctlr_el1,
            options(nomem, nostack, preserves_flags)
        )
    };
    El1TranslationState::from_sctlr_el1(raw_sctlr_el1)
}

/// Returns whether IRQ exceptions are currently masked in PSTATE.DAIF.
#[cfg(target_arch = "aarch64")]
pub fn irqs_masked() -> bool {
    let daif: u64;
    // SAFETY: DAIF is readable at EL1.
    unsafe {
        asm!("mrs {daif}, DAIF", daif = out(reg) daif, options(nomem, nostack, preserves_flags))
    };
    daif & DAIF_IRQ_MASK != 0
}

/// Installs the one-shot high-half callback invoked immediately before each WFI.
///
/// The callback address is intentionally supplied as an integer because it is registered while the
/// kernel still executes through the physical alias but must later be called through TTBR1.
#[cfg(target_arch = "aarch64")]
pub fn install_wait_hook_address(address: u64) -> Result<(), WaitHookError> {
    if !valid_wait_hook_address(address) {
        return Err(WaitHookError::InvalidAddress);
    }
    WAIT_HOOK_ADDRESS
        .compare_exchange(0, address, Ordering::Release, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| WaitHookError::AlreadyInstalled)
}

#[cfg(target_arch = "aarch64")]
unsafe fn run_wait_hook() {
    let address = WAIT_HOOK_ADDRESS.load(Ordering::Acquire);
    if address == 0 {
        return;
    }
    // SAFETY: install_wait_hook_address is a kernel bootstrap contract. The registered address is a
    // non-returning-or-normal AAPCS64 `unsafe extern "C" fn()` in mapped executable TTBR1 text.
    let hook: unsafe extern "C" fn() = unsafe { core::mem::transmute(address as usize) };
    unsafe { hook() };
}

/// Masks IRQ exceptions on the current PE.
///
/// # Safety
/// Caller must run at an exception level permitted to modify DAIF and must preserve the kernel's
/// interrupt/preemption invariants.
#[cfg(target_arch = "aarch64")]
pub unsafe fn disable_irqs() {
    // SAFETY: delegated to caller; immediate #2 selects the IRQ mask bit.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
}

/// Unmasks IRQ exceptions on the current PE.
///
/// # Safety
/// Caller must have installed valid exception vectors and initialized the interrupt controller for
/// the current CPU before enabling IRQ delivery.
#[cfg(target_arch = "aarch64")]
pub unsafe fn enable_irqs() {
    // SAFETY: delegated to caller; immediate #2 selects the IRQ mask bit.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
}

/// Runs the registered transition callback, then waits until an interrupt wakes the current PE.
///
/// # Safety
/// Caller owns the surrounding interrupt-state race protocol. Any registered callback must preserve
/// the current stack and AAPCS64 callee-saved state before returning to this wait boundary.
#[cfg(target_arch = "aarch64")]
pub unsafe fn wait_for_interrupt() {
    // SAFETY: delegated wait-hook contract above.
    unsafe { run_wait_hook() };
    // SAFETY: delegated to caller.
    unsafe { asm!("wfi", options(nomem, nostack)) };
}

#[cfg(target_arch = "aarch64")]
pub fn send_event() {
    // SAFETY: SEV is an architectural event broadcast and does not access memory.
    unsafe { asm!("sev", options(nomem, nostack)) };
}

#[cfg(target_arch = "aarch64")]
pub fn instruction_sync_barrier() {
    // SAFETY: ISB only orders instruction/system-register visibility.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "aarch64")]
pub fn data_sync_barrier_inner_shareable() {
    // SAFETY: DSB ISH only orders memory accesses in the inner-shareable domain.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpidr_affinity_decoding_preserves_all_four_levels() {
        let raw = (0x44u64 << 32) | (0x33u64 << 16) | (0x22u64 << 8) | 0x11;
        let affinity = CpuAffinity::from_mpidr(raw);
        assert_eq!(
            affinity,
            CpuAffinity {
                aff0: 0x11,
                aff1: 0x22,
                aff2: 0x33,
                aff3: 0x44
            }
        );
        assert_eq!(affinity.packed(), 0x4433_2211);
    }

    #[test]
    fn current_el_decoder_uses_architectural_el_field() {
        assert_eq!(exception_level_from_current_el(0b0000), 0);
        assert_eq!(exception_level_from_current_el(0b0100), 1);
        assert_eq!(exception_level_from_current_el(0b1000), 2);
        assert_eq!(exception_level_from_current_el(0b1100), 3);
    }

    #[test]
    fn translation_probe_decodes_success_and_fault_status() {
        let success = TranslationProbe::from_par_el1(0);
        assert!(!success.faulted());
        assert_eq!(success.fault_status(), None);

        let fault = TranslationProbe::from_par_el1(1 | (0b10_0101 << PAR_FAULT_STATUS_SHIFT));
        assert!(fault.faulted());
        assert_eq!(fault.fault_status(), Some(0b10_0101));
    }

    #[test]
    fn sctlr_state_requires_both_mmu_and_wxn_bits_for_protected_regime() {
        let disabled = El1TranslationState::from_sctlr_el1(0);
        assert!(!disabled.mmu_enabled());
        assert!(!disabled.write_xor_execute_enabled());

        let protected = El1TranslationState::from_sctlr_el1(SCTLR_M | SCTLR_WXN);
        assert!(protected.mmu_enabled());
        assert!(protected.write_xor_execute_enabled());
    }

    #[test]
    fn wait_hook_address_validation_rejects_null_and_misalignment() {
        assert!(!valid_wait_hook_address(0));
        assert!(!valid_wait_hook_address(3));
        assert!(valid_wait_hook_address(4));
    }
}
