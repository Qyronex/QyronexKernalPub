// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::{Error, validate_table_address};
use super::{SCTLR_SPAN, TCR_EPD0};

pub type UserTtbr0SwitchObserver = fn();

static USER_TTBR0_SWITCH_OBSERVER: AtomicUsize = AtomicUsize::new(0);

/// Installs the one canonical observer notified before every TTBR0 activation/deactivation.
///
/// Reinstalling the exact same observer is idempotent. A different observer is rejected so lower
/// layers cannot silently replace the process-current security observer once process execution is
/// active. The observer is intentionally never uninstalled.
pub fn install_user_ttbr0_switch_observer(observer: UserTtbr0SwitchObserver) -> bool {
    let address = observer as *const () as usize;
    match USER_TTBR0_SWITCH_OBSERVER.compare_exchange(
        0,
        address,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => true,
        Err(existing) => existing == address,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn notify_user_ttbr0_switch() {
    let address = USER_TTBR0_SWITCH_OBSERVER.load(Ordering::Acquire);
    if address == 0 {
        return;
    }
    // SAFETY: the atomic is written only by `install_user_ttbr0_switch_observer`, which stores the
    // address of the exact `UserTtbr0SwitchObserver` function type and never clears/replaces it.
    let observer: UserTtbr0SwitchObserver = unsafe { core::mem::transmute(address) };
    observer();
}

pub const fn tcr_with_ttbr0_enabled(value: u64) -> u64 {
    value & !TCR_EPD0
}

pub const fn tcr_with_ttbr0_disabled(value: u64) -> u64 {
    value | TCR_EPD0
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn active_user_ttbr0_from(tcr_el1: u64, ttbr0_el1: u64) -> Option<u64> {
    if tcr_el1 & TCR_EPD0 == 0 {
        Some(ttbr0_el1)
    } else {
        None
    }
}

/// Reports the lower-half root that is architecturally active on the current PE.
///
/// This is a read-only ownership check for higher-level process/dispatch code. A root is reported
/// only while TTBR0 walks are enabled; the Step-7 deactivation path sets EPD0 before clearing TTBR0,
/// so a retained process witness cannot remain current after the lower half is disabled.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn current_user_ttbr0() -> Option<u64> {
    let tcr_el1: u64;
    let ttbr0_el1: u64;
    // SAFETY: Kernal calls this helper only from EL1. Reading these registers does not mutate
    // translation state and the surrounding exception/switch owner provides serialization.
    unsafe {
        asm!(
            "mrs {tcr}, TCR_EL1",
            "mrs {ttbr0}, TTBR0_EL1",
            tcr = out(reg) tcr_el1,
            ttbr0 = out(reg) ttbr0_el1,
            options(nomem, nostack, preserves_flags)
        )
    };
    active_user_ttbr0_from(tcr_el1, ttbr0_el1)
}

/// Host builds cannot observe a freestanding AArch64 TTBR0 activation.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn current_user_ttbr0() -> Option<u64> {
    None
}

/// Returns the SCTLR_EL1 value required by Step 10 so every exception taken to EL1 forces
/// `PSTATE.PAN=1` before privileged handler code executes.
///
/// Step 6 deliberately selected `SPAN=1` as the backwards-compatible baseline because the field is
/// RES1 when FEAT_PAN is absent. Step 10 may clear SPAN only after independently proving FEAT_PAN is
/// implemented on the current PE.
pub const fn sctlr_with_pan_exception_entry(value: u64) -> u64 {
    value & !SCTLR_SPAN
}

pub const fn pan_exception_entry_enabled(value: u64) -> bool {
    value & SCTLR_SPAN == 0
}

/// Enables the architectural default-deny PAN policy on every subsequent exception entry to EL1.
///
/// With `SCTLR_EL1.SPAN=0`, hardware sets `PSTATE.PAN=1` when taking an exception to EL1. This is
/// required before Step-10 usercopy becomes part of the normal syscall path; otherwise an EL0->EL1
/// SVC/abort can inherit a PAN-disabled PSTATE and execute privileged code with user access open.
///
/// # Safety
/// Caller must execute at EL1, must have verified FEAT_PAN is implemented on this PE, and must own
/// the local exception/user-access policy while changing SCTLR_EL1. If FEAT_PAN is absent SPAN may be
/// RES1 and must not be cleared.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn enable_pan_exception_entry() {
    let current: u64;
    // SAFETY: delegated to the caller contract; SCTLR_EL1 is readable at EL1.
    unsafe {
        asm!(
            "mrs {value}, SCTLR_EL1",
            value = out(reg) current,
            options(nomem, nostack, preserves_flags)
        )
    };
    let hardened = sctlr_with_pan_exception_entry(current);
    if hardened == current {
        return;
    }
    // SAFETY: caller verified FEAT_PAN and owns this PE's EL1 control state. ISB makes the updated
    // exception-entry policy visible before later privilege transitions/exceptions are permitted.
    unsafe {
        asm!(
            "msr SCTLR_EL1, {value}",
            "isb",
            value = in(reg) hardened,
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// Reports whether EL1 exception entry currently forces PAN closed (`SCTLR_EL1.SPAN=0`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn pan_exception_entry_is_enabled() -> bool {
    let current: u64;
    // SAFETY: SCTLR_EL1 is readable at EL1 and this helper does not mutate machine state.
    unsafe {
        asm!(
            "mrs {value}, SCTLR_EL1",
            value = out(reg) current,
            options(nomem, nostack, preserves_flags)
        )
    };
    pan_exception_entry_enabled(current)
}

/// Encodes a 4 KiB-aligned lower-half user VA for `TLBI VAE1IS` while Step 7 uses ASID 0.
///
/// Callers must validate alignment and user-range ownership before using the operand in a TLBI.
pub const fn tlbi_vae1is_operand(virtual_address: u64) -> u64 {
    virtual_address >> 12
}

/// Installs a new lower-half user root and enables TTBR0 walks.
///
/// Step 7 deliberately reuses ASID 0 and performs a broadcast `VMALLE1IS` on every switch. This is
/// slower than ASID-tagged switching but provides a simple correctness baseline: no non-global user
/// translation from the previous address space can survive the switch. ASIDs are a later
/// optimization and must not weaken this contract.
///
/// # Safety
/// Caller must execute at EL1 with migration/preemption and interrupts controlled, `root_table`
/// must be an owned lower-half user page-table root, and no concurrent code may access user VAs
/// while TTBR0 walks are temporarily disabled during the switch.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn activate_user_ttbr0(root_table: u64) -> Result<(), Error> {
    validate_table_address(root_table)?;

    let current_tcr: u64;
    // SAFETY: TCR_EL1 is readable at EL1.
    unsafe {
        asm!(
            "mrs {value}, TCR_EL1",
            value = out(reg) current_tcr,
            options(nomem, nostack, preserves_flags)
        )
    };
    let disabled_tcr = tcr_with_ttbr0_disabled(current_tcr);
    let enabled_tcr = tcr_with_ttbr0_enabled(current_tcr);

    // Invalidate higher-level process-current witnesses before the hardware state can change. This
    // keeps even a correctly serialized raw `Aarch64Root::activate` from preserving stale logical
    // Linux authority when two safe backends expose the same numeric root.
    notify_user_ttbr0_switch();

    // Disable lower-half walks before replacing TTBR0, publish table writes, install the new root,
    // discard all old EL1 stage-1 translations, then re-enable walks. This avoids a window where
    // speculative lower-half accesses can use a new root with stale translations from the old one.
    // SAFETY: delegated to the caller contract above.
    unsafe {
        asm!(
            "msr TCR_EL1, {disabled}",
            "isb",
            "dsb ishst",
            "msr TTBR0_EL1, {root}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "msr TCR_EL1, {enabled}",
            "isb",
            disabled = in(reg) disabled_tcr,
            root = in(reg) root_table,
            enabled = in(reg) enabled_tcr,
            options(nostack)
        )
    };
    Ok(())
}

/// Invalidates one already-validated lower-half user page for ASID 0 on every PE in the
/// inner-shareable domain.
///
/// # Safety
/// `virtual_address` must be a 4 KiB-aligned canonical lower-half user page whose page-table write
/// has already been published by the caller. The caller must serialize the mapping mutation against
/// concurrent users of the address space.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn invalidate_user_page(virtual_address: u64) {
    let operand = tlbi_vae1is_operand(virtual_address);
    // SAFETY: delegated to the caller contract above; the sequence publishes the PTE write before
    // invalidating the ASID-0 VA on every PE and completes before subsequent translation use.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vae1is, {operand}",
            "dsb ish",
            "isb",
            operand = in(reg) operand,
            options(nostack)
        )
    };
}

/// Disables all lower-half walks and clears TTBR0 before returning to a kernel-only regime.
///
/// # Safety
/// Caller must execute at EL1 with user execution quiesced and must not require a live TTBR0
/// translation after this call returns.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn deactivate_user_ttbr0() {
    let current_tcr: u64;
    // SAFETY: TCR_EL1 is readable at EL1.
    unsafe {
        asm!(
            "mrs {value}, TCR_EL1",
            value = out(reg) current_tcr,
            options(nomem, nostack, preserves_flags)
        )
    };
    let disabled_tcr = tcr_with_ttbr0_disabled(current_tcr);

    // Revoke any published higher-level process-current generation before lower-half hardware state
    // changes. Process-aware deactivation additionally holds its logical registry switch lock.
    notify_user_ttbr0_switch();

    // SAFETY: delegated to the caller contract above.
    unsafe {
        asm!(
            "msr TCR_EL1, {disabled}",
            "isb",
            "msr TTBR0_EL1, xzr",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            disabled = in(reg) disabled_tcr,
            options(nostack)
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttbr0_enable_disable_only_changes_epd0() {
        let base = 0x1234_5678_9abc_def0;
        assert_eq!(tcr_with_ttbr0_disabled(base), base | TCR_EPD0);
        assert_eq!(tcr_with_ttbr0_enabled(base | TCR_EPD0), base & !TCR_EPD0);
    }

    #[test]
    fn active_ttbr0_requires_walks_enabled() {
        let root = 0x1234_5000;
        assert_eq!(active_user_ttbr0_from(0, root), Some(root));
        assert_eq!(active_user_ttbr0_from(TCR_EPD0, root), None);
    }

    #[test]
    fn user_switch_observer_install_is_idempotent_for_same_function() {
        fn observer() {}
        assert!(install_user_ttbr0_switch_observer(observer));
        assert!(install_user_ttbr0_switch_observer(observer));
    }

    #[test]
    fn pan_exception_entry_clears_only_span() {
        let base = 0x1234_5678_9abc_def0 | SCTLR_SPAN;
        let hardened = sctlr_with_pan_exception_entry(base);
        assert_eq!(hardened, base & !SCTLR_SPAN);
        assert!(pan_exception_entry_enabled(hardened));
        assert!(!pan_exception_entry_enabled(base));
    }

    #[test]
    fn user_tlbi_operand_drops_page_offset_and_keeps_lower_va_bits() {
        assert_eq!(tlbi_vae1is_operand(0x0000_1234_5678_9000), 0x0001_2345_6789);
    }
}
