// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_fdt_aarch64::MmioRegion;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static RUNTIME_STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static RUNTIME_TABLE_POOL_READY: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static RUNTIME_PROTECTED: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn cpu_on_bootstrap_available_for_state(runtime_started: bool) -> bool {
    !runtime_started
}

/// Returns whether PSCI CPU_ON may still target the physical protected-secondary trampoline.
///
/// The physical trampoline is valid only while the temporary low aliases still exist. CPU_ON is
/// therefore closed as soon as final-regime retirement starts, not only after the final protected
/// barrier publishes ready. This removes the race window in which low leaves may already be gone.
pub fn cpu_on_bootstrap_available() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        return cpu_on_bootstrap_available_for_state(RUNTIME_STARTED.load(Ordering::Acquire));
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        true
    }
}

/// Resolves a DTB-derived physical MMIO aperture to the protected TTBR1 alias while the Step-6
/// bootstrap is active. Outside the protected bootstrap the original physical region is returned.
///
/// Only apertures published by the protected bootstrap are accepted once it owns the machine. This
/// makes a missing alias fail closed before TTBR0 can be retired.
pub fn runtime_mmio_region(region: MmioRegion) -> MmioRegion {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if super::is_active() {
            let state = super::boot_state();
            for alias in state.mmio_aliases.iter().copied() {
                if alias.physical == region {
                    return alias.virtual_region;
                }
            }
            super::fatal_silent();
        }
    }
    region
}

/// Returns whether the BSP may claim the post-bootstrap page-table pool while secondary PEs remain
/// held at the final runtime-release barrier.
///
/// Publication occurs only after every expected PE has retired the temporary TTBR0 regime and the
/// BSP has completed the architectural W^X/null/guard/high-MMIO checks. It is deliberately distinct
/// from [`runtime_protected_regime_ready`], which releases secondary PEs only after all BSP-only
/// address-space and EL0 proofs have completed.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) fn runtime_table_pool_claim_ready() -> bool {
    RUNTIME_TABLE_POOL_READY.load(Ordering::Acquire)
}

/// Moves the already-high Step-6 runtime into its final TTBR1-only regime.
///
/// The BSP calls this after every expected secondary has published Online while all PEs still have
/// IRQs masked. It performs the single shared low-leaf removal, publishes the per-PE TTBR0-retire
/// request, waits for every PE to finalize locally, and runs the architectural protection probes.
/// It deliberately uses only the SEV/shared-state rendezvous: the reschedule SGI is reserved for the
/// later acceptance proof and must not be left pending by this barrier.
pub fn enter_runtime_protected_regime() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if !super::is_active() || RUNTIME_PROTECTED.load(Ordering::Acquire) {
            return;
        }
        if RUNTIME_STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            super::fatal_silent();
        }

        let state = super::boot_state();
        let serial = super::Serial::new(state.mmio_aliases[0].virtual_region);
        if !kernal_arch_aarch64::irqs_masked() {
            super::fatal(&serial, "KERNAL/ARM64: final regime requires IRQs masked\n");
        }
        super::wait_for_all_high(state, &serial);

        // SAFETY: every expected PE is already executing high with high MMIO handles and IRQs
        // masked; BSP is the single owner of the shared page-table mutation.
        unsafe {
            super::remove_step6_low_aliases(state.root_table, state.layout, &state.physical_mmio)
        }
        .unwrap_or_else(|_| {
            super::fatal(&serial, "KERNAL/ARM64: runtime low-alias removal failed\n")
        });
        super::TRANSITION
            .publish_low_aliases_removed(0)
            .unwrap_or_else(|_| {
                super::fatal(
                    &serial,
                    "KERNAL/ARM64: runtime low-alias publication failed\n",
                )
            });

        super::RETIRE_REQUESTED.store(true, Ordering::Release);
        kernal_arch_aarch64::data_sync_barrier_inner_shareable();
        kernal_arch_aarch64::send_event();

        // SAFETY: BSP has already installed its CpuLocal and the global low-leaf phase is published.
        unsafe { super::kernal_aarch64_transition_wait_hook() };

        let start = kernal_arch_aarch64::read_virtual_counter();
        let frequency = kernal_arch_aarch64::counter_frequency_hz();
        loop {
            match super::TRANSITION.all_protected() {
                Ok(true) => break,
                Ok(false) => {}
                Err(_) => {
                    super::fatal(&serial, "KERNAL/ARM64: runtime protected barrier invalid\n")
                }
            }
            if super::timeout_expired(start, frequency) {
                super::fatal(
                    &serial,
                    "KERNAL/ARM64: timeout entering final TTBR1-only regime\n",
                );
            }
            core::hint::spin_loop();
        }

        super::verify_final_protection(state).unwrap_or_else(|_| {
            super::fatal(&serial, "KERNAL/ARM64: runtime protection proof failed\n")
        });
        serial.write_str("KERNAL/ARM64: all PEs retired TTBR0 before IRQ proof\n");
        serial.write_str("KERNAL/ARM64: W^X + null + guard + high-MMIO runtime proof passed\n");

        // Publish a narrower BSP-only construction phase. Secondary PEs remain blocked on
        // RUNTIME_PROTECTED until all temporary TTBR0/EL0 proofs below have been dismantled.
        RUNTIME_TABLE_POOL_READY.store(true, Ordering::Release);

        #[cfg(feature = "step7-qemu-proof")]
        {
            // SAFETY: this is the BSP's single post-transition owner. Steps 7-14 share this one
            // monotonic cursor so no page-table frame can be allocated twice.
            let mut backend = unsafe { super::claim_runtime_table_pool() }.unwrap_or_else(|_| {
                super::fatal(&serial, "KERNAL/ARM64: runtime table-pool claim failed\n")
            });
            super::step7_qemu::run(&serial, &mut backend);
            #[cfg(feature = "step8-qemu-proof")]
            {
                super::step8_qemu::prepare(&serial, &mut backend);
                super::step8_qemu::run(&serial);
                #[cfg(feature = "step9-qemu-proof")]
                {
                    super::step9_qemu::prepare(&serial, &mut backend);
                    super::step9_qemu::run(&serial);
                    #[cfg(feature = "step10-qemu-proof")]
                    {
                        super::step10_qemu::run(&serial, &mut backend);
                        #[cfg(feature = "step11-qemu-proof")]
                        {
                            super::step11_qemu::run(&serial, &mut backend);
                        }
                    }
                }
            }

            #[cfg(feature = "step14-qemu-proof")]
            {
                // All Step-7 through Step-14 calls above have returned, so no outer `&mut backend`
                // borrow spans the live Step-15 callback. The raw handle remains stable because the
                // RuntimeTablePool value itself stays owned by this suspended BSP stack frame.
                let backend = NonNull::from(&mut backend);
                super::step15_callback::run_if_installed(&serial, backend);
            }
        }

        // PAN is a production EL1 invariant, not a QEMU-only proof side effect. Establish it while
        // the BSP is still IRQ-masked and before the final runtime-release publication.
        if kernal_usercopy_aarch64::enable_pan_default().is_err()
            || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
        {
            super::fatal(&serial, "KERNAL/ARM64: PAN default-on setup failed\n");
        }

        // Keep secondary PEs at their IRQ-masked rendezvous until every BSP-only address-space proof
        // has completed. The secondaries establish the same PAN default before returning below.
        RUNTIME_PROTECTED.store(true, Ordering::Release);
        kernal_arch_aarch64::data_sync_barrier_inner_shareable();
        kernal_arch_aarch64::send_event();
    }
}

/// Secondary-PE rendezvous paired with [`enter_runtime_protected_regime`].
///
/// A secondary reaches this point high, Online and IRQ-masked. It waits for the BSP to publish the
/// low-alias removal, performs its existing PE-local TTBR0 finalization through the installed hook,
/// then waits until the BSP has observed all PEs protected and completed the final permission proof.
/// No interrupt is unmasked and no proof SGI is sent before the final regime is globally ready.
pub fn wait_for_runtime_protected_regime() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if !super::is_active() {
            return;
        }

        // SAFETY: secondary bootstrap installed a static CpuLocal before entering this rendezvous.
        let local = unsafe { kernal_percpu_aarch64::current() };
        let index = local.index().0 as usize;
        let state = super::boot_state();
        if index == 0 || index >= state.expected_pes || index >= super::MAX_PROOF_PES {
            super::fatal_silent();
        }

        let start = kernal_arch_aarch64::read_virtual_counter();
        let frequency = kernal_arch_aarch64::counter_frequency_hz();
        loop {
            if super::RETIRE_REQUESTED.load(Ordering::Acquire) {
                // SAFETY: the BSP publishes RETIRE_REQUESTED only after global low-leaf removal and
                // broadcast invalidation. The hook is idempotent per PE through PE_FINALIZED.
                unsafe { super::kernal_aarch64_transition_wait_hook() };
            }

            if super::PE_FINALIZED[index].load(Ordering::Acquire)
                && RUNTIME_PROTECTED.load(Ordering::Acquire)
            {
                if kernal_usercopy_aarch64::enable_pan_default().is_err()
                    || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
                {
                    super::fatal_silent();
                }
                return;
            }

            if super::timeout_expired(start, frequency) {
                super::fatal_silent();
            }
            core::hint::spin_loop();
        }
    }
}

/// Returns whether the protected bootstrap has completed global low-alias removal, every PE's local
/// TTBR0 retirement and the final architectural permission probes.
pub fn runtime_protected_regime_ready() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        return RUNTIME_PROTECTED.load(Ordering::Acquire);
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_runtime_mmio_resolution_is_identity() {
        let region = MmioRegion {
            base: 0x0800_0000,
            size: 0x1_0000,
        };
        assert_eq!(runtime_mmio_region(region), region);
        assert!(!runtime_protected_regime_ready());
    }

    #[test]
    fn cpu_on_bootstrap_closes_as_soon_as_retirement_starts() {
        assert!(cpu_on_bootstrap_available_for_state(false));
        assert!(!cpu_on_bootstrap_available_for_state(true));
        assert!(cpu_on_bootstrap_available());
    }
}
