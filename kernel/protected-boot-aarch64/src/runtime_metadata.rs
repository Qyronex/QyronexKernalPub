// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_paging::PAGE_SIZE;

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const ROOT_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

/// Returns the immutable physical root-table address of the active protected TTBR1 hierarchy.
///
/// This is metadata only: it grants no page-table mutation, mapping, allocator or borrow authority.
/// Step-15 uses it solely to bind the existing CPU-local AArch64 KMap controller to the same already
/// active TTBR1 hierarchy whose mutations remain serialized by the canonical RuntimeTablePool owner.
///
/// The root becomes observable in the BSP-only construction phase: every expected PE has retired
/// TTBR0, final W^X/null/guard/high-MMIO checks have passed, and the runtime table-pool cursor may be
/// claimed, but the Step-15 Core callback has not yet returned. Waiting for the later global
/// `runtime_protected_regime_ready()` publication would deadlock the intended KMap construction,
/// because that flag is published only after this callback completes.
///
/// `None` is returned before that construction-safe phase, before the validated BootState is
/// available, on non-freestanding hosts, or if the stored root violates the architectural shape.
pub fn runtime_ttbr1_root() -> Option<u64> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if !crate::runtime::runtime_table_pool_claim_ready() {
            return None;
        }
        let state = crate::BOOT_STATE.get()?;
        return validate_root(true, state.root_table);
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        None
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn validate_root(construction_ready: bool, root: u64) -> Option<u64> {
    if !construction_ready
        || root == 0
        || root & (PAGE_SIZE - 1) != 0
        || root & !ROOT_ADDRESS_MASK != 0
    {
        return None;
    }
    Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_metadata_requires_construction_ready_aligned_48bit_physical_root() {
        assert_eq!(validate_root(true, 0x4020_0000), Some(0x4020_0000));
        assert_eq!(validate_root(false, 0x4020_0000), None);
        assert_eq!(validate_root(true, 0), None);
        assert_eq!(validate_root(true, 0x4020_0001), None);
        assert_eq!(validate_root(true, 1_u64 << 52), None);
    }

    #[test]
    fn host_api_never_invents_freestanding_boot_metadata() {
        assert_eq!(runtime_ttbr1_root(), None);
    }
}
