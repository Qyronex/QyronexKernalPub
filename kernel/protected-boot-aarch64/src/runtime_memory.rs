// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_paging::PAGE_SIZE;

use crate::mmu::PageRange;

/// Returns the protected QEMU RAM prefix that must never enter the Step-15 frame allocator.
///
/// The range begins at the validated QEMU `virt` RAM base and ends at the linker-owned kernel image
/// boundary. It therefore covers the live DTB window, every kernel section, guarded stacks and the
/// protected boot page-table pool. The value is reservation metadata only; it grants no mapping,
/// dereference or allocator authority.
///
/// `None` is returned before protected boot has published its validated layout and on non-freestanding
/// hosts. The external initrd remains a separate reservation supplied by `ProtectedInitrd`.
pub fn qemu_runtime_reserved_low_range() -> Option<PageRange> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if !crate::is_active() {
            return None;
        }
        let state = crate::BOOT_STATE.get()?;
        return reserved_low_range(true, crate::QEMU_VIRT_RAM_BASE, state.layout.bss.end);
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        None
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn reserved_low_range(active: bool, ram_base: u64, kernel_end: u64) -> Option<PageRange> {
    if !active
        || ram_base == 0
        || ram_base & (PAGE_SIZE - 1) != 0
        || kernel_end & (PAGE_SIZE - 1) != 0
        || kernel_end <= ram_base
    {
        return None;
    }
    Some(PageRange::new(ram_base, kernel_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAM_BASE: u64 = 0x4000_0000;
    const KERNEL_END: u64 = 0x4080_0000;

    #[test]
    fn validated_prefix_covers_dtb_and_complete_linker_kernel() {
        let range = reserved_low_range(true, RAM_BASE, KERNEL_END).unwrap();
        assert_eq!(range, PageRange::new(RAM_BASE, KERNEL_END));
        assert!(range.contains(RAM_BASE));
        assert!(range.contains(0x4020_0000));
        assert!(!range.contains(KERNEL_END));
    }

    #[test]
    fn inactive_or_malformed_layout_never_publishes_allocator_metadata() {
        assert_eq!(reserved_low_range(false, RAM_BASE, KERNEL_END), None);
        assert_eq!(reserved_low_range(true, 0, KERNEL_END), None);
        assert_eq!(reserved_low_range(true, RAM_BASE + 1, KERNEL_END), None);
        assert_eq!(reserved_low_range(true, RAM_BASE, KERNEL_END + 1), None);
        assert_eq!(reserved_low_range(true, RAM_BASE, RAM_BASE), None);
        assert_eq!(
            reserved_low_range(true, RAM_BASE, RAM_BASE - PAGE_SIZE),
            None
        );
    }

    #[test]
    fn host_api_fails_closed_without_freestanding_boot_state() {
        assert_eq!(qemu_runtime_reserved_low_range(), None);
    }
}
