// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const BOOTINFO_MAGIC: u64 = 0x4b45_524e_414c_4249;
pub const BOOTINFO_ABI_VERSION: u32 = 1;
pub const MEMORY_REGION_ABI_VERSION: u32 = 1;
pub const X86_AP_BOOTSTRAP_PAGE_SIZE: u64 = 4096;
pub const X86_AP_BOOTSTRAP_PAGE_COUNT: u64 = 2;
pub const X86_AP_BOOTSTRAP_SIZE: u64 = X86_AP_BOOTSTRAP_PAGE_SIZE * X86_AP_BOOTSTRAP_PAGE_COUNT;
pub const X86_AP_BOOTSTRAP_LIMIT: u64 = 1024 * 1024;

pub mod memory_kind {
    pub const USABLE: u32 = 1;
    pub const RECLAIMABLE: u32 = 2;
    pub const RESERVED: u32 = 3;
    pub const MMIO: u32 = 4;
    pub const FIRMWARE: u32 = 5;
    pub const ACPI_RECLAIMABLE: u32 = 6;
    pub const ACPI_NVS: u32 = 7;
}

pub mod memory_attr {
    pub const NONE: u64 = 0;
    pub const RUNTIME: u64 = 1 << 0;
    pub const NON_VOLATILE: u64 = 1 << 1;
    pub const WRITE_COMBINE: u64 = 1 << 2;
    pub const UNCACHED: u64 = 1 << 3;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysSlice {
    pub phys_addr: u64,
    pub len: u64,
}
impl PhysSlice {
    pub const EMPTY: Self = Self {
        phys_addr: 0,
        len: 0,
    };
    pub const fn is_empty(self) -> bool {
        self.phys_addr == 0 && self.len == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegionV1 {
    pub start: u64,
    pub len: u64,
    pub kind: u32,
    pub abi_version: u32,
    pub attributes: u64,
}
impl MemoryRegionV1 {
    pub const fn new(start: u64, len: u64, kind: u32, attributes: u64) -> Self {
        Self {
            start,
            len,
            kind,
            abi_version: MEMORY_REGION_ABI_VERSION,
            attributes,
        }
    }
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
    pub const fn is_structurally_valid(self) -> bool {
        self.abi_version == MEMORY_REGION_ABI_VERSION && self.len != 0 && self.end().is_some()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferInfo {
    pub base: u64,
    pub len: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
}
impl FramebufferInfo {
    pub const NONE: Self = Self {
        base: 0,
        len: 0,
        width: 0,
        height: 0,
        stride: 0,
        pixel_format: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInfoV1 {
    // Stable V1 prefix. Append-only fields belong after the original entropy_seed member.
    pub magic: u64,
    pub abi_version: u32,
    pub struct_size: u32,
    pub memory_map: PhysSlice,
    pub memory_region_size: u32,
    pub memory_region_count: u32,
    pub rsdp_phys: u64,
    pub initrd: PhysSlice,
    pub cmdline: PhysSlice,
    pub framebuffer: FramebufferInfo,
    pub entropy_seed: [u8; 64],
    // V1 append-only extension: optional two-page x86 AP bootstrap region below 1 MiB.
    // First page is immutable executable trampoline code, second is RW-NX mailbox/GDT data.
    pub ap_trampoline: PhysSlice,
}

impl BootInfoV1 {
    pub const fn empty() -> Self {
        Self {
            magic: BOOTINFO_MAGIC,
            abi_version: BOOTINFO_ABI_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            memory_map: PhysSlice::EMPTY,
            memory_region_size: core::mem::size_of::<MemoryRegionV1>() as u32,
            memory_region_count: 0,
            rsdp_phys: 0,
            initrd: PhysSlice::EMPTY,
            cmdline: PhysSlice::EMPTY,
            framebuffer: FramebufferInfo::NONE,
            entropy_seed: [0; 64],
            ap_trampoline: PhysSlice::EMPTY,
        }
    }

    pub const fn is_compatible(&self) -> bool {
        self.magic == BOOTINFO_MAGIC
            && self.abi_version == BOOTINFO_ABI_VERSION
            && self.struct_size as usize >= core::mem::size_of::<Self>()
            && self.memory_region_size as usize >= core::mem::size_of::<MemoryRegionV1>()
    }

    pub const fn ap_trampoline_is_valid(&self) -> bool {
        if self.ap_trampoline.is_empty() {
            return true;
        }
        if self.ap_trampoline.len != X86_AP_BOOTSTRAP_SIZE {
            return false;
        }
        if self.ap_trampoline.phys_addr & (X86_AP_BOOTSTRAP_PAGE_SIZE - 1) != 0 {
            return false;
        }
        match self
            .ap_trampoline
            .phys_addr
            .checked_add(self.ap_trampoline.len)
        {
            Some(end) => end <= X86_AP_BOOTSTRAP_LIMIT,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bootinfo_is_compatible() {
        assert!(BootInfoV1::empty().is_compatible());
    }
    #[test]
    fn bad_magic_is_rejected() {
        let mut info = BootInfoV1::empty();
        info.magic ^= 1;
        assert!(!info.is_compatible());
    }
    #[test]
    fn undersized_memory_region_is_rejected() {
        let mut info = BootInfoV1::empty();
        info.memory_region_size = 8;
        assert!(!info.is_compatible());
    }
    #[test]
    fn memory_region_rejects_address_overflow() {
        let region = MemoryRegionV1::new(u64::MAX - 1, 4, memory_kind::USABLE, 0);
        assert!(!region.is_structurally_valid());
    }
    #[test]
    fn optional_ap_bootstrap_is_two_aligned_pages_below_one_megabyte() {
        let mut info = BootInfoV1::empty();
        assert!(info.ap_trampoline_is_valid());
        info.ap_trampoline = PhysSlice {
            phys_addr: 0x8000,
            len: X86_AP_BOOTSTRAP_SIZE,
        };
        assert!(info.ap_trampoline_is_valid());
        info.ap_trampoline = PhysSlice {
            phys_addr: 0x8123,
            len: X86_AP_BOOTSTRAP_SIZE,
        };
        assert!(!info.ap_trampoline_is_valid());
        info.ap_trampoline = PhysSlice {
            phys_addr: 0xff000,
            len: X86_AP_BOOTSTRAP_SIZE,
        };
        assert!(!info.ap_trampoline_is_valid());
    }
}
