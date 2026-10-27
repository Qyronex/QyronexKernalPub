// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use kernal_bootstrap_memory::BootstrapFrameAllocator;
use kernal_frame_allocator::{ExtentAllocator, FrameRange};
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_kmap_x86_64::KmapController;
use kernal_page_table::Backend;
use kernal_paging::PAGE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidRoot,
}

/// Minimal physical page source required by runtime page-table growth.
/// Implementations may support release so an initialization failure does not leak metadata RAM.
pub trait FrameSource {
    fn allocate_page(&mut self) -> Option<u64>;
    fn release_page(&mut self, _physical: u64) -> bool {
        false
    }
}

impl FrameSource for BootstrapFrameAllocator<'_> {
    fn allocate_page(&mut self) -> Option<u64> {
        self.allocate().map(|frame| frame.start_address())
    }
}

impl<const N: usize> FrameSource for ExtentAllocator<N> {
    fn allocate_page(&mut self) -> Option<u64> {
        ExtentAllocator::allocate_page(self).ok()
    }

    fn release_page(&mut self, physical: u64) -> bool {
        let Ok(range) = FrameRange::new(physical, 1) else {
            return false;
        };
        self.free(range).is_ok()
    }
}

pub struct RuntimePageTableBackend<'a, F: FrameSource> {
    frames: &'a mut F,
    kmap: &'a KmapController,
}

impl<'a, F: FrameSource> RuntimePageTableBackend<'a, F> {
    pub fn new(frames: &'a mut F, kmap: &'a KmapController) -> Self {
        Self { frames, kmap }
    }

    pub fn current_root() -> Result<u64, Error> {
        let value: u64;
        // SAFETY: this crate is used only in the CPL0 x86_64 kernel after CR3 handoff.
        unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags)) };
        let root = value & 0x000f_ffff_ffff_f000;
        if root == 0 || root & (PAGE_SIZE - 1) != 0 {
            Err(Error::InvalidRoot)
        } else {
            Ok(root)
        }
    }
}

impl<F: FrameSource> Backend for RuntimePageTableBackend<'_, F> {
    fn allocate_zeroed_table(&mut self) -> Option<u64> {
        let physical = self.frames.allocate_page()?;
        if physical & (PAGE_SIZE - 1) != 0 {
            let _ = self.frames.release_page(physical);
            return None;
        }
        let mapping = match self.kmap.map(MappingRequest {
            physical_address: physical,
            writable: true,
            cache: CachePolicy::WriteBack,
        }) {
            Ok(mapping) => mapping,
            Err(_) => {
                let _ = self.frames.release_page(physical);
                return None;
            }
        };
        // SAFETY: freshly allocated frame is exclusively owned and mapped writable for one page.
        let Some(base) = (unsafe { mapping.as_mut_ptr::<u8>() }) else {
            drop(mapping);
            let _ = self.frames.release_page(physical);
            return None;
        };
        // SAFETY: the live mapping spans exactly PAGE_SIZE bytes.
        unsafe { write_bytes(base, 0, PAGE_SIZE as usize) };
        Some(physical)
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
        if index >= 512 || table_phys & (PAGE_SIZE - 1) != 0 {
            return None;
        }
        let mapping = self
            .kmap
            .map(MappingRequest {
                physical_address: table_phys,
                writable: false,
                cache: CachePolicy::WriteBack,
            })
            .ok()?;
        // SAFETY: page-table entry index is bounded to the mapped 4 KiB frame.
        let pointer = unsafe { mapping.as_ptr::<u64>().add(index) };
        // SAFETY: page tables are naturally u64-aligned and mapping is live for this read.
        Some(unsafe { read_volatile(pointer) })
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
        if index >= 512 || table_phys & (PAGE_SIZE - 1) != 0 {
            return false;
        }
        let Ok(mapping) = self.kmap.map(MappingRequest {
            physical_address: table_phys,
            writable: true,
            cache: CachePolicy::WriteBack,
        }) else {
            return false;
        };
        // SAFETY: writable mapping and bounded index identify one PTE within the page.
        let Some(base) = (unsafe { mapping.as_mut_ptr::<u64>() }) else {
            return false;
        };
        // SAFETY: index < 512 keeps the volatile write inside the page-table frame.
        unsafe { write_volatile(base.add(index), value) };
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr3_address_mask_covers_architectural_page_frame_bits() {
        assert_eq!(0x000f_ffff_ffff_f000u64 & 0xfff, 0);
        assert_eq!(PAGE_SIZE, 4096);
    }

    #[test]
    fn extent_allocator_implements_reclaimable_frame_source() {
        let mut allocator = ExtentAllocator::<4>::new();
        allocator
            .free(FrameRange::new(0x20_0000, 2).unwrap())
            .unwrap();
        let page = FrameSource::allocate_page(&mut allocator).unwrap();
        assert_eq!(page, 0x20_0000);
        assert!(FrameSource::release_page(&mut allocator, page));
        assert_eq!(allocator.free_pages(), 2);
    }
}
