// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::ptr::{copy_nonoverlapping, read_volatile, write_volatile};
use kernal_kmap::{CachePolicy, KmapLease, KmapWindow, MappingRequest};
use kernal_paging::{PAGE_SIZE, PageTableEntry};
use kernal_physical_io::{Error as PhysicalIoError, PhysicalReader};
use kernal_recursive_paging_x86_64::{RECURSIVE_PML4_SLOT, pte_virtual};

pub const KMAP_REGION_BASE: u64 = 0xffff_ff80_0100_0000;
pub const KMAP_CPU_STRIDE: u64 = 2 * 1024 * 1024;
pub const KMAP_SLOTS_PER_CPU: usize = 64;
pub const MAX_CPU_WINDOWS: usize = 256;

const PRESENT: u64 = 1 << 0;
const PAGE_WRITE_THROUGH: u64 = 1 << 3;
const PAGE_CACHE_DISABLE: u64 = 1 << 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuIndexOutOfRange,
    AddressOverflow,
    Window(kernal_kmap::Error),
    Recursive(kernal_recursive_paging_x86_64::Error),
    Paging(kernal_paging::Error),
    SlotAlreadyMapped,
    WriteCombiningUnavailable,
}

impl From<kernal_kmap::Error> for Error {
    fn from(value: kernal_kmap::Error) -> Self {
        Self::Window(value)
    }
}

impl From<kernal_recursive_paging_x86_64::Error> for Error {
    fn from(value: kernal_recursive_paging_x86_64::Error) -> Self {
        Self::Recursive(value)
    }
}

impl From<kernal_paging::Error> for Error {
    fn from(value: kernal_paging::Error) -> Self {
        Self::Paging(value)
    }
}

pub fn window_base(cpu_index: usize) -> Result<u64, Error> {
    if cpu_index >= MAX_CPU_WINDOWS {
        return Err(Error::CpuIndexOutOfRange);
    }
    let offset = (cpu_index as u64)
        .checked_mul(KMAP_CPU_STRIDE)
        .ok_or(Error::AddressOverflow)?;
    KMAP_REGION_BASE
        .checked_add(offset)
        .ok_or(Error::AddressOverflow)
}

/// A CPU-local temporary physical mapping controller.
///
/// The loader/kernel must pre-create the intermediate page-table path for this CPU's complete
/// 2 MiB window and install `RECURSIVE_PML4_SLOT` before constructing this object.
pub struct KmapController {
    window: KmapWindow,
}

impl KmapController {
    /// # Safety
    /// The active CR3 must contain the recursive PML4 slot and an allocated PT for this CPU's
    /// kmap window. This controller must only be used on `cpu_index` and must not migrate CPUs.
    pub unsafe fn assume_prepared(cpu_index: usize) -> Result<Self, Error> {
        let base = window_base(cpu_index)?;
        Ok(Self {
            window: KmapWindow::new(base, KMAP_SLOTS_PER_CPU)?,
        })
    }

    pub const fn base(&self) -> u64 {
        self.window.base()
    }

    pub fn map(&self, request: MappingRequest) -> Result<ActiveMapping<'_>, Error> {
        let lease = self.window.claim(request)?;
        let virtual_address = lease.virtual_address();
        let pte_address = pte_virtual(RECURSIVE_PML4_SLOT, virtual_address)?;

        // SAFETY: construction contract guarantees that the recursive PT page is present. The
        // derived address points to the exact PTE associated with this CPU-local kmap slot.
        let existing = unsafe { read_volatile(pte_address as *const u64) };
        if existing & PRESENT != 0 {
            return Err(Error::SlotAlreadyMapped);
        }

        let mut entry =
            PageTableEntry::leaf(request.physical_address, request.page_flags())?.bits();
        match request.cache {
            CachePolicy::WriteBack => {}
            // Architectural reset PAT maps PCD=1,PWT=1 (index 3) to UC.
            CachePolicy::Uncached => entry |= PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH,
            CachePolicy::WriteCombining => return Err(Error::WriteCombiningUnavailable),
        }

        // SAFETY: this lease owns the absent leaf slot exclusively; PageTableEntry::leaf keeps
        // the temporary alias supervisor-only and NX.
        unsafe { write_volatile(pte_address as *mut u64, entry) };
        invalidate_page(virtual_address);
        Ok(ActiveMapping { lease, pte_address })
    }

    pub fn occupied_slots(&self) -> u32 {
        self.window.occupied_slots()
    }
}

impl PhysicalReader for KmapController {
    fn read_exact(
        &self,
        physical_address: u64,
        destination: &mut [u8],
    ) -> Result<(), PhysicalIoError> {
        let mut copied = 0usize;
        while copied < destination.len() {
            let current = physical_address
                .checked_add(copied as u64)
                .ok_or(PhysicalIoError::AddressOverflow)?;
            let frame = current & !(PAGE_SIZE - 1);
            let offset = (current - frame) as usize;
            let count = core::cmp::min(PAGE_SIZE as usize - offset, destination.len() - copied);
            let mapping = self
                .map(MappingRequest {
                    physical_address: frame,
                    writable: false,
                    cache: CachePolicy::WriteBack,
                })
                .map_err(|_| PhysicalIoError::Backend)?;
            // SAFETY: lease maps exactly one frame and offset/count stay within that page.
            unsafe {
                copy_nonoverlapping(
                    mapping.as_ptr::<u8>().add(offset),
                    destination.as_mut_ptr().add(copied),
                    count,
                );
            }
            copied += count;
        }
        Ok(())
    }
}

pub struct ActiveMapping<'a> {
    lease: KmapLease<'a>,
    pte_address: u64,
}

impl ActiveMapping<'_> {
    pub const fn virtual_address(&self) -> u64 {
        self.lease.virtual_address()
    }

    pub const fn physical_address(&self) -> u64 {
        self.lease.request().physical_address
    }

    pub const fn writable(&self) -> bool {
        self.lease.request().writable
    }

    pub const fn cache_policy(&self) -> CachePolicy {
        self.lease.request().cache
    }

    /// # Safety
    /// Caller must ensure `T` is valid for the mapped physical object, including alignment,
    /// provenance and lifetime. The mapping itself does not establish typed-memory validity.
    pub unsafe fn as_ptr<T>(&self) -> *const T {
        self.virtual_address() as *const T
    }

    /// # Safety
    /// In addition to `as_ptr` requirements, the lease must have been requested writable and the
    /// caller must ensure aliasing rules for `T` are respected.
    pub unsafe fn as_mut_ptr<T>(&self) -> Option<*mut T> {
        if self.writable() {
            Some(self.virtual_address() as *mut T)
        } else {
            None
        }
    }
}

impl Drop for ActiveMapping<'_> {
    fn drop(&mut self) {
        // SAFETY: ActiveMapping exclusively owns this kmap leaf for its entire lifetime.
        unsafe { write_volatile(self.pte_address as *mut u64, 0) };
        invalidate_page(self.lease.virtual_address());
        // KmapLease::drop releases the software slot after the hardware PTE is gone.
    }
}

fn invalidate_page(virtual_address: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: INVLPG is valid at CPL0 for a canonical address and only invalidates local TLB.
        unsafe { asm!("invlpg [{}]", in(reg) virtual_address, options(nostack, preserves_flags)) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // The x86 kmap hardware path is never executed on a foreign host; retaining the parameter
        // keeps the shared source shape without emitting an unused-variable warning under -D warnings.
        let _ = virtual_address;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_cpu_gets_distinct_two_megabyte_window() {
        assert_eq!(window_base(0).unwrap(), KMAP_REGION_BASE);
        assert_eq!(window_base(1).unwrap(), KMAP_REGION_BASE + KMAP_CPU_STRIDE);
        assert_eq!(window_base(MAX_CPU_WINDOWS), Err(Error::CpuIndexOutOfRange));
        assert!((KMAP_SLOTS_PER_CPU as u64) * PAGE_SIZE <= KMAP_CPU_STRIDE);
    }

    #[test]
    fn windows_are_two_megabyte_aligned_for_one_pt_each() {
        for cpu in [0usize, 1, 63, 255] {
            assert_eq!(window_base(cpu).unwrap() & (KMAP_CPU_STRIDE - 1), 0);
        }
    }

    #[test]
    fn recursive_pte_address_exists_for_bsp_window() {
        let address = pte_virtual(RECURSIVE_PML4_SLOT, window_base(0).unwrap()).unwrap();
        assert_eq!(address & 7, 0);
        assert_eq!(address >> 48, 0xffff);
    }
}
