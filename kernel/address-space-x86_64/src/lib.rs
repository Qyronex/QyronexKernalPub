// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::arch::asm;

use kernal_memory::{PhysFrame, ReservationSet};
use kernal_page_table::{Backend, Error as PageTableError, Mapper};
use kernal_paging::{MapFlags, PAGE_SIZE};
use kernal_recursive_paging_x86_64::RECURSIVE_PML4_SLOT;
use kernal_vm::{
    AddressSpace, Backing, Error as VmError, USER_MAX_EXCLUSIVE, USER_MIN, VmPerms, Vma,
};

const PML4_ENTRIES: usize = 512;
const FIRST_KERNEL_PML4_SLOT: usize = 256;
const PML4_USER: u64 = 1 << 2;
#[cfg(test)]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Vm(VmError),
    PageTable(PageTableError),
    RootAllocationFailed,
    BackendFailure,
    KernelHalfUserAccessible,
    ReservedFrame,
    UnsupportedPermissions,
    MultiPageMappingUnsupported,
    TlbInvalidationFailed,
    RollbackFailed,
    UnsupportedHostArchitecture,
}

impl From<VmError> for Error {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

impl From<PageTableError> for Error {
    fn from(value: PageTableError) -> Self {
        Self::PageTable(value)
    }
}

/// x86_64 page-table root owned by one user address space.
///
/// Only the root identity is owned here. The page-table backend is a shared kernel service and is
/// borrowed transiently for create/map/unmap/translate operations. This is intentional: multiple
/// address spaces must coexist while sharing one runtime frame allocator and kmap mechanism.
///
/// The lower PML4 half starts empty. Kernel-half entries are shared from the accepted kernel root,
/// except for the recursive slot, which is rebound to this new root. Kernel-half entries fail closed
/// if the source root exposes them through the top-level U/S bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86Root {
    root_phys: u64,
}

impl X86Root {
    pub fn from_kernel_root<B: Backend>(backend: &mut B, kernel_root: u64) -> Result<Self, Error> {
        // Validate the accepted source root with the existing page-table mechanism before copying.
        Mapper::new(backend, kernel_root)?;

        let root_phys = backend
            .allocate_zeroed_table()
            .ok_or(Error::RootAllocationFailed)?;
        Mapper::new(backend, root_phys)?;

        for slot in FIRST_KERNEL_PML4_SLOT..PML4_ENTRIES {
            if slot == RECURSIVE_PML4_SLOT {
                continue;
            }
            let entry = backend
                .read_entry(kernel_root, slot)
                .ok_or(Error::BackendFailure)?;
            if entry & PML4_USER != 0 {
                return Err(Error::KernelHalfUserAccessible);
            }
            if !backend.write_entry(root_phys, slot, entry) {
                return Err(Error::BackendFailure);
            }
        }

        Mapper::new(backend, root_phys)?.install_recursive_slot(RECURSIVE_PML4_SLOT)?;
        Ok(Self { root_phys })
    }

    pub const fn root_phys(self) -> u64 {
        self.root_phys
    }

    pub fn translate<B: Backend>(
        self,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<u64, Error> {
        Ok(Mapper::new(backend, self.root_phys)?.translate(virtual_address)?)
    }

    fn map_user_leaf<B: Backend>(
        self,
        backend: &mut B,
        virtual_address: u64,
        physical_address: u64,
        perms: VmPerms,
    ) -> Result<(), Error> {
        validate_user_leaf(virtual_address, perms)?;
        let flags = x86_flags(perms)?;
        let mut mapper = Mapper::new(backend, self.root_phys)?;
        mapper.map_page(virtual_address, physical_address, flags)?;
        if let Err(error) = invalidate_current_leaf(virtual_address) {
            if mapper.unmap_page(virtual_address).is_err() {
                return Err(Error::RollbackFailed);
            }
            return Err(error);
        }
        Ok(())
    }

    fn unmap_user_leaf<B: Backend>(
        self,
        backend: &mut B,
        virtual_address: u64,
        perms: VmPerms,
    ) -> Result<u64, Error> {
        validate_user_leaf(virtual_address, perms)?;
        let flags = x86_flags(perms)?;
        let mut mapper = Mapper::new(backend, self.root_phys)?;
        let physical = mapper.unmap_page(virtual_address)?;
        if let Err(error) = invalidate_current_leaf(virtual_address) {
            if mapper.map_page(virtual_address, physical, flags).is_err() {
                return Err(Error::RollbackFailed);
            }
            return Err(error);
        }
        Ok(physical)
    }

    /// Activates this root with PCID/no-flush deliberately disabled.
    ///
    /// A normal CR3 write invalidates non-global translations, which is the Step-7 correctness
    /// baseline for preventing stale user translations across address-space switches. PCID can be
    /// introduced later as a measured optimization without changing this API contract.
    ///
    /// # Safety
    /// Caller must execute at CPL0 on freestanding x86_64, ensure this root retains all live kernel
    /// mappings and stack/code mappings, and serialize address-space ownership against the scheduler.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub unsafe fn activate(self) -> Result<(), Error> {
        // SAFETY: caller owns the privileged address-space switch contract documented above.
        unsafe {
            asm!(
                "mov cr3, {root}",
                root = in(reg) self.root_phys,
                options(nostack, preserves_flags)
            )
        };
        Ok(())
    }

    /// Host-build stub. Runtime activation is intentionally unavailable outside freestanding x86_64.
    ///
    /// # Safety
    /// The host stub executes no privileged instruction; it remains unsafe only to preserve the
    /// target API contract and always returns [`Error::UnsupportedHostArchitecture`].
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    pub unsafe fn activate(self) -> Result<(), Error> {
        Err(Error::UnsupportedHostArchitecture)
    }

    #[cfg(test)]
    fn root_entry<B: Backend>(self, backend: &B, slot: usize) -> Option<u64> {
        backend.read_entry(self.root_phys, slot)
    }
}

/// Architecture operations for the shared address-space owner.
///
/// The backend is supplied per operation rather than stored in the address space. This permits many
/// roots to share one synchronized runtime allocator/kmap backend without aliasing `&mut` ownership.
pub trait X86AddressSpaceExt {
    fn map_user_page<B: Backend, const R: usize>(
        &mut self,
        backend: &mut B,
        vma: Vma,
        frame: PhysFrame,
        reserved: &ReservationSet<R>,
    ) -> Result<(), Error>;

    fn unmap_user_page<B: Backend>(
        &mut self,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<PhysFrame, Error>;

    fn translate_user<B: Backend>(
        &self,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<u64, Error>;
}

impl<const N: usize> X86AddressSpaceExt for AddressSpace<X86Root, N> {
    fn map_user_page<B: Backend, const R: usize>(
        &mut self,
        backend: &mut B,
        vma: Vma,
        frame: PhysFrame,
        reserved: &ReservationSet<R>,
    ) -> Result<(), Error> {
        let vma = vma.validate()?;
        if vma.len != PAGE_SIZE {
            return Err(Error::MultiPageMappingUnsupported);
        }
        if reserved.contains(frame) {
            return Err(Error::ReservedFrame);
        }
        x86_flags(vma.perms)?;

        self.reserve(vma)?;
        if let Err(error) =
            self.root()
                .map_user_leaf(backend, vma.start, frame.start_address(), vma.perms)
        {
            if self.release(vma.start, vma.len).is_err() {
                return Err(Error::RollbackFailed);
            }
            return Err(error);
        }
        Ok(())
    }

    fn unmap_user_page<B: Backend>(
        &mut self,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<PhysFrame, Error> {
        let vma = self.find(virtual_address).ok_or(VmError::NotFound)?;
        if vma.start != virtual_address || vma.len != PAGE_SIZE {
            return Err(Error::MultiPageMappingUnsupported);
        }
        self.release(vma.start, vma.len)?;
        match self
            .root()
            .unmap_user_leaf(backend, virtual_address, vma.perms)
        {
            Ok(physical) => PhysFrame::from_start_address(physical)
                .ok_or(Error::PageTable(PageTableError::InvalidTableAddress)),
            Err(error) => {
                if self.reserve(vma).is_err() {
                    return Err(Error::RollbackFailed);
                }
                Err(error)
            }
        }
    }

    fn translate_user<B: Backend>(
        &self,
        backend: &mut B,
        virtual_address: u64,
    ) -> Result<u64, Error> {
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&virtual_address) {
            return Err(Error::Vm(VmError::OutsideUserRange));
        }
        self.root().translate(backend, virtual_address)
    }
}

fn validate_user_leaf(virtual_address: u64, perms: VmPerms) -> Result<(), Error> {
    Vma::new(virtual_address, PAGE_SIZE, perms, Backing::Anonymous)?;
    x86_flags(perms)?;
    Ok(())
}

fn x86_flags(perms: VmPerms) -> Result<MapFlags, Error> {
    if !perms.readable() {
        return Err(Error::UnsupportedPermissions);
    }
    let mut flags = MapFlags::READ.union(MapFlags::USER);
    if perms.writable() {
        flags = flags.union(MapFlags::WRITE);
    }
    if perms.executable() {
        flags = flags.union(MapFlags::EXECUTE);
    }
    Ok(flags)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn invalidate_current_leaf(virtual_address: u64) -> Result<(), Error> {
    // SAFETY: callers validate the address as an aligned canonical user leaf before reaching here.
    unsafe { kernal_tlb_x86_64::invalidate_page(virtual_address) }
        .map_err(|_| Error::TlbInvalidationFailed)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn invalidate_current_leaf(virtual_address: u64) -> Result<(), Error> {
    let _ = virtual_address;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: usize = 64;
    const BASE: u64 = 0x10_0000;
    const KERNEL_MARKER: u64 = 0x20_0000 | 0x3;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
    }

    impl TestBackend {
        fn with_kernel_root() -> Self {
            let mut backend = Self {
                tables: [[0; 512]; TABLES],
                used: 1,
            };
            backend.tables[0][511] = KERNEL_MARKER;
            backend.tables[0][RECURSIVE_PML4_SLOT] = BASE | 0x3;
            backend
        }

        fn with_user_accessible_kernel_root() -> Self {
            let mut backend = Self::with_kernel_root();
            backend.tables[0][511] |= PML4_USER;
            backend
        }

        fn index(phys: u64) -> Option<usize> {
            if phys < BASE || !(phys - BASE).is_multiple_of(PAGE_SIZE) {
                return None;
            }
            let index = ((phys - BASE) / PAGE_SIZE) as usize;
            (index < TABLES).then_some(index)
        }
    }

    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == TABLES {
                return None;
            }
            let index = self.used;
            self.used += 1;
            self.tables[index] = [0; 512];
            Some(BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = Self::index(table_phys).and_then(|i| self.tables.get_mut(i)) else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    fn new_space<const N: usize>(backend: &mut TestBackend) -> AddressSpace<X86Root, N> {
        AddressSpace::new(X86Root::from_kernel_root(backend, BASE).unwrap())
    }

    fn page_vma(virtual_address: u64, perms: VmPerms) -> Vma {
        Vma::new(virtual_address, PAGE_SIZE, perms, Backing::Anonymous).unwrap()
    }

    #[test]
    fn new_root_keeps_kernel_half_and_rebinds_recursive_slot() {
        let mut backend = TestBackend::with_kernel_root();
        let root = X86Root::from_kernel_root(&mut backend, BASE).unwrap();
        assert_eq!(root.root_entry(&backend, 0), Some(0));
        assert_eq!(root.root_entry(&backend, 511), Some(KERNEL_MARKER));
        let recursive = root.root_entry(&backend, RECURSIVE_PML4_SLOT).unwrap();
        assert_eq!(recursive & ADDRESS_MASK, root.root_phys());
        assert_ne!(recursive & ADDRESS_MASK, BASE);
    }

    #[test]
    fn kernel_half_copy_rejects_user_accessible_top_level_entry() {
        let mut backend = TestBackend::with_user_accessible_kernel_root();
        assert_eq!(
            X86Root::from_kernel_root(&mut backend, BASE),
            Err(Error::KernelHalfUserAccessible)
        );
    }

    #[test]
    fn two_roots_share_one_backend_and_map_same_va_to_different_frames() {
        let mut backend = TestBackend::with_kernel_root();
        let mut left = new_space::<4>(&mut backend);
        let mut right = new_space::<4>(&mut backend);
        let reserved = ReservationSet::<4>::new();
        let va = USER_MIN + 0x20_000;
        let left_frame = PhysFrame::from_start_address(0x40_0000).unwrap();
        let right_frame = PhysFrame::from_start_address(0x80_0000).unwrap();

        left.map_user_page(
            &mut backend,
            page_vma(va, VmPerms::READ),
            left_frame,
            &reserved,
        )
        .unwrap();
        right
            .map_user_page(
                &mut backend,
                page_vma(va, VmPerms::READ),
                right_frame,
                &reserved,
            )
            .unwrap();

        assert_ne!(left.root().root_phys(), right.root().root_phys());
        assert_eq!(
            left.translate_user(&mut backend, va).unwrap(),
            left_frame.start_address()
        );
        assert_eq!(
            right.translate_user(&mut backend, va).unwrap(),
            right_frame.start_address()
        );
    }

    #[test]
    fn user_mapping_rejects_null_kernel_half_wx_and_reserved_frames() {
        let mut backend = TestBackend::with_kernel_root();
        let mut space = new_space::<4>(&mut backend);
        let mut reserved = ReservationSet::<4>::new();
        reserved.reserve(0x60_0000, PAGE_SIZE).unwrap();
        let normal = PhysFrame::from_start_address(0x40_0000).unwrap();
        let reserved_frame = PhysFrame::from_start_address(0x60_0000).unwrap();

        assert_eq!(
            space.map_user_page(
                &mut backend,
                Vma {
                    start: 0,
                    len: PAGE_SIZE,
                    perms: VmPerms::READ,
                    backing: Backing::Anonymous,
                },
                normal,
                &reserved,
            ),
            Err(Error::Vm(VmError::NullGuard))
        );
        assert_eq!(
            space.map_user_page(
                &mut backend,
                Vma {
                    start: USER_MAX_EXCLUSIVE,
                    len: PAGE_SIZE,
                    perms: VmPerms::READ,
                    backing: Backing::Anonymous,
                },
                normal,
                &reserved,
            ),
            Err(Error::Vm(VmError::OutsideUserRange))
        );
        assert_eq!(
            space.map_user_page(
                &mut backend,
                Vma {
                    start: USER_MIN,
                    len: PAGE_SIZE,
                    perms: VmPerms::WRITE.union(VmPerms::EXECUTE),
                    backing: Backing::Anonymous,
                },
                normal,
                &reserved,
            ),
            Err(Error::Vm(VmError::WritableExecutable))
        );
        assert_eq!(
            space.map_user_page(
                &mut backend,
                page_vma(USER_MIN, VmPerms::READ),
                reserved_frame,
                &reserved,
            ),
            Err(Error::ReservedFrame)
        );
    }

    #[test]
    fn overlap_and_unmap_are_fail_closed() {
        let mut backend = TestBackend::with_kernel_root();
        let mut space = new_space::<4>(&mut backend);
        let reserved = ReservationSet::<1>::new();
        let va = USER_MIN + 0x40_000;
        let frame = PhysFrame::from_start_address(0x40_0000).unwrap();
        let other = PhysFrame::from_start_address(0x50_0000).unwrap();

        space
            .map_user_page(&mut backend, page_vma(va, VmPerms::READ), frame, &reserved)
            .unwrap();
        assert_eq!(
            space.map_user_page(&mut backend, page_vma(va, VmPerms::READ), other, &reserved,),
            Err(Error::Vm(VmError::Overlap))
        );
        assert_eq!(space.unmap_user_page(&mut backend, va).unwrap(), frame);
        assert_eq!(
            space.translate_user(&mut backend, va),
            Err(Error::PageTable(PageTableError::NotMapped))
        );
    }
}
