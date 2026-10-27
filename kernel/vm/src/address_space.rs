// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{Error, VmPerms, Vma, VmaTable};

/// Architecture-neutral ownership container for one user virtual address space.
///
/// `R` is the architecture-specific root object. It may own a physical page-table root, an
/// allocator/backend and architecture tags such as an ASID/PCID, but those mechanisms stay outside
/// this common policy crate. `AddressSpace` owns the root and the existing VMA policy table so both
/// primary architectures use the same mapping bookkeeping rather than creating parallel VM models.
pub struct AddressSpace<R, const N: usize> {
    root: R,
    vmas: VmaTable<N>,
}

impl<R, const N: usize> AddressSpace<R, N> {
    pub const fn new(root: R) -> Self {
        Self {
            root,
            vmas: VmaTable::new(),
        }
    }

    /// Returns the architecture-specific root without transferring ownership.
    pub const fn root(&self) -> &R {
        &self.root
    }

    /// Gives the architecture mechanism mutable access to its owned root.
    ///
    /// Mapping code must keep hardware page tables and the VMA policy synchronized. This method
    /// deliberately exposes no architecture registers or page-table semantics to the common layer.
    pub const fn root_mut(&mut self) -> &mut R {
        &mut self.root
    }

    pub const fn vmas(&self) -> &VmaTable<N> {
        &self.vmas
    }

    /// Reserves one validated VMA in this address space.
    pub fn reserve(&mut self, vma: Vma) -> Result<(), Error> {
        self.vmas.insert(vma)
    }

    /// Reserves one VMA while compacting compatible adjacent anonymous policy ranges.
    ///
    /// Architecture leaf mappings remain page-granular. This only prevents a long run of identical
    /// anonymous pages from consuming one bounded policy slot per hardware page.
    pub fn reserve_coalescing_anonymous(&mut self, vma: Vma) -> Result<(), Error> {
        self.vmas.insert_coalescing_anonymous(vma)
    }

    /// Removes exactly one VMA after the architecture layer has removed the corresponding mapping.
    pub fn release(&mut self, start: u64, len: u64) -> Result<Vma, Error> {
        self.vmas.remove_exact(start, len)
    }

    /// Removes one subrange from policy, splitting the containing VMA when necessary.
    ///
    /// Architecture code uses this before removing one or more hardware leaves so rollback can
    /// restore the returned exact subrange if page-table mutation fails.
    pub fn release_range(&mut self, start: u64, len: u64) -> Result<Vma, Error> {
        self.vmas.remove_range(start, len)
    }

    /// Changes common permission policy for exactly one VMA.
    pub fn protect(&mut self, start: u64, len: u64, perms: VmPerms) -> Result<(), Error> {
        self.vmas.protect_exact(start, len, perms)
    }

    pub fn find(&self, address: u64) -> Option<Vma> {
        self.vmas.find(address)
    }

    /// Validates a complete candidate range through the shared VMA policy and reports whether it is
    /// currently unreserved. This is a read-only placement query; it does not promise that a later
    /// mapping will succeed once allocator/page-table mutation begins.
    pub fn range_is_free(&self, start: u64, len: u64) -> Result<bool, Error> {
        self.vmas.range_is_free(start, len)
    }

    /// Finds one page-aligned top-down gap using the same VMA table that owns mapping policy.
    /// Address-selection policy may supply a ceiling, while this common owner remains the sole
    /// source of overlap/null/user-range truth.
    pub fn find_gap_top_down(&self, len: u64, ceiling: u64) -> Result<u64, Error> {
        self.vmas.find_gap_top_down(len, ceiling)
    }

    /// Consumes the address space and returns its architecture-specific root owner.
    pub fn into_root(self) -> R {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Backing, PAGE_SIZE, USER_MAX_EXCLUSIVE, USER_MIN, VmPerms};

    #[derive(Debug, Eq, PartialEq)]
    struct Root(u64);

    fn mapping(start: u64) -> Vma {
        Vma::new(
            start,
            PAGE_SIZE,
            VmPerms::READ.union(VmPerms::WRITE),
            Backing::Anonymous,
        )
        .unwrap()
    }

    #[test]
    fn address_space_owns_root_and_policy_table() {
        let mut space = AddressSpace::<Root, 4>::new(Root(0x1000));
        space.reserve(mapping(USER_MIN)).unwrap();

        assert_eq!(space.root(), &Root(0x1000));
        assert_eq!(space.vmas().len(), 1);
        assert!(space.find(USER_MIN).is_some());
        assert_eq!(space.into_root(), Root(0x1000));
    }

    #[test]
    fn independent_spaces_can_reserve_the_same_user_va() {
        let mut left = AddressSpace::<Root, 2>::new(Root(0x1000));
        let mut right = AddressSpace::<Root, 2>::new(Root(0x2000));
        let vma = mapping(USER_MIN + PAGE_SIZE);

        left.reserve(vma).unwrap();
        right.reserve(vma).unwrap();

        assert_ne!(left.root(), right.root());
        assert_eq!(left.find(vma.start), Some(vma));
        assert_eq!(right.find(vma.start), Some(vma));
    }

    #[test]
    fn address_space_reuses_vma_range_overlap_and_wx_policy() {
        let mut space = AddressSpace::<Root, 2>::new(Root(0x1000));
        let vma = mapping(USER_MIN + 2 * PAGE_SIZE);
        space.reserve(vma).unwrap();

        assert_eq!(space.reserve(vma), Err(Error::Overlap));
        assert_eq!(
            Vma::new(
                USER_MAX_EXCLUSIVE,
                PAGE_SIZE,
                VmPerms::READ,
                Backing::Anonymous
            ),
            Err(Error::OutsideUserRange)
        );
        assert_eq!(
            space.protect(vma.start, vma.len, VmPerms::WRITE.union(VmPerms::EXECUTE)),
            Err(Error::WritableExecutable)
        );
    }

    #[test]
    fn anonymous_page_policy_coalesces_and_can_be_split_again() {
        let mut space = AddressSpace::<Root, 2>::new(Root(0x1000));
        let start = USER_MIN + 0x20_000;
        space.reserve_coalescing_anonymous(mapping(start)).unwrap();
        space
            .reserve_coalescing_anonymous(mapping(start + PAGE_SIZE))
            .unwrap();
        space
            .reserve_coalescing_anonymous(mapping(start + 2 * PAGE_SIZE))
            .unwrap();

        assert_eq!(space.vmas().len(), 1);
        assert_eq!(space.find(start + PAGE_SIZE).unwrap().len, 3 * PAGE_SIZE);

        let removed = space.release_range(start + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(removed, mapping(start + PAGE_SIZE));
        assert_eq!(space.vmas().len(), 2);
        assert!(space.find(start).is_some());
        assert!(space.find(start + PAGE_SIZE).is_none());
        assert!(space.find(start + 2 * PAGE_SIZE).is_some());
    }

    #[test]
    fn address_space_exposes_read_only_placement_queries_without_leaking_table_mutation() {
        let mut space = AddressSpace::<Root, 4>::new(Root(0x1000));
        space.reserve(mapping(0x70_000)).unwrap();

        assert_eq!(space.range_is_free(0x60_000, PAGE_SIZE), Ok(true));
        assert_eq!(space.range_is_free(0x70_000, PAGE_SIZE), Ok(false));
        assert_eq!(space.find_gap_top_down(PAGE_SIZE, 0x80_000), Ok(0x7f_000));
        assert!(space.find(0x70_000).is_some());
    }
}
