// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod address_space;
pub use address_space::AddressSpace;

pub const PAGE_SIZE: u64 = 4096;
pub const USER_MIN: u64 = 0x0000_0000_0001_0000;
pub const USER_MAX_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmPerms(u8);

impl VmPerms {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const EXECUTE: Self = Self(4);
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn readable(self) -> bool {
        self.0 & Self::READ.0 != 0
    }
    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }
    pub const fn executable(self) -> bool {
        self.0 & Self::EXECUTE.0 != 0
    }
    pub const fn validate(self) -> Result<Self, Error> {
        if self.writable() && self.executable() {
            Err(Error::WritableExecutable)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backing {
    Anonymous,
    SharedMemory(u64),
    File { object: u64, offset: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vma {
    pub start: u64,
    pub len: u64,
    pub perms: VmPerms,
    pub backing: Backing,
}

impl Vma {
    pub fn new(start: u64, len: u64, perms: VmPerms, backing: Backing) -> Result<Self, Error> {
        Self {
            start,
            len,
            perms,
            backing,
        }
        .validate()
    }

    /// Revalidates the complete VMA even when a kernel caller constructed it as a struct literal.
    /// This keeps VMA-table insertion fail-closed rather than relying on callers to use `new()`.
    pub fn validate(self) -> Result<Self, Error> {
        self.perms.validate()?;
        if self.len == 0 || self.start & (PAGE_SIZE - 1) != 0 || self.len & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedOrEmpty);
        }
        if self.start < USER_MIN {
            return Err(Error::NullGuard);
        }
        let end = self.start.checked_add(self.len).ok_or(Error::Overflow)?;
        if end > USER_MAX_EXCLUSIVE {
            return Err(Error::OutsideUserRange);
        }
        if let Backing::File { offset, .. } = self.backing
            && offset & (PAGE_SIZE - 1) != 0
        {
            return Err(Error::UnalignedFileOffset);
        }
        Ok(self)
    }

    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    UnalignedOrEmpty,
    UnalignedFileOffset,
    NullGuard,
    OutsideUserRange,
    WritableExecutable,
    Overflow,
    Overlap,
    NotFound,
    GapUnavailable,
}

#[derive(Clone, Copy)]
struct Slot {
    vma: Vma,
}
impl Slot {
    const EMPTY: Self = Self {
        vma: Vma {
            start: USER_MIN,
            len: PAGE_SIZE,
            perms: VmPerms::NONE,
            backing: Backing::Anonymous,
        },
    };
}

/// Fixed-capacity sorted VMA policy table. Page-table mutation is intentionally separate so
/// a syscall can validate the full operation before changing hardware mappings.
pub struct VmaTable<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> Default for VmaTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> VmaTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns one copied VMA in canonical sorted-table order without exposing storage authority.
    ///
    /// This bounded observation is intended for cross-owner operations such as Linux `fork`, where
    /// the caller must reproduce an exact parent mapping policy using the existing mapping owners.
    /// Out-of-range indices return `None`; no allocation, mutation or internal slot reference escapes.
    pub fn get(&self, index: usize) -> Option<Vma> {
        (index < self.len).then(|| self.slots[index].vma)
    }

    pub fn insert(&mut self, vma: Vma) -> Result<(), Error> {
        let vma = vma.validate()?;
        let end = vma.end().ok_or(Error::Overflow)?;
        if self.len == N {
            return Err(Error::Capacity);
        }
        let mut pos = 0;
        while pos < self.len && self.slots[pos].vma.start < vma.start {
            pos += 1;
        }
        if pos > 0 {
            let previous = self.slots[pos - 1].vma;
            if previous.end().ok_or(Error::Overflow)? > vma.start {
                return Err(Error::Overlap);
            }
        }
        if pos < self.len && end > self.slots[pos].vma.start {
            return Err(Error::Overlap);
        }
        self.insert_at(pos, vma)
    }

    /// Inserts a VMA while compacting adjacent anonymous regions with identical permissions.
    ///
    /// Physical pages remain independently owned by the architecture page tables; this operation
    /// only compresses common policy metadata. File and shared-memory VMAs are deliberately not
    /// merged because their offset/alias contracts are not represented strongly enough here.
    pub fn insert_coalescing_anonymous(&mut self, vma: Vma) -> Result<(), Error> {
        let vma = vma.validate()?;
        let end = vma.end().ok_or(Error::Overflow)?;
        let mut pos = 0;
        while pos < self.len && self.slots[pos].vma.start < vma.start {
            pos += 1;
        }

        if pos > 0 {
            let previous = self.slots[pos - 1].vma;
            if previous.end().ok_or(Error::Overflow)? > vma.start {
                return Err(Error::Overlap);
            }
        }
        if pos < self.len && end > self.slots[pos].vma.start {
            return Err(Error::Overlap);
        }

        let merge_left = pos > 0 && can_merge_anonymous(self.slots[pos - 1].vma, vma)?;
        let merge_right = pos < self.len && can_merge_anonymous(vma, self.slots[pos].vma)?;

        match (merge_left, merge_right) {
            (true, true) => {
                let left = self.slots[pos - 1].vma;
                let right = self.slots[pos].vma;
                let len = left
                    .len
                    .checked_add(vma.len)
                    .and_then(|len| len.checked_add(right.len))
                    .ok_or(Error::Overflow)?;
                self.slots[pos - 1].vma =
                    Vma::new(left.start, len, left.perms, Backing::Anonymous)?;
                self.remove_slot(pos);
                Ok(())
            }
            (true, false) => {
                let left = self.slots[pos - 1].vma;
                let len = left.len.checked_add(vma.len).ok_or(Error::Overflow)?;
                self.slots[pos - 1].vma =
                    Vma::new(left.start, len, left.perms, Backing::Anonymous)?;
                Ok(())
            }
            (false, true) => {
                let right = self.slots[pos].vma;
                let len = vma.len.checked_add(right.len).ok_or(Error::Overflow)?;
                self.slots[pos].vma = Vma::new(vma.start, len, vma.perms, Backing::Anonymous)?;
                Ok(())
            }
            (false, false) => self.insert_at(pos, vma),
        }
    }

    pub fn remove_exact(&mut self, start: u64, len: u64) -> Result<Vma, Error> {
        let index = self.slots[..self.len]
            .iter()
            .position(|slot| slot.vma.start == start && slot.vma.len == len)
            .ok_or(Error::NotFound)?;
        let old = self.slots[index].vma;
        self.remove_slot(index);
        Ok(old)
    }

    /// Removes a validated subrange from one existing VMA and preserves the remaining policy.
    ///
    /// Removing an interior range may split one VMA into two and therefore needs one spare metadata
    /// slot. The operation checks capacity before mutation so a failure leaves the table unchanged.
    pub fn remove_range(&mut self, start: u64, len: u64) -> Result<Vma, Error> {
        let candidate = Vma::new(start, len, VmPerms::READ, Backing::Anonymous)?;
        let end = candidate.end().ok_or(Error::Overflow)?;
        let index = self.slots[..self.len]
            .iter()
            .position(|slot| {
                let vma = slot.vma;
                vma.start <= start && vma.end().is_some_and(|vma_end| end <= vma_end)
            })
            .ok_or(Error::NotFound)?;
        let old = self.slots[index].vma;
        let old_end = old.end().ok_or(Error::Overflow)?;
        let left_len = start - old.start;
        let right_len = old_end - end;

        if left_len != 0 && right_len != 0 && self.len == N {
            return Err(Error::Capacity);
        }

        let removed_backing = backing_at_delta(old.backing, start - old.start)?;
        let removed = Vma::new(start, len, old.perms, removed_backing)?;

        match (left_len != 0, right_len != 0) {
            (false, false) => self.remove_slot(index),
            (true, false) => {
                self.slots[index].vma = Vma::new(old.start, left_len, old.perms, old.backing)?;
            }
            (false, true) => {
                let right_backing = backing_at_delta(old.backing, end - old.start)?;
                self.slots[index].vma = Vma::new(end, right_len, old.perms, right_backing)?;
            }
            (true, true) => {
                let right_backing = backing_at_delta(old.backing, end - old.start)?;
                let left = Vma::new(old.start, left_len, old.perms, old.backing)?;
                let right = Vma::new(end, right_len, old.perms, right_backing)?;
                self.slots[index].vma = left;
                let mut i = self.len;
                while i > index + 1 {
                    self.slots[i] = self.slots[i - 1];
                    i -= 1;
                }
                self.slots[index + 1] = Slot { vma: right };
                self.len += 1;
            }
        }
        Ok(removed)
    }

    pub fn protect_exact(&mut self, start: u64, len: u64, perms: VmPerms) -> Result<(), Error> {
        perms.validate()?;
        let slot = self.slots[..self.len]
            .iter_mut()
            .find(|slot| slot.vma.start == start && slot.vma.len == len)
            .ok_or(Error::NotFound)?;
        slot.vma.perms = perms;
        Ok(())
    }

    pub fn find(&self, address: u64) -> Option<Vma> {
        self.slots[..self.len]
            .iter()
            .map(|slot| slot.vma)
            .find(|vma| {
                vma.end()
                    .is_some_and(|end| (vma.start..end).contains(&address))
            })
    }

    /// Validates a complete candidate user range and reports whether it is disjoint from every
    /// currently reserved VMA without mutating policy state.
    ///
    /// The validation deliberately reuses [`Vma::new`] so callers cannot make a fixed-address mmap
    /// or brk placement decision with weaker alignment, null-guard, overflow or user-range rules
    /// than insertion itself will enforce later.
    pub fn range_is_free(&self, start: u64, len: u64) -> Result<bool, Error> {
        let candidate = Vma::new(start, len, VmPerms::READ, Backing::Anonymous)?;
        let end = candidate.end().ok_or(Error::Overflow)?;
        for slot in &self.slots[..self.len] {
            let existing = slot.vma;
            let existing_end = existing.end().ok_or(Error::Overflow)?;
            if existing.start < end && existing_end > start {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Finds a page-aligned gap from high to low. `ceiling` permits ASLR policy to choose a
    /// randomized search ceiling without putting randomness inside the VMA mechanism.
    pub fn find_gap_top_down(&self, len: u64, ceiling: u64) -> Result<u64, Error> {
        if len == 0 || len & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedOrEmpty);
        }
        let mut high = align_down(core::cmp::min(ceiling, USER_MAX_EXCLUSIVE), PAGE_SIZE);
        if high < USER_MIN || high.checked_sub(len).is_none() {
            return Err(Error::GapUnavailable);
        }
        for slot in self.slots[..self.len].iter().rev() {
            let vma = slot.vma;
            if vma.start >= high {
                continue;
            }
            if high
                .checked_sub(len)
                .is_some_and(|start| start >= vma.end().unwrap_or(u64::MAX))
            {
                return Ok(high - len);
            }
            high = vma.start;
            if high < USER_MIN || high.checked_sub(len).is_none() {
                return Err(Error::GapUnavailable);
            }
        }
        let start = high - len;
        if start >= USER_MIN {
            Ok(start)
        } else {
            Err(Error::GapUnavailable)
        }
    }

    fn insert_at(&mut self, pos: usize, vma: Vma) -> Result<(), Error> {
        if self.len == N {
            return Err(Error::Capacity);
        }
        let mut i = self.len;
        while i > pos {
            self.slots[i] = self.slots[i - 1];
            i -= 1;
        }
        self.slots[pos] = Slot { vma };
        self.len += 1;
        Ok(())
    }

    fn remove_slot(&mut self, index: usize) {
        let mut i = index;
        while i + 1 < self.len {
            self.slots[i] = self.slots[i + 1];
            i += 1;
        }
        self.len -= 1;
        self.slots[self.len] = Slot::EMPTY;
    }
}

fn can_merge_anonymous(left: Vma, right: Vma) -> Result<bool, Error> {
    Ok(matches!(left.backing, Backing::Anonymous)
        && matches!(right.backing, Backing::Anonymous)
        && left.perms == right.perms
        && left.end().ok_or(Error::Overflow)? == right.start)
}

fn backing_at_delta(backing: Backing, delta: u64) -> Result<Backing, Error> {
    match backing {
        Backing::File { object, offset } => Ok(Backing::File {
            object,
            offset: offset.checked_add(delta).ok_or(Error::Overflow)?,
        }),
        other => Ok(other),
    }
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rw(start: u64, len: u64) -> Vma {
        Vma::new(
            start,
            len,
            VmPerms::READ.union(VmPerms::WRITE),
            Backing::Anonymous,
        )
        .unwrap()
    }

    #[test]
    fn null_page_and_wx_are_rejected() {
        assert_eq!(
            Vma::new(0, PAGE_SIZE, VmPerms::READ, Backing::Anonymous),
            Err(Error::NullGuard)
        );
        assert_eq!(
            Vma::new(
                USER_MIN,
                PAGE_SIZE,
                VmPerms::WRITE.union(VmPerms::EXECUTE),
                Backing::Anonymous
            ),
            Err(Error::WritableExecutable)
        );
    }

    #[test]
    fn overlapping_vmas_are_rejected() {
        let mut table = VmaTable::<4>::new();
        table.insert(rw(0x20_000, 0x4000)).unwrap();
        assert_eq!(table.insert(rw(0x22_000, 0x4000)), Err(Error::Overlap));
    }

    #[test]
    fn insertion_revalidates_struct_literals() {
        let mut table = VmaTable::<2>::new();
        let forged = Vma {
            start: USER_MAX_EXCLUSIVE,
            len: PAGE_SIZE,
            perms: VmPerms::READ,
            backing: Backing::Anonymous,
        };
        assert_eq!(table.insert(forged), Err(Error::OutsideUserRange));
        assert!(table.is_empty());
    }

    #[test]
    fn indexed_observation_is_sorted_bounded_and_copied() {
        let mut table = VmaTable::<4>::new();
        let high = rw(0x50_000, PAGE_SIZE);
        let low = rw(0x20_000, 2 * PAGE_SIZE);
        table.insert(high).unwrap();
        table.insert(low).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.get(0), Some(low));
        assert_eq!(table.get(1), Some(high));
        assert_eq!(table.get(2), None);
        assert_eq!(table.get(usize::MAX), None);

        let observed = table.get(0).unwrap();
        assert_eq!(observed, low);
        assert_eq!(table.find(low.start), Some(low));
    }

    #[test]
    fn anonymous_page_insertions_coalesce_without_consuming_capacity() {
        let mut table = VmaTable::<1>::new();
        let start = 0x40_000;
        table
            .insert_coalescing_anonymous(rw(start, PAGE_SIZE))
            .unwrap();
        table
            .insert_coalescing_anonymous(rw(start + PAGE_SIZE, PAGE_SIZE))
            .unwrap();
        table
            .insert_coalescing_anonymous(rw(start + 2 * PAGE_SIZE, PAGE_SIZE))
            .unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.find(start + PAGE_SIZE).unwrap().start, start);
        assert_eq!(table.find(start + PAGE_SIZE).unwrap().len, 3 * PAGE_SIZE);
    }

    #[test]
    fn range_removal_splits_and_preserves_file_offsets() {
        let mut table = VmaTable::<3>::new();
        let start = 0x80_000;
        table
            .insert(
                Vma::new(
                    start,
                    3 * PAGE_SIZE,
                    VmPerms::READ,
                    Backing::File {
                        object: 7,
                        offset: 0x20_000,
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let removed = table.remove_range(start + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            removed.backing,
            Backing::File {
                object: 7,
                offset: 0x21_000
            }
        );
        assert_eq!(table.len(), 2);
        assert_eq!(table.find(start).unwrap().len, PAGE_SIZE);
        assert_eq!(
            table.find(start + 2 * PAGE_SIZE).unwrap().backing,
            Backing::File {
                object: 7,
                offset: 0x22_000
            }
        );
    }

    #[test]
    fn interior_range_removal_fails_without_spare_slot_and_keeps_state() {
        let mut table = VmaTable::<1>::new();
        let start = 0xa0_000;
        table.insert(rw(start, 3 * PAGE_SIZE)).unwrap();
        assert_eq!(
            table.remove_range(start + PAGE_SIZE, PAGE_SIZE),
            Err(Error::Capacity)
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.find(start + PAGE_SIZE).unwrap().len, 3 * PAGE_SIZE);
    }

    #[test]
    fn exact_protection_change_preserves_wx_policy() {
        let mut table = VmaTable::<2>::new();
        table.insert(rw(0x40_000, 0x2000)).unwrap();
        assert_eq!(
            table.protect_exact(0x40_000, 0x2000, VmPerms::WRITE.union(VmPerms::EXECUTE)),
            Err(Error::WritableExecutable)
        );
        table
            .protect_exact(0x40_000, 0x2000, VmPerms::READ.union(VmPerms::EXECUTE))
            .unwrap();
        assert!(table.find(0x40_123).unwrap().perms.executable());
    }

    #[test]
    fn range_query_reuses_vma_validation_and_detects_overlap_without_mutation() {
        let mut table = VmaTable::<4>::new();
        table.insert(rw(0x70_000, 0x20_000)).unwrap();
        let before = table.len();

        assert_eq!(table.range_is_free(0x60_000, 0x10_000), Ok(true));
        assert_eq!(table.range_is_free(0x70_000, PAGE_SIZE), Ok(false));
        assert_eq!(table.range_is_free(0x68_000, 0x10_000), Ok(false));
        assert_eq!(table.range_is_free(0x80_000, 0x20_000), Ok(false));
        assert_eq!(table.len(), before);
    }

    #[test]
    fn range_query_rejects_invalid_candidate_shapes() {
        let table = VmaTable::<1>::new();
        assert_eq!(table.range_is_free(0, PAGE_SIZE), Err(Error::NullGuard));
        assert_eq!(
            table.range_is_free(USER_MIN + 1, PAGE_SIZE),
            Err(Error::UnalignedOrEmpty)
        );
        assert_eq!(
            table.range_is_free(USER_MIN, PAGE_SIZE - 1),
            Err(Error::UnalignedOrEmpty)
        );
        assert_eq!(
            table.range_is_free(USER_MAX_EXCLUSIVE, PAGE_SIZE),
            Err(Error::OutsideUserRange)
        );
    }

    #[test]
    fn top_down_gap_search_avoids_existing_mapping() {
        let mut table = VmaTable::<4>::new();
        table.insert(rw(0x70_000, 0x20_000)).unwrap();
        assert_eq!(
            table.find_gap_top_down(0x10_000, 0x90_000).unwrap(),
            0x60_000
        );
    }
}
