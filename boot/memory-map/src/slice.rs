use kernal_bootinfo::MemoryRegionV1;

use crate::{Error, FirmwareRegion, normalize};

/// Normalizes and sorts firmware descriptors directly into caller-provided storage.
/// This is intended for the post-ExitBootServices path where heap allocation is forbidden.
pub struct NormalizedSlice<'a> {
    storage: &'a mut [MemoryRegionV1],
    len: usize,
}

impl<'a> NormalizedSlice<'a> {
    pub fn new(storage: &'a mut [MemoryRegionV1]) -> Self {
        Self { storage, len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[MemoryRegionV1] {
        &self.storage[..self.len]
    }

    pub fn push_firmware(&mut self, region: FirmwareRegion) -> Result<(), Error> {
        self.insert(normalize(region)?)
    }

    pub fn insert(&mut self, region: MemoryRegionV1) -> Result<(), Error> {
        let end = region.end().ok_or(Error::AddressOverflow)?;
        let mut pos = 0usize;
        while pos < self.len && self.storage[pos].start < region.start {
            pos += 1;
        }

        if pos > 0 {
            let previous = self.storage[pos - 1];
            let previous_end = previous.end().ok_or(Error::AddressOverflow)?;
            if previous_end > region.start {
                return Err(Error::Overlap);
            }
            if can_merge(previous, region, previous_end) {
                self.storage[pos - 1].len = previous
                    .len
                    .checked_add(region.len)
                    .ok_or(Error::LengthOverflow)?;
                self.merge_forward(pos - 1)?;
                return Ok(());
            }
        }
        if pos < self.len && end > self.storage[pos].start {
            return Err(Error::Overlap);
        }
        if self.len == self.storage.len() {
            return Err(Error::Capacity);
        }

        self.storage.copy_within(pos..self.len, pos + 1);
        self.storage[pos] = region;
        self.len += 1;
        self.merge_forward(pos)
    }

    fn merge_forward(&mut self, index: usize) -> Result<(), Error> {
        if index + 1 >= self.len {
            return Ok(());
        }
        let current = self.storage[index];
        let next = self.storage[index + 1];
        let current_end = current.end().ok_or(Error::AddressOverflow)?;
        if can_merge(current, next, current_end) {
            self.storage[index].len = current
                .len
                .checked_add(next.len)
                .ok_or(Error::LengthOverflow)?;
            self.storage.copy_within(index + 2..self.len, index + 1);
            self.len -= 1;
        }
        Ok(())
    }
}

const fn can_merge(left: MemoryRegionV1, right: MemoryRegionV1, left_end: u64) -> bool {
    left_end == right.start && left.kind == right.kind && left.attributes == right.attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_bootinfo::memory_kind;

    #[test]
    fn sorts_and_merges_without_heap() {
        let empty = MemoryRegionV1::new(0, 1, memory_kind::RESERVED, 0);
        let mut storage = [empty; 4];
        let mut map = NormalizedSlice::new(&mut storage);
        map.insert(MemoryRegionV1::new(0x3000, 0x1000, memory_kind::USABLE, 0))
            .unwrap();
        map.insert(MemoryRegionV1::new(0x1000, 0x2000, memory_kind::USABLE, 0))
            .unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.as_slice()[0].start, 0x1000);
        assert_eq!(map.as_slice()[0].len, 0x3000);
    }

    #[test]
    fn capacity_failure_does_not_overwrite_storage() {
        let empty = MemoryRegionV1::new(0, 1, memory_kind::RESERVED, 0);
        let mut storage = [empty; 1];
        let mut map = NormalizedSlice::new(&mut storage);
        map.insert(MemoryRegionV1::new(0x1000, 0x1000, memory_kind::USABLE, 0))
            .unwrap();
        assert_eq!(
            map.insert(MemoryRegionV1::new(
                0x4000,
                0x1000,
                memory_kind::RESERVED,
                0
            )),
            Err(Error::Capacity)
        );
        assert_eq!(map.as_slice()[0].start, 0x1000);
    }
}
