// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::InitialStackPlan;
use kernal_load_plan::{PAGE_SIZE, PlannedSegment};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationError {
    AddressOverflow,
    SourceRangeInvalid,
    DestinationSizeMismatch,
    MemoryRangeInvalid,
    StackSizeMismatch,
    PageSizeMismatch,
    PageIndexOutOfRange,
}

struct SegmentLayout<'a> {
    source: &'a [u8],
    expected_len: usize,
    memory_start: usize,
    memory_end: usize,
    file_destination_end: usize,
}

fn segment_layout<'a>(
    image: &'a [u8],
    segment: PlannedSegment,
) -> Result<SegmentLayout<'a>, InitializationError> {
    let expected_len = segment
        .page_count
        .checked_mul(PAGE_SIZE as usize)
        .ok_or(InitializationError::AddressOverflow)?;
    let file_end = segment
        .file_offset
        .checked_add(segment.file_size)
        .ok_or(InitializationError::AddressOverflow)?;
    let source = image
        .get(segment.file_offset..file_end)
        .ok_or(InitializationError::SourceRangeInvalid)?;
    let memory_start = segment.in_page_offset;
    let memory_end = memory_start
        .checked_add(segment.memory_size)
        .ok_or(InitializationError::AddressOverflow)?;
    if memory_end > expected_len || segment.file_size > segment.memory_size {
        return Err(InitializationError::MemoryRangeInvalid);
    }
    let file_destination_end = memory_start
        .checked_add(segment.file_size)
        .ok_or(InitializationError::AddressOverflow)?;
    if file_destination_end > memory_end {
        return Err(InitializationError::MemoryRangeInvalid);
    }
    Ok(SegmentLayout {
        source,
        expected_len,
        memory_start,
        memory_end,
        file_destination_end,
    })
}

/// Initializes the complete backing storage for one validated PT_LOAD segment.
///
/// `destination` must describe exactly the pages reserved by `segment`. Every range is validated
/// before the first write, so an error leaves `destination` unchanged. On success all bytes are
/// deterministic: file-backed bytes are copied at the segment's in-page offset and everything else,
/// including `p_memsz - p_filesz` BSS and page padding, is zero.
pub fn initialize_segment(
    image: &[u8],
    segment: PlannedSegment,
    destination: &mut [u8],
) -> Result<(), InitializationError> {
    let layout = segment_layout(image, segment)?;
    if destination.len() != layout.expected_len {
        return Err(InitializationError::DestinationSizeMismatch);
    }

    destination.fill(0);
    destination[layout.memory_start..layout.file_destination_end].copy_from_slice(layout.source);
    debug_assert!(layout.file_destination_end <= layout.memory_end);
    Ok(())
}

/// Initializes exactly one backing page for a validated PT_LOAD segment.
///
/// This is the physical-frame-friendly Step-12 interface: callers may initialize arbitrary distinct
/// frames one page at a time before installing their final user mappings. The whole ELF source range
/// and segment memory layout are validated on every call before the destination page is mutated.
pub fn initialize_segment_page(
    image: &[u8],
    segment: PlannedSegment,
    page_index: usize,
    destination: &mut [u8],
) -> Result<(), InitializationError> {
    if destination.len() != PAGE_SIZE as usize {
        return Err(InitializationError::PageSizeMismatch);
    }
    if page_index >= segment.page_count {
        return Err(InitializationError::PageIndexOutOfRange);
    }
    let layout = segment_layout(image, segment)?;
    let page_start = page_index
        .checked_mul(PAGE_SIZE as usize)
        .ok_or(InitializationError::AddressOverflow)?;
    let page_end = page_start
        .checked_add(PAGE_SIZE as usize)
        .ok_or(InitializationError::AddressOverflow)?;
    if page_end > layout.expected_len {
        return Err(InitializationError::MemoryRangeInvalid);
    }

    let copy_start = core::cmp::max(page_start, layout.memory_start);
    let copy_end = core::cmp::min(page_end, layout.file_destination_end);
    let copy = if copy_start < copy_end {
        let source_start = copy_start
            .checked_sub(layout.memory_start)
            .ok_or(InitializationError::AddressOverflow)?;
        let source_end = copy_end
            .checked_sub(layout.memory_start)
            .ok_or(InitializationError::AddressOverflow)?;
        Some((
            source_start,
            source_end,
            copy_start - page_start,
            copy_end - page_start,
        ))
    } else {
        None
    };

    destination.fill(0);
    if let Some((source_start, source_end, destination_start, destination_end)) = copy {
        destination[destination_start..destination_end]
            .copy_from_slice(&layout.source[source_start..source_end]);
    }
    Ok(())
}

/// Initializes the complete mapped initial stack allocation.
///
/// Step 12 has no argc/argv/envp/auxv ABI yet. Its native first-entry contract therefore uses a
/// completely zeroed stack while the guard range remains unmapped by the architecture adapter.
/// Exact-size validation occurs before mutation.
pub fn initialize_stack(
    plan: InitialStackPlan,
    destination: &mut [u8],
) -> Result<(), InitializationError> {
    let expected_len = plan
        .stack_pages()
        .checked_mul(PAGE_SIZE as usize)
        .ok_or(InitializationError::AddressOverflow)?;
    if destination.len() != expected_len {
        return Err(InitializationError::StackSizeMismatch);
    }
    destination.fill(0);
    Ok(())
}

/// Initializes one physical backing page for the initial user stack.
pub fn initialize_stack_page(
    plan: InitialStackPlan,
    page_index: usize,
    destination: &mut [u8],
) -> Result<(), InitializationError> {
    if destination.len() != PAGE_SIZE as usize {
        return Err(InitializationError::PageSizeMismatch);
    }
    if page_index >= plan.stack_pages() {
        return Err(InitializationError::PageIndexOutOfRange);
    }
    destination.fill(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoadPolicy, UserLoadPlan};
    use kernal_elf::{Image, Machine};
    use kernal_vm::USER_MIN;

    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    const ET_EXEC: u16 = 2;
    const EM_AARCH64: u16 = 183;
    const PT_LOAD: u32 = 1;
    const PHOFF: usize = 64;
    const PHENT: usize = 56;

    fn write_header(bytes: &mut [u8], virtual_address: u64) {
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(virtual_address + 1).to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    }

    fn write_segment(bytes: &mut [u8], virtual_address: u64, file_size: u64, memory_size: u64) {
        let program = PHOFF;
        bytes[program..program + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[program + 4..program + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[program + 8..program + 16].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[program + 16..program + 24].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[program + 24..program + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[program + 32..program + 40].copy_from_slice(&file_size.to_le_bytes());
        bytes[program + 40..program + 48].copy_from_slice(&memory_size.to_le_bytes());
        bytes[program + 48..program + 56].copy_from_slice(&1u64.to_le_bytes());
    }

    fn bss_elf() -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        let virtual_address = USER_MIN + 0x90_123;
        write_header(&mut bytes, virtual_address);
        write_segment(&mut bytes, virtual_address, 4, 0x500);
        bytes[0x200..0x204].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        bytes
    }

    fn cross_page_elf() -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        let virtual_address = USER_MIN + 0x9f_ffe;
        write_header(&mut bytes, virtual_address);
        write_segment(&mut bytes, virtual_address, 6, 0x20);
        bytes[0x200..0x206].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes
    }

    fn planned_segment(bytes: &[u8]) -> PlannedSegment {
        let image = Image::parse_for_machine(bytes, Machine::Aarch64).unwrap();
        let plan = UserLoadPlan::<2>::from_image(&image, LoadPolicy::default()).unwrap();
        *plan.segments().next().unwrap()
    }

    #[test]
    fn copies_file_bytes_and_zeroes_bss_and_padding() {
        let bytes = bss_elf();
        let segment = planned_segment(&bytes);
        let mut destination = [0x5au8; PAGE_SIZE as usize];
        initialize_segment(&bytes, segment, &mut destination).unwrap();

        let start = segment.in_page_offset;
        assert_eq!(&destination[start..start + 4], &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(destination[..start].iter().all(|byte| *byte == 0));
        assert!(
            destination[start + 4..start + 0x500]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(destination[start + 0x500..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn page_initialization_matches_whole_segment_across_frame_boundary() {
        let bytes = cross_page_elf();
        let segment = planned_segment(&bytes);
        assert_eq!(segment.page_count, 2);

        let mut whole = [0x5au8; 2 * PAGE_SIZE as usize];
        initialize_segment(&bytes, segment, &mut whole).unwrap();

        let mut first = [0x5au8; PAGE_SIZE as usize];
        let mut second = [0x5au8; PAGE_SIZE as usize];
        initialize_segment_page(&bytes, segment, 0, &mut first).unwrap();
        initialize_segment_page(&bytes, segment, 1, &mut second).unwrap();

        assert_eq!(&whole[..PAGE_SIZE as usize], &first);
        assert_eq!(&whole[PAGE_SIZE as usize..], &second);
        assert_eq!(&first[PAGE_SIZE as usize - 2..], &[1, 2]);
        assert_eq!(&second[..4], &[3, 4, 5, 6]);
        assert!(second[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn source_error_is_transactional() {
        let bytes = bss_elf();
        let segment = planned_segment(&bytes);
        let truncated = &bytes[..0x202];
        let mut destination = [0x5au8; PAGE_SIZE as usize];
        let before = destination;
        assert_eq!(
            initialize_segment(truncated, segment, &mut destination),
            Err(InitializationError::SourceRangeInvalid)
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn page_preflight_error_is_transactional() {
        let bytes = cross_page_elf();
        let segment = planned_segment(&bytes);
        let mut destination = [0x5au8; PAGE_SIZE as usize];
        let before = destination;
        assert_eq!(
            initialize_segment_page(&bytes, segment, segment.page_count, &mut destination),
            Err(InitializationError::PageIndexOutOfRange)
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn destination_size_error_is_transactional() {
        let bytes = bss_elf();
        let segment = planned_segment(&bytes);
        let mut destination = [0x5au8; 64];
        let before = destination;
        assert_eq!(
            initialize_segment(&bytes, segment, &mut destination),
            Err(InitializationError::DestinationSizeMismatch)
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn stack_is_exact_size_and_fully_zeroed() {
        let bytes = bss_elf();
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let plan = UserLoadPlan::<2>::from_image(&image, LoadPolicy::default()).unwrap();
        let stack = plan.stack();
        let mut destination = [0x5au8; 4 * PAGE_SIZE as usize];
        initialize_stack(stack, &mut destination).unwrap();
        assert!(destination.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn stack_page_is_zeroed_for_distinct_frame_initialization() {
        let bytes = bss_elf();
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let plan = UserLoadPlan::<2>::from_image(&image, LoadPolicy::default()).unwrap();
        let mut destination = [0x5au8; PAGE_SIZE as usize];
        initialize_stack_page(plan.stack(), 2, &mut destination).unwrap();
        assert!(destination.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn stack_size_failure_does_not_mutate_destination() {
        let bytes = bss_elf();
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let plan = UserLoadPlan::<2>::from_image(&image, LoadPolicy::default()).unwrap();
        let mut destination = [0x5au8; PAGE_SIZE as usize];
        let before = destination;
        assert_eq!(
            initialize_stack(plan.stack(), &mut destination),
            Err(InitializationError::StackSizeMismatch)
        );
        assert_eq!(destination, before);
    }
}
