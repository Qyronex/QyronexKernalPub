// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_load_plan::PlannedSegment;
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_user_elf::{Error as UserElfError, UserLoadPlan};
use kernal_vm::{Backing, Error as VmError, PAGE_SIZE, VmPerms, Vma};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    PageCountOverflow,
    AddressOverflow,
    FrameCountMismatch { expected: usize, actual: usize },
    DuplicateFrame,
    ReservedFrame,
    UserPolicy(UserElfError),
    Vm(VmError),
    AddressSpace(ProcessAddressSpaceError),
    RollbackFailed,
}

impl From<UserElfError> for Error {
    fn from(value: UserElfError) -> Self {
        Self::UserPolicy(value)
    }
}

impl From<VmError> for Error {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

impl From<ProcessAddressSpaceError> for Error {
    fn from(value: ProcessAddressSpaceError) -> Self {
        Self::AddressSpace(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedImage {
    pub segment_pages: usize,
    pub stack_pages: usize,
}

impl MappedImage {
    pub fn total_pages(self) -> Result<usize, Error> {
        self.segment_pages
            .checked_add(self.stack_pages)
            .ok_or(Error::PageCountOverflow)
    }
}

/// Returns the number of distinct physical frames required to map the validated image and stack.
pub fn required_pages<const SEGMENTS: usize>(
    plan: &UserLoadPlan<SEGMENTS>,
) -> Result<usize, Error> {
    let mut pages = plan.stack().stack_pages();
    for segment in plan.segments() {
        pages = pages
            .checked_add(segment.page_count)
            .ok_or(Error::PageCountOverflow)?;
    }
    Ok(pages)
}

/// Maps a validated Step-12 user image through the accepted Step-11 process/CSpace authority path.
///
/// The caller supplies exactly one distinct, non-reserved frame for every planned segment page,
/// followed by one frame for every stack page. Segment frames are consumed in `plan.segments()`
/// order and then in ascending virtual-page order. Stack frames follow in ascending virtual-page
/// order. The guard range is deliberately left unmapped.
///
/// This lane performs mapping only. It does not initialize file bytes, zero BSS, populate the stack,
/// or enter EL0; those operations belong to the segment-initialization and QEMU-proof lanes.
///
/// All frame-count, duplicate-frame, reservation and permission checks happen before page-table
/// mutation. If an architecture mapping fails after earlier pages were installed, every previously
/// installed page from this call is removed again. A rollback failure is reported separately because
/// the address space can no longer be claimed transactional in that case.
#[allow(clippy::too_many_arguments)]
pub fn map_user_image_pages<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    plan: &UserLoadPlan<SEGMENTS>,
    frames: &[PhysFrame],
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
) -> Result<MappedImage, Error> {
    let expected = required_pages(plan)?;
    if frames.len() != expected {
        return Err(Error::FrameCountMismatch {
            expected,
            actual: frames.len(),
        });
    }
    validate_frames(frames, reserved)?;
    validate_plan(plan)?;

    let mut frame_cursor = 0usize;
    let mut mapped_pages = 0usize;
    let mut segment_pages = 0usize;

    for segment in plan.segments() {
        let perms = UserLoadPlan::<SEGMENTS>::vm_perms(segment)?;
        for page_index in 0..segment.page_count {
            let address = page_address(segment, page_index)?;
            let frame = frames[frame_cursor];
            if let Err(error) = map_page(
                process, objects, space, backend, reserved, address, perms, frame,
            ) {
                rollback_or_fail(plan, mapped_pages, process, objects, space, backend)?;
                return Err(error);
            }
            frame_cursor += 1;
            mapped_pages += 1;
            segment_pages += 1;
        }
    }

    let stack = plan.stack();
    let stack_perms = VmPerms::READ.union(VmPerms::WRITE);
    for page_index in 0..stack.stack_pages() {
        let address = stack_page_address(stack.stack_start(), page_index)?;
        let frame = frames[frame_cursor];
        if let Err(error) = map_page(
            process,
            objects,
            space,
            backend,
            reserved,
            address,
            stack_perms,
            frame,
        ) {
            rollback_or_fail(plan, mapped_pages, process, objects, space, backend)?;
            return Err(error);
        }
        frame_cursor += 1;
        mapped_pages += 1;
    }

    Ok(MappedImage {
        segment_pages,
        stack_pages: stack.stack_pages(),
    })
}

fn validate_plan<const SEGMENTS: usize>(plan: &UserLoadPlan<SEGMENTS>) -> Result<(), Error> {
    for segment in plan.segments() {
        UserLoadPlan::<SEGMENTS>::vm_perms(segment)?;
        if segment.page_count == 0 {
            return Err(Error::PageCountOverflow);
        }
        page_address(segment, segment.page_count - 1)?;
    }
    let stack = plan.stack();
    if stack.stack_pages() == 0 {
        return Err(Error::PageCountOverflow);
    }
    stack_page_address(stack.stack_start(), stack.stack_pages() - 1)?;
    Ok(())
}

fn validate_frames<const RESERVED: usize>(
    frames: &[PhysFrame],
    reserved: &ReservationSet<RESERVED>,
) -> Result<(), Error> {
    for (index, frame) in frames.iter().copied().enumerate() {
        if reserved.contains(frame) {
            return Err(Error::ReservedFrame);
        }
        if frames[..index].contains(&frame) {
            return Err(Error::DuplicateFrame);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn map_page<
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
    address: u64,
    perms: VmPerms,
    frame: PhysFrame,
) -> Result<(), Error> {
    let vma = Vma::new(address, PAGE_SIZE, perms, Backing::Anonymous)?;
    space
        .map_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            vma,
            frame,
            reserved,
        )
        .map_err(Error::from)
}

fn page_address(segment: &PlannedSegment, page_index: usize) -> Result<u64, Error> {
    let offset = (page_index as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::AddressOverflow)?;
    segment
        .virtual_page_start
        .checked_add(offset)
        .ok_or(Error::AddressOverflow)
}

fn stack_page_address(stack_start: u64, page_index: usize) -> Result<u64, Error> {
    let offset = (page_index as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::AddressOverflow)?;
    stack_start
        .checked_add(offset)
        .ok_or(Error::AddressOverflow)
}

fn rollback_or_fail<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
>(
    plan: &UserLoadPlan<SEGMENTS>,
    mapped_pages: usize,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
) -> Result<(), Error> {
    if rollback_prefix(plan, mapped_pages, process, objects, space, backend).is_err() {
        space.poison();
        return Err(Error::RollbackFailed);
    }
    Ok(())
}

fn rollback_prefix<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
>(
    plan: &UserLoadPlan<SEGMENTS>,
    mapped_pages: usize,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
) -> Result<(), Error> {
    let mut remaining = mapped_pages;
    for segment in plan.segments() {
        for page_index in 0..segment.page_count {
            if remaining == 0 {
                return Ok(());
            }
            let address = page_address(segment, page_index)?;
            space
                .unmap_user_page_coalescing_anonymous(
                    process,
                    objects,
                    process.address_space_handle(),
                    backend,
                    address,
                )
                .map_err(Error::from)?;
            remaining -= 1;
        }
    }

    let stack = plan.stack();
    for page_index in 0..stack.stack_pages() {
        if remaining == 0 {
            return Ok(());
        }
        let address = stack_page_address(stack.stack_start(), page_index)?;
        space
            .unmap_user_page_coalescing_anonymous(
                process,
                objects,
                process.address_space_handle(),
                backend,
                address,
            )
            .map_err(Error::from)?;
        remaining -= 1;
    }

    if remaining == 0 {
        Ok(())
    } else {
        Err(Error::RollbackFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_elf::{Image, Machine};
    use kernal_process::Personality;
    use kernal_user_elf::LoadPolicy;
    use kernal_vm::USER_MIN;

    const TABLES: usize = 64;
    const TABLE_BASE: u64 = 0x10_0000;
    const ET_EXEC: u16 = 2;
    const EM_AARCH64: u16 = 183;
    const PT_LOAD: u32 = 1;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TABLES],
                used: 0,
            }
        }

        fn index(physical: u64) -> Option<usize> {
            if physical < TABLE_BASE || !(physical - TABLE_BASE).is_multiple_of(PAGE_SIZE) {
                return None;
            }
            let index = ((physical - TABLE_BASE) / PAGE_SIZE) as usize;
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
            Some(TABLE_BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = Self::index(table_phys).and_then(|index| self.tables.get_mut(index))
            else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    fn minimal_aarch64_exec() -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        let vaddr = USER_MIN + 0x20_000;
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(vaddr + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = 64;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    fn plan() -> UserLoadPlan<4> {
        let bytes = minimal_aarch64_exec();
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        UserLoadPlan::from_image(&image, LoadPolicy::default()).unwrap()
    }

    fn frames() -> [PhysFrame; 5] {
        core::array::from_fn(|index| {
            PhysFrame::from_start_address(0x40_0000 + index as u64 * PAGE_SIZE).unwrap()
        })
    }

    #[test]
    fn maps_segments_and_stack_through_process_owned_address_space() {
        let plan = plan();
        assert_eq!(required_pages(&plan), Ok(5));
        let frames = frames();
        let mut objects = ObjectTable::<8>::new();
        let process = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<8>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();

        let mapped = map_user_image_pages(
            &plan,
            &frames,
            &process,
            &objects,
            &mut space,
            &mut backend,
            &reserved,
        )
        .unwrap();
        assert_eq!(mapped.segment_pages, 1);
        assert_eq!(mapped.stack_pages, 4);
        assert_eq!(mapped.total_pages(), Ok(5));

        let segment_address = plan.segments().next().unwrap().virtual_page_start;
        assert_eq!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    segment_address,
                )
                .unwrap(),
            frames[0].start_address()
        );
        assert_eq!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    plan.stack().stack_start(),
                )
                .unwrap(),
            frames[1].start_address()
        );
        assert!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    plan.stack().guard_start(),
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_bad_frame_sets_before_mutating_the_address_space() {
        let plan = plan();
        let mut frames = frames();
        frames[4] = frames[0];
        let mut objects = ObjectTable::<8>::new();
        let process = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<8>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();

        assert_eq!(
            map_user_image_pages(
                &plan,
                &frames,
                &process,
                &objects,
                &mut space,
                &mut backend,
                &reserved,
            ),
            Err(Error::DuplicateFrame)
        );
        let segment_address = plan.segments().next().unwrap().virtual_page_start;
        assert!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    segment_address,
                )
                .is_err()
        );
    }

    #[test]
    fn coalesces_contiguous_pages_under_tight_vma_capacity() {
        let plan = plan();
        let frames = frames();
        let mut objects = ObjectTable::<8>::new();
        let process = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<2>::create(&process, &objects, &mut backend).unwrap();
        let reserved = ReservationSet::<1>::new();

        let mapped = map_user_image_pages(
            &plan,
            &frames,
            &process,
            &objects,
            &mut space,
            &mut backend,
            &reserved,
        )
        .unwrap();
        assert_eq!(mapped.total_pages(), Ok(5));

        let segment_address = plan.segments().next().unwrap().virtual_page_start;
        assert_eq!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    segment_address,
                )
                .unwrap(),
            frames[0].start_address()
        );
        assert_eq!(
            space
                .translate_user(
                    &process,
                    &objects,
                    process.address_space_handle(),
                    &mut backend,
                    plan.stack().stack_start(),
                )
                .unwrap(),
            frames[1].start_address()
        );
    }

    #[test]
    fn poisons_address_space_when_final_mapping_rollback_cannot_complete() {
        let plan = plan();
        let mut objects = ObjectTable::<8>::new();
        let process = Process::<8>::create(&mut objects, Personality::Native).unwrap();
        let mut backend = TestBackend::new();
        let mut space =
            BoundProcessAddressSpace::<8>::create(&process, &objects, &mut backend).unwrap();

        assert!(!space.is_poisoned());
        assert_eq!(
            rollback_or_fail(&plan, 1, &process, &objects, &mut space, &mut backend),
            Err(Error::RollbackFailed)
        );
        assert!(space.is_poisoned());

        let segment_address = plan.segments().next().unwrap().virtual_page_start;
        assert_eq!(
            space.translate_user(
                &process,
                &objects,
                process.address_space_handle(),
                &mut backend,
                segment_address,
            ),
            Err(ProcessAddressSpaceError::Poisoned)
        );
    }
}
