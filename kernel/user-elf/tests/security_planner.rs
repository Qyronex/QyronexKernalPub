// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_elf::{Error as ElfError, Image, Machine};
use kernal_user_elf::{Error as PlanError, LoadPolicy, UserLoadPlan};
use kernal_vm::{PAGE_SIZE, USER_MAX_EXCLUSIVE, USER_MIN};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ET_EXEC: u16 = 2;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PHOFF: usize = 64;
const PHENT: usize = 56;

fn base_elf(entry: u64, phnum: u16) -> [u8; 0x800] {
    let mut bytes = [0u8; 0x800];
    bytes[0..4].copy_from_slice(ELF_MAGIC);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&phnum.to_le_bytes());
    bytes
}

#[allow(clippy::too_many_arguments)]
fn write_segment(
    bytes: &mut [u8],
    index: usize,
    vaddr: u64,
    offset: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
    align: u64,
) {
    let p = PHOFF + index * PHENT;
    bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
    bytes[p + 8..p + 16].copy_from_slice(&offset.to_le_bytes());
    bytes[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
    bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[p + 32..p + 40].copy_from_slice(&file_size.to_le_bytes());
    bytes[p + 40..p + 48].copy_from_slice(&memory_size.to_le_bytes());
    bytes[p + 48..p + 56].copy_from_slice(&align.to_le_bytes());
}

#[test]
fn writable_executable_segment_is_rejected_by_shared_parser() {
    let vaddr = USER_MIN + 0x20_000;
    let mut bytes = base_elf(vaddr + 0x10, 1);
    write_segment(&mut bytes, 0, vaddr, 0x200, 0x20, PAGE_SIZE, 7, 1);

    assert_eq!(
        Image::parse_for_machine(&bytes, Machine::Aarch64),
        Err(ElfError::WritableExecutableSegment)
    );
}

#[test]
fn segment_crossing_null_guard_is_rejected_before_mapping() {
    let vaddr = USER_MIN - 0x800;
    let mut bytes = base_elf(USER_MIN + 0x10, 1);
    write_segment(&mut bytes, 0, vaddr, 0x200, 0x20, PAGE_SIZE, 5, 1);
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();

    assert_eq!(
        UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
        Err(PlanError::SegmentOutsideUserRange)
    );
}

#[test]
fn segment_crossing_user_ceiling_is_rejected_before_mapping() {
    let vaddr = USER_MAX_EXCLUSIVE - 0x800;
    let mut bytes = base_elf(USER_MAX_EXCLUSIVE - 0x400, 1);
    write_segment(&mut bytes, 0, vaddr, 0x200, 0x20, PAGE_SIZE, 5, 1);
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();

    assert_eq!(
        UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
        Err(PlanError::SegmentOutsideUserRange)
    );
}

#[test]
fn initial_stack_guard_overlap_is_rejected_before_mapping() {
    let guard_start = USER_MAX_EXCLUSIVE - 5 * PAGE_SIZE;
    let mut bytes = base_elf(guard_start + 0x10, 1);
    write_segment(&mut bytes, 0, guard_start, 0x200, 0x20, PAGE_SIZE, 5, 1);
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();

    assert_eq!(
        UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
        Err(PlanError::StackConflict)
    );
}

#[test]
fn bss_sizes_are_preserved_for_zero_fill_stage() {
    let text = USER_MIN + 0x20_000;
    let data = USER_MIN + 0x40_000;
    let mut bytes = base_elf(text + 0x10, 2);
    write_segment(&mut bytes, 0, text, 0x200, 0x20, PAGE_SIZE, 5, 1);
    write_segment(&mut bytes, 1, data, 0x300, 0x40, 2 * PAGE_SIZE, 6, 1);
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
    let writable = plan
        .segments()
        .find(|segment| segment.perms.writable)
        .unwrap();

    assert_eq!(writable.file_size, 0x40);
    assert_eq!(writable.memory_size, (2 * PAGE_SIZE) as usize);
}

#[test]
fn stack_policy_requires_a_real_guard_page() {
    let vaddr = USER_MIN + 0x20_000;
    let mut bytes = base_elf(vaddr + 0x10, 1);
    write_segment(&mut bytes, 0, vaddr, 0x200, 0x20, PAGE_SIZE, 5, 1);
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let policy = LoadPolicy {
        stack_guard_pages: 0,
        ..LoadPolicy::default()
    };

    assert_eq!(
        UserLoadPlan::<4>::from_image(&image, policy).map(|_| ()),
        Err(PlanError::InvalidStackLayout)
    );
}
