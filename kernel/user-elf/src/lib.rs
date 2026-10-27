// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod initialization;
pub mod linux_stack;

use kernal_elf::{Image, ImageType};
use kernal_load_plan::{Error as LoadPlanError, LoadPlan, PAGE_SIZE, PlannedSegment};
use kernal_vm::{USER_MAX_EXCLUSIVE, USER_MIN, VmPerms};

pub const DEFAULT_DYN_LOAD_BIAS: u64 = USER_MIN + 0x0100_0000;
pub const DEFAULT_STACK_PAGES: usize = 4;
pub const DEFAULT_STACK_GUARD_PAGES: usize = 1;
const STACK_ALIGNMENT: u64 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    LoadPlan(LoadPlanError),
    InvalidDynamicLoadBias,
    SegmentOutsideUserRange,
    EntryOutsideUserRange,
    UnsupportedPermissions,
    InvalidStackLayout,
    StackConflict,
}

impl From<LoadPlanError> for Error {
    fn from(value: LoadPlanError) -> Self {
        Self::LoadPlan(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPolicy {
    pub dynamic_load_bias: u64,
    pub stack_pages: usize,
    pub stack_guard_pages: usize,
}

impl Default for LoadPolicy {
    fn default() -> Self {
        Self {
            dynamic_load_bias: DEFAULT_DYN_LOAD_BIAS,
            stack_pages: DEFAULT_STACK_PAGES,
            stack_guard_pages: DEFAULT_STACK_GUARD_PAGES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialStackPlan {
    guard_start: u64,
    stack_start: u64,
    stack_end: u64,
    initial_sp: u64,
    stack_pages: usize,
    guard_pages: usize,
}

impl InitialStackPlan {
    pub const fn guard_start(self) -> u64 {
        self.guard_start
    }

    pub const fn stack_start(self) -> u64 {
        self.stack_start
    }

    pub const fn stack_end(self) -> u64 {
        self.stack_end
    }

    pub const fn initial_sp(self) -> u64 {
        self.initial_sp
    }

    pub const fn stack_pages(self) -> usize {
        self.stack_pages
    }

    pub const fn guard_pages(self) -> usize {
        self.guard_pages
    }
}

/// User-process policy wrapped around the shared architecture-neutral ELF load plan.
///
/// `kernal-load-plan` owns ELF segment/page arithmetic, p_align validation, relocation bias and
/// page-conflict rejection. This type adds only the constraints that are specific to a user process:
/// the lower canonical half, representable user VMA permissions and a guarded initial stack.
pub struct UserLoadPlan<const N: usize> {
    plan: LoadPlan<N>,
    image_type: ImageType,
    load_bias: u64,
    stack: InitialStackPlan,
}

impl<const N: usize> UserLoadPlan<N> {
    /// Validates the complete user layout before any address-space mutation is allowed.
    pub fn from_image(image: &Image<'_>, policy: LoadPolicy) -> Result<Self, Error> {
        let load_bias = match image.image_type() {
            ImageType::Executable => 0,
            ImageType::SharedObject => {
                if policy.dynamic_load_bias < USER_MIN
                    || policy.dynamic_load_bias >= USER_MAX_EXCLUSIVE
                    || !policy.dynamic_load_bias.is_multiple_of(PAGE_SIZE)
                {
                    return Err(Error::InvalidDynamicLoadBias);
                }
                policy.dynamic_load_bias
            }
        };

        let plan = LoadPlan::<N>::from_image_with_bias(image, load_bias)?;
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&plan.entry()) {
            return Err(Error::EntryOutsideUserRange);
        }

        let stack = plan_initial_stack(policy)?;
        for segment in plan.segments() {
            validate_user_segment(segment)?;
            if range_overlaps_stack(segment, stack)? {
                return Err(Error::StackConflict);
            }
        }

        Ok(Self {
            plan,
            image_type: image.image_type(),
            load_bias,
            stack,
        })
    }

    pub const fn image_type(&self) -> ImageType {
        self.image_type
    }

    pub const fn load_bias(&self) -> u64 {
        self.load_bias
    }

    pub const fn entry(&self) -> u64 {
        self.plan.entry()
    }

    pub const fn len(&self) -> usize {
        self.plan.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.plan.is_empty()
    }

    pub const fn stack(&self) -> InitialStackPlan {
        self.stack
    }

    pub fn segments(&self) -> impl Iterator<Item = &PlannedSegment> {
        self.plan.segments()
    }

    /// Converts the shared ELF permission plan into the current user VMA permission model without
    /// silently widening execute-only or otherwise unsupported segments.
    pub fn vm_perms(segment: &PlannedSegment) -> Result<VmPerms, Error> {
        if !segment.perms.readable {
            return Err(Error::UnsupportedPermissions);
        }
        let mut perms = VmPerms::READ;
        if segment.perms.writable {
            perms = perms.union(VmPerms::WRITE);
        }
        if segment.perms.executable {
            perms = perms.union(VmPerms::EXECUTE);
        }
        perms.validate().map_err(|_| Error::UnsupportedPermissions)
    }
}

fn validate_user_segment(segment: &PlannedSegment) -> Result<(), Error> {
    let end = segment.virtual_end()?;
    if segment.virtual_page_start < USER_MIN
        || segment.virtual_page_start >= USER_MAX_EXCLUSIVE
        || end > USER_MAX_EXCLUSIVE
        || segment.virtual_page_start >= end
    {
        return Err(Error::SegmentOutsideUserRange);
    }
    UserLoadPlan::<1>::vm_perms(segment)?;
    Ok(())
}

fn plan_initial_stack(policy: LoadPolicy) -> Result<InitialStackPlan, Error> {
    if policy.stack_pages == 0 || policy.stack_guard_pages == 0 {
        return Err(Error::InvalidStackLayout);
    }
    let stack_bytes = (policy.stack_pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::InvalidStackLayout)?;
    let guard_bytes = (policy.stack_guard_pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::InvalidStackLayout)?;
    let stack_end = USER_MAX_EXCLUSIVE;
    let stack_start = stack_end
        .checked_sub(stack_bytes)
        .ok_or(Error::InvalidStackLayout)?;
    let guard_start = stack_start
        .checked_sub(guard_bytes)
        .ok_or(Error::InvalidStackLayout)?;
    if guard_start < USER_MIN {
        return Err(Error::InvalidStackLayout);
    }
    let initial_sp = stack_end
        .checked_sub(STACK_ALIGNMENT)
        .ok_or(Error::InvalidStackLayout)?;
    if initial_sp < stack_start || !initial_sp.is_multiple_of(STACK_ALIGNMENT) {
        return Err(Error::InvalidStackLayout);
    }
    Ok(InitialStackPlan {
        guard_start,
        stack_start,
        stack_end,
        initial_sp,
        stack_pages: policy.stack_pages,
        guard_pages: policy.stack_guard_pages,
    })
}

fn range_overlaps_stack(segment: &PlannedSegment, stack: InitialStackPlan) -> Result<bool, Error> {
    Ok(
        segment.virtual_page_start < stack.stack_end
            && stack.guard_start < segment.virtual_end()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_elf::{Error as ElfError, Machine};

    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const EM_AARCH64: u16 = 183;
    const EM_X86_64: u16 = 62;
    const PT_LOAD: u32 = 1;
    const PHOFF: usize = 64;
    const PHENT: usize = 56;

    fn one_segment_elf(image_type: u16, machine: u16, vaddr: u64, flags: u32) -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&image_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(vaddr + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        write_segment(&mut bytes, 0, vaddr, 0, 0x200, 0x1000, flags, 0x1000);
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
    fn fixed_aarch64_exec_reuses_shared_plan_and_plans_stack() {
        let bytes = one_segment_elf(ET_EXEC, EM_AARCH64, USER_MIN + 0x20_000, 5);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
        assert_eq!(plan.image_type(), ImageType::Executable);
        assert_eq!(plan.load_bias(), 0);
        assert_eq!(plan.entry(), USER_MIN + 0x20_100);
        let segment = plan.segments().next().unwrap();
        assert_eq!(segment.virtual_page_start, USER_MIN + 0x20_000);
        assert_eq!(segment.page_count, 1);
        let perms = UserLoadPlan::<4>::vm_perms(segment).unwrap();
        assert!(perms.readable());
        assert!(perms.executable());
        assert!(!perms.writable());
        assert_eq!(plan.stack().stack_end(), USER_MAX_EXCLUSIVE);
        assert_eq!(plan.stack().initial_sp(), USER_MAX_EXCLUSIVE - 16);
    }

    #[test]
    fn controlled_dynamic_bias_is_delegated_to_shared_plan() {
        let bytes = one_segment_elf(ET_DYN, EM_AARCH64, 0, 5);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let policy = LoadPolicy {
            dynamic_load_bias: USER_MIN + 0x40_000,
            ..LoadPolicy::default()
        };
        let plan = UserLoadPlan::<4>::from_image(&image, policy).unwrap();
        assert_eq!(plan.image_type(), ImageType::SharedObject);
        assert_eq!(plan.load_bias(), USER_MIN + 0x40_000);
        assert_eq!(plan.entry(), USER_MIN + 0x40_100);
        assert_eq!(
            plan.segments().next().unwrap().virtual_page_start,
            USER_MIN + 0x40_000
        );
    }

    #[test]
    fn dynamic_bias_must_be_page_aligned_and_inside_user_range() {
        let bytes = one_segment_elf(ET_DYN, EM_AARCH64, 0, 5);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        let bad = LoadPolicy {
            dynamic_load_bias: USER_MIN + 1,
            ..LoadPolicy::default()
        };
        assert_eq!(
            UserLoadPlan::<4>::from_image(&image, bad).map(|_| ()),
            Err(Error::InvalidDynamicLoadBias)
        );
    }

    #[test]
    fn kernel_half_exec_is_rejected_by_user_policy() {
        let bytes = one_segment_elf(ET_EXEC, EM_AARCH64, 0xffff_8000_0020_0000, 5);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(
            UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
            Err(Error::EntryOutsideUserRange)
        );
    }

    #[test]
    fn page_conflict_is_owned_by_shared_load_plan() {
        let base = USER_MIN + 0x60_000;
        let mut bytes = one_segment_elf(ET_EXEC, EM_AARCH64, base, 5);
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        write_segment(&mut bytes, 0, base, 0x200, 0x40, 0x800, 5, 1);
        write_segment(&mut bytes, 1, base + 0x800, 0x300, 0x40, 0x400, 6, 1);
        bytes[24..32].copy_from_slice(&(base + 0x100).to_le_bytes());
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(
            UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
            Err(Error::LoadPlan(LoadPlanError::OverlappingPageMappings))
        );
    }

    #[test]
    fn execute_only_segment_is_rejected_instead_of_widening_permissions() {
        let bytes = one_segment_elf(ET_EXEC, EM_AARCH64, USER_MIN + 0x80_000, 1);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(
            UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
            Err(Error::UnsupportedPermissions)
        );
    }

    #[test]
    fn stack_overlap_is_rejected_after_shared_plan_succeeds() {
        let vaddr = USER_MAX_EXCLUSIVE - (2 * PAGE_SIZE);
        let bytes = one_segment_elf(ET_EXEC, EM_AARCH64, vaddr, 5);
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(
            UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).map(|_| ()),
            Err(Error::StackConflict)
        );
    }

    #[test]
    fn cross_architecture_rejection_still_occurs_in_shared_parser() {
        let bytes = one_segment_elf(ET_EXEC, EM_X86_64, USER_MIN + 0x20_000, 5);
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(ElfError::UnsupportedMachine)
        );
    }
}
