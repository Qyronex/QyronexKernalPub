// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod linux;
pub use kernal_user_elf::linux_stack::{MAX_ARGC, MAX_ARGV0_BYTES, MAX_ENVC, MAX_STRING_BYTES};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use linux::load_aarch64_linux_elf;
pub use linux::{
    AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE, LinuxInitialStackLayout, LinuxProcessStart,
    plan_aarch64_linux_initial_stack,
};

use kernal_elf::{Error as ElfError, Image, Machine};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_user_elf::{
    Error as UserElfError, LoadPolicy, UserLoadPlan,
    initialization::{InitializationError, initialize_segment_page, initialize_stack_page},
};
use kernal_user_elf_aarch64::{Error as MappingError, MappedImage, required_pages};
use kernal_vm::PAGE_SIZE;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_object::ObjectTable;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::Backend;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process::Process;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process_aarch64::BoundProcessAddressSpace;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_elf_aarch64::map_user_image_pages;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_vm::{Backing, VmPerms, Vma};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Elf(ElfError),
    UserPolicy(UserElfError),
    Initialization(InitializationError),
    LinuxStack(kernal_user_elf::linux_stack::Error),
    LinuxStackInvariant,
    Mapping(MappingError),
    FrameCountMismatch { expected: usize, actual: usize },
    DuplicateFrame,
    ReservedFrame,
    AddressOverflow,
    Vm,
    AddressSpace,
    Usercopy,
    CacheMaintenance,
    StagingRollbackFailed,
}

impl From<ElfError> for Error {
    fn from(value: ElfError) -> Self {
        Self::Elf(value)
    }
}

impl From<UserElfError> for Error {
    fn from(value: UserElfError) -> Self {
        Self::UserPolicy(value)
    }
}

impl From<InitializationError> for Error {
    fn from(value: InitializationError) -> Self {
        Self::Initialization(value)
    }
}

impl From<kernal_user_elf::linux_stack::Error> for Error {
    fn from(value: kernal_user_elf::linux_stack::Error) -> Self {
        Self::LinuxStack(value)
    }
}

impl From<MappingError> for Error {
    fn from(value: MappingError) -> Self {
        Self::Mapping(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedImage {
    pub mapped: MappedImage,
    pub entry: u64,
    pub initial_sp: u64,
}

/// Parses an ELF64 image with explicit `EM_AARCH64` selection and builds the shared Step-12 plan.
///
/// This is intentionally the only architecture-specific parser entry in the runtime layer; all ELF
/// validation remains owned by `kernal-elf` and all user layout policy remains owned by
/// `kernal-user-elf`.
pub fn plan_aarch64_elf<const SEGMENTS: usize>(
    image: &[u8],
    policy: LoadPolicy,
) -> Result<UserLoadPlan<SEGMENTS>, Error> {
    let parsed = Image::parse_for_machine(image, Machine::Aarch64)?;
    Ok(UserLoadPlan::from_image(&parsed, policy)?)
}

/// Validates the complete frame and initialization plan before the first page-table mutation.
#[cfg_attr(
    not(any(test, all(target_arch = "aarch64", target_os = "none"))),
    allow(dead_code)
)]
fn preflight<const SEGMENTS: usize, const RESERVED: usize>(
    image: &[u8],
    plan: &UserLoadPlan<SEGMENTS>,
    frames: &[PhysFrame],
    reserved: &ReservationSet<RESERVED>,
) -> Result<usize, Error> {
    let expected = required_pages(plan)?;
    if frames.len() != expected {
        return Err(Error::FrameCountMismatch {
            expected,
            actual: frames.len(),
        });
    }

    for (index, frame) in frames.iter().copied().enumerate() {
        if reserved.contains(frame) {
            return Err(Error::ReservedFrame);
        }
        if frames[..index].contains(&frame) {
            return Err(Error::DuplicateFrame);
        }
    }

    // Reuse Agent C as the single owner of ELF file/BSS/page-layout arithmetic. Building each page
    // into a scratch buffer proves all source and destination ranges before any user mapping exists.
    let mut scratch = [0u8; PAGE_SIZE as usize];
    for segment in plan.segments() {
        for page_index in 0..segment.page_count {
            initialize_segment_page(image, *segment, page_index, &mut scratch)?;
        }
    }
    let stack = plan.stack();
    for page_index in 0..stack.stack_pages() {
        initialize_stack_page(stack, page_index, &mut scratch)?;
    }

    Ok(expected)
}

/// Loads one validated AArch64 ELF image through the accepted Step-11 process address-space path.
///
/// The runtime deliberately follows the already-proven Step-9 code-loading sequence without
/// introducing a second VM or privilege-transition mechanism:
///
/// 1. parse with explicit `EM_AARCH64` and build the shared user load plan;
/// 2. reject bad frame sets and validate every Agent-C initialization page before page-table mutation;
/// 3. temporarily map every image/stack frame RW-NX through the process's MAP capability;
/// 4. with that exact process root active, initialize pages through Agent C and write them only via
///    the PAN-safe Step-10 `copy_to_user` primitive;
/// 5. synchronize modified executable pages to the instruction stream;
/// 6. deactivate TTBR0 and remove every staging mapping;
/// 7. remap the same frames with the final ELF permissions through `map_user_image_pages`.
///
/// The guard range is never mapped. Agent C deterministically zeroes BSS and page padding. No
/// writable+executable mapping exists at any point. If staging cleanup cannot prove every temporary
/// mapping was removed, the process-bound address space is poisoned and becomes unusable.
///
/// # Safety
///
/// The caller must own the current PE's scheduler/preemption/address-space switch window exactly as
/// required by `BoundProcessAddressSpace::activate_owner`. No EL0 thread may execute from this process
/// while the temporary RW-NX staging mappings are active.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn load_aarch64_elf<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    image: &[u8],
    policy: LoadPolicy,
    frames: &[PhysFrame],
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
) -> Result<LoadedImage, Error> {
    let plan = plan_aarch64_elf::<SEGMENTS>(image, policy)?;
    let initial_sp = plan.stack().initial_sp();
    // SAFETY: this function exposes the same owner/quiescence contract as the shared loader below.
    unsafe {
        load_aarch64_elf_prepared(
            image,
            plan,
            initial_sp,
            frames,
            process,
            objects,
            space,
            backend,
            reserved,
            |_| Ok(()),
        )
    }
}

/// Executes the one canonical AArch64 process-image mapping transaction for an already prepared
/// layout. `initialize_after_base` may add personality-specific data only while the same temporary
/// RW-NX staging mappings and exact process TTBR0 are active. Native Step-12 loading passes a no-op;
/// the Linux wrapper uses this hook solely to replace the zeroed initial stack with its validated
/// argc/argv/envp/auxv image.
///
/// # Safety
/// The caller must satisfy the same owner/quiescence contract as [`load_aarch64_elf`]. The callback
/// must use only the active process mappings, must not context-switch or replace TTBR0, and must
/// restore PAN/default-deny before returning.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
unsafe fn load_aarch64_elf_prepared<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
    F: FnOnce(&UserLoadPlan<SEGMENTS>) -> Result<(), Error>,
>(
    image: &[u8],
    plan: UserLoadPlan<SEGMENTS>,
    initial_sp: u64,
    frames: &[PhysFrame],
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
    initialize_after_base: F,
) -> Result<LoadedImage, Error> {
    let total_pages = preflight(image, &plan, frames, reserved)?;

    map_staging_pages(&plan, frames, process, objects, space, backend, reserved)?;

    if unsafe { space.activate_owner(process, objects) }.is_err() {
        rollback_staging_prefix(&plan, frames, total_pages, process, objects, space, backend)?;
        return Err(Error::AddressSpace);
    }

    let initialize_result =
        initialize_staging(image, &plan).and_then(|()| initialize_after_base(&plan));
    if unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() }.is_err() {
        // A failed process-aware deactivation leaves TTBR0 state intentionally unchanged. Quarantine
        // this binding and return the address-space failure without attempting resumable cleanup.
        space.poison();
        return Err(Error::AddressSpace);
    }
    if let Err(error) = initialize_result {
        rollback_staging_prefix(&plan, frames, total_pages, process, objects, space, backend)?;
        return Err(error);
    }

    rollback_staging_prefix(&plan, frames, total_pages, process, objects, space, backend)?;

    let mapped = map_user_image_pages(&plan, frames, process, objects, space, backend, reserved)?;
    Ok(LoadedImage {
        mapped,
        entry: plan.entry(),
        initial_sp,
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
fn map_staging_pages<
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
) -> Result<(), Error> {
    let staging_perms = VmPerms::READ.union(VmPerms::WRITE);
    let mut frame_cursor = 0usize;
    let mut mapped_pages = 0usize;

    for segment in plan.segments() {
        for page_index in 0..segment.page_count {
            let address = segment_page_address(segment.virtual_page_start, page_index)?;
            let result = map_staging_page(
                address,
                frames[frame_cursor],
                staging_perms,
                process,
                objects,
                space,
                backend,
                reserved,
            );
            if let Err(error) = result {
                if rollback_staging_prefix(
                    plan,
                    frames,
                    mapped_pages,
                    process,
                    objects,
                    space,
                    backend,
                )
                .is_err()
                {
                    return Err(Error::StagingRollbackFailed);
                }
                return Err(error);
            }
            frame_cursor += 1;
            mapped_pages += 1;
        }
    }

    let stack = plan.stack();
    for page_index in 0..stack.stack_pages() {
        let address = segment_page_address(stack.stack_start(), page_index)?;
        let result = map_staging_page(
            address,
            frames[frame_cursor],
            staging_perms,
            process,
            objects,
            space,
            backend,
            reserved,
        );
        if let Err(error) = result {
            if rollback_staging_prefix(plan, frames, mapped_pages, process, objects, space, backend)
                .is_err()
            {
                return Err(Error::StagingRollbackFailed);
            }
            return Err(error);
        }
        frame_cursor += 1;
        mapped_pages += 1;
    }

    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
fn map_staging_page<
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    address: u64,
    frame: PhysFrame,
    perms: VmPerms,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
) -> Result<(), Error> {
    let vma = Vma::new(address, PAGE_SIZE, perms, Backing::Anonymous).map_err(|_| Error::Vm)?;
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
        .map_err(|_| Error::AddressSpace)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn initialize_staging<const SEGMENTS: usize>(
    image: &[u8],
    plan: &UserLoadPlan<SEGMENTS>,
) -> Result<(), Error> {
    let mut page = [0u8; PAGE_SIZE as usize];

    for segment in plan.segments() {
        for page_index in 0..segment.page_count {
            initialize_segment_page(image, *segment, page_index, &mut page)?;
            let address = segment_page_address(segment.virtual_page_start, page_index)?;
            kernal_usercopy_aarch64::copy_to_user(address, &page).map_err(|_| Error::Usercopy)?;
        }

        if segment.perms.executable {
            let page_count =
                u64::try_from(segment.page_count).map_err(|_| Error::AddressOverflow)?;
            let length = page_count
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::AddressOverflow)?;
            // SAFETY: the staging root is active and this VA range resolves to the same dedicated
            // Normal-memory frames later remapped at the identical execution VA. The VA translation
            // is valid for both cache-maintenance operands and no PE may execute it until completion.
            unsafe {
                kernal_cache_aarch64::sync_modified_code(
                    segment.virtual_page_start,
                    segment.virtual_page_start,
                    length,
                )
            }
            .map_err(|_| Error::CacheMaintenance)?;
        }
    }

    let stack = plan.stack();
    for page_index in 0..stack.stack_pages() {
        initialize_stack_page(stack, page_index, &mut page)?;
        let address = segment_page_address(stack.stack_start(), page_index)?;
        kernal_usercopy_aarch64::copy_to_user(address, &page).map_err(|_| Error::Usercopy)?;
    }

    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        return Err(Error::Usercopy);
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
fn rollback_staging_prefix<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
>(
    plan: &UserLoadPlan<SEGMENTS>,
    frames: &[PhysFrame],
    mapped_pages: usize,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
) -> Result<(), Error> {
    let mut remaining = mapped_pages;
    let mut frame_cursor = 0usize;
    let mut cleanup_failed = false;

    for segment in plan.segments() {
        for page_index in 0..segment.page_count {
            if remaining == 0 {
                break;
            }
            let expected_frame = frames.get(frame_cursor).copied();
            match segment_page_address(segment.virtual_page_start, page_index) {
                Ok(address) => match space.unmap_user_page_coalescing_anonymous(
                    process,
                    objects,
                    process.address_space_handle(),
                    backend,
                    address,
                ) {
                    Ok(frame) if expected_frame == Some(frame) => {}
                    Ok(_) | Err(_) => cleanup_failed = true,
                },
                Err(_) => cleanup_failed = true,
            }
            frame_cursor += 1;
            remaining -= 1;
        }
        if remaining == 0 {
            break;
        }
    }

    if remaining != 0 {
        let stack = plan.stack();
        for page_index in 0..stack.stack_pages() {
            if remaining == 0 {
                break;
            }
            let expected_frame = frames.get(frame_cursor).copied();
            match segment_page_address(stack.stack_start(), page_index) {
                Ok(address) => match space.unmap_user_page_coalescing_anonymous(
                    process,
                    objects,
                    process.address_space_handle(),
                    backend,
                    address,
                ) {
                    Ok(frame) if expected_frame == Some(frame) => {}
                    Ok(_) | Err(_) => cleanup_failed = true,
                },
                Err(_) => cleanup_failed = true,
            }
            frame_cursor += 1;
            remaining -= 1;
        }
    }

    if remaining != 0 {
        cleanup_failed = true;
    }
    if cleanup_failed {
        space.poison();
        Err(Error::StagingRollbackFailed)
    } else {
        Ok(())
    }
}

#[cfg_attr(
    not(all(target_arch = "aarch64", target_os = "none")),
    allow(dead_code)
)]
fn segment_page_address(start: u64, page_index: usize) -> Result<u64, Error> {
    let index = u64::try_from(page_index).map_err(|_| Error::AddressOverflow)?;
    let offset = index.checked_mul(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    start.checked_add(offset).ok_or(Error::AddressOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_vm::USER_MIN;

    const ET_EXEC: u16 = 2;
    const EM_AARCH64: u16 = 183;
    const EM_X86_64: u16 = 62;
    const PT_LOAD: u32 = 1;

    fn minimal_exec(machine: u16) -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        // Keep p_vaddr and p_offset congruent modulo p_align while preserving an unaligned
        // in-page ELF payload. The segment still occupies exactly one 4-KiB page.
        let vaddr = USER_MIN + 0x20_200;
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(vaddr + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = 64;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&4u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x800u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        bytes
    }

    fn frames() -> [PhysFrame; 5] {
        core::array::from_fn(|index| {
            PhysFrame::from_start_address(0x40_0000 + index as u64 * PAGE_SIZE).unwrap()
        })
    }

    #[test]
    fn explicit_aarch64_machine_selection_rejects_x86() {
        let bytes = minimal_exec(EM_X86_64);
        assert_eq!(
            plan_aarch64_elf::<4>(&bytes, LoadPolicy::default()).map(|_| ()),
            Err(Error::Elf(ElfError::UnsupportedMachine))
        );
    }

    #[test]
    fn preflight_rejects_duplicate_frames_before_mapping() {
        let bytes = minimal_exec(EM_AARCH64);
        let plan = plan_aarch64_elf::<4>(&bytes, LoadPolicy::default()).unwrap();
        let mut frames = frames();
        frames[4] = frames[0];
        let reserved = ReservationSet::<1>::new();
        assert_eq!(
            preflight(&bytes, &plan, &frames, &reserved),
            Err(Error::DuplicateFrame)
        );
    }

    #[test]
    fn preflight_rejects_reserved_frames_before_mapping() {
        let bytes = minimal_exec(EM_AARCH64);
        let plan = plan_aarch64_elf::<4>(&bytes, LoadPolicy::default()).unwrap();
        let frames = frames();
        let mut reserved = ReservationSet::<1>::new();
        reserved
            .reserve(frames[0].start_address(), PAGE_SIZE)
            .unwrap();
        assert_eq!(
            preflight(&bytes, &plan, &frames, &reserved),
            Err(Error::ReservedFrame)
        );
    }

    #[test]
    fn preflight_rejects_truncated_source_without_mutation() {
        let bytes = minimal_exec(EM_AARCH64);
        let plan = plan_aarch64_elf::<4>(&bytes, LoadPolicy::default()).unwrap();
        let frames = frames();
        let reserved = ReservationSet::<1>::new();
        assert_eq!(
            preflight(&bytes[..0x202], &plan, &frames, &reserved),
            Err(Error::Initialization(
                InitializationError::SourceRangeInvalid
            ))
        );
    }

    #[test]
    fn preflight_accepts_valid_aarch64_exec_and_exact_frame_count() {
        let bytes = minimal_exec(EM_AARCH64);
        let plan = plan_aarch64_elf::<4>(&bytes, LoadPolicy::default()).unwrap();
        let frames = frames();
        let reserved = ReservationSet::<1>::new();
        assert_eq!(preflight(&bytes, &plan, &frames, &reserved), Ok(5));
        assert_eq!(plan.entry(), USER_MIN + 0x20_300);
        assert_eq!(plan.stack().stack_pages(), 4);
    }
}
