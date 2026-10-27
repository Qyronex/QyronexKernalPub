// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::Error;
use kernal_elf::{Image, Machine};
use kernal_user_elf::{DEFAULT_STACK_GUARD_PAGES, DEFAULT_STACK_PAGES};
use kernal_user_elf::{
    LoadPolicy, UserLoadPlan,
    linux_stack::{LinuxInitialStackSpec, initialize_linux_stack_page, plan_linux_initial_stack},
};
use kernal_vm::{PAGE_SIZE, USER_MAX_EXCLUSIVE};

pub use kernal_user_elf::linux_stack::LinuxInitialStackLayout;

/// Default Linux/AArch64 rt_sigreturn trampoline VA. The page immediately below the guarded stack
/// reservation is kept outside every PT_LOAD mapping by the Linux preflight below.
pub const AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE: u64 =
    USER_MAX_EXCLUSIVE - ((DEFAULT_STACK_PAGES + DEFAULT_STACK_GUARD_PAGES + 1) as u64 * PAGE_SIZE);

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const RT_SIGRETURN_TRAMPOLINE_BYTES: [u8; 12] = [
    0x68, 0x11, 0x80, 0xd2, // movz x8, #139 (__NR_rt_sigreturn)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x20, 0xd4, // brk #0: rt_sigreturn must not return
];

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::{Error as LoaderError, LoadedImage, load_aarch64_elf_prepared};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_memory::{PhysFrame, ReservationSet};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_object::ObjectTable;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::Backend;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process::Process;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process_aarch64::BoundProcessAddressSpace;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_vm::{Backing, VmPerms, Vma};

/// Linux process-start data that is not derivable from the parsed ELF image.
///
/// The loader derives AT_PHDR, AT_PHENT, AT_PHNUM and AT_ENTRY from the canonical parser/load plan.
/// Callers supply only argv[0] and the sixteen AT_RANDOM bytes. Production callers must provide
/// actual entropy; the loader deliberately does not invent an entropy guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxProcessStart<'a> {
    pub argv0: &'a [u8],
    pub argv_tail: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    pub random: [u8; 16],
}

impl<'a> LinuxProcessStart<'a> {
    pub const fn new(argv0: &'a [u8], random: [u8; 16]) -> Self {
        Self {
            argv0,
            argv_tail: &[],
            envp: &[],
            random,
        }
    }

    pub const fn with_vectors(
        argv0: &'a [u8],
        argv_tail: &'a [&'a [u8]],
        envp: &'a [&'a [u8]],
        random: [u8; 16],
    ) -> Self {
        Self {
            argv0,
            argv_tail,
            envp,
            random,
        }
    }
}

/// Plans the exact Linux AArch64 process-start stack without mutating an address space.
///
/// Program-header metadata comes from `kernal-elf::Image::program_header_table`; the same accepted
/// ET_DYN load bias used by `UserLoadPlan` is applied before publishing AT_PHDR. The complete compact
/// stack image is built for every mapped stack page before this function returns, so the production
/// loader can fail before its first page-table mutation.
pub fn plan_aarch64_linux_initial_stack<const SEGMENTS: usize>(
    image: &[u8],
    policy: LoadPolicy,
    start: LinuxProcessStart<'_>,
) -> Result<LinuxInitialStackLayout, Error> {
    let (_, _, layout) = prepare_linux_image::<SEGMENTS>(image, policy, start)?;
    Ok(layout)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn load_aarch64_linux_elf<
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    image: &[u8],
    policy: LoadPolicy,
    start: LinuxProcessStart<'_>,
    frames: &[PhysFrame],
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
) -> Result<LoadedImage, Error> {
    let (plan, spec, layout) = prepare_linux_image::<SEGMENTS>(image, policy, start)?;
    let initial_sp = layout.initial_sp();
    let trampoline_address = signal_trampoline_address(&plan)?;
    let base_pages = kernal_user_elf_aarch64::required_pages(&plan)?;
    let expected = base_pages.checked_add(1).ok_or(Error::AddressOverflow)?;
    if frames.len() != expected {
        return Err(Error::FrameCountMismatch {
            expected,
            actual: frames.len(),
        });
    }
    let (base_frames, trampoline_frames) = frames.split_at(base_pages);
    let trampoline_frame = trampoline_frames[0];
    if reserved.contains(trampoline_frame) {
        return Err(Error::ReservedFrame);
    }
    if base_frames.contains(&trampoline_frame) {
        return Err(Error::DuplicateFrame);
    }

    // SAFETY: this wrapper exposes exactly the canonical loader's owner/quiescence contract. The
    // callback runs only while the same temporary process mappings and TTBR0 owner remain active.
    let loaded = unsafe {
        load_aarch64_elf_prepared(
            image,
            plan,
            initial_sp,
            base_frames,
            process,
            objects,
            space,
            backend,
            reserved,
            move |plan| initialize_linux_stack(plan, spec, layout),
        )
    }?;

    // The base image is now final and TTBR0 is inactive. Install the one extra anonymous page through
    // the same Process/AddressSpace owner. Any failure poisons the staged image at the caller boundary.
    unsafe {
        install_rt_sigreturn_trampoline(
            trampoline_address,
            trampoline_frame,
            process,
            objects,
            space,
            backend,
            reserved,
        )?;
    }
    Ok(loaded)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
unsafe fn install_rt_sigreturn_trampoline<
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    B: Backend,
>(
    address: u64,
    frame: PhysFrame,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    reserved: &ReservationSet<RESERVED>,
) -> Result<(), Error> {
    let staging = Vma::new(
        address,
        PAGE_SIZE,
        VmPerms::READ.union(VmPerms::WRITE),
        Backing::Anonymous,
    )
    .map_err(|_| Error::Vm)?;
    space
        .map_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            staging,
            frame,
            reserved,
        )
        .map_err(|_| Error::AddressSpace)?;

    // SAFETY: delegated caller owns the exact process/address-space switch window.
    if unsafe { space.activate_owner(process, objects) }.is_err() {
        let rollback = space.unmap_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            address,
        );
        if rollback != Ok(frame) {
            space.poison();
        }
        return Err(Error::AddressSpace);
    }

    let mut page = [0u8; PAGE_SIZE as usize];
    page[..RT_SIGRETURN_TRAMPOLINE_BYTES.len()].copy_from_slice(&RT_SIGRETURN_TRAMPOLINE_BYTES);
    let initialize = kernal_usercopy_aarch64::copy_to_user(address, &page)
        .map_err(|_| Error::Usercopy)
        .and_then(|()| {
            // SAFETY: same active user VA aliases the exact dedicated Normal-memory frame that will
            // immediately be remapped RX at this VA before any EL0 execution is possible.
            unsafe { kernal_cache_aarch64::sync_modified_code(address, address, PAGE_SIZE) }
                .map_err(|_| Error::CacheMaintenance)
        });
    if unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() }.is_err() {
        space.poison();
        return Err(Error::AddressSpace);
    }
    if let Err(error) = initialize {
        match space.unmap_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            address,
        ) {
            Ok(actual) if actual == frame => return Err(error),
            Ok(_) | Err(_) => {
                space.poison();
                return Err(Error::StagingRollbackFailed);
            }
        }
    }

    let actual = space
        .unmap_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            address,
        )
        .map_err(|_| Error::StagingRollbackFailed)?;
    if actual != frame {
        space.poison();
        return Err(Error::StagingRollbackFailed);
    }
    let final_vma = Vma::new(
        address,
        PAGE_SIZE,
        VmPerms::READ.union(VmPerms::EXECUTE),
        Backing::Anonymous,
    )
    .map_err(|_| Error::Vm)?;
    space
        .map_user_page_coalescing_anonymous(
            process,
            objects,
            process.address_space_handle(),
            backend,
            final_vma,
            frame,
            reserved,
        )
        .map_err(|_| {
            space.poison();
            Error::AddressSpace
        })?;
    Ok(())
}

fn prepare_linux_image<'a, const SEGMENTS: usize>(
    image: &[u8],
    policy: LoadPolicy,
    start: LinuxProcessStart<'a>,
) -> Result<
    (
        UserLoadPlan<SEGMENTS>,
        LinuxInitialStackSpec<'a>,
        LinuxInitialStackLayout,
    ),
    Error,
> {
    let parsed = Image::parse_for_machine(image, Machine::Aarch64)?;
    let program_header_table = parsed.program_header_table()?;
    let plan = UserLoadPlan::from_image(&parsed, policy)?;
    validate_signal_trampoline_gap(&plan)?;
    let program_headers = program_header_table
        .virtual_addr()
        .checked_add(plan.load_bias())
        .ok_or(Error::AddressOverflow)?;
    let program_header_entry_size =
        u64::try_from(program_header_table.entry_size()).map_err(|_| Error::AddressOverflow)?;
    let program_header_count =
        u64::try_from(program_header_table.entry_count()).map_err(|_| Error::AddressOverflow)?;
    let spec = LinuxInitialStackSpec {
        argv0: start.argv0,
        argv_tail: start.argv_tail,
        envp: start.envp,
        program_headers,
        program_header_entry_size,
        program_header_count,
        entry: plan.entry(),
        random: start.random,
    };
    let layout = plan_linux_initial_stack(plan.stack(), spec)?;
    preflight_linux_stack(&plan, spec, layout)?;
    Ok((plan, spec, layout))
}

fn signal_trampoline_address<const SEGMENTS: usize>(
    plan: &UserLoadPlan<SEGMENTS>,
) -> Result<u64, Error> {
    plan.stack()
        .guard_start()
        .checked_sub(PAGE_SIZE)
        .ok_or(Error::AddressOverflow)
}

fn validate_signal_trampoline_gap<const SEGMENTS: usize>(
    plan: &UserLoadPlan<SEGMENTS>,
) -> Result<(), Error> {
    let start = signal_trampoline_address(plan)?;
    let end = start.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    for segment in plan.segments() {
        let pages = u64::try_from(segment.page_count).map_err(|_| Error::AddressOverflow)?;
        let segment_end = segment
            .virtual_page_start
            .checked_add(pages.checked_mul(PAGE_SIZE).ok_or(Error::AddressOverflow)?)
            .ok_or(Error::AddressOverflow)?;
        if segment.virtual_page_start < end && start < segment_end {
            return Err(Error::Vm);
        }
    }
    Ok(())
}

fn preflight_linux_stack<const SEGMENTS: usize>(
    plan: &UserLoadPlan<SEGMENTS>,
    spec: LinuxInitialStackSpec<'_>,
    expected_layout: LinuxInitialStackLayout,
) -> Result<(), Error> {
    let stack = plan.stack();
    let mut scratch = [0u8; PAGE_SIZE as usize];
    for page_index in 0..stack.stack_pages() {
        let layout = initialize_linux_stack_page(stack, spec, page_index, &mut scratch)?;
        if layout != expected_layout {
            return Err(Error::LinuxStackInvariant);
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn initialize_linux_stack<const SEGMENTS: usize>(
    plan: &UserLoadPlan<SEGMENTS>,
    spec: LinuxInitialStackSpec<'_>,
    expected_layout: LinuxInitialStackLayout,
) -> Result<(), Error> {
    let stack = plan.stack();
    let mut page = [0u8; PAGE_SIZE as usize];
    for page_index in 0..stack.stack_pages() {
        let layout = initialize_linux_stack_page(stack, spec, page_index, &mut page)?;
        if layout != expected_layout {
            return Err(Error::LinuxStackInvariant);
        }
        let page_index = u64::try_from(page_index).map_err(|_| Error::AddressOverflow)?;
        let address = stack
            .stack_start()
            .checked_add(
                page_index
                    .checked_mul(PAGE_SIZE)
                    .ok_or(Error::AddressOverflow)?,
            )
            .ok_or(Error::AddressOverflow)?;
        kernal_usercopy_aarch64::copy_to_user(address, &page).map_err(|_| Error::Usercopy)?;
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        return Err(Error::Usercopy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_elf::Error as ElfError;
    use kernal_user_elf::DEFAULT_DYN_LOAD_BIAS;
    use kernal_vm::USER_MIN;

    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const EM_AARCH64: u16 = 183;
    const PT_LOAD: u32 = 1;
    const PHOFF: usize = 64;
    const PHENT: usize = 56;
    const RANDOM: [u8; 16] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];

    fn linux_elf(image_type: u16, virtual_address: u64) -> [u8; 0x400] {
        let mut bytes = [0u8; 0x400];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&image_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(virtual_address + 0x200).to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = PHOFF;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x300u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        bytes
    }

    fn unmapped_program_headers_elf() -> [u8; 0x400] {
        let base = USER_MIN + 0x40_000;
        let mut bytes = linux_elf(ET_EXEC, base);
        let p = PHOFF;
        bytes[24..32].copy_from_slice(&(base + 0x300).to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&(base + 0x200).to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&4u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x800u64.to_le_bytes());
        bytes
    }

    fn start() -> LinuxProcessStart<'static> {
        LinuxProcessStart::new(b"/step15-musl-proof", RANDOM)
    }

    #[test]
    fn default_rt_sigreturn_trampoline_is_one_page_below_stack_guard() {
        let base = USER_MIN + 0x20_000;
        let bytes = linux_elf(ET_EXEC, base);
        let (plan, _, _) =
            prepare_linux_image::<4>(&bytes, LoadPolicy::default(), start()).unwrap();
        let address = signal_trampoline_address(&plan).unwrap();
        assert_eq!(address, AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE);
        assert_eq!(address + PAGE_SIZE, plan.stack().guard_start());
        assert_eq!(
            u32::from_le_bytes(RT_SIGRETURN_TRAMPOLINE_BYTES[0..4].try_into().unwrap()),
            0xd280_1168
        );
        assert_eq!(
            u32::from_le_bytes(RT_SIGRETURN_TRAMPOLINE_BYTES[4..8].try_into().unwrap()),
            0xd400_0001
        );
        assert_eq!(
            u32::from_le_bytes(RT_SIGRETURN_TRAMPOLINE_BYTES[8..12].try_into().unwrap()),
            0xd420_0000
        );
    }

    #[test]
    fn process_start_vector_constructor_preserves_legacy_wrapper_and_full_vectors() {
        static TAIL: [&[u8]; 1] = [b"arg1"];
        static ENV: [&[u8]; 1] = [b"KEY=value"];
        let legacy = LinuxProcessStart::new(b"/bin/app", RANDOM);
        assert!(legacy.argv_tail.is_empty());
        assert!(legacy.envp.is_empty());
        let full = LinuxProcessStart::with_vectors(b"/bin/app", &TAIL, &ENV, RANDOM);
        assert_eq!(full.argv_tail, &TAIL);
        assert_eq!(full.envp, &ENV);
    }

    #[test]
    fn executable_stack_uses_parser_owned_mapped_program_headers() {
        let base = USER_MIN + 0x20_000;
        let bytes = linux_elf(ET_EXEC, base);
        let (plan, spec, layout) =
            prepare_linux_image::<4>(&bytes, LoadPolicy::default(), start()).unwrap();

        assert_eq!(plan.load_bias(), 0);
        assert_eq!(spec.program_headers, base + PHOFF as u64);
        assert_eq!(spec.program_header_entry_size, PHENT as u64);
        assert_eq!(spec.program_header_count, 1);
        assert_eq!(spec.entry, base + 0x200);
        assert_eq!(layout.initial_sp() % 16, 0);
        assert_ne!(layout.initial_sp(), plan.stack().initial_sp());
    }

    #[test]
    fn dynamic_stack_applies_the_exact_user_load_bias_to_at_phdr() {
        let bytes = linux_elf(ET_DYN, 0);
        let policy = LoadPolicy::default();
        let (plan, spec, _) = prepare_linux_image::<4>(&bytes, policy, start()).unwrap();

        assert_eq!(plan.load_bias(), DEFAULT_DYN_LOAD_BIAS);
        assert_eq!(spec.program_headers, DEFAULT_DYN_LOAD_BIAS + PHOFF as u64);
        assert_eq!(spec.entry, DEFAULT_DYN_LOAD_BIAS + 0x200);
    }

    #[test]
    fn unmapped_program_header_table_fails_before_linux_stack_publication() {
        let bytes = unmapped_program_headers_elf();
        assert_eq!(
            plan_aarch64_linux_initial_stack::<4>(&bytes, LoadPolicy::default(), start()),
            Err(Error::Elf(ElfError::ProgramHeaderTableNotMapped))
        );
    }

    #[test]
    fn invalid_linux_start_data_is_reported_through_the_shared_loader_error() {
        let base = USER_MIN + 0x60_000;
        let bytes = linux_elf(ET_EXEC, base);
        let bad = LinuxProcessStart::new(b"bad\0name", RANDOM);
        assert_eq!(
            plan_aarch64_linux_initial_stack::<4>(&bytes, LoadPolicy::default(), bad),
            Err(Error::LinuxStack(
                kernal_user_elf::linux_stack::Error::Argv0ContainsNul
            ))
        );
    }
}
