// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::InitialStackPlan;
use kernal_load_plan::PAGE_SIZE;

const STACK_ALIGNMENT: u64 = 16;
const WORD_BYTES: u64 = 8;
const RANDOM_BYTES: usize = 16;
pub const MAX_ARGV0_BYTES: usize = 127;
pub const MAX_ARGC: usize = 16;
pub const MAX_ENVC: usize = 16;
pub const MAX_STRING_BYTES: usize = 2048;
const MAX_INITIAL_IMAGE_BYTES: usize = 4096;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

const AUX_ENTRIES_WITH_NULL: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyArgv0,
    Argv0TooLong,
    Argv0ContainsNul,
    TooManyArguments,
    TooManyEnvironmentEntries,
    VectorStringContainsNul,
    VectorStringsTooLarge,
    InvalidElfMetadata,
    AddressOverflow,
    StackTooSmall,
    PageSizeMismatch,
    PageIndexOutOfRange,
}

/// Already-validated Linux ELF metadata needed by the initial userspace ABI.
///
/// ELF parsing and load-bias arithmetic stay owned by the existing ELF/load-plan layers. This
/// encoder only serializes those trusted scalar results into the Linux process-start stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxInitialStackSpec<'a> {
    pub argv0: &'a [u8],
    /// Additional argv entries after argv[0]. The complete argv vector is bounded and allocation-free.
    pub argv_tail: &'a [&'a [u8]],
    /// Environment strings without trailing NUL bytes.
    pub envp: &'a [&'a [u8]],
    pub program_headers: u64,
    pub program_header_entry_size: u64,
    pub program_header_count: u64,
    pub entry: u64,
    /// Sixteen caller-supplied bytes exposed through AT_RANDOM. The stack encoder does not claim
    /// that these bytes are cryptographically random; production callers must supply real entropy.
    pub random: [u8; RANDOM_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxInitialStackLayout {
    initial_sp: u64,
    argv0: u64,
    random: u64,
    image_end: u64,
}

impl LinuxInitialStackLayout {
    pub const fn initial_sp(self) -> u64 {
        self.initial_sp
    }

    pub const fn argv0(self) -> u64 {
        self.argv0
    }

    pub const fn random(self) -> u64 {
        self.random
    }

    pub const fn image_end(self) -> u64 {
        self.image_end
    }
}

struct BuiltStack {
    layout: LinuxInitialStackLayout,
    bytes: [u8; MAX_INITIAL_IMAGE_BYTES],
    len: usize,
}

/// Plans the Linux process-start image without mutating an address space.
pub fn plan_linux_initial_stack(
    stack: InitialStackPlan,
    spec: LinuxInitialStackSpec<'_>,
) -> Result<LinuxInitialStackLayout, Error> {
    Ok(build_stack(stack, spec)?.layout)
}

/// Initializes one physical stack page with a Linux argc/argv/envp/auxv process-start image.
///
/// The complete compact image is validated and built in scratch storage before `destination` is
/// touched. Pages outside the initial image are deterministically zeroed, preserving the accepted
/// Step-12 stack behavior while allowing the Linux runtime to opt into the richer ABI.
pub fn initialize_linux_stack_page(
    stack: InitialStackPlan,
    spec: LinuxInitialStackSpec<'_>,
    page_index: usize,
    destination: &mut [u8],
) -> Result<LinuxInitialStackLayout, Error> {
    if destination.len() != PAGE_SIZE as usize {
        return Err(Error::PageSizeMismatch);
    }
    if page_index >= stack.stack_pages() {
        return Err(Error::PageIndexOutOfRange);
    }

    let built = build_stack(stack, spec)?;
    let page_offset = (page_index as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::AddressOverflow)?;
    let page_start = stack
        .stack_start()
        .checked_add(page_offset)
        .ok_or(Error::AddressOverflow)?;
    let page_end = page_start
        .checked_add(PAGE_SIZE)
        .ok_or(Error::AddressOverflow)?;

    let copy_start = core::cmp::max(page_start, built.layout.initial_sp);
    let copy_end = core::cmp::min(page_end, built.layout.image_end);
    let copy = if copy_start < copy_end {
        let source_start = usize::try_from(
            copy_start
                .checked_sub(built.layout.initial_sp)
                .ok_or(Error::AddressOverflow)?,
        )
        .map_err(|_| Error::AddressOverflow)?;
        let source_end = usize::try_from(
            copy_end
                .checked_sub(built.layout.initial_sp)
                .ok_or(Error::AddressOverflow)?,
        )
        .map_err(|_| Error::AddressOverflow)?;
        let destination_start = usize::try_from(
            copy_start
                .checked_sub(page_start)
                .ok_or(Error::AddressOverflow)?,
        )
        .map_err(|_| Error::AddressOverflow)?;
        let destination_end = usize::try_from(
            copy_end
                .checked_sub(page_start)
                .ok_or(Error::AddressOverflow)?,
        )
        .map_err(|_| Error::AddressOverflow)?;
        if source_end > built.len || destination_end > destination.len() {
            return Err(Error::AddressOverflow);
        }
        Some((source_start, source_end, destination_start, destination_end))
    } else {
        None
    };

    destination.fill(0);
    if let Some((source_start, source_end, destination_start, destination_end)) = copy {
        destination[destination_start..destination_end]
            .copy_from_slice(&built.bytes[source_start..source_end]);
    }
    Ok(built.layout)
}

fn build_stack(
    stack: InitialStackPlan,
    spec: LinuxInitialStackSpec<'_>,
) -> Result<BuiltStack, Error> {
    validate_spec(spec)?;

    let argc = 1usize
        .checked_add(spec.argv_tail.len())
        .ok_or(Error::AddressOverflow)?;
    let envc = spec.envp.len();
    let mut argv_addresses = [0u64; MAX_ARGC];
    let mut env_addresses = [0u64; MAX_ENVC];
    let mut string_cursor = stack.stack_end();

    for (index, address) in argv_addresses.iter_mut().enumerate().take(argc) {
        let value = if index == 0 {
            spec.argv0
        } else {
            spec.argv_tail[index - 1]
        };
        string_cursor = reserve_c_string(string_cursor, value)?;
        *address = string_cursor;
    }
    for (index, value) in spec.envp.iter().copied().enumerate() {
        string_cursor = reserve_c_string(string_cursor, value)?;
        env_addresses[index] = string_cursor;
    }

    let random = string_cursor
        .checked_sub(RANDOM_BYTES as u64)
        .ok_or(Error::StackTooSmall)?;
    let vector_words = 1u64
        .checked_add(u64::try_from(argc).map_err(|_| Error::AddressOverflow)?)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(u64::try_from(envc).ok()?))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(AUX_ENTRIES_WITH_NULL * 2))
        .ok_or(Error::AddressOverflow)?;
    let vector_bytes = vector_words
        .checked_mul(WORD_BYTES)
        .ok_or(Error::AddressOverflow)?;
    let vector_unaligned = random
        .checked_sub(vector_bytes)
        .ok_or(Error::StackTooSmall)?;
    let initial_sp = align_down(vector_unaligned, STACK_ALIGNMENT);
    if initial_sp < stack.stack_start() || initial_sp >= stack.stack_end() {
        return Err(Error::StackTooSmall);
    }

    let image_span = stack
        .stack_end()
        .checked_sub(initial_sp)
        .ok_or(Error::AddressOverflow)?;
    let len = usize::try_from(image_span).map_err(|_| Error::AddressOverflow)?;
    if len > MAX_INITIAL_IMAGE_BYTES {
        return Err(Error::StackTooSmall);
    }

    let layout = LinuxInitialStackLayout {
        initial_sp,
        argv0: argv_addresses[0],
        random,
        image_end: stack.stack_end(),
    };
    let mut bytes = [0u8; MAX_INITIAL_IMAGE_BYTES];
    let mut cursor = initial_sp;

    write_word(
        &mut bytes,
        layout,
        &mut cursor,
        u64::try_from(argc).map_err(|_| Error::AddressOverflow)?,
    )?;
    for address in argv_addresses[..argc].iter().copied() {
        write_word(&mut bytes, layout, &mut cursor, address)?;
    }
    write_word(&mut bytes, layout, &mut cursor, 0)?;
    for address in env_addresses[..envc].iter().copied() {
        write_word(&mut bytes, layout, &mut cursor, address)?;
    }
    write_word(&mut bytes, layout, &mut cursor, 0)?;

    for (kind, value) in [
        (AT_PHDR, spec.program_headers),
        (AT_PHENT, spec.program_header_entry_size),
        (AT_PHNUM, spec.program_header_count),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_ENTRY, spec.entry),
        (AT_RANDOM, random),
        (AT_EXECFN, argv_addresses[0]),
        (AT_NULL, 0),
    ] {
        write_word(&mut bytes, layout, &mut cursor, kind)?;
        write_word(&mut bytes, layout, &mut cursor, value)?;
    }
    if cursor > random {
        return Err(Error::StackTooSmall);
    }

    write_bytes(&mut bytes, layout, random, &spec.random)?;
    for (index, address) in argv_addresses.iter().copied().enumerate().take(argc) {
        let value = if index == 0 {
            spec.argv0
        } else {
            spec.argv_tail[index - 1]
        };
        write_c_string(&mut bytes, layout, address, value)?;
    }
    for (index, value) in spec.envp.iter().copied().enumerate() {
        write_c_string(&mut bytes, layout, env_addresses[index], value)?;
    }

    Ok(BuiltStack { layout, bytes, len })
}

fn reserve_c_string(cursor: u64, value: &[u8]) -> Result<u64, Error> {
    cursor
        .checked_sub(
            u64::try_from(value.len())
                .map_err(|_| Error::AddressOverflow)?
                .checked_add(1)
                .ok_or(Error::AddressOverflow)?,
        )
        .ok_or(Error::StackTooSmall)
}

fn write_c_string(
    bytes: &mut [u8; MAX_INITIAL_IMAGE_BYTES],
    layout: LinuxInitialStackLayout,
    address: u64,
    value: &[u8],
) -> Result<(), Error> {
    write_bytes(bytes, layout, address, value)?;
    let nul = address
        .checked_add(u64::try_from(value.len()).map_err(|_| Error::AddressOverflow)?)
        .ok_or(Error::AddressOverflow)?;
    write_bytes(bytes, layout, nul, &[0])
}

fn validate_spec(spec: LinuxInitialStackSpec<'_>) -> Result<(), Error> {
    if spec.argv0.is_empty() {
        return Err(Error::EmptyArgv0);
    }
    if spec.argv0.len() > MAX_ARGV0_BYTES {
        return Err(Error::Argv0TooLong);
    }
    if spec.argv0.contains(&0) {
        return Err(Error::Argv0ContainsNul);
    }
    if spec.argv_tail.len() >= MAX_ARGC {
        return Err(Error::TooManyArguments);
    }
    if spec.envp.len() > MAX_ENVC {
        return Err(Error::TooManyEnvironmentEntries);
    }
    let mut total_strings = spec
        .argv0
        .len()
        .checked_add(1)
        .ok_or(Error::AddressOverflow)?;
    for value in spec.argv_tail.iter().chain(spec.envp.iter()) {
        if value.contains(&0) {
            return Err(Error::VectorStringContainsNul);
        }
        total_strings = total_strings
            .checked_add(value.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::AddressOverflow)?;
    }
    if total_strings > MAX_STRING_BYTES {
        return Err(Error::VectorStringsTooLarge);
    }
    if spec.program_headers == 0
        || spec.program_header_entry_size == 0
        || spec.program_header_count == 0
        || spec.entry == 0
    {
        return Err(Error::InvalidElfMetadata);
    }
    Ok(())
}

fn write_word(
    bytes: &mut [u8; MAX_INITIAL_IMAGE_BYTES],
    layout: LinuxInitialStackLayout,
    cursor: &mut u64,
    value: u64,
) -> Result<(), Error> {
    write_bytes(bytes, layout, *cursor, &value.to_le_bytes())?;
    *cursor = cursor
        .checked_add(WORD_BYTES)
        .ok_or(Error::AddressOverflow)?;
    Ok(())
}

fn write_bytes(
    bytes: &mut [u8; MAX_INITIAL_IMAGE_BYTES],
    layout: LinuxInitialStackLayout,
    address: u64,
    source: &[u8],
) -> Result<(), Error> {
    if address < layout.initial_sp || address > layout.image_end {
        return Err(Error::AddressOverflow);
    }
    let offset = usize::try_from(
        address
            .checked_sub(layout.initial_sp)
            .ok_or(Error::AddressOverflow)?,
    )
    .map_err(|_| Error::AddressOverflow)?;
    let end = offset
        .checked_add(source.len())
        .ok_or(Error::AddressOverflow)?;
    let image_len = usize::try_from(
        layout
            .image_end
            .checked_sub(layout.initial_sp)
            .ok_or(Error::AddressOverflow)?,
    )
    .map_err(|_| Error::AddressOverflow)?;
    if end > image_len || end > bytes.len() {
        return Err(Error::AddressOverflow);
    }
    bytes[offset..end].copy_from_slice(source);
    Ok(())
}

const fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK_START: u64 = 0x0000_0001_0000_0000;
    const STACK_PAGES: usize = 4;
    const STACK_END: u64 = STACK_START + (STACK_PAGES as u64 * PAGE_SIZE);
    const RANDOM: [u8; RANDOM_BYTES] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];

    fn stack() -> InitialStackPlan {
        InitialStackPlan {
            guard_start: STACK_START - PAGE_SIZE,
            stack_start: STACK_START,
            stack_end: STACK_END,
            initial_sp: STACK_END - STACK_ALIGNMENT,
            stack_pages: STACK_PAGES,
            guard_pages: 1,
        }
    }

    fn spec() -> LinuxInitialStackSpec<'static> {
        LinuxInitialStackSpec {
            argv0: b"/step15-musl-proof",
            argv_tail: &[],
            envp: &[],
            program_headers: 0x0000_0000_0040_0040,
            program_header_entry_size: 56,
            program_header_count: 7,
            entry: 0x0000_0000_0040_1000,
            random: RANDOM,
        }
    }

    fn read_u64(page: &[u8], page_start: u64, address: u64) -> u64 {
        let offset = usize::try_from(address - page_start).unwrap();
        u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn linux_stack_has_aligned_sp_and_expected_vectors() {
        let layout = plan_linux_initial_stack(stack(), spec()).unwrap();
        assert_eq!(layout.initial_sp() % STACK_ALIGNMENT, 0);
        assert!(layout.initial_sp() >= STACK_START);
        assert!(layout.argv0() < STACK_END);
        assert!(layout.random() < layout.argv0());

        let mut page = [0xa5u8; PAGE_SIZE as usize];
        let page_index = STACK_PAGES - 1;
        let returned = initialize_linux_stack_page(stack(), spec(), page_index, &mut page).unwrap();
        assert_eq!(returned, layout);
        let page_start = STACK_END - PAGE_SIZE;
        let mut cursor = layout.initial_sp();

        assert_eq!(read_u64(&page, page_start, cursor), 1);
        cursor += 8;
        assert_eq!(read_u64(&page, page_start, cursor), layout.argv0());
        cursor += 8;
        assert_eq!(read_u64(&page, page_start, cursor), 0);
        cursor += 8;
        assert_eq!(read_u64(&page, page_start, cursor), 0);
        cursor += 8;

        for (kind, value) in [
            (AT_PHDR, spec().program_headers),
            (AT_PHENT, 56),
            (AT_PHNUM, 7),
            (AT_PAGESZ, PAGE_SIZE),
            (AT_ENTRY, spec().entry),
            (AT_RANDOM, layout.random()),
            (AT_EXECFN, layout.argv0()),
            (AT_NULL, 0),
        ] {
            assert_eq!(read_u64(&page, page_start, cursor), kind);
            cursor += 8;
            assert_eq!(read_u64(&page, page_start, cursor), value);
            cursor += 8;
        }

        let argv_offset = usize::try_from(layout.argv0() - page_start).unwrap();
        assert_eq!(
            &page[argv_offset..argv_offset + spec().argv0.len()],
            spec().argv0
        );
        assert_eq!(page[argv_offset + spec().argv0.len()], 0);
        let random_offset = usize::try_from(layout.random() - page_start).unwrap();
        assert_eq!(&page[random_offset..random_offset + RANDOM_BYTES], &RANDOM);
    }

    #[test]
    fn linux_stack_serializes_bounded_argv_and_envp_vectors() {
        static ARGV_TAIL: [&[u8]; 2] = [b"--mode", b"test"];
        static ENVP: [&[u8]; 2] = [b"A=1", b"B=two"];
        let mut rich = spec();
        rich.argv_tail = &ARGV_TAIL;
        rich.envp = &ENVP;
        let layout = plan_linux_initial_stack(stack(), rich).unwrap();
        let mut page = [0u8; PAGE_SIZE as usize];
        initialize_linux_stack_page(stack(), rich, STACK_PAGES - 1, &mut page).unwrap();
        let page_start = STACK_END - PAGE_SIZE;
        let mut cursor = layout.initial_sp();
        assert_eq!(read_u64(&page, page_start, cursor), 3);
        cursor += 8;
        let argv0 = read_u64(&page, page_start, cursor);
        cursor += 8;
        let argv1 = read_u64(&page, page_start, cursor);
        cursor += 8;
        let argv2 = read_u64(&page, page_start, cursor);
        cursor += 8;
        assert_eq!(read_u64(&page, page_start, cursor), 0);
        cursor += 8;
        let env0 = read_u64(&page, page_start, cursor);
        cursor += 8;
        let env1 = read_u64(&page, page_start, cursor);
        cursor += 8;
        assert_eq!(read_u64(&page, page_start, cursor), 0);
        assert_eq!(argv0, layout.argv0());
        for (address, value) in [
            (argv0, rich.argv0),
            (argv1, ARGV_TAIL[0]),
            (argv2, ARGV_TAIL[1]),
            (env0, ENVP[0]),
            (env1, ENVP[1]),
        ] {
            let offset = usize::try_from(address - page_start).unwrap();
            assert_eq!(&page[offset..offset + value.len()], value);
            assert_eq!(page[offset + value.len()], 0);
        }
    }

    #[test]
    fn pages_below_initial_image_remain_zero() {
        let mut page = [0xa5u8; PAGE_SIZE as usize];
        initialize_linux_stack_page(stack(), spec(), 0, &mut page).unwrap();
        assert!(page.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_input_does_not_mutate_destination() {
        let mut bad = spec();
        bad.argv0 = b"bad\0name";
        let mut page = [0xa5u8; PAGE_SIZE as usize];
        assert_eq!(
            initialize_linux_stack_page(stack(), bad, STACK_PAGES - 1, &mut page),
            Err(Error::Argv0ContainsNul)
        );
        assert!(page.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn invalid_page_does_not_mutate_destination() {
        let mut page = [0xa5u8; PAGE_SIZE as usize];
        assert_eq!(
            initialize_linux_stack_page(stack(), spec(), STACK_PAGES, &mut page),
            Err(Error::PageIndexOutOfRange)
        );
        assert!(page.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn invalid_elf_metadata_is_rejected() {
        let mut bad = spec();
        bad.program_headers = 0;
        assert_eq!(
            plan_linux_initial_stack(stack(), bad),
            Err(Error::InvalidElfMetadata)
        );
    }
}
