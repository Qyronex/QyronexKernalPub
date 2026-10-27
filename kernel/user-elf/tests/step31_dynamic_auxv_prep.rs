// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_elf::{Image, Machine};
use kernal_load_plan::PAGE_SIZE;
use kernal_user_elf::linux_stack::{LinuxInitialStackSpec, initialize_linux_stack_page};
use kernal_user_elf::{DEFAULT_DYN_LOAD_BIAS, LoadPolicy, UserLoadPlan};

const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

fn dynamic_aarch64_elf() -> [u8; 0x200] {
    let mut bytes = [0u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(ELF64_EHDR_SIZE as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let image_len = bytes.len() as u64;
    let ph = ELF64_EHDR_SIZE;
    bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R-X
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&image_len.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes
}

fn word(page: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap())
}

fn auxv_value(auxv: &[(u64, u64)], kind: u64) -> Option<u64> {
    auxv.iter()
        .find_map(|(candidate, value)| (*candidate == kind).then_some(*value))
}

fn encoded_auxv<const N: usize>(
    plan: &UserLoadPlan<N>,
    spec: LinuxInitialStackSpec<'_>,
) -> Vec<(u64, u64)> {
    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let page_start = stack.stack_start() + (last_page as u64 * PAGE_SIZE);
    let mut page = [0u8; PAGE_SIZE as usize];
    let layout = initialize_linux_stack_page(stack, spec, last_page, &mut page).unwrap();
    let mut cursor = usize::try_from(layout.initial_sp() - page_start).unwrap();

    assert_eq!(word(&page, cursor), 1);
    cursor += 4 * 8; // argc, argv[0], argv terminator, envp terminator

    let mut auxv = Vec::new();
    loop {
        let kind = word(&page, cursor);
        let value = word(&page, cursor + 8);
        cursor += 16;
        if kind == AT_NULL {
            assert_eq!(value, 0);
            break;
        }
        auxv.push((kind, value));
    }
    auxv
}

#[test]
fn et_dyn_metadata_flows_into_current_linux_auxv_without_fabricating_at_base() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();

    assert_eq!(plan.load_bias(), DEFAULT_DYN_LOAD_BIAS);
    assert_eq!(plan.entry(), DEFAULT_DYN_LOAD_BIAS + 0x100);
    assert_eq!(headers.virtual_addr(), ELF64_EHDR_SIZE as u64);

    let program_headers = plan.load_bias() + headers.virtual_addr();
    let random = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-dynamic",
        argv_tail: &[],
        envp: &[],
        program_headers,
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        entry: plan.entry(),
        random,
    };

    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let page_start = stack.stack_start() + (last_page as u64 * PAGE_SIZE);
    let mut page = [0u8; PAGE_SIZE as usize];
    let layout = initialize_linux_stack_page(stack, spec, last_page, &mut page).unwrap();
    let auxv = encoded_auxv(&plan, spec);

    assert_eq!(auxv_value(&auxv, AT_PHDR), Some(program_headers));
    assert_eq!(
        auxv_value(&auxv, AT_PHENT),
        Some(headers.entry_size() as u64)
    );
    assert_eq!(
        auxv_value(&auxv, AT_PHNUM),
        Some(headers.entry_count() as u64)
    );
    assert_eq!(auxv_value(&auxv, AT_PAGESZ), Some(PAGE_SIZE));
    assert_eq!(auxv_value(&auxv, AT_ENTRY), Some(plan.entry()));
    assert_eq!(auxv_value(&auxv, AT_RANDOM), Some(layout.random()));
    assert_eq!(auxv_value(&auxv, AT_EXECFN), Some(layout.argv0()));

    // Step 31 runtime composition still owns interpreter mapping and AT_BASE publication. PREP
    // records the current boundary explicitly instead of fabricating a loader base before that owner
    // is released after Step 30.7.
    assert_eq!(auxv_value(&auxv, AT_BASE), None);

    let random_offset = usize::try_from(layout.random() - page_start).unwrap();
    assert_eq!(&page[random_offset..random_offset + random.len()], &random);
}

#[test]
fn custom_et_dyn_load_bias_is_preserved_in_auxv_metadata() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let custom_bias = DEFAULT_DYN_LOAD_BIAS + 0x20_0000;
    let policy = LoadPolicy {
        dynamic_load_bias: custom_bias,
        ..LoadPolicy::default()
    };
    let plan = UserLoadPlan::<4>::from_image(&image, policy).unwrap();

    assert_eq!(plan.load_bias(), custom_bias);
    assert_eq!(plan.entry(), custom_bias + 0x100);

    let program_headers = custom_bias + headers.virtual_addr();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-custom-bias",
        argv_tail: &[],
        envp: &[],
        program_headers,
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        entry: plan.entry(),
        random: [0x5a; 16],
    };
    let auxv = encoded_auxv(&plan, spec);

    assert_eq!(auxv_value(&auxv, AT_PHDR), Some(program_headers));
    assert_eq!(auxv_value(&auxv, AT_ENTRY), Some(custom_bias + 0x100));
    assert_eq!(auxv_value(&auxv, AT_BASE), None);
}

#[test]
fn identity_and_secure_auxv_entries_remain_explicit_step31_integration_deltas() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-identity-auxv",
        argv_tail: &[],
        envp: &[],
        program_headers: plan.load_bias() + headers.virtual_addr(),
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        entry: plan.entry(),
        random: [0xa5; 16],
    };
    let auxv = encoded_auxv(&plan, spec);

    for kind in [AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE] {
        assert_eq!(
            auxv_value(&auxv, kind),
            None,
            "identity/security auxv kind {kind} became visible during PREP; replace this delta assertion with its final Step-31 value contract"
        );
    }
}

#[test]
fn all_zero_at_random_remains_an_explicit_step31_integration_delta() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-zero-random",
        argv_tail: &[],
        envp: &[],
        program_headers: plan.load_bias() + headers.virtual_addr(),
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        entry: plan.entry(),
        random: [0; 16],
    };

    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let page_start = stack.stack_start() + (last_page as u64 * PAGE_SIZE);
    let mut page = [0u8; PAGE_SIZE as usize];
    let layout = initialize_linux_stack_page(stack, spec, last_page, &mut page).unwrap();
    let auxv = encoded_auxv(&plan, spec);
    assert_eq!(auxv_value(&auxv, AT_RANDOM), Some(layout.random()));

    let random_offset = usize::try_from(layout.random() - page_start).unwrap();
    assert_eq!(&page[random_offset..random_offset + 16], &[0; 16]);
}
