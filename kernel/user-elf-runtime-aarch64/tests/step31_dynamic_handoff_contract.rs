use kernal_elf::{Image, Machine};
use kernal_user_elf::{
    DEFAULT_DYN_LOAD_BIAS, LoadPolicy, UserLoadPlan,
    linux_stack::{LinuxInitialStackSpec, plan_linux_initial_stack},
};
use kernal_user_elf_runtime_aarch64::{
    LinuxProcessStart, plan_aarch64_elf, plan_aarch64_linux_initial_stack,
};

const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PHOFF: usize = 64;
const PHENT: usize = 56;
const ENTRY_OFFSET: u64 = 0x200;
const ARGV0: &[u8] = b"/bin/step31-dynamic";
const RANDOM: [u8; 16] = [
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
];

fn dynamic_aarch64_elf() -> [u8; 0x400] {
    let mut bytes = [0u8; 0x400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&ENTRY_OFFSET.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let p = PHOFF;
    bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[p + 16..p + 24].copy_from_slice(&0u64.to_le_bytes());
    bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
    let file_size = bytes.len() as u64;
    bytes[p + 32..p + 40].copy_from_slice(&file_size.to_le_bytes());
    bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ENTRY_OFFSET as usize..ENTRY_OFFSET as usize + 4]
        .copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    bytes
}

fn expected_layout(
    bytes: &[u8],
    policy: LoadPolicy,
    start: LinuxProcessStart<'_>,
) -> (
    UserLoadPlan<4>,
    kernal_user_elf::linux_stack::LinuxInitialStackLayout,
) {
    let parsed = Image::parse_for_machine(bytes, Machine::Aarch64).unwrap();
    let headers = parsed.program_header_table().unwrap();
    let owner_plan = UserLoadPlan::<4>::from_image(&parsed, policy).unwrap();
    let expected_headers = headers
        .virtual_addr()
        .checked_add(owner_plan.load_bias())
        .unwrap();
    let expected_spec = LinuxInitialStackSpec {
        argv0: start.argv0,
        argv_tail: start.argv_tail,
        envp: start.envp,
        program_headers: expected_headers,
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        entry: owner_plan.entry(),
        random: start.random,
    };
    let layout = plan_linux_initial_stack(owner_plan.stack(), expected_spec).unwrap();
    (owner_plan, layout)
}

#[test]
fn linux_runtime_handoff_matches_public_parser_load_plan_and_stack_owners() {
    let bytes = dynamic_aarch64_elf();
    let policy = LoadPolicy::default();
    let start = LinuxProcessStart::new(ARGV0, RANDOM);

    let runtime_layout = plan_aarch64_linux_initial_stack::<4>(&bytes, policy, start).unwrap();
    let (owner_plan, expected_layout) = expected_layout(&bytes, policy, start);
    assert_eq!(runtime_layout, expected_layout);

    let runtime_plan = plan_aarch64_elf::<4>(&bytes, policy).unwrap();
    assert_eq!(runtime_plan.load_bias(), owner_plan.load_bias());
    assert_eq!(runtime_plan.entry(), owner_plan.entry());
    assert_eq!(runtime_plan.stack(), owner_plan.stack());
}

#[test]
fn custom_et_dyn_policy_is_driven_through_the_public_linux_runtime_planner() {
    let bytes = dynamic_aarch64_elf();
    let custom_bias = DEFAULT_DYN_LOAD_BIAS + 0x20_0000;
    let policy = LoadPolicy {
        dynamic_load_bias: custom_bias,
        ..LoadPolicy::default()
    };
    let start = LinuxProcessStart::new(b"/bin/step31-runtime-custom-bias", [0x6d; 16]);

    let runtime_layout = plan_aarch64_linux_initial_stack::<4>(&bytes, policy, start).unwrap();
    let (owner_plan, expected_layout) = expected_layout(&bytes, policy, start);
    assert_eq!(runtime_layout, expected_layout);
    assert_eq!(owner_plan.load_bias(), custom_bias);
    assert_eq!(owner_plan.entry(), custom_bias + ENTRY_OFFSET);

    let runtime_plan = plan_aarch64_elf::<4>(&bytes, policy).unwrap();
    assert_eq!(runtime_plan.load_bias(), custom_bias);
    assert_eq!(runtime_plan.entry(), owner_plan.entry());
    assert_eq!(runtime_plan.stack(), owner_plan.stack());
}
