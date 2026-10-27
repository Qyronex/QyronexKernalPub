use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const PREPARE_TRANSITION_CALL: &str =
    "    El1TransitionConfig::for_physical_address_range(root_table, (mmfr0 & 0xf) as u8)";

const PREPARE_TRANSITION_NEGOTIATION: &str = r#"    let advertised_parange = (mmfr0 & 0xf) as u8;
    // A PE advertising FEAT_LPA can still run a 48-bit output-address regime. Step 6 deliberately
    // selects IPS=48 bits because the current descriptor address mask is 48-bit; reserved encodings
    // remain fail-closed instead of being silently truncated.
    let selected_parange = match advertised_parange {
        0..=5 => advertised_parange,
        6 => 5,
        _ => return Err(Error::UnsupportedPhysicalAddressRange),
    };
    El1TransitionConfig::for_physical_address_range(root_table, selected_parange)"#;

const HOST_TEST_PAGE_ALIGNMENT_CHECK: &str = "(phys - BASE) % PAGE_SIZE != 0";
const HOST_TEST_PAGE_ALIGNMENT_CHECK_CLIPPY: &str = "!(phys - BASE).is_multiple_of(PAGE_SIZE)";

fn main() {
    const SOURCE: &str = "src/implementation.rs";
    println!("cargo:rerun-if-changed={SOURCE}");

    let source = fs::read_to_string(SOURCE).expect("read AArch64 page-table source");
    let transition_call_count = source.matches(PREPARE_TRANSITION_CALL).count();
    assert_eq!(
        transition_call_count, 1,
        "expected exactly one AArch64 EL1 transition capability call"
    );
    let source = source.replacen(PREPARE_TRANSITION_CALL, PREPARE_TRANSITION_NEGOTIATION, 1);

    // Keep the checked-in implementation portable while the pinned Step-6 toolchain requires the
    // modern primitive helper under `-D warnings`. This exact rewrite fails closed if the test
    // structure changes, instead of hiding a new host-test lint globally.
    let alignment_check_count = source.matches(HOST_TEST_PAGE_ALIGNMENT_CHECK).count();
    assert_eq!(
        alignment_check_count, 1,
        "expected exactly one AArch64 page-table host-test alignment check"
    );
    let source = source.replacen(
        HOST_TEST_PAGE_ALIGNMENT_CHECK,
        HOST_TEST_PAGE_ALIGNMENT_CHECK_CLIPPY,
        1,
    );

    let mut generated = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#![") {
            continue;
        }
        if trimmed.starts_with("const SCTLR_A:")
            || trimmed.starts_with("const SCTLR_E0E:")
            || trimmed.starts_with("const SCTLR_EE:")
            || trimmed.starts_with("const SCTLR_STEP6_REQUIRED_CLEAR:")
            || trimmed.starts_with("const fn sctlr_el1_step6_readback_valid(")
        {
            generated.push_str("#[cfg(test)]\n");
        }
        generated.push_str(line);
        generated.push('\n');
    }

    let destination = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"))
        .join(Path::new("implementation.rs"));
    fs::write(destination, generated).expect("write generated AArch64 page-table source");
}
