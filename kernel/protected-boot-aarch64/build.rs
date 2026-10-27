use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const FREESTANDING_CONSTANT_PREFIXES: &[&str] = &[
    "const MAX_PROOF_PES:",
    "const BOOT_MMIO_REGIONS:",
    "const QEMU_VIRT_RAM_BASE:",
    "const MAX_QEMU_DTB_BYTES:",
    "const FDT_MAGIC:",
    "const FDT_HEADER_BYTES:",
    "const RESCHEDULE_SGI:",
    "const PROOF_TIMEOUT_SECONDS:",
    "const PL011_DR:",
    "const PL011_FR:",
    "const PL011_LCR_H:",
    "const PL011_CR:",
    "const PL011_IMSC:",
    "const PL011_ICR:",
    "const PL011_FR_TXFF:",
    "const PL011_LCR_H_WLEN_8:",
    "const PL011_CR_UARTEN:",
    "const PL011_CR_TXE:",
    "const PL011_CR_RXE:",
];

fn sanitize(path: &Path, remove_module_declarations: bool) -> String {
    let source = fs::read_to_string(path).expect("read protected ARM source");
    let mut generated = String::with_capacity(source.len());
    let implementation_source = path.ends_with("implementation.rs");
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#![") {
            continue;
        }
        if remove_module_declarations && matches!(trimmed, "mod mmu;" | "mod transition_state;") {
            continue;
        }
        if implementation_source
            && FREESTANDING_CONSTANT_PREFIXES
                .iter()
                .any(|prefix| trimmed.starts_with(prefix))
        {
            generated.push_str("#[cfg(all(target_arch = \"aarch64\", target_os = \"none\"))]\n");
        }
        generated.push_str(line);
        generated.push('\n');
    }

    // Rust 1.98 does not coerce a bare function item returning `!` to every `FnOnce() -> T`
    // required by Option::unwrap_or_else. A closure has the expected return context and preserves
    // the fail-stop function's real diverging type, including in `let ... else` and statement use.
    let generated = generated.replace(
        ".unwrap_or_else(fatal_silent)",
        ".unwrap_or_else(|| fatal_silent())",
    );

    // QEMU's direct bare-metal ELF path used by this project does not guarantee a DTB pointer in
    // x0. The already-proven ARM entry explicitly used the documented QEMU virt RAM base where the
    // generated DTB is placed. Preserve that contract in the protected replacement entry as well.
    let generated = generated.replace(
        "    mov x0, x20\n    bl kernal_aarch64_protected_boot",
        "    mov x0, #1\n    lsl x0, x0, #30\n    bl kernal_aarch64_protected_boot",
    );

    // The published allocation count is part of the transition evidence, not diagnostic baggage.
    // Reject an impossible zero-table high state before trusting SCTLR/PC/SP observations.
    generated.replace(
        "fn verify_initial_high_state(state: &BootState) -> Result<(), ()> {\n    let translation",
        "fn verify_initial_high_state(state: &BootState) -> Result<(), ()> {\n    if state.table_pages_used == 0 {\n        return Err(());\n    }\n    let translation",
    )
}

fn write_generated(out_dir: &Path, name: &str, source: String) {
    fs::write(out_dir.join(name), source).expect("write generated protected ARM source");
}

fn user_elf_rustc(root: &Path) -> Command {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let configured_wrapper = env::var_os("RUSTC_WRAPPER").filter(|value| !value.is_empty());
    let wrapper = configured_wrapper
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("tools/rustup-rustc-wrapper.sh"));
    let wrapper = if wrapper.is_absolute() {
        wrapper
    } else {
        root.join(wrapper)
    };

    if wrapper.is_file() {
        let mut command = Command::new(wrapper);
        // Cargo's rustc-wrapper contract passes the real compiler path as argv[1]. Reproduce that
        // exact contract so generated user ELFs use the same pinned Rust 1.98 toolchain as the
        // kernel build instead of accidentally invoking a different host rustc directly.
        command.arg(rustc);
        command
    } else {
        Command::new(rustc)
    }
}

fn run_user_elf_rustc(
    root: &Path,
    crate_name: &str,
    source: &Path,
    linker: &Path,
    output: &Path,
) -> ExitStatus {
    let mut command = user_elf_rustc(root);
    let linker_arg = format!("link-arg=-T{}", linker.display());
    command
        .arg("--crate-name")
        .arg(crate_name)
        .arg("--edition=2024")
        .arg("--crate-type=bin")
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .arg("-Cpanic=abort")
        .arg("-Crelocation-model=static")
        .arg("-Cdebuginfo=0")
        .arg("-Copt-level=s")
        .arg("-C")
        .arg(linker_arg)
        .arg("-Clink-arg=-no-pie")
        .arg("-Clink-arg=--build-id=none")
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("spawn rustc for AArch64 user ELF")
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn build_step12_user_elf(out_dir: &Path) {
    let root = workspace_root();
    let source = root.join("tests/step12-user-aarch64/src/main.rs");
    let linker = root.join("tests/step12-user-aarch64/linker.ld");
    let output = out_dir.join("step12-user-aarch64.elf");

    let status = run_user_elf_rustc(
        &root,
        "kernal_step12_user_aarch64",
        &source,
        &linker,
        &output,
    );
    if !status.success() {
        panic!("Step-12 native AArch64 user ELF build failed: {status}");
    }
    println!(
        "cargo:rustc-env=KERNAL_STEP12_USER_ELF={}",
        output.display()
    );
}

fn build_step14_user_elfs(out_dir: &Path) {
    let root = workspace_root();
    let linker = root.join("tests/step14-linux-aarch64/linker.ld");
    let main_source = root.join("tests/step14-linux-aarch64/src/main.rs");
    let exit_source = root.join("tests/step14-linux-aarch64/src/exit.rs");
    let main_output = out_dir.join("step14-linux-aarch64.elf");
    let exit_output = out_dir.join("step14-linux-exit-aarch64.elf");

    let main_status = run_user_elf_rustc(
        &root,
        "kernal_step14_linux_aarch64",
        &main_source,
        &linker,
        &main_output,
    );
    if !main_status.success() {
        panic!("Step-14 Linux AArch64 bootstrap ELF build failed: {main_status}");
    }

    let exit_status = run_user_elf_rustc(
        &root,
        "kernal_step14_linux_exit_aarch64",
        &exit_source,
        &linker,
        &exit_output,
    );
    if !exit_status.success() {
        panic!("Step-14 Linux AArch64 exit ELF build failed: {exit_status}");
    }

    println!(
        "cargo:rustc-env=KERNAL_STEP14_USER_ELF={}",
        main_output.display()
    );
    println!(
        "cargo:rustc-env=KERNAL_STEP14_EXIT_USER_ELF={}",
        exit_output.display()
    );
}

fn main() {
    for source in [
        "src/implementation.rs",
        "src/mmu.rs",
        "src/transition_state.rs",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_STEP12_QEMU_PROOF");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_STEP14_QEMU_PROOF");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=RUSTC_WRAPPER");
    println!("cargo:rerun-if-changed=../../tools/rustup-rustc-wrapper.sh");
    println!("cargo:rerun-if-changed=../../tests/step12-user-aarch64/src/main.rs");
    println!("cargo:rerun-if-changed=../../tests/step12-user-aarch64/linker.ld");
    println!("cargo:rerun-if-changed=../../tests/step14-linux-aarch64/src/main.rs");
    println!("cargo:rerun-if-changed=../../tests/step14-linux-aarch64/src/exit.rs");
    println!("cargo:rerun-if-changed=../../tests/step14-linux-aarch64/linker.ld");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    write_generated(
        &out_dir,
        "implementation.rs",
        sanitize(Path::new("src/implementation.rs"), true),
    );
    write_generated(&out_dir, "mmu.rs", sanitize(Path::new("src/mmu.rs"), false));
    write_generated(
        &out_dir,
        "transition_state.rs",
        sanitize(Path::new("src/transition_state.rs"), false),
    );

    if env::var_os("CARGO_FEATURE_STEP12_QEMU_PROOF").is_some() {
        build_step12_user_elf(&out_dir);
    }
    if env::var_os("CARGO_FEATURE_STEP14_QEMU_PROOF").is_some() {
        build_step14_user_elfs(&out_dir);
    }
}
