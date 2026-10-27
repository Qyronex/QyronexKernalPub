// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

mod step28;
mod step29_final_fs_qemu;
mod step30_final_qemu;

use kernal_tsc_x86_64::QEMU_PROOF_TSC_HZ;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

const UEFI_TARGET: &str = "x86_64-unknown-uefi";
const BOOT_PACKAGE: &str = "kernal-boot-uefi";
const CORE_TARGET: &str = "x86_64-unknown-none";
const CORE_PACKAGE: &str = "kernal-core";
const AARCH64_CORE_TARGET: &str = "aarch64-unknown-none-softfloat";
const AARCH64_CORE_PACKAGE: &str = "kernal-core-aarch64";
const PINNED_RUST: &str = "1.98.0";
const QEMU_SUCCESS_STATUS: i32 = 33;
const AARCH64_QEMU_SUCCESS_STATUS: i32 = 0;
const QEMU_TIMEOUT_SECS: u64 = 45;
const HOST_TEST_PACKAGES: &[&str] = &[
    "kernal-bootinfo",
    "kernal-linux-x86-64-abi",
    "kernal-native-abi",
    "kernal-elf",
    "kernal-handoff",
    "kernal-load-plan",
    "kernal-mapping-plan",
    "kernal-memory-map",
    "kernal-transition-x86-64",
    "kernal-pci",
    "kernal-acpi",
    "kernal-acpi-fadt",
    "kernal-acpi-fadt-physical",
    "kernal-acpi-mcfg",
    "kernal-acpi-physical",
    "kernal-acpi-srat",
    "kernal-fdt",
    "kernal-fdt-aarch64",
    "kernal-address-space-aarch64",
    "kernal-address-space-x86-64",
    "kernal-ap-startup-x86-64",
    "kernal-apic-runtime-x86-64",
    "kernal-apic-timer-x86-64",
    "kernal-apic-x86-64",
    "kernal-arch-aarch64",
    "kernal-arch-x86-64",
    "kernal-bootstrap-memory",
    "kernal-capability",
    "kernal-context-aarch64",
    "kernal-context-x86-64",
    "kernal-descriptors-x86-64",
    "kernal-exceptions-aarch64",
    "kernal-exceptions-x86-64",
    "kernal-frame-allocator",
    "kernal-futex",
    "kernal-gicv3-aarch64",
    "kernal-idle-x86-64",
    "kernal-iommu",
    "kernal-interrupt-control-x86-64",
    "kernal-interrupts-x86-64",
    "kernal-ioapic-x86-64",
    "kernal-ipc",
    "kernal-irq-runtime-x86-64",
    "kernal-irq-state-x86-64",
    "kernal-kmap",
    "kernal-kmap-x86-64",
    "kernal-memory",
    "kernal-object",
    "kernal-page-table",
    "kernal-page-table-aarch64",
    "kernal-paging",
    "kernal-percpu",
    "kernal-percpu-aarch64",
    "kernal-percpu-layout-x86-64",
    "kernal-percpu-x86-64",
    "kernal-physical-io",
    "kernal-pic8259-x86-64",
    "kernal-pm-timer-x86-64",
    "kernal-protected-boot-aarch64",
    "kernal-psci-aarch64",
    "kernal-recursive-paging-x86-64",
    "kernal-reschedule-x86-64",
    "kernal-runtime-page-table-x86-64",
    "kernal-scheduler",
    "kernal-scheduler-cpu",
    "kernal-scheduler-smp",
    "kernal-smp-x86-64",
    "kernal-thread-bootstrap-x86-64",
    "kernal-thread-context",
    "kernal-thread-reaper-x86-64",
    "kernal-thread-stack-x86-64",
    "kernal-tickless-x86-64",
    "kernal-time",
    "kernal-timer-aarch64",
    "kernal-timer-runtime-x86-64",
    "kernal-tlb-x86-64",
    "kernal-topology",
    "kernal-tsc-bootstrap-x86-64",
    "kernal-tsc-x86-64",
    "kernal-vm",
    "xtask",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "arm-build" => build_aarch64(false),
        "arm-qemu" => {
            step28::run()?;
            step29_final_fs_qemu::run()?;
            step30_final_qemu::run()
        }
        "build" => build(false),
        "doctor" => doctor(),
        "image" => {
            build(false)?;
            image()
        }
        "qemu" => {
            build(true)?;
            image()?;
            qemu_with_cpus(1)
        }
        "qemu-smp" => {
            build(true)?;
            image()?;
            qemu_with_cpus(2)?;
            qemu_with_cpus(4)
        }
        "test" => test(),
        "verify" => verify(),
        "loc" => {
            let write_report = matches!(args.next().as_deref(), Some("--write"));
            line_count(write_report)
        }
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!("Kernal xtask");
    println!("  cargo xtask doctor      - validate local Rust/QEMU/OVMF prerequisites");
    println!(
        "  cargo xtask verify      - execute the current multi-architecture Step 7 address-space proof pipeline"
    );
    println!("  cargo xtask build       - build x86 UEFI loader and freestanding kernel core");
    println!("  cargo xtask image       - create a FAT-directory x86 EFI system partition");
    println!("  cargo xtask qemu        - single-CPU x86 bootstrap/scheduler/IRQ proof");
    println!("  cargo xtask qemu-smp    - boot the x86 proof with 2 and 4 vCPUs");
    println!("  cargo xtask arm-build   - build the freestanding AArch64 bring-up core");
    println!(
        "  cargo xtask arm-qemu    - run accepted Step-28/29 regressions, then the final Step-30 process-runtime QEMU oracle"
    );
    println!(
        "  cargo xtask test        - run host tests and x86 QEMU proofs with 1, 2 and 4 vCPUs"
    );
    println!("  cargo xtask loc         - print local physical line counts by source category");
    println!("  cargo xtask loc --write - also write the deterministic report to LOC.md");
}

fn qemu_cpu_profile() -> String {
    format!("max,tsc-frequency={QEMU_PROOF_TSC_HZ}")
}

fn doctor() -> Result<(), String> {
    println!("xtask doctor: checking local multi-architecture Step 7 prerequisites");
    let host_arch = env::consts::ARCH;
    println!("  host architecture: {host_arch}");
    if !matches!(host_arch, "x86_64" | "aarch64") {
        return Err(format!(
            "unsupported Step 7 developer host architecture {host_arch}; expected x86_64 or aarch64"
        ));
    }

    let rustc = command_output(Command::new("rustc").arg("--version"), "rustc --version")?;
    println!("  rustc: {rustc}");
    if !rustc.contains(PINNED_RUST) {
        return Err(format!(
            "expected pinned Rust {PINNED_RUST}; rust-toolchain.toml should select it"
        ));
    }

    let cargo_version = command_output(Command::new(cargo()).arg("--version"), "cargo --version")?;
    println!("  cargo: {cargo_version}");

    let qemu_x86 = command_output(
        Command::new("qemu-system-x86_64").arg("--version"),
        "qemu-system-x86_64 --version",
    )?;
    println!(
        "  qemu x86_64: {}",
        qemu_x86.lines().next().unwrap_or(&qemu_x86)
    );

    let qemu_arm = command_output(
        Command::new("qemu-system-aarch64").arg("--version"),
        "qemu-system-aarch64 --version",
    )?;
    println!(
        "  qemu aarch64: {}",
        qemu_arm.lines().next().unwrap_or(&qemu_arm)
    );

    let ovmf_code = find_ovmf_code()?;
    println!("  OVMF CODE: {}", ovmf_code.display());
    if let Some(vars) = find_ovmf_vars(&ovmf_code) {
        println!("  OVMF VARS template: {}", vars.display());
    } else {
        println!("  OVMF VARS template: not found; QEMU will use code-only firmware mode");
    }
    println!("  x86 QEMU CPU proof profile: {}", qemu_cpu_profile());
    println!("  AArch64 QEMU machine: virt,gic-version=3; CPU max");
    println!("  QEMU proof timeout: {QEMU_TIMEOUT_SECS}s per boot");

    let root = workspace_root()?;
    for target in [UEFI_TARGET, CORE_TARGET, AARCH64_CORE_TARGET] {
        let target_dir = root.join("target").join(target);
        println!(
            "  target {target}: configured{}",
            if target_dir.exists() {
                " (build directory exists)"
            } else {
                ""
            }
        );
    }
    println!("xtask doctor: prerequisites look usable");
    Ok(())
}

fn verify() -> Result<(), String> {
    doctor()?;
    println!("xtask verify: 1/12 format");
    let mut fmt = Command::new(cargo());
    fmt.args(["fmt", "--all", "--check"]);
    run_checked(&mut fmt, "cargo fmt")?;

    println!("xtask verify: 2/12 host unit tests (x86_64 + AArch64 support crates)");
    host_tests()?;

    println!("xtask verify: 3/12 clippy host support crates");
    host_clippy()?;

    println!("xtask verify: 4/12 x86 UEFI + freestanding builds");
    build(true)?;
    image()?;

    println!("xtask verify: 5/12 x86 QEMU 1 vCPU");
    qemu_with_cpus(1)?;

    println!("xtask verify: 6/12 x86 QEMU 2 vCPUs");
    qemu_with_cpus(2)?;

    println!("xtask verify: 7/12 x86 QEMU 4 vCPUs");
    qemu_with_cpus(4)?;

    println!("xtask verify: 8/12 AArch64 freestanding proof build");
    build_aarch64(true)?;

    println!("xtask verify: 9/12 AArch64 QEMU 1 vCPU");
    qemu_aarch64_with_cpus(1)?;

    println!("xtask verify: 10/12 AArch64 QEMU 2 vCPUs");
    qemu_aarch64_with_cpus(2)?;

    println!("xtask verify: 11/12 AArch64 QEMU 4 vCPUs");
    qemu_aarch64_with_cpus(4)?;

    println!("xtask verify: 12/12 deterministic LOC report");
    line_count(true)?;
    println!("xtask verify: Step 7 multi-architecture address-space isolation proof passed");
    Ok(())
}

fn host_tests() -> Result<(), String> {
    let mut tests = Command::new(cargo());
    tests.arg("test");
    for package in HOST_TEST_PACKAGES {
        tests.args(["-p", package]);
    }
    run_checked(&mut tests, "host unit tests")
}

fn host_clippy() -> Result<(), String> {
    let mut clippy = Command::new(cargo());
    clippy.arg("clippy");
    for package in HOST_TEST_PACKAGES {
        clippy.args(["-p", package]);
    }
    clippy.args(["--all-targets", "--", "-D", "warnings"]);
    run_checked(&mut clippy, "host clippy")
}

fn build(qemu_exit: bool) -> Result<(), String> {
    let mut loader = Command::new(cargo());
    loader.args(["build", "-p", BOOT_PACKAGE, "--target", UEFI_TARGET]);
    run_checked(&mut loader, "UEFI build")?;

    let mut core = Command::new(cargo());
    core.args(["build", "-p", CORE_PACKAGE, "--target", CORE_TARGET]);
    if qemu_exit {
        core.args(["--features", "qemu-exit"]);
    }
    run_checked(&mut core, "kernel core build")
}

fn build_aarch64(qemu_proof: bool) -> Result<(), String> {
    let mut core = Command::new(cargo());
    core.args([
        "build",
        "-p",
        AARCH64_CORE_PACKAGE,
        "--target",
        AARCH64_CORE_TARGET,
    ]);
    if qemu_proof {
        core.args(["--features", "qemu-proof"]);
    }
    run_checked(&mut core, "AArch64 kernel core build")
}

fn image() -> Result<(), String> {
    let root = workspace_root()?;
    let source = root
        .join("target")
        .join(UEFI_TARGET)
        .join("debug")
        .join("kernal-boot-uefi.efi");
    let destination = root
        .join("target")
        .join("esp")
        .join("EFI")
        .join("BOOT")
        .join("BOOTX64.EFI");
    let core_source = root
        .join("target")
        .join(CORE_TARGET)
        .join("debug")
        .join("kernal-core");
    let core_destination = root
        .join("target")
        .join("esp")
        .join("KERNAL")
        .join("CORE.ELF");
    fs::create_dir_all(destination.parent().ok_or("invalid ESP destination")?)
        .map_err(|e| format!("create ESP directory: {e}"))?;
    fs::copy(&source, &destination).map_err(|e| {
        format!(
            "copy {} -> {}: {e}",
            source.display(),
            destination.display()
        )
    })?;
    fs::create_dir_all(
        core_destination
            .parent()
            .ok_or("invalid kernel destination")?,
    )
    .map_err(|e| format!("create kernel directory: {e}"))?;
    fs::copy(&core_source, &core_destination).map_err(|e| {
        format!(
            "copy {} -> {}: {e}",
            core_source.display(),
            core_destination.display()
        )
    })?;
    println!(
        "xtask: EFI image directory ready at {}",
        destination.display()
    );
    Ok(())
}

fn qemu_with_cpus(cpus: usize) -> Result<(), String> {
    if cpus == 0 {
        return Err("QEMU CPU count must be non-zero".to_string());
    }
    let root = workspace_root()?;
    let ovmf_code = find_ovmf_code()?;
    let esp = root.join("target").join("esp");
    let fat_drive = format!("format=raw,file=fat:rw:{}", esp.display());
    let cpu_count = cpus.to_string();
    let cpu_profile = qemu_cpu_profile();
    println!("xtask: booting x86 QEMU with {cpus} vCPU(s), CPU {cpu_profile}");

    let mut command = Command::new("qemu-system-x86_64");
    command
        .args(["-machine", "q35", "-m", "256M", "-cpu"])
        .arg(&cpu_profile)
        .args(["-smp"])
        .arg(&cpu_count)
        .args([
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "stdio",
            "-no-reboot",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive",
        ])
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            ovmf_code.display()
        ));

    if let Some(vars_template) = find_ovmf_vars(&ovmf_code) {
        let vars_copy = root.join("target").join(format!("ovmf-vars-{cpus}.fd"));
        fs::copy(&vars_template, &vars_copy).map_err(|e| {
            format!(
                "copy OVMF VARS {} -> {}: {e}",
                vars_template.display(),
                vars_copy.display()
            )
        })?;
        command
            .args(["-drive"])
            .arg(format!("if=pflash,format=raw,file={}", vars_copy.display()));
    }
    command.args(["-drive", &fat_drive]);

    let mut child = command
        .spawn()
        .map_err(|e| format!("start x86 QEMU ({cpus} vCPUs): {e}"))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("poll x86 QEMU ({cpus} vCPUs): {e}"))?
        {
            return qemu_status(status);
        }
        if start.elapsed() >= Duration::from_secs(QEMU_TIMEOUT_SECS) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "x86 QEMU {cpus}-vCPU proof exceeded {QEMU_TIMEOUT_SECS}s and was killed"
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn qemu_aarch64_with_cpus(cpus: usize) -> Result<(), String> {
    if cpus == 0 {
        return Err("AArch64 QEMU CPU count must be non-zero".to_string());
    }
    let root = workspace_root()?;
    let kernel = root
        .join("target")
        .join(AARCH64_CORE_TARGET)
        .join("debug")
        .join(AARCH64_CORE_PACKAGE);
    if !kernel.exists() {
        return Err(format!(
            "AArch64 kernel image not found: {}; run cargo xtask arm-build first",
            kernel.display()
        ));
    }

    let cpu_count = cpus.to_string();
    println!("xtask: booting AArch64 QEMU virt bring-up with {cpus} vCPU(s), GICv3, CPU max");
    let mut command = Command::new("qemu-system-aarch64");
    command
        .args([
            "-machine",
            "virt,gic-version=3",
            "-cpu",
            "max",
            "-m",
            "512M",
            "-smp",
        ])
        .arg(&cpu_count)
        .args(["-nographic", "-monitor", "none", "-no-reboot", "-kernel"])
        .arg(&kernel);

    let mut child = command
        .spawn()
        .map_err(|e| format!("start AArch64 QEMU ({cpus} vCPUs): {e}"))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("poll AArch64 QEMU ({cpus} vCPUs): {e}"))?
        {
            return qemu_aarch64_status(status);
        }
        if start.elapsed() >= Duration::from_secs(QEMU_TIMEOUT_SECS) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "AArch64 QEMU {cpus}-vCPU proof exceeded {QEMU_TIMEOUT_SECS}s and was killed"
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn qemu_status(status: ExitStatus) -> Result<(), String> {
    match status.code() {
        Some(QEMU_SUCCESS_STATUS) => Ok(()),
        Some(code) => Err(format!("x86 QEMU exited with unexpected status {code}")),
        None => Err("x86 QEMU terminated by signal".to_string()),
    }
}

fn qemu_aarch64_status(status: ExitStatus) -> Result<(), String> {
    match status.code() {
        Some(AARCH64_QEMU_SUCCESS_STATUS) => Ok(()),
        Some(code) => Err(format!("AArch64 QEMU exited with unexpected status {code}")),
        None => Err("AArch64 QEMU terminated by signal".to_string()),
    }
}

fn test() -> Result<(), String> {
    host_tests()?;
    build(true)?;
    image()?;
    qemu_with_cpus(1)?;
    qemu_with_cpus(2)?;
    qemu_with_cpus(4)
}

#[derive(Clone, Copy, Default)]
struct LineStats {
    files: u64,
    total: u64,
    blank: u64,
    comment: u64,
    content: u64,
}

impl LineStats {
    fn add(&mut self, other: Self) {
        self.files += other.files;
        self.total += other.total;
        self.blank += other.blank;
        self.comment += other.comment;
        self.content += other.content;
    }
}

fn line_count(write_report: bool) -> Result<(), String> {
    let root = workspace_root()?;
    let mut by_category = BTreeMap::<&'static str, LineStats>::new();
    scan_loc_directory(&root, &mut by_category)?;

    let mut total = LineStats::default();
    let mut report = String::from(
        "# Kernal line count\n\nGenerated by `cargo xtask loc --write`. Counts are physical UTF-8 text lines; comment classification is intentionally conservative and is not a semantic parser.\n\n| Category | Files | Total | Content | Comment | Blank |\n| --- | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for (category, stats) in &by_category {
        total.add(*stats);
        report.push_str(&format!(
            "| {category} | {} | {} | {} | {} | {} |\n",
            stats.files, stats.total, stats.content, stats.comment, stats.blank
        ));
    }
    report.push_str(&format!(
        "| **TOTAL** | **{}** | **{}** | **{}** | **{}** | **{}** |\n",
        total.files, total.total, total.content, total.comment, total.blank
    ));
    report.push_str(
        "\nExcluded directories: `.git`, `target`, `.idea`, `.vscode`, `node_modules`, `vendor`. `Cargo.lock` and generated `LOC.md` are excluded from the count.\n",
    );

    print!("{report}");
    if write_report {
        let destination = root.join("LOC.md");
        fs::write(&destination, report.as_bytes())
            .map_err(|e| format!("write {}: {e}", destination.display()))?;
        println!("xtask: wrote {}", destination.display());
    }
    Ok(())
}

fn scan_loc_directory(
    directory: &Path,
    by_category: &mut BTreeMap<&'static str, LineStats>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|e| format!("read directory {}: {e}", directory.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("read directory entry in {}: {e}", directory.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "target" | ".idea" | ".vscode" | "node_modules" | "vendor"
            ) {
                continue;
            }
            scan_loc_directory(&path, by_category)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "Cargo.lock" | "LOC.md"))
        {
            continue;
        }
        let Some(category) = loc_category(&path) else {
            continue;
        };
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let stats = classify_text_lines(text);
        by_category.entry(category).or_default().add(stats);
    }
    Ok(())
}

fn loc_category(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "rs" => Some("Rust"),
        "s" | "asm" | "ld" => Some("Assembly / linker"),
        "toml" | "yml" | "yaml" | "json" => Some("Build / config"),
        "md" => Some("Documentation"),
        "sh" | "py" => Some("Scripts"),
        _ => None,
    }
}

fn classify_text_lines(text: &str) -> LineStats {
    let mut stats = LineStats {
        files: 1,
        ..LineStats::default()
    };
    for line in text.lines() {
        stats.total += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            stats.blank += 1;
        } else if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("<!--")
        {
            stats.comment += 1;
        } else {
            stats.content += 1;
        }
    }
    stats
}

fn find_ovmf_code() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("OVMF_CODE") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("OVMF_CODE does not exist: {}", path.display()));
    }
    [
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/x64/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
        "/usr/local/share/qemu/edk2-x86_64-code.fd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
    .ok_or_else(|| "OVMF not found; set OVMF_CODE=/path/to/OVMF_CODE.fd".to_string())
}

fn find_ovmf_vars(code: &Path) -> Option<PathBuf> {
    if let Ok(path) = env::var("OVMF_VARS") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    let sibling = code
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| {
            if name.contains("CODE") {
                Some(code.with_file_name(name.replace("CODE", "VARS")))
            } else if name == "edk2-x86_64-code.fd" {
                Some(code.with_file_name("edk2-x86_64-vars.fd"))
            } else {
                None
            }
        });
    if sibling.as_ref().is_some_and(|path| path.exists()) {
        return sibling;
    }

    [
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
        "/usr/share/edk2/x64/OVMF_VARS.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        "/opt/homebrew/share/qemu/edk2-x86_64-vars.fd",
        "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
        "/usr/local/share/qemu/edk2-x86_64-vars.fd",
        "/usr/local/share/qemu/edk2-i386-vars.fd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn command_output(command: &mut Command, label: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|e| format!("start {label}: {e}"))?;
    if !output.status.success() {
        return Err(format!("{label} failed with {}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stdout.is_empty() {
        Ok(stdout)
    } else if !stderr.is_empty() {
        Ok(stderr)
    } else {
        Ok("ok".to_string())
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot determine workspace root".to_string())
}

fn cargo() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn run_checked(command: &mut Command, label: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|e| format!("start {label}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loc_classifier_separates_content_comments_and_blanks() {
        let stats = classify_text_lines("fn main() {}\n// comment\n\n# heading\n");
        assert_eq!(stats.files, 1);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.content, 1);
        assert_eq!(stats.comment, 2);
        assert_eq!(stats.blank, 1);
    }

    #[test]
    fn loc_categories_cover_kernel_sources_and_project_docs() {
        assert_eq!(
            loc_category(Path::new("kernel/core/src/main.rs")),
            Some("Rust")
        );
        assert_eq!(
            loc_category(Path::new("kernel/core/linker.ld")),
            Some("Assembly / linker")
        );
        assert_eq!(loc_category(Path::new("STATUS.md")), Some("Documentation"));
        assert_eq!(loc_category(Path::new("image.png")), None);
    }

    #[test]
    fn timing_and_aarch64_foundations_are_in_host_gate() {
        for required in [
            "kernal-address-space-aarch64",
            "kernal-address-space-x86-64",
            "kernal-acpi-fadt",
            "kernal-acpi-fadt-physical",
            "kernal-apic-timer-x86-64",
            "kernal-pm-timer-x86-64",
            "kernal-tsc-bootstrap-x86-64",
            "kernal-fdt",
            "kernal-fdt-aarch64",
            "kernal-arch-aarch64",
            "kernal-context-aarch64",
            "kernal-exceptions-aarch64",
            "kernal-gicv3-aarch64",
            "kernal-page-table-aarch64",
            "kernal-percpu-aarch64",
            "kernal-protected-boot-aarch64",
            "kernal-psci-aarch64",
            "kernal-timer-aarch64",
        ] {
            assert!(
                HOST_TEST_PACKAGES.contains(&required),
                "missing host gate for {required}"
            );
        }
    }

    #[test]
    fn qemu_profile_uses_canonical_synthetic_tsc_frequency() {
        assert_eq!(
            qemu_cpu_profile(),
            format!("max,tsc-frequency={QEMU_PROOF_TSC_HZ}")
        );
    }

    #[test]
    fn aarch64_kernel_target_is_soft_float_until_simd_state_is_managed() {
        assert_eq!(AARCH64_CORE_TARGET, "aarch64-unknown-none-softfloat");
    }

    #[test]
    fn qemu_timeout_is_bounded() {
        assert!((10..=120).contains(&QEMU_TIMEOUT_SECS));
    }
}
