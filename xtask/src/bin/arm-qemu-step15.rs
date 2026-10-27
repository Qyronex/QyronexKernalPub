// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const AARCH64_TARGET: &str = "aarch64-unknown-none-softfloat";
const AARCH64_CORE_PACKAGE: &str = "kernal-core-aarch64";
const QEMU_TIMEOUT_SECS: u64 = 45;
const CPU_MATRIX: [usize; 3] = [1, 2, 4];

fn main() {
    if let Err(error) = run() {
        eprintln!("step15-qemu: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = workspace_root()?;
    println!("step15-qemu: building unchanged static-musl pthread fixture");
    let fixture = xtask::step15::build_musl_fixture(&root)?;

    println!("step15-qemu: building AArch64 protected proof kernel");
    let mut build = Command::new(cargo());
    // This proof runs inside a one-shot runner worktree. Incremental and debug-symbol artifacts have
    // no reuse value here and previously exhausted the runner volume before QEMU could start. Keep
    // debug assertions and optimization semantics unchanged while bounding only artifact footprint.
    build
        .current_dir(&root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .args([
            "build",
            "--locked",
            "-p",
            AARCH64_CORE_PACKAGE,
            "--target",
            AARCH64_TARGET,
            "--features",
            "step15-qemu-proof",
        ]);
    let status = build
        .status()
        .map_err(|error| format!("start AArch64 Step-15 kernel build: {error}"))?;
    if !status.success() {
        return Err(format!("AArch64 Step-15 kernel build failed with {status}"));
    }

    let kernel = root
        .join("target")
        .join(AARCH64_TARGET)
        .join("debug")
        .join(AARCH64_CORE_PACKAGE);
    let qemu = env::var("STEP15_QEMU").unwrap_or_else(|_| "qemu-system-aarch64".to_string());

    for cpus in CPU_MATRIX {
        println!(
            "step15-qemu: BEGIN {cpus}-vCPU unchanged-musl boot with initrd {}",
            fixture.display()
        );
        let transcript = xtask::step15_qemu::run_step15_qemu_with_cpus(
            Path::new(&qemu),
            &kernel,
            &fixture,
            cpus,
            Duration::from_secs(QEMU_TIMEOUT_SECS),
        )?;

        // Step 15 already owns the unchanged-musl marker and normal-exit contract. Once that
        // milestone is accepted, keep this existing distributed runner job useful for Step 16 by
        // additionally requiring diagnostics that prove the same unchanged program traversed the
        // normal Process/EL0/SVC/write/group-exit owners end to end.
        xtask::step16::require_production_path(&transcript)?;

        print!("{transcript}");
        if !transcript.ends_with('\n') {
            println!();
        }
        println!("step15-qemu: END {cpus}-vCPU unchanged-musl boot accepted");
    }

    println!("step15-qemu: 1/2/4-vCPU unchanged-musl pthread acceptance passed");
    Ok(())
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
