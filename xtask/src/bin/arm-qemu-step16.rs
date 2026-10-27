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
        eprintln!("step16-qemu: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = workspace_root()?;
    println!("step16-qemu: building the unchanged static-musl Step-15 fixture");
    let fixture = xtask::step15::build_musl_fixture(&root)?;

    println!("step16-qemu: building the accepted AArch64 production-path proof kernel");
    let mut build = Command::new(cargo());
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
        .map_err(|error| format!("start AArch64 Step-16 proof kernel build: {error}"))?;
    if !status.success() {
        return Err(format!(
            "AArch64 Step-16 proof kernel build failed with {status}"
        ));
    }

    let kernel = root
        .join("target")
        .join(AARCH64_TARGET)
        .join("debug")
        .join(AARCH64_CORE_PACKAGE);
    let qemu = env::var("STEP16_QEMU")
        .or_else(|_| env::var("STEP15_QEMU"))
        .unwrap_or_else(|_| "qemu-system-aarch64".to_string());

    for cpus in CPU_MATRIX {
        println!(
            "step16-qemu: BEGIN {cpus}-vCPU unchanged-Linux production proof with initrd {}",
            fixture.display()
        );
        let transcript = xtask::step15_qemu::run_step15_qemu_with_cpus(
            Path::new(&qemu),
            &kernel,
            &fixture,
            cpus,
            Duration::from_secs(QEMU_TIMEOUT_SECS),
        )?;
        xtask::step16::require_production_path(&transcript)?;

        print!("{transcript}");
        if !transcript.ends_with('\n') {
            println!();
        }
        println!("step16-qemu: END {cpus}-vCPU unchanged-Linux production proof accepted");
    }

    println!("step16-qemu: 1/2/4-vCPU unchanged Linux ARM64 program proof passed");
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
