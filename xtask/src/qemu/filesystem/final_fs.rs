// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const POSITIVE_BUILDER: &str = "tools/step29/build-fs-breadth-fixture.sh";
const NEGATIVE_BUILDER: &str = "tools/step29/build-fs-breadth-negative-fixture.sh";
const POSITIVE_FIXTURE: &str = "target/step29/fs-breadth-roundtrip";
const NEGATIVE_FIXTURE: &str = "target/step29/fs-breadth-negative";
const POSITIVE_INITRAMFS: &str = "target/step29/fs-breadth-initramfs.cpio";
const NEGATIVE_INITRAMFS: &str = "target/step29/fs-breadth-negative-initramfs.cpio";
const POSITIVE_KERNEL: &str = "target/step29/kernal-core-aarch64-fs-breadth";
const NEGATIVE_KERNEL: &str = "target/step29/kernal-core-aarch64-fs-breadth-negative";
const INITRAMFS_EXECUTABLE: &str = "bin/busybox";
const CPIO_TRAILER: &str = "TRAILER!!!";
const CPIO_HEADER_BYTES: usize = 110;
const MAX_INITRAMFS_BYTES: u64 = 16 * 1024 * 1024;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

const POSITIVE_SUCCESS_MARKER: &str = "KERNAL/S29FS: mutable filesystem roundtrip passed";
const POSITIVE_FINALIZED_MARKER: &str =
    "KERNAL/S29FS: mutable filesystem fixture finalized status=0";
const NEGATIVE_SUCCESS_MARKER: &str = "KERNAL/S29FSN: negative filesystem contract passed";
const NEGATIVE_FINALIZED_MARKER: &str =
    "KERNAL/S29FSN: negative filesystem fixture finalized status=0";

pub(super) fn run(root: &Path) -> Result<(), String> {
    let positive_fixture = build_fixture(root, POSITIVE_BUILDER, POSITIVE_FIXTURE, "positive")?;
    let negative_fixture = build_fixture(root, NEGATIVE_BUILDER, NEGATIVE_FIXTURE, "negative")?;
    let positive_initramfs =
        build_fixture_initramfs(root, &positive_fixture, POSITIVE_INITRAMFS, "positive")?;
    let negative_initramfs =
        build_fixture_initramfs(root, &negative_fixture, NEGATIVE_INITRAMFS, "negative")?;

    let positive_kernel =
        super::build_step29_kernel(root, "step29-fs-breadth-qemu-proof", POSITIVE_KERNEL)?;
    let negative_kernel = super::build_step29_kernel(
        root,
        "step29-fs-breadth-negative-qemu-proof",
        NEGATIVE_KERNEL,
    )?;

    for cpus in super::ACCEPTED_CPU_COUNTS {
        println!("xtask: Step 29 mutable filesystem positive QEMU proof with {cpus} vCPU(s)");
        let positive = super::run_qemu(
            root,
            &positive_kernel,
            &positive_initramfs,
            cpus,
            "filesystem-positive",
        )?;
        require_positive_markers(&positive)?;

        println!("xtask: Step 29 mutable filesystem negative QEMU proof with {cpus} vCPU(s)");
        let negative = super::run_qemu(
            root,
            &negative_kernel,
            &negative_initramfs,
            cpus,
            "filesystem-negative",
        )?;
        require_negative_markers(&negative)?;
    }

    println!("xtask: Step 29 mutable filesystem positive+negative 1/2/4-vCPU matrix passed");
    Ok(())
}

fn build_fixture(root: &Path, builder: &str, output: &str, proof: &str) -> Result<Vec<u8>, String> {
    let builder = root.join(builder);
    if !builder.is_file() {
        return Err(format!(
            "Step-29 {proof} filesystem fixture builder not found: {}",
            builder.display()
        ));
    }

    let status = Command::new("bash")
        .arg(&builder)
        .current_dir(root)
        .status()
        .map_err(|error| {
            format!(
                "start Step-29 {proof} filesystem fixture builder {}: {error}",
                builder.display()
            )
        })?;
    if !status.success() {
        return Err(format!(
            "Step-29 {proof} filesystem fixture builder failed with {status}"
        ));
    }

    let path = root.join(output);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "read Step-29 {proof} filesystem fixture {}: {error}",
            path.display()
        )
    })?;
    validate_static_aarch64_elf(&bytes, proof)?;
    Ok(bytes)
}

fn build_fixture_initramfs(
    root: &Path,
    fixture: &[u8],
    output_path: &str,
    proof: &str,
) -> Result<PathBuf, String> {
    let mut output = Vec::new();
    newc_entry(&mut output, 1, ".", 0o040755, &[])?;
    newc_entry(&mut output, 2, "bin", 0o040755, &[])?;
    // Reuse the exact Step-28/29 CPIO+ELF selection boundary. Only the executable bytes at the
    // canonical archive member differ; the kernel loader still parses `bin/busybox` through the
    // accepted protected-initrd owner and canonical AArch64 ELF path.
    newc_entry(&mut output, 3, INITRAMFS_EXECUTABLE, 0o100755, fixture)?;
    newc_entry(&mut output, 4, CPIO_TRAILER, 0, &[])?;
    while !output.len().is_multiple_of(512) {
        output.push(0);
    }
    if output.is_empty() || output.len() as u64 > MAX_INITRAMFS_BYTES {
        return Err(format!(
            "Step-29 {proof} filesystem initramfs size is outside policy: {} bytes",
            output.len()
        ));
    }

    let path = root.join(output_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create Step-29 {proof} filesystem initramfs directory {}: {error}",
                parent.display()
            )
        })?;
    }
    fs::write(&path, &output).map_err(|error| {
        format!(
            "write Step-29 {proof} filesystem initramfs {}: {error}",
            path.display()
        )
    })?;
    super::validate_initramfs(&path)?;
    Ok(path)
}

fn newc_entry(
    output: &mut Vec<u8>,
    inode: u32,
    path: &str,
    mode: u32,
    payload: &[u8],
) -> Result<(), String> {
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err("invalid Step-29 filesystem proof initramfs path".to_string());
    }
    let file_size = u32::try_from(payload.len())
        .map_err(|_| "Step-29 filesystem proof CPIO payload exceeds u32".to_string())?;
    let name_size = u32::try_from(path.len() + 1)
        .map_err(|_| "Step-29 filesystem proof CPIO path exceeds u32".to_string())?;
    let fields = [inode, mode, 0, 0, 1, 0, file_size, 0, 0, 0, 0, name_size, 0];

    let header_start = output.len();
    output.extend_from_slice(b"070701");
    for value in fields {
        let encoded = format!("{value:08x}");
        output.extend_from_slice(encoded.as_bytes());
    }
    if output.len() - header_start != CPIO_HEADER_BYTES {
        return Err("internal Step-29 filesystem proof CPIO header length error".to_string());
    }
    output.extend_from_slice(path.as_bytes());
    output.push(0);
    align4(output);
    output.extend_from_slice(payload);
    align4(output);
    Ok(())
}

fn align4(output: &mut Vec<u8>) {
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

fn validate_static_aarch64_elf(bytes: &[u8], proof: &str) -> Result<(), String> {
    if bytes.len() < 64 || bytes.get(..4) != Some(b"\x7fELF") {
        return Err(format!(
            "Step-29 {proof} filesystem fixture is not an ELF image"
        ));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(format!(
            "Step-29 {proof} filesystem fixture must be ELF64 little-endian version 1"
        ));
    }
    if read_u16(bytes, 18, proof)? != EM_AARCH64 {
        return Err(format!(
            "Step-29 {proof} filesystem fixture is not AArch64 ELF"
        ));
    }

    let phoff = usize::try_from(read_u64(bytes, 32, proof)?)
        .map_err(|_| format!("Step-29 {proof} program-header offset exceeds usize"))?;
    let phentsize = usize::from(read_u16(bytes, 54, proof)?);
    let phnum = usize::from(read_u16(bytes, 56, proof)?);
    if phnum == 0 || phentsize < 56 {
        return Err(format!(
            "Step-29 {proof} filesystem fixture has no valid program-header table"
        ));
    }
    let table_bytes = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| format!("Step-29 {proof} program-header table overflow"))?;
    let table_end = phoff
        .checked_add(table_bytes)
        .ok_or_else(|| format!("Step-29 {proof} program-header end overflow"))?;
    if table_end > bytes.len() {
        return Err(format!(
            "Step-29 {proof} filesystem program-header table is out of bounds"
        ));
    }

    let mut load_segments = 0usize;
    for index in 0..phnum {
        let header = phoff + index * phentsize;
        match read_u32(bytes, header, proof)? {
            PT_INTERP => {
                return Err(format!(
                    "Step-29 {proof} filesystem proof requires a static ELF without PT_INTERP"
                ));
            }
            PT_LOAD => load_segments += 1,
            _ => {}
        }
    }
    if load_segments == 0 {
        return Err(format!(
            "Step-29 {proof} filesystem fixture contains no PT_LOAD segment"
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, proof: &str) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("Step-29 {proof} ELF u16 offset overflow"))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| format!("Step-29 {proof} ELF u16 read is out of bounds"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, proof: &str) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("Step-29 {proof} ELF u32 offset overflow"))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| format!("Step-29 {proof} ELF u32 read is out of bounds"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize, proof: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| format!("Step-29 {proof} ELF u64 offset overflow"))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| format!("Step-29 {proof} ELF u64 read is out of bounds"))?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn require_positive_markers(transcript: &str) -> Result<(), String> {
    super::require_markers(
        transcript,
        &[POSITIVE_SUCCESS_MARKER, POSITIVE_FINALIZED_MARKER],
        &[
            "KERNAL/ARM64: Step 29 path/fd invariant failed",
            "KERNAL/ARM64: Step 29 mutable filesystem fixture returned non-zero status",
            "KERNAL/ARM64: Step 29 mutable filesystem loader proof-state incomplete",
            "KERNAL/S29FSN:",
            "KERNAL/S29D:",
            "KERNAL/S29IO:",
        ],
        "filesystem-positive",
    )
}

fn require_negative_markers(transcript: &str) -> Result<(), String> {
    super::require_markers(
        transcript,
        &[NEGATIVE_SUCCESS_MARKER, NEGATIVE_FINALIZED_MARKER],
        &[
            "KERNAL/ARM64: Step 29 path/fd invariant failed",
            "KERNAL/ARM64: Step 29 negative filesystem fixture returned non-zero status",
            "KERNAL/ARM64: Step 29 negative filesystem loader proof-state incomplete",
            "KERNAL/S29FS:",
            "KERNAL/S29D:",
            "KERNAL/S29IO:",
        ],
        "filesystem-negative",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_filesystem_marker_gates_require_success_before_kernel_finalization() {
        let positive = format!("boot\n{POSITIVE_SUCCESS_MARKER}\n{POSITIVE_FINALIZED_MARKER}\n");
        require_positive_markers(&positive).unwrap();
        assert!(
            require_positive_markers(&format!(
                "{POSITIVE_FINALIZED_MARKER}\n{POSITIVE_SUCCESS_MARKER}\n"
            ))
            .is_err()
        );

        let negative = format!("boot\n{NEGATIVE_SUCCESS_MARKER}\n{NEGATIVE_FINALIZED_MARKER}\n");
        require_negative_markers(&negative).unwrap();
        assert!(
            require_negative_markers(&format!(
                "{NEGATIVE_FINALIZED_MARKER}\n{NEGATIVE_SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn filesystem_proof_boots_cannot_satisfy_each_other() {
        assert!(
            require_positive_markers(&format!(
                "{NEGATIVE_SUCCESS_MARKER}\n{NEGATIVE_FINALIZED_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_negative_markers(&format!(
                "{POSITIVE_SUCCESS_MARKER}\n{POSITIVE_FINALIZED_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn cpio_builder_rejects_invalid_paths_and_aligns_entries() {
        let mut output = Vec::new();
        assert!(newc_entry(&mut output, 1, "", 0o100755, b"x").is_err());
        newc_entry(&mut output, 1, "bin/test", 0o100755, b"abc").unwrap();
        assert!(output.len().is_multiple_of(4));
    }
}
