// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ACCEPTED_CPU_COUNTS: [usize; 3] = [1, 2, 4];
const GUEST_INITRD_ADDRESS: u64 = 0x4800_0000;
const MAX_INITRAMFS_BYTES: u64 = 16 * 1024 * 1024;
const BUILDER: &str = "tools/step29/build-fd-pipe-fixture.sh";
const FIXTURE: &str = "target/step29/fd-pipe-roundtrip";
const INITRAMFS: &str = "target/step29/fd-pipe-initramfs.cpio";
const KERNEL: &str = "target/step29/kernal-core-aarch64-fd-pipe";
const INITRAMFS_EXECUTABLE: &str = "bin/busybox";
const CPIO_TRAILER: &str = "TRAILER!!!";
const CPIO_HEADER_BYTES: usize = 110;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

const ALIAS_MARKER: &str = "KERNAL/S29IO: external stderr alias write passed";
const ROUNDTRIP_MARKER: &str = "KERNAL/S29IO: fd-pipe roundtrip passed";
const FINALIZED_MARKER: &str = "KERNAL/S29IO: fd-pipe fixture finalized status=0";
const REQUIRED_MARKERS: [&str; 3] = [ALIAS_MARKER, ROUNDTRIP_MARKER, FINALIZED_MARKER];

pub(super) fn run(root: &Path) -> Result<(), String> {
    let fixture = build_fixture(root)?;
    let initramfs = build_fixture_initramfs(root, &fixture)?;
    let kernel = build_kernel(root)?;

    for cpus in ACCEPTED_CPU_COUNTS {
        println!(
            "xtask: Step 29 unchanged static Linux fd/pipe roundtrip QEMU proof with {cpus} vCPU(s)"
        );
        let transcript = run_qemu(root, &kernel, &initramfs, cpus)?;
        require_fd_pipe_proof_markers(&transcript)?;
    }

    println!("xtask: Step 29 unchanged static Linux fd/pipe roundtrip 1/2/4-vCPU matrix passed");
    Ok(())
}

fn build_fixture(root: &Path) -> Result<Vec<u8>, String> {
    let builder = root.join(BUILDER);
    if !builder.is_file() {
        return Err(format!(
            "Step-29 fd/pipe fixture builder not found: {}",
            builder.display()
        ));
    }

    let status = Command::new("bash")
        .arg(&builder)
        .current_dir(root)
        .status()
        .map_err(|error| format!("start Step-29 fd/pipe fixture builder: {error}"))?;
    if !status.success() {
        return Err(format!(
            "Step-29 fd/pipe fixture builder failed with {status}"
        ));
    }

    let path = root.join(FIXTURE);
    let bytes = fs::read(&path)
        .map_err(|error| format!("read Step-29 fd/pipe fixture {}: {error}", path.display()))?;
    validate_static_aarch64_elf(&bytes)?;
    Ok(bytes)
}

fn build_fixture_initramfs(root: &Path, fixture: &[u8]) -> Result<PathBuf, String> {
    let mut output = Vec::new();
    newc_entry(&mut output, 1, ".", 0o040755, &[])?;
    newc_entry(&mut output, 2, "bin", 0o040755, &[])?;
    // Reuse the already-proven Step-28/29 CPIO selection path. The proof feature changes only the
    // executable bytes stored at the canonical archive member; ELF parsing, loading, Process
    // creation and scheduler publication remain owned by the existing accepted implementation.
    newc_entry(&mut output, 3, INITRAMFS_EXECUTABLE, 0o100755, fixture)?;
    newc_entry(&mut output, 4, CPIO_TRAILER, 0, &[])?;
    while !output.len().is_multiple_of(512) {
        output.push(0);
    }
    if output.is_empty() || output.len() as u64 > MAX_INITRAMFS_BYTES {
        return Err(format!(
            "Step-29 fd/pipe initramfs size is outside policy: {} bytes",
            output.len()
        ));
    }

    let path = root.join(INITRAMFS);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create Step-29 fd/pipe initramfs directory {}: {error}",
                parent.display()
            )
        })?;
    }
    fs::write(&path, &output).map_err(|error| {
        format!(
            "write Step-29 fd/pipe initramfs {}: {error}",
            path.display()
        )
    })?;
    validate_initramfs(&path)?;
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
        return Err("invalid Step-29 fd/pipe initramfs path".to_string());
    }
    let file_size = u32::try_from(payload.len())
        .map_err(|_| "Step-29 fd/pipe CPIO payload exceeds u32".to_string())?;
    let name_size = u32::try_from(path.len() + 1)
        .map_err(|_| "Step-29 fd/pipe CPIO path exceeds u32".to_string())?;
    let fields = [inode, mode, 0, 0, 1, 0, file_size, 0, 0, 0, 0, name_size, 0];

    let header_start = output.len();
    output.extend_from_slice(b"070701");
    for value in fields {
        let encoded = format!("{value:08x}");
        output.extend_from_slice(encoded.as_bytes());
    }
    if output.len() - header_start != CPIO_HEADER_BYTES {
        return Err("internal Step-29 fd/pipe CPIO header length error".to_string());
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

fn validate_static_aarch64_elf(bytes: &[u8]) -> Result<(), String> {
    if len_lt(bytes, 64) || bytes.get(..4) != Some(b"\x7fELF") {
        return Err("Step-29 fd/pipe fixture is not an ELF image".to_string());
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err("Step-29 fd/pipe fixture must be ELF64 little-endian version 1".to_string());
    }
    if read_u16(bytes, 18)? != EM_AARCH64 {
        return Err("Step-29 fd/pipe fixture is not AArch64 ELF".to_string());
    }

    let phoff = usize::try_from(read_u64(bytes, 32)?)
        .map_err(|_| "Step-29 fd/pipe program-header offset exceeds usize".to_string())?;
    let phentsize = usize::from(read_u16(bytes, 54)?);
    let phnum = usize::from(read_u16(bytes, 56)?);
    if phnum == 0 || phentsize < 56 {
        return Err("Step-29 fd/pipe fixture has no valid program-header table".to_string());
    }
    let table_bytes = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| "Step-29 fd/pipe program-header table overflow".to_string())?;
    let table_end = phoff
        .checked_add(table_bytes)
        .ok_or_else(|| "Step-29 fd/pipe program-header end overflow".to_string())?;
    if table_end > bytes.len() {
        return Err("Step-29 fd/pipe program-header table is out of bounds".to_string());
    }

    let mut load_segments = 0usize;
    for index in 0..phnum {
        let header = phoff + index * phentsize;
        match read_u32(bytes, header)? {
            PT_INTERP => {
                return Err(
                    "Step-29 fd/pipe proof requires a static ELF without PT_INTERP".to_string(),
                );
            }
            PT_LOAD => load_segments += 1,
            _ => {}
        }
    }
    if load_segments == 0 {
        return Err("Step-29 fd/pipe fixture contains no PT_LOAD segment".to_string());
    }
    Ok(())
}

fn len_lt(bytes: &[u8], minimum: usize) -> bool {
    bytes.len() < minimum
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "Step-29 fd/pipe ELF u16 offset overflow".to_string())?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| "Step-29 fd/pipe ELF u16 read is out of bounds".to_string())?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "Step-29 fd/pipe ELF u32 offset overflow".to_string())?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| "Step-29 fd/pipe ELF u32 read is out of bounds".to_string())?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| "Step-29 fd/pipe ELF u64 offset overflow".to_string())?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| "Step-29 fd/pipe ELF u64 read is out of bounds".to_string())?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn validate_initramfs(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("stat Step-29 fd/pipe initramfs {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INITRAMFS_BYTES {
        return Err(format!(
            "Step-29 fd/pipe initramfs is missing, empty or too large: {} ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn build_kernel(root: &Path) -> Result<PathBuf, String> {
    let mut core = Command::new(super::super::cargo());
    core.args([
        "build",
        "-p",
        super::super::AARCH64_CORE_PACKAGE,
        "--target",
        super::super::AARCH64_CORE_TARGET,
        "--features",
        "step29-fd-pipe-qemu-proof",
    ]);
    super::super::run_checked(&mut core, "Step-29 fd/pipe AArch64 kernel core build")?;

    let built = root
        .join("target")
        .join(super::super::AARCH64_CORE_TARGET)
        .join("debug")
        .join(super::super::AARCH64_CORE_PACKAGE);
    let metadata = fs::metadata(&built).map_err(|error| {
        format!(
            "stat Step-29 fd/pipe AArch64 kernel {}: {error}",
            built.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-29 fd/pipe AArch64 kernel is missing or empty: {}",
            built.display()
        ));
    }

    let frozen = root.join(KERNEL);
    let parent = frozen.parent().ok_or_else(|| {
        format!(
            "Step-29 fd/pipe frozen kernel has no parent: {}",
            frozen.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create Step-29 fd/pipe output directory {}: {error}",
            parent.display()
        )
    })?;
    fs::copy(&built, &frozen).map_err(|error| {
        format!(
            "freeze Step-29 fd/pipe kernel {} -> {}: {error}",
            built.display(),
            frozen.display()
        )
    })?;
    Ok(frozen)
}

fn run_qemu(root: &Path, kernel: &Path, initramfs: &Path, cpus: usize) -> Result<String, String> {
    if !ACCEPTED_CPU_COUNTS.contains(&cpus) {
        return Err(format!(
            "Step-29 fd/pipe QEMU CPU count {cpus} is outside the accepted 1/2/4-vCPU matrix"
        ));
    }
    validate_initramfs(initramfs)?;
    let metadata = fs::metadata(kernel)
        .map_err(|error| format!("stat Step-29 fd/pipe kernel {}: {error}", kernel.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-29 fd/pipe AArch64 kernel is missing or empty: {}",
            kernel.display()
        ));
    }

    let guest_loader = guest_loader_argument(initramfs)?;
    let cpu_count = cpus.to_string();
    let mut command = Command::new("qemu-system-aarch64");
    command
        .current_dir(root)
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
        .args([
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "stdio",
            "-no-reboot",
            "-kernel",
        ])
        .arg(kernel)
        .arg("-device")
        .arg(guest_loader)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("start Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU): {error}"))?;
    let stdout = match child.stdout.take() {
        Some(stream) => stream,
        None => {
            terminate(&mut child);
            return Err("capture Step-29 fd/pipe QEMU stdout failed".to_string());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stream) => stream,
        None => {
            terminate(&mut child);
            return Err("capture Step-29 fd/pipe QEMU stderr failed".to_string());
        }
    };
    let stdout_reader = drain(stdout, "stdout");
    let stderr_reader = drain(stderr, "stderr");

    let status = wait_bounded(
        &mut child,
        cpus,
        Duration::from_secs(super::super::QEMU_TIMEOUT_SECS),
    );
    let stdout = join(stdout_reader, "stdout")?;
    let stderr = join(stderr_reader, "stderr")?;
    let transcript = combine(&stdout, &stderr);
    let status = status.map_err(|error| format!("{error}; transcript:\n{transcript}"))?;
    require_status(status, cpus, &transcript)?;
    Ok(transcript)
}

fn guest_loader_argument(initramfs: &Path) -> Result<String, String> {
    let path = initramfs.to_str().ok_or_else(|| {
        format!(
            "Step-29 fd/pipe initramfs path is not UTF-8: {}",
            initramfs.display()
        )
    })?;
    if path.contains(',') {
        return Err(format!(
            "Step-29 fd/pipe initramfs path contains a comma unsupported by guest-loader: {}",
            initramfs.display()
        ));
    }
    Ok(format!(
        "guest-loader,addr=0x{GUEST_INITRD_ADDRESS:x},initrd={path}"
    ))
}

fn require_fd_pipe_proof_markers(transcript: &str) -> Result<(), String> {
    xtask::step29_preflight::validate_unique_ordered_markers(transcript, &REQUIRED_MARKERS)
        .map_err(|error| format!("Step-29 fd/pipe marker validation failed: {error:?}"))?;

    for forbidden in [
        "KERNAL/ARM64: Step 29 fd-io invariant failed",
        "KERNAL/ARM64: Step 29 path/fd invariant failed",
        "KERNAL/ARM64: Step 29 fd-pipe fixture returned non-zero status",
        "KERNAL/ARM64: Step 29 fd-pipe loader proof-state incomplete",
        "KERNAL/S29:",
        "KERNAL/S29D:",
    ] {
        if transcript.lines().any(|line| line.starts_with(forbidden)) {
            return Err(format!(
                "Step-29 fd/pipe transcript contains forbidden/fail-closed boundary {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn drain<R>(mut stream: R, label: &'static str) -> JoinHandle<Result<Vec<u8>, String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read Step-29 fd/pipe QEMU {label}: {error}"))?;
        Ok(bytes)
    })
}

fn wait_bounded(child: &mut Child, cpus: usize, timeout: Duration) -> Result<ExitStatus, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                terminate(child);
                return Err(format!(
                    "poll Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU): {error}"
                ));
            }
        }
        if start.elapsed() >= timeout {
            let kill_error = child.kill().err();
            let _ = child.wait();
            return Err(match kill_error {
                Some(error) => format!(
                    "Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU) exceeded {}s; kill failed: {error}",
                    timeout.as_secs_f64()
                ),
                None => format!(
                    "Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU) exceeded {}s and was killed",
                    timeout.as_secs_f64()
                ),
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn join(
    handle: JoinHandle<Result<Vec<u8>, String>>,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    handle
        .join()
        .map_err(|_| format!("Step-29 fd/pipe QEMU {label} reader panicked"))?
}

fn combine(stdout: &[u8], stderr: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(stdout.len().saturating_add(stderr.len()).saturating_add(1));
    bytes.extend_from_slice(stdout);
    if !stdout.is_empty() && !stdout.ends_with(b"\n") && !stderr.is_empty() {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(stderr);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn require_status(status: ExitStatus, cpus: usize, transcript: &str) -> Result<(), String> {
    match status.code() {
        Some(super::super::AARCH64_QEMU_SUCCESS_STATUS) => Ok(()),
        Some(code) => Err(format!(
            "Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU) exited with status {code}; transcript:\n{transcript}"
        )),
        None => Err(format!(
            "Step-29 fd/pipe AArch64 QEMU ({cpus} vCPU) terminated by signal; transcript:\n{transcript}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_gate_requires_exact_causal_fixture_completion() {
        let transcript =
            format!("boot\n{ALIAS_MARKER}\nnoise\n{ROUNDTRIP_MARKER}\n{FINALIZED_MARKER}\nexit\n");
        require_fd_pipe_proof_markers(&transcript).unwrap();
        assert!(
            require_fd_pipe_proof_markers(&format!(
                "{ROUNDTRIP_MARKER}\n{ALIAS_MARKER}\n{FINALIZED_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_fd_pipe_proof_markers(&format!(
                "{ALIAS_MARKER}\n{ROUNDTRIP_MARKER}\n{ROUNDTRIP_MARKER}\n{FINALIZED_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn newc_fixture_archive_is_bounded_and_aligned() {
        let mut archive = Vec::new();
        newc_entry(&mut archive, 1, ".", 0o040755, &[]).unwrap();
        newc_entry(&mut archive, 2, "bin", 0o040755, &[]).unwrap();
        newc_entry(&mut archive, 3, INITRAMFS_EXECUTABLE, 0o100755, b"fixture").unwrap();
        newc_entry(&mut archive, 4, CPIO_TRAILER, 0, &[]).unwrap();
        while !archive.len().is_multiple_of(512) {
            archive.push(0);
        }
        assert!(!archive.is_empty());
        assert!(archive.len().is_multiple_of(512));
        assert!(archive.windows(6).any(|window| window == b"070701"));
        assert!(
            archive
                .windows(INITRAMFS_EXECUTABLE.len())
                .any(|window| window == INITRAMFS_EXECUTABLE.as_bytes())
        );
    }
}
