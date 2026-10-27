// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod fd_pipe;
mod final_fs;

pub const APPLET_MARKER: &str = "KERNAL/S29: unchanged static ARM64 BusyBox date selected";
pub const SYMLINK_MARKER: &str =
    "KERNAL/S29: relative localtime symlink followed to pinned UTC target";
pub const PATH_FD_MARKER: &str =
    "KERNAL/S29: immutable initramfs open-stat-read-close sequence passed";
pub const SUCCESS_MARKER: &str = "KERNAL/S29: BusyBox date finalized status=0";

pub const DIRECTORY_APPLET_MARKER: &str = "KERNAL/S29D: unchanged static ARM64 BusyBox ls selected";
pub const DIRECTORY_GETDENTS_MARKER: &str =
    "KERNAL/S29D: committed getdents64 directory listing observed";
pub const DIRECTORY_SYMLINK_MARKER: &str =
    "KERNAL/S29D: symlink dirent observed and directory fd closed";
pub const DIRECTORY_SUCCESS_MARKER: &str = "KERNAL/S29D: BusyBox ls finalized status=0";

const ACCEPTED_CPU_COUNTS: [usize; 3] = [1, 2, 4];
const GUEST_INITRD_ADDRESS: u64 = 0x4800_0000;
const MAX_INITRAMFS_BYTES: u64 = 16 * 1024 * 1024;
const BUILDER: &str = "tools/step29/build-busybox-initramfs.py";
const INITRAMFS: &str = "target/step29/busybox-initramfs.cpio";
const DATE_KERNEL: &str = "target/step29/kernal-core-aarch64-date";
const DIRECTORY_KERNEL: &str = "target/step29/kernal-core-aarch64-directory";

pub fn run() -> Result<(), String> {
    let root = super::workspace_root()?;
    let initramfs = build_initramfs(&root)?;
    let date_kernel = build_step29_kernel(&root, "step29-qemu-proof", DATE_KERNEL)?;
    let directory_kernel =
        build_step29_kernel(&root, "step29-directory-qemu-proof", DIRECTORY_KERNEL)?;

    for cpus in ACCEPTED_CPU_COUNTS {
        println!(
            "xtask: Step 29 unchanged BusyBox date symlink/path-FD QEMU proof with {cpus} vCPU(s)"
        );
        let transcript = run_qemu(&root, &date_kernel, &initramfs, cpus, "date")?;
        require_proof_markers(&transcript)?;

        println!(
            "xtask: Step 29 unchanged BusyBox ls directory/getdents QEMU proof with {cpus} vCPU(s)"
        );
        let transcript = run_qemu(&root, &directory_kernel, &initramfs, cpus, "directory")?;
        require_directory_proof_markers(&transcript)?;
    }

    println!("xtask: Step 29 pinned Debian static BusyBox ARM64 date+ls 1/2/4-vCPU matrix passed");
    fd_pipe::run(&root)?;
    final_fs::run(&root)?;
    Ok(())
}

fn build_initramfs(root: &Path) -> Result<PathBuf, String> {
    let builder = root.join(BUILDER);
    if !builder.is_file() {
        return Err(format!(
            "Step-29 initramfs builder not found: {}",
            builder.display()
        ));
    }
    let status = Command::new("python3")
        .arg(&builder)
        .current_dir(root)
        .status()
        .map_err(|error| format!("start Step-29 initramfs builder: {error}"))?;
    if !status.success() {
        return Err(format!("Step-29 initramfs builder failed with {status}"));
    }

    let output = root.join(INITRAMFS);
    validate_initramfs(&output)?;
    Ok(output)
}

fn validate_initramfs(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("stat Step-29 initramfs {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INITRAMFS_BYTES {
        return Err(format!(
            "Step-29 initramfs is missing, empty or too large: {} ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn build_step29_kernel(root: &Path, feature: &str, frozen_output: &str) -> Result<PathBuf, String> {
    let mut core = Command::new(super::cargo());
    core.args([
        "build",
        "-p",
        super::AARCH64_CORE_PACKAGE,
        "--target",
        super::AARCH64_CORE_TARGET,
        "--features",
        feature,
    ]);
    super::run_checked(
        &mut core,
        &format!("Step-29 AArch64 kernel core build ({feature})"),
    )?;

    let built = root
        .join("target")
        .join(super::AARCH64_CORE_TARGET)
        .join("debug")
        .join(super::AARCH64_CORE_PACKAGE);
    let metadata = fs::metadata(&built)
        .map_err(|error| format!("stat Step-29 AArch64 kernel {}: {error}", built.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-29 AArch64 kernel is missing or empty after {feature}: {}",
            built.display()
        ));
    }

    let frozen = root.join(frozen_output);
    let parent = frozen
        .parent()
        .ok_or_else(|| format!("Step-29 frozen kernel has no parent: {}", frozen.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create Step-29 output directory {}: {error}",
            parent.display()
        )
    })?;
    fs::copy(&built, &frozen).map_err(|error| {
        format!(
            "freeze Step-29 kernel {} -> {}: {error}",
            built.display(),
            frozen.display()
        )
    })?;
    let frozen_metadata = fs::metadata(&frozen)
        .map_err(|error| format!("stat frozen Step-29 kernel {}: {error}", frozen.display()))?;
    if !frozen_metadata.is_file() || frozen_metadata.len() != metadata.len() {
        return Err(format!(
            "frozen Step-29 kernel is missing or size-mismatched: {}",
            frozen.display()
        ));
    }
    Ok(frozen)
}

fn run_qemu(
    root: &Path,
    kernel: &Path,
    initramfs: &Path,
    cpus: usize,
    proof: &str,
) -> Result<String, String> {
    validate_cpu_count(cpus)?;
    validate_initramfs(initramfs)?;
    let metadata = fs::metadata(kernel)
        .map_err(|error| format!("stat Step-29 {proof} kernel {}: {error}", kernel.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-29 {proof} AArch64 kernel is missing or empty: {}",
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
        .map_err(|error| format!("start Step-29 {proof} AArch64 QEMU ({cpus} vCPU): {error}"))?;
    let stdout = match child.stdout.take() {
        Some(stream) => stream,
        None => {
            terminate(&mut child);
            return Err(format!("capture Step-29 {proof} QEMU stdout failed"));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stream) => stream,
        None => {
            terminate(&mut child);
            return Err(format!("capture Step-29 {proof} QEMU stderr failed"));
        }
    };
    let stdout_reader = drain(stdout, "stdout");
    let stderr_reader = drain(stderr, "stderr");

    let status = wait_bounded(
        &mut child,
        cpus,
        Duration::from_secs(super::QEMU_TIMEOUT_SECS),
    );
    let stdout = join(stdout_reader, "stdout")?;
    let stderr = join(stderr_reader, "stderr")?;
    let transcript = combine(&stdout, &stderr);
    let status = status.map_err(|error| format!("{error}; transcript:\n{transcript}"))?;
    require_status(status, cpus, proof, &transcript)?;
    Ok(transcript)
}

fn validate_cpu_count(cpus: usize) -> Result<(), String> {
    if ACCEPTED_CPU_COUNTS.contains(&cpus) {
        Ok(())
    } else {
        Err(format!(
            "Step-29 QEMU CPU count {cpus} is outside the accepted 1/2/4-vCPU matrix"
        ))
    }
}

fn guest_loader_argument(initramfs: &Path) -> Result<String, String> {
    let path = initramfs.to_str().ok_or_else(|| {
        format!(
            "Step-29 initramfs path is not UTF-8: {}",
            initramfs.display()
        )
    })?;
    if path.contains(',') {
        return Err(format!(
            "Step-29 initramfs path contains a comma unsupported by guest-loader: {}",
            initramfs.display()
        ));
    }
    Ok(format!(
        "guest-loader,addr=0x{GUEST_INITRD_ADDRESS:x},initrd={path}"
    ))
}

/// Fails closed unless every Step-29 `date` proof boundary occurs exactly once and in causal order.
pub fn require_proof_markers(transcript: &str) -> Result<(), String> {
    require_markers(
        transcript,
        &[
            APPLET_MARKER,
            SYMLINK_MARKER,
            PATH_FD_MARKER,
            SUCCESS_MARKER,
        ],
        &[
            "KERNAL/ARM64: Step 29 path/fd invariant failed",
            "KERNAL/ARM64: Step 29 path/fd proof-state incomplete",
            "KERNAL/ARM64: Step 29 BusyBox loader proof-state incomplete",
            "KERNAL/ARM64: Step 29 BusyBox date returned non-zero status",
            "KERNAL/S29D:",
        ],
        "date",
    )
}

/// Fails closed unless every Step-29 `ls` directory proof boundary occurs exactly once and in causal
/// order. A marker from the date proof is rejected so the two independent boots cannot satisfy one
/// another accidentally.
pub fn require_directory_proof_markers(transcript: &str) -> Result<(), String> {
    require_markers(
        transcript,
        &[
            DIRECTORY_APPLET_MARKER,
            DIRECTORY_GETDENTS_MARKER,
            DIRECTORY_SYMLINK_MARKER,
            DIRECTORY_SUCCESS_MARKER,
        ],
        &[
            "KERNAL/ARM64: Step 29 path/fd invariant failed",
            "KERNAL/ARM64: Step 29 directory/getdents proof-state incomplete",
            "KERNAL/ARM64: Step 29 directory loader proof-state incomplete",
            "KERNAL/ARM64: Step 29 BusyBox ls returned non-zero status",
            "KERNAL/S29:",
        ],
        "directory",
    )
}

fn require_markers(
    transcript: &str,
    markers: &[&str],
    forbidden_prefixes: &[&str],
    proof: &str,
) -> Result<(), String> {
    let mut previous = None;
    for marker in markers {
        let mut count = 0usize;
        let mut position = None;
        for (line_index, line) in transcript.lines().enumerate() {
            if line.trim_end_matches('\r') == *marker {
                count += 1;
                position = Some(line_index);
            }
        }
        if count != 1 {
            return Err(format!(
                "Step-29 {proof} transcript contains marker {marker:?} {count} times; expected exactly once"
            ));
        }
        let position = position
            .ok_or_else(|| format!("Step-29 {proof} transcript is missing marker {marker:?}"))?;
        if let Some(previous) = previous
            && position <= previous
        {
            return Err(format!(
                "Step-29 {proof} proof markers are out of causal order at {marker:?}: previous={previous}, current={position}"
            ));
        }
        previous = Some(position);
    }

    for forbidden in forbidden_prefixes {
        if transcript.lines().any(|line| line.starts_with(forbidden)) {
            return Err(format!(
                "Step-29 {proof} transcript contains forbidden/fail-closed boundary {forbidden:?}"
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
            .map_err(|error| format!("read Step-29 QEMU {label}: {error}"))?;
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
                return Err(format!("poll Step-29 AArch64 QEMU ({cpus} vCPU): {error}"));
            }
        }
        if start.elapsed() >= timeout {
            let kill_error = child.kill().err();
            let _ = child.wait();
            return Err(match kill_error {
                Some(error) => format!(
                    "Step-29 AArch64 QEMU ({cpus} vCPU) exceeded {}s; kill failed: {error}",
                    timeout.as_secs_f64()
                ),
                None => format!(
                    "Step-29 AArch64 QEMU ({cpus} vCPU) exceeded {}s and was killed",
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
        .map_err(|_| format!("Step-29 QEMU {label} reader panicked"))?
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

fn require_status(
    status: ExitStatus,
    cpus: usize,
    proof: &str,
    transcript: &str,
) -> Result<(), String> {
    match status.code() {
        Some(super::AARCH64_QEMU_SUCCESS_STATUS) => Ok(()),
        Some(code) => Err(format!(
            "Step-29 {proof} AArch64 QEMU ({cpus} vCPU) exited with status {code}; transcript:\n{transcript}"
        )),
        None => Err(format!(
            "Step-29 {proof} AArch64 QEMU ({cpus} vCPU) terminated by signal; transcript:\n{transcript}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_date_transcript() -> String {
        format!("boot\n{APPLET_MARKER}\n{SYMLINK_MARKER}\n{PATH_FD_MARKER}\n{SUCCESS_MARKER}\n")
    }

    fn valid_directory_transcript() -> String {
        format!(
            "boot\n{DIRECTORY_APPLET_MARKER}\n{DIRECTORY_GETDENTS_MARKER}\n{DIRECTORY_SYMLINK_MARKER}\n{DIRECTORY_SUCCESS_MARKER}\n"
        )
    }

    #[test]
    fn date_marker_gate_requires_all_boundaries_once_in_order() {
        require_proof_markers(&valid_date_transcript()).unwrap();
        for missing in [
            APPLET_MARKER,
            SYMLINK_MARKER,
            PATH_FD_MARKER,
            SUCCESS_MARKER,
        ] {
            let transcript = valid_date_transcript()
                .lines()
                .filter(|line| *line != missing)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(require_proof_markers(&transcript).is_err());
        }
        assert!(
            require_proof_markers(&format!(
                "{APPLET_MARKER}\n{SYMLINK_MARKER}\n{PATH_FD_MARKER}\n{PATH_FD_MARKER}\n{SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_proof_markers(&format!(
                "{SYMLINK_MARKER}\n{APPLET_MARKER}\n{PATH_FD_MARKER}\n{SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_proof_markers(&format!(
                "{APPLET_MARKER}\n{SYMLINK_MARKER}\n{PATH_FD_MARKER}\n{SUCCESS_MARKER}\n{DIRECTORY_SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn directory_marker_gate_requires_all_boundaries_once_in_order() {
        require_directory_proof_markers(&valid_directory_transcript()).unwrap();
        for missing in [
            DIRECTORY_APPLET_MARKER,
            DIRECTORY_GETDENTS_MARKER,
            DIRECTORY_SYMLINK_MARKER,
            DIRECTORY_SUCCESS_MARKER,
        ] {
            let transcript = valid_directory_transcript()
                .lines()
                .filter(|line| *line != missing)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(require_directory_proof_markers(&transcript).is_err());
        }
        assert!(
            require_directory_proof_markers(&format!(
                "{DIRECTORY_APPLET_MARKER}\n{DIRECTORY_GETDENTS_MARKER}\n{DIRECTORY_GETDENTS_MARKER}\n{DIRECTORY_SYMLINK_MARKER}\n{DIRECTORY_SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_directory_proof_markers(&format!(
                "{DIRECTORY_GETDENTS_MARKER}\n{DIRECTORY_APPLET_MARKER}\n{DIRECTORY_SYMLINK_MARKER}\n{DIRECTORY_SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_directory_proof_markers(&format!(
                "{DIRECTORY_APPLET_MARKER}\n{DIRECTORY_GETDENTS_MARKER}\n{DIRECTORY_SYMLINK_MARKER}\n{DIRECTORY_SUCCESS_MARKER}\n{SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn only_accepted_cpu_matrix_is_valid() {
        for cpus in ACCEPTED_CPU_COUNTS {
            validate_cpu_count(cpus).unwrap();
        }
        for cpus in [0, 3, 5, usize::MAX] {
            assert!(validate_cpu_count(cpus).is_err());
        }
    }

    #[test]
    fn guest_loader_uses_bounded_step29_address() {
        assert_eq!(
            guest_loader_argument(Path::new("/tmp/step29.cpio")).unwrap(),
            "guest-loader,addr=0x48000000,initrd=/tmp/step29.cpio"
        );
        assert!(guest_loader_argument(Path::new("/tmp/bad,path")).is_err());
    }
}
