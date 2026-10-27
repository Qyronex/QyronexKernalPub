// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::step15;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const SUCCESS_MARKER: &str = "KERNAL/S15: unchanged musl pthread minimum passed";
const ACCEPTED_CPU_COUNTS: [usize; 3] = [1, 2, 4];
/// QEMU ARM bare-metal ELF boots do not consume classic `-initrd`. Keep the fixture at the same
/// bounded 128-MiB-in-RAM address used by QEMU's Linux ARM initrd policy and publish it through the
/// `guest-loader` FDT module contract instead.
const GUEST_INITRD_ADDRESS: u64 = 0x4800_0000;

/// Runs the dedicated single-vCPU Step-15 AArch64 acceptance boot.
///
/// Kept as a compatibility wrapper for focused diagnostics. Final Step-15 acceptance must use
/// [`run_step15_qemu_with_cpus`] separately for every value in the 1/2/4-vCPU matrix.
pub fn run_step15_qemu(
    qemu_binary: &Path,
    kernel: &Path,
    initrd: &Path,
    timeout: Duration,
) -> Result<String, String> {
    run_step15_qemu_with_cpus(qemu_binary, kernel, initrd, 1, timeout)
}

/// Runs one independent Step-15 AArch64 acceptance boot for an accepted matrix CPU count.
///
/// This is a transport/verifier helper only. It does not parse the initrd or ELF contents. The
/// kernel's canonical FDT/initrd, ELF and Linux loader owners remain responsible for validating and
/// consuming the payload. Every invocation starts a separate QEMU process and requires both a normal
/// exit and exactly one complete userspace success-marker line in that boot's captured transcript.
pub fn run_step15_qemu_with_cpus(
    qemu_binary: &Path,
    kernel: &Path,
    initrd: &Path,
    cpus: usize,
    timeout: Duration,
) -> Result<String, String> {
    validate_cpu_count(cpus)?;
    validate_kernel(kernel)?;
    step15::validate_initrd(initrd)?;
    if timeout.is_zero() {
        return Err("Step-15 QEMU timeout must be non-zero".to_string());
    }
    let guest_loader = guest_loader_argument(initrd)?;

    let cpu_count = cpus.to_string();
    let mut command = Command::new(qemu_binary);
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

    let mut child = command.spawn().map_err(|error| {
        format!(
            "start Step-15 AArch64 QEMU {} ({cpus} vCPU): {error}",
            qemu_binary.display()
        )
    })?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_child(&mut child);
            return Err(format!("capture Step-15 QEMU stdout failed ({cpus} vCPU)"));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_child(&mut child);
            return Err(format!("capture Step-15 QEMU stderr failed ({cpus} vCPU)"));
        }
    };
    let stdout_reader = drain_stream(stdout, "stdout");
    let stderr_reader = drain_stream(stderr, "stderr");

    // Always drain and join both pipes even if QEMU times out or polling fails. This keeps a failed
    // verifier run self-contained and preserves the serial diagnostics that explain the failure.
    let wait_result = wait_bounded(&mut child, cpus, timeout);
    let stdout_result = join_stream(stdout_reader, "stdout");
    let stderr_result = join_stream(stderr_reader, "stderr");
    let stdout = stdout_result?;
    let stderr = stderr_result?;
    let transcript = combine_transcript(&stdout, &stderr);
    let status = wait_result.map_err(|error| format!("{error}; transcript:\n{transcript}"))?;

    require_success_status(status, cpus, &transcript)?;
    if let Err(error) = require_success_marker(&transcript) {
        return Err(format!("{error}; transcript:\n{transcript}"));
    }
    Ok(transcript)
}

pub fn require_success_marker(transcript: &str) -> Result<(), String> {
    let count = transcript
        .lines()
        .filter(|line| *line == SUCCESS_MARKER)
        .count();
    match count {
        1 => Ok(()),
        0 => Err(format!(
            "Step-15 QEMU transcript is missing exact userspace marker `{SUCCESS_MARKER}`"
        )),
        count => Err(format!(
            "Step-15 QEMU transcript contains exact userspace marker {count} times; expected exactly once"
        )),
    }
}

fn validate_cpu_count(cpus: usize) -> Result<(), String> {
    if ACCEPTED_CPU_COUNTS.contains(&cpus) {
        Ok(())
    } else {
        Err(format!(
            "Step-15 QEMU CPU count {cpus} is outside the accepted 1/2/4-vCPU matrix"
        ))
    }
}

fn validate_kernel(kernel: &Path) -> Result<(), String> {
    let metadata = fs::metadata(kernel)
        .map_err(|error| format!("stat AArch64 Step-15 kernel {}: {error}", kernel.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "AArch64 Step-15 kernel is missing or empty: {}",
            kernel.display()
        ));
    }
    Ok(())
}

fn guest_loader_argument(initrd: &Path) -> Result<String, String> {
    let path = initrd.to_str().ok_or_else(|| {
        format!(
            "Step-15 initrd path is not valid UTF-8: {}",
            initrd.display()
        )
    })?;
    if path.contains(',') {
        return Err(format!(
            "Step-15 initrd path contains a comma unsupported by QEMU guest-loader syntax: {}",
            initrd.display()
        ));
    }
    Ok(format!(
        "guest-loader,addr=0x{GUEST_INITRD_ADDRESS:x},initrd={path}"
    ))
}

fn drain_stream<R>(mut stream: R, label: &'static str) -> JoinHandle<Result<Vec<u8>, String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read Step-15 QEMU {label}: {error}"))?;
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
                terminate_child(child);
                return Err(format!("poll Step-15 AArch64 QEMU ({cpus} vCPU): {error}"));
            }
        }
        if start.elapsed() >= timeout {
            let kill_error = child.kill().err();
            let _ = child.wait();
            return Err(match kill_error {
                Some(error) => format!(
                    "Step-15 AArch64 QEMU ({cpus} vCPU) exceeded {}s; kill also failed: {error}",
                    timeout.as_secs_f64()
                ),
                None => format!(
                    "Step-15 AArch64 QEMU ({cpus} vCPU) exceeded {}s and was killed",
                    timeout.as_secs_f64()
                ),
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn join_stream(
    handle: JoinHandle<Result<Vec<u8>, String>>,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    handle
        .join()
        .map_err(|_| format!("Step-15 QEMU {label} reader panicked"))?
}

fn combine_transcript(stdout: &[u8], stderr: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(stdout.len().saturating_add(stderr.len()).saturating_add(1));
    bytes.extend_from_slice(stdout);
    if !stdout.is_empty() && !stdout.ends_with(b"\n") && !stderr.is_empty() {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(stderr);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn require_success_status(status: ExitStatus, cpus: usize, transcript: &str) -> Result<(), String> {
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(format!(
            "Step-15 AArch64 QEMU ({cpus} vCPU) exited with status {code}; transcript:\n{transcript}"
        )),
        None => Err(format!(
            "Step-15 AArch64 QEMU ({cpus} vCPU) terminated by signal; transcript:\n{transcript}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_marker_once_with_lf_or_crlf() {
        require_success_marker(&format!("boot\n{SUCCESS_MARKER}\nshutdown\n")).unwrap();
        require_success_marker(&format!("boot\r\n{SUCCESS_MARKER}\r\nshutdown\r\n")).unwrap();
    }

    #[test]
    fn rejects_missing_partial_or_kernel_prefixed_marker() {
        assert!(require_success_marker("boot only\n").is_err());
        assert!(require_success_marker("KERNAL/S15: unchanged musl pthread minimum\n").is_err());
        assert!(require_success_marker(&format!("kernel says: {SUCCESS_MARKER}\n")).is_err());
    }

    #[test]
    fn rejects_duplicate_marker_lines() {
        let transcript = format!("{SUCCESS_MARKER}\n{SUCCESS_MARKER}\n");
        assert!(require_success_marker(&transcript).is_err());
    }

    #[test]
    fn only_the_required_cpu_matrix_is_accepted() {
        for cpus in ACCEPTED_CPU_COUNTS {
            validate_cpu_count(cpus).unwrap();
        }
        for cpus in [0, 3, 5, usize::MAX] {
            assert!(validate_cpu_count(cpus).is_err());
        }
    }

    #[test]
    fn guest_loader_publishes_fixture_at_bounded_address() {
        assert_eq!(
            guest_loader_argument(Path::new("/tmp/pthread_minimum")).unwrap(),
            "guest-loader,addr=0x48000000,initrd=/tmp/pthread_minimum"
        );
        assert!(guest_loader_argument(Path::new("/tmp/fixture,invalid")).is_err());
    }

    #[test]
    fn combines_stdout_and_stderr_without_gluing_lines() {
        assert_eq!(combine_transcript(b"serial", b"qemu\n"), "serial\nqemu\n");
        assert_eq!(combine_transcript(b"serial\n", b"qemu\n"), "serial\nqemu\n");
    }
}
