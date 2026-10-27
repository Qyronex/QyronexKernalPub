// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ACCEPTED_CPU_COUNTS: [usize; 3] = [1, 2, 4];
const GUEST_INITRD_ADDRESS: u64 = 0x4800_0000;
const MAX_INITRAMFS_BYTES: u64 = 16 * 1024 * 1024;
const INITRAMFS: &str = "target/step30/process-runtime-initramfs.cpio";
const GUEST_SOURCE_PATH: &str = "target/step30/process-runtime-proof.c";
const GUEST_BINARY_PATH: &str = "target/step30/step30-proof";
const KERNEL: &str = "target/step30/kernal-core-aarch64-process";
const FEATURE: &str = "step30-final-qemu-proof";
// linker-aarch64.ld links the ELF at the QEMU physical load address, while protected boot executes
// the same image through an equal-offset canonical TTBR1 alias. Normalize trapped runtime PCs back
// to the linked address domain before consulting the exact-build ELF symbol table.
const KERNEL_LINK_PHYS_BASE: u64 = 0x4020_0000;
const KERNEL_RUNTIME_VIRT_BASE: u64 = 0xffff_ffff_8020_0000;

pub const FOREGROUND_MARKER: &str = "KERNAL/S30: foreground child lifecycle/reap passed";
pub const BACKGROUND_MARKER: &str = "KERNAL/S30: background child lifecycle/reap passed";
pub const FD_EXEC_MARKER: &str = "KERNAL/S30: fork shared OFD and exec CLOEXEC passed";
pub const NORMAL_WAIT_MARKER: &str = "KERNAL/S30: normal exit wait status passed";
pub const SIGNAL_WAIT_MARKER: &str = "KERNAL/S30: signal termination wait status passed";
pub const RESTART_MARKER: &str = "KERNAL/S30: EINTR and SA_RESTART passed";
pub const SIGNAL_FRAME_MARKER: &str =
    "KERNAL/S30: malformed signal frame and bad pointer failed closed";
pub const JOB_CONTROL_MARKER: &str = "KERNAL/S30: Stop Continue lifecycle passed";
pub const SUCCESS_MARKER: &str = "KERNAL/S30: process runtime finalized status=0";

const REQUIRED_MARKERS: [&str; 9] = [
    FOREGROUND_MARKER,
    BACKGROUND_MARKER,
    FD_EXEC_MARKER,
    NORMAL_WAIT_MARKER,
    SIGNAL_WAIT_MARKER,
    RESTART_MARKER,
    SIGNAL_FRAME_MARKER,
    JOB_CONTROL_MARKER,
    SUCCESS_MARKER,
];

const FORBIDDEN_PREFIXES: [&str; 4] = [
    "KERNAL/ARM64: Step 30 invariant failed",
    "KERNAL/ARM64: Step 30 proof-state incomplete",
    "KERNAL/S30: FAIL",
    "KERNAL/S30: process runtime finalized status=1",
];

/// Ordinary static AArch64 Linux userspace used only by the final QEMU acceptance image.
///
/// It deliberately observes Linux-visible outcomes instead of relying on kernel-private state. Each
/// success marker is written only after the corresponding syscall/lifecycle contract has completed:
/// fork/wait, background zombie retention, shared-OFD + CLOEXEC exec, signaled wait status,
/// futex-EINTR + SA_RESTART, malformed rt_sigreturn/bad-pointer fail-closed behavior and
/// Stop/Continue. The kernel never matches this process name or grants it special semantics.
const GUEST_SOURCE: &str = r#"#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif

static volatile sig_atomic_t got_usr1;

static void marker(const char *line) {
    char buffer[128];
    size_t n = strlen(line);
    if (n >= sizeof(buffer))
        _exit(120);
    memcpy(buffer, line, n);
    buffer[n] = '\n';
    if (write(STDOUT_FILENO, buffer, n + 1) != (ssize_t)(n + 1))
        _exit(120);
}

__attribute__((noreturn)) static void fail(const char *why) {
    static const char prefix[] = "KERNAL/S30: FAIL ";
    (void)write(STDOUT_FILENO, prefix, sizeof(prefix) - 1);
    (void)write(STDOUT_FILENO, why, strlen(why));
    (void)write(STDOUT_FILENO, "\n", 1);
    _exit(121);
}

static void usr1_handler(int signo) {
    if (signo == SIGUSR1)
        got_usr1 = 1;
}

static void install_usr1(int restart) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    sa.sa_flags = restart ? SA_RESTART : 0;
    if (sigemptyset(&sa.sa_mask) != 0 || sigaction(SIGUSR1, &sa, NULL) != 0)
        fail("sigaction");
}

static pid_t checked_fork(const char *where) {
    pid_t pid = fork();
    if (pid < 0)
        fail(where);
    return pid;
}

static int reap_exact(pid_t pid) {
    int status = 0;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != pid)
        fail("waitpid exact");
    return status;
}

static void spin_forever(void) {
    for (;;)
        __asm__ __volatile__("" ::: "memory");
}

static int exec_child(void) {
    char c = 0;
    if (read(3, &c, 1) != 1 || c != 'B')
        return 91;
    errno = 0;
    if (read(4, &c, 1) != -1 || errno != EBADF)
        return 92;
    return 23;
}

static void prove_foreground_background(void) {
    pid_t background = checked_fork("fork background");
    if (background == 0) {
        if (setpgid(0, 0) != 0)
            _exit(112);
        _exit(12);
    }

    pid_t foreground = checked_fork("fork foreground");
    if (foreground == 0)
        _exit(7);

    int status = reap_exact(foreground);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 7)
        fail("foreground status");
    marker("KERNAL/S30: foreground child lifecycle/reap passed");

    status = reap_exact(background);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 12)
        fail("background status");
    marker("KERNAL/S30: background child lifecycle/reap passed");
}

static void prove_exec_cloexec(void) {
    int shared = open("/proof-data", O_RDONLY);
    int cloexec = open("/proof-data", O_RDONLY | O_CLOEXEC);
    if (shared != 3 || cloexec != 4)
        fail("fd allocation");
    if (lseek(shared, 1, SEEK_SET) != 1)
        fail("shared seek");

    pid_t child = checked_fork("fork exec");
    if (child == 0) {
        char *const argv[] = {(char *)"step30-proof", (char *)"exec-child", NULL};
        execv("/bin/step30-proof", argv);
        _exit(93);
    }
    int status = reap_exact(child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 23)
        fail("exec child status");

    char c = 0;
    if (read(shared, &c, 1) != 1 || c != 'C')
        fail("shared OFD offset");
    if (read(cloexec, &c, 1) != 1 || c != 'A')
        fail("parent CLOEXEC isolation");
    if (close(shared) != 0 || close(cloexec) != 0)
        fail("fd close");
    marker("KERNAL/S30: fork shared OFD and exec CLOEXEC passed");
}

static void prove_normal_wait(void) {
    pid_t child = checked_fork("fork normal wait");
    if (child == 0)
        _exit(42);
    int status = reap_exact(child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
        fail("normal wait status");
    marker("KERNAL/S30: normal exit wait status passed");
}

static void prove_signal_wait(void) {
    pid_t child = checked_fork("fork signal wait");
    if (child == 0)
        spin_forever();
    if (kill(child, SIGTERM) != 0)
        fail("kill SIGTERM");
    int status = reap_exact(child);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
        fail("signal wait status");
    marker("KERNAL/S30: signal termination wait status passed");
}

static void prove_eintr_restart(void) {
    install_usr1(0);
    got_usr1 = 0;
    volatile int futex_word = 0;
    pid_t sender = checked_fork("fork futex sender");
    if (sender == 0) {
        pid_t parent = getppid();
        for (;;) {
            if (kill(parent, SIGUSR1) != 0)
                _exit(101);
        }
    }
    errno = 0;
    long futex_rc = syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    if (futex_rc != -1 || errno != EINTR || !got_usr1)
        fail("futex EINTR");
    if (kill(sender, SIGTERM) != 0)
        fail("futex sender terminate");
    int status = reap_exact(sender);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
        fail("futex sender status");

    install_usr1(1);
    got_usr1 = 0;
    int pipefd[2];
    if (pipe(pipefd) != 0)
        fail("restart pipe");
    sender = checked_fork("fork restart sender");
    if (sender == 0) {
        close(pipefd[0]);
        if (kill(getppid(), SIGUSR1) != 0)
            _exit(102);
        if (write(pipefd[1], "R", 1) != 1)
            _exit(103);
        _exit(0);
    }
    close(pipefd[1]);
    char c = 0;
    if (read(pipefd[0], &c, 1) != 1 || c != 'R' || !got_usr1)
        fail("SA_RESTART read");
    close(pipefd[0]);
    status = reap_exact(sender);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fail("restart sender status");
    marker("KERNAL/S30: EINTR and SA_RESTART passed");
}

static void prove_bad_signal_frame(void) {
    errno = 0;
    if (syscall(SYS_rt_sigaction, SIGUSR2, (void *)(uintptr_t)1, NULL, sizeof(uint64_t)) != -1 ||
        errno != EFAULT)
        fail("rt_sigaction bad pointer");

    pid_t child = checked_fork("fork bad sigreturn");
    if (child == 0) {
        (void)syscall(SYS_rt_sigreturn);
        _exit(88);
    }
    int status = reap_exact(child);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV)
        fail("malformed rt_sigreturn status");
    marker("KERNAL/S30: malformed signal frame and bad pointer failed closed");
}

static void prove_job_control(void) {
    pid_t child = checked_fork("fork job control");
    if (child == 0)
        spin_forever();
    if (kill(child, SIGSTOP) != 0)
        fail("SIGSTOP send");
    int status = 0;
    if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP)
        fail("SIGSTOP wait");
    if (kill(child, SIGCONT) != 0)
        fail("SIGCONT send");
    if (waitpid(child, &status, WCONTINUED) != child || !WIFCONTINUED(status))
        fail("SIGCONT wait");
    if (kill(child, SIGTERM) != 0)
        fail("job-control terminate");
    status = reap_exact(child);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
        fail("job-control final status");
    marker("KERNAL/S30: Stop Continue lifecycle passed");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "exec-child") == 0)
        return exec_child();
    if (argc != 1)
        fail("initial argc");

    prove_foreground_background();
    prove_exec_cloexec();
    prove_normal_wait();
    prove_signal_wait();
    prove_eintr_restart();
    prove_bad_signal_frame();
    prove_job_control();
    marker("KERNAL/S30: process runtime finalized status=0");
    return 0;
}
"#;

/// Runs the final unchanged-userspace Step-30 proof only after the already accepted Step-28/29
/// matrix has completed in `xtask arm-qemu`.
///
/// The guest binary is a normal static Linux executable. It is compiled once before QEMU, placed in
/// a deterministic initramfs and then executed unchanged through the production ELF/syscall path.
/// The harness merely validates the markers emitted after Linux-visible assertions; it never
/// synthesizes a success condition.
pub fn run() -> Result<(), String> {
    let root = super::workspace_root()?;
    let initramfs = build_guest_initramfs(&root)?;
    validate_initramfs(&initramfs)?;
    let kernel = build_kernel(&root)?;

    for cpus in ACCEPTED_CPU_COUNTS {
        println!("xtask: Step 30 final process-runtime QEMU proof with {cpus} vCPU(s)");
        let transcript = run_qemu(&root, &kernel, &initramfs, cpus)
            .map_err(|error| annotate_qemu_error(&kernel, error))?;
        require_process_runtime_markers(&transcript)
            .map_err(|error| annotate_marker_error(error, &transcript))?;
    }

    println!("xtask: Step 30 process/runtime 1/2/4-vCPU matrix passed");
    Ok(())
}

fn annotate_qemu_error(kernel: &Path, error: String) -> String {
    let mut annotations = Vec::new();
    for field in ["elr", "lr"] {
        let Some(address) = extract_hex_field(&error, field) else {
            continue;
        };
        let lookup_address = elf_lookup_address(address);
        match nearest_elf_function(kernel, lookup_address) {
            Ok(Some((name, start))) => annotations.push(format!(
                "{field}=0x{address:016x} => {name}+0x{:x}",
                lookup_address.saturating_sub(start)
            )),
            Ok(None) => annotations.push(format!(
                "{field}=0x{address:016x} => <no preceding ELF function symbol>"
            )),
            Err(symbol_error) => annotations.push(format!(
                "{field}=0x{address:016x} => <symbolication failed: {symbol_error}>"
            )),
        }
    }

    if annotations.is_empty() {
        error
    } else {
        format!(
            "{error}\nStep-30 exact-build ELF symbolication: {}",
            annotations.join(", ")
        )
    }
}

fn extract_hex_field(text: &str, field: &str) -> Option<u64> {
    let marker = format!("{field}=0x");
    let start = text.rfind(&marker)?.checked_add(marker.len())?;
    let digits = text[start..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    (digits != 0)
        .then(|| u64::from_str_radix(&text[start..start + digits], 16).ok())
        .flatten()
}

fn elf_lookup_address(address: u64) -> u64 {
    let alias_offset = KERNEL_RUNTIME_VIRT_BASE - KERNEL_LINK_PHYS_BASE;
    if address >= KERNEL_RUNTIME_VIRT_BASE {
        address - alias_offset
    } else {
        address
    }
}

fn nearest_elf_function(kernel: &Path, address: u64) -> Result<Option<(String, u64)>, String> {
    let bytes = fs::read(kernel)
        .map_err(|error| format!("read exact Step-30 kernel {}: {error}", kernel.display()))?;
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err("kernel is not a little-endian ELF64 image".to_string());
    }
    if elf_u16(&bytes, 18)? != 183 {
        return Err("kernel ELF e_machine is not AArch64".to_string());
    }

    let section_offset = usize::try_from(elf_u64(&bytes, 40)?)
        .map_err(|_| "kernel ELF section-table offset does not fit usize".to_string())?;
    let section_size = usize::from(elf_u16(&bytes, 58)?);
    let section_count = usize::from(elf_u16(&bytes, 60)?);
    if section_size < 64 || section_count == 0 {
        return Err("kernel ELF has no ordinary section table".to_string());
    }

    let mut best: Option<(String, u64)> = None;
    for section_index in 0..section_count {
        let section = elf_section_offset(section_offset, section_size, section_index)?;
        let section_type = elf_u32(&bytes, section + 4)?;
        if section_type != 2 && section_type != 11 {
            continue;
        }

        let symbols_offset = usize::try_from(elf_u64(&bytes, section + 24)?)
            .map_err(|_| "ELF symbol-table offset does not fit usize".to_string())?;
        let symbols_size = usize::try_from(elf_u64(&bytes, section + 32)?)
            .map_err(|_| "ELF symbol-table size does not fit usize".to_string())?;
        let string_section_index = usize::try_from(elf_u32(&bytes, section + 40)?)
            .map_err(|_| "ELF string-table index does not fit usize".to_string())?;
        let entry_size = usize::try_from(elf_u64(&bytes, section + 56)?)
            .map_err(|_| "ELF symbol entry size does not fit usize".to_string())?;
        if entry_size < 24 || string_section_index >= section_count {
            continue;
        }

        let string_section =
            elf_section_offset(section_offset, section_size, string_section_index)?;
        let strings_offset = usize::try_from(elf_u64(&bytes, string_section + 24)?)
            .map_err(|_| "ELF string-table offset does not fit usize".to_string())?;
        let strings_size = usize::try_from(elf_u64(&bytes, string_section + 32)?)
            .map_err(|_| "ELF string-table size does not fit usize".to_string())?;
        let symbol_count = symbols_size / entry_size;

        for symbol_index in 0..symbol_count {
            let symbol = symbols_offset
                .checked_add(
                    symbol_index
                        .checked_mul(entry_size)
                        .ok_or_else(|| "ELF symbol-table index overflow".to_string())?,
                )
                .ok_or_else(|| "ELF symbol-table offset overflow".to_string())?;
            let info = *bytes
                .get(symbol + 4)
                .ok_or_else(|| "truncated ELF symbol entry".to_string())?;
            if info & 0x0f != 2 || elf_u16(&bytes, symbol + 6)? == 0 {
                continue;
            }
            let value = elf_u64(&bytes, symbol + 8)?;
            if value > address {
                continue;
            }
            let name_offset = usize::try_from(elf_u32(&bytes, symbol)?)
                .map_err(|_| "ELF symbol-name offset does not fit usize".to_string())?;
            let Some(name) = elf_string(&bytes, strings_offset, strings_size, name_offset)? else {
                continue;
            };

            if best
                .as_ref()
                .is_none_or(|(_, best_start)| value > *best_start)
            {
                best = Some((name.to_string(), value));
            }
        }
    }
    Ok(best)
}

fn elf_section_offset(base: usize, entry_size: usize, index: usize) -> Result<usize, String> {
    base.checked_add(
        index
            .checked_mul(entry_size)
            .ok_or_else(|| "ELF section-table index overflow".to_string())?,
    )
    .ok_or_else(|| "ELF section-table offset overflow".to_string())
}

fn elf_string(
    bytes: &[u8],
    table_offset: usize,
    table_size: usize,
    name_offset: usize,
) -> Result<Option<&str>, String> {
    if name_offset >= table_size {
        return Ok(None);
    }
    let start = table_offset
        .checked_add(name_offset)
        .ok_or_else(|| "ELF string offset overflow".to_string())?;
    let table_end = table_offset
        .checked_add(table_size)
        .ok_or_else(|| "ELF string-table end overflow".to_string())?;
    let tail = bytes
        .get(start..table_end)
        .ok_or_else(|| "truncated ELF string table".to_string())?;
    let Some(length) = tail.iter().position(|byte| *byte == 0) else {
        return Err("unterminated ELF symbol name".to_string());
    };
    if length == 0 {
        return Ok(None);
    }
    std::str::from_utf8(&tail[..length])
        .map(Some)
        .map_err(|error| format!("ELF symbol name is not UTF-8: {error}"))
}

fn elf_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw: [u8; 2] = elf_bytes(bytes, offset, 2)?
        .try_into()
        .map_err(|_| "invalid ELF u16 slice".to_string())?;
    Ok(u16::from_le_bytes(raw))
}

fn elf_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw: [u8; 4] = elf_bytes(bytes, offset, 4)?
        .try_into()
        .map_err(|_| "invalid ELF u32 slice".to_string())?;
    Ok(u32::from_le_bytes(raw))
}

fn elf_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let raw: [u8; 8] = elf_bytes(bytes, offset, 8)?
        .try_into()
        .map_err(|_| "invalid ELF u64 slice".to_string())?;
    Ok(u64::from_le_bytes(raw))
}

fn elf_bytes(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "ELF byte-range overflow".to_string())?;
    bytes
        .get(offset..end)
        .ok_or_else(|| "truncated ELF image".to_string())
}

fn build_guest_initramfs(root: &Path) -> Result<PathBuf, String> {
    let source = root.join(GUEST_SOURCE_PATH);
    let binary = root.join(GUEST_BINARY_PATH);
    let initramfs = root.join(INITRAMFS);
    let output_dir = binary
        .parent()
        .ok_or_else(|| format!("Step-30 guest binary has no parent: {}", binary.display()))?;
    fs::create_dir_all(output_dir).map_err(|error| {
        format!(
            "create Step-30 guest output directory {}: {error}",
            output_dir.display()
        )
    })?;
    fs::write(&source, GUEST_SOURCE)
        .map_err(|error| format!("write Step-30 guest source {}: {error}", source.display()))?;

    let compiler = resolve_musl_compiler(root)?;
    let mut compile = Command::new(&compiler);
    compile.args([
        "-O2",
        "-static",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-stack-protector",
        "-Wl,--build-id=none",
        "-o",
    ]);
    compile.arg(&binary).arg(&source);
    super::run_checked(
        &mut compile,
        "Step-30 static AArch64 process-runtime guest build",
    )?;
    let binary_bytes = fs::read(&binary)
        .map_err(|error| format!("read Step-30 guest binary {}: {error}", binary.display()))?;
    if binary_bytes.len() < 64 || &binary_bytes[..4] != b"\x7fELF" || binary_bytes[18] != 0xb7 {
        return Err(format!(
            "Step-30 guest is not an AArch64 ELF payload: {}",
            binary.display()
        ));
    }

    let mut archive = Vec::new();
    append_newc(&mut archive, 1, ".", 0o040755, &[])?;
    append_newc(&mut archive, 2, "bin", 0o040755, &[])?;
    append_newc(&mut archive, 3, "bin/busybox", 0o100755, &binary_bytes)?;
    append_newc(&mut archive, 4, "bin/step30-proof", 0o100755, &binary_bytes)?;
    append_newc(&mut archive, 5, "proof-data", 0o100644, b"ABCDEF\n")?;
    append_newc(&mut archive, 6, "TRAILER!!!", 0, &[])?;
    while archive.len() % 512 != 0 {
        archive.push(0);
    }
    fs::write(&initramfs, &archive)
        .map_err(|error| format!("write Step-30 initramfs {}: {error}", initramfs.display()))?;
    Ok(initramfs)
}

fn resolve_musl_compiler(root: &Path) -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("KERNAL_AARCH64_MUSL_CC") {
        let compiler = PathBuf::from(value);
        validate_musl_compiler(&compiler)?;
        return Ok(compiler);
    }

    for candidate in ["aarch64-linux-musl-gcc", "aarch64-unknown-linux-musl-gcc"] {
        let compiler = PathBuf::from(candidate);
        if validate_musl_compiler(&compiler).is_ok() {
            return Ok(compiler);
        }
    }

    if cfg!(target_os = "macos") {
        let provisioner = root.join("tools/ensure-step15-musl-toolchain-macos.sh");
        let output = Command::new("bash")
            .arg(&provisioner)
            .current_dir(root)
            .output()
            .map_err(|error| {
                format!(
                    "run AArch64 musl provisioner {}: {error}",
                    provisioner.display()
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "AArch64 musl provisioner failed with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let path = String::from_utf8(output.stdout)
            .map_err(|error| format!("AArch64 musl provisioner returned non-UTF8 path: {error}"))?;
        let compiler = PathBuf::from(path.trim());
        validate_musl_compiler(&compiler)?;
        return Ok(compiler);
    }

    Err("AArch64 musl compiler not found; set KERNAL_AARCH64_MUSL_CC".to_string())
}

fn validate_musl_compiler(compiler: &Path) -> Result<(), String> {
    let output = Command::new(compiler)
        .arg("-dumpmachine")
        .output()
        .map_err(|error| {
            format!(
                "query AArch64 musl compiler {}: {error}",
                compiler.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "AArch64 musl compiler {} rejected -dumpmachine",
            compiler.display()
        ));
    }
    let triple = String::from_utf8_lossy(&output.stdout);
    let triple = triple.trim();
    if !triple.starts_with("aarch64") || !triple.contains("linux-musl") {
        return Err(format!(
            "Step-30 compiler is not AArch64 musl: {} reports {triple}",
            compiler.display()
        ));
    }
    Ok(())
}

fn append_newc(
    archive: &mut Vec<u8>,
    ino: u32,
    name: &str,
    mode: u32,
    data: &[u8],
) -> Result<(), String> {
    let name_size = name
        .len()
        .checked_add(1)
        .ok_or_else(|| "Step-30 CPIO name length overflow".to_string())?;
    let name_size =
        u32::try_from(name_size).map_err(|_| format!("Step-30 CPIO name too long: {name}"))?;
    let file_size =
        u32::try_from(data.len()).map_err(|_| format!("Step-30 CPIO file too large: {name}"))?;
    let nlink = if mode & 0o170000 == 0o040000 { 2 } else { 1 };
    let fields = [
        ino, mode, 0, 0, nlink, 0, file_size, 0, 0, 0, 0, name_size, 0,
    ];
    archive.extend_from_slice(b"070701");
    for value in fields {
        archive.extend_from_slice(format!("{value:08x}").as_bytes());
    }
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    pad_four(archive);
    archive.extend_from_slice(data);
    pad_four(archive);
    Ok(())
}

fn pad_four(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

fn validate_initramfs(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("stat Step-30 initramfs {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INITRAMFS_BYTES {
        return Err(format!(
            "Step-30 initramfs is missing, empty or too large: {} ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn build_kernel(root: &Path) -> Result<PathBuf, String> {
    let mut core = Command::new(super::cargo());
    core.args([
        "build",
        "-p",
        super::AARCH64_CORE_PACKAGE,
        "--target",
        super::AARCH64_CORE_TARGET,
        "--features",
        FEATURE,
    ]);
    super::run_checked(
        &mut core,
        "Step-30 final AArch64 process-runtime kernel build",
    )?;

    let built = root
        .join("target")
        .join(super::AARCH64_CORE_TARGET)
        .join("debug")
        .join(super::AARCH64_CORE_PACKAGE);
    let metadata = fs::metadata(&built)
        .map_err(|error| format!("stat Step-30 AArch64 kernel {}: {error}", built.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-30 AArch64 kernel is missing or empty after {FEATURE}: {}",
            built.display()
        ));
    }

    let frozen = root.join(KERNEL);
    let parent = frozen
        .parent()
        .ok_or_else(|| format!("Step-30 frozen kernel has no parent: {}", frozen.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create Step-30 output directory {}: {error}",
            parent.display()
        )
    })?;
    fs::copy(&built, &frozen).map_err(|error| {
        format!(
            "freeze Step-30 kernel {} -> {}: {error}",
            built.display(),
            frozen.display()
        )
    })?;
    let frozen_metadata = fs::metadata(&frozen)
        .map_err(|error| format!("stat frozen Step-30 kernel {}: {error}", frozen.display()))?;
    if !frozen_metadata.is_file() || frozen_metadata.len() != metadata.len() {
        return Err(format!(
            "frozen Step-30 kernel is missing or size-mismatched: {}",
            frozen.display()
        ));
    }
    Ok(frozen)
}

fn run_qemu(root: &Path, kernel: &Path, initramfs: &Path, cpus: usize) -> Result<String, String> {
    if !ACCEPTED_CPU_COUNTS.contains(&cpus) {
        return Err(format!(
            "Step-30 QEMU CPU count {cpus} is outside the accepted 1/2/4-vCPU matrix"
        ));
    }
    validate_initramfs(initramfs)?;
    let metadata = fs::metadata(kernel)
        .map_err(|error| format!("stat Step-30 kernel {}: {error}", kernel.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-30 AArch64 kernel is missing or empty: {}",
            kernel.display()
        ));
    }

    let initrd = initramfs.to_str().ok_or_else(|| {
        format!(
            "Step-30 initramfs path is not UTF-8: {}",
            initramfs.display()
        )
    })?;
    if initrd.contains(',') {
        return Err(format!(
            "Step-30 initramfs path contains a comma unsupported by guest-loader: {}",
            initramfs.display()
        ));
    }
    let guest_loader = format!("guest-loader,addr=0x{GUEST_INITRD_ADDRESS:x},initrd={initrd}");
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
        .map_err(|error| format!("start Step-30 AArch64 QEMU ({cpus} vCPU): {error}"))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate(&mut child);
        "capture Step-30 QEMU stdout failed".to_string()
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate(&mut child);
        "capture Step-30 QEMU stderr failed".to_string()
    })?;
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
    require_status(status, cpus, &transcript)?;
    Ok(transcript)
}

const MARKER_ERROR_TAIL_LINES: usize = 24;

fn annotate_marker_error(error: String, transcript: &str) -> String {
    let explicit_failures = transcript
        .lines()
        .filter(|line| line.starts_with("KERNAL/S30: FAIL"))
        .collect::<Vec<_>>();
    let lines = transcript.lines().collect::<Vec<_>>();
    let tail_start = lines.len().saturating_sub(MARKER_ERROR_TAIL_LINES);
    let tail = lines[tail_start..].join("\n");

    let mut diagnostic = error;
    if !explicit_failures.is_empty() {
        diagnostic.push_str("\nStep-30 explicit failure boundary:");
        for line in explicit_failures {
            diagnostic.push_str("\n  ");
            diagnostic.push_str(line);
        }
    }
    diagnostic.push_str(&format!(
        "\nStep-30 transcript tail (last {} of {} lines):\n{}",
        lines.len().saturating_sub(tail_start),
        lines.len(),
        tail
    ));
    diagnostic
}

/// Fails closed unless every Step-30 process-runtime boundary occurs exactly once and in order.
pub fn require_process_runtime_markers(transcript: &str) -> Result<(), String> {
    let mut previous = None;
    for marker in REQUIRED_MARKERS {
        let mut count = 0usize;
        let mut position = None;
        for (line_index, line) in transcript.lines().enumerate() {
            if line.trim_end_matches('\r') == marker {
                count += 1;
                position = Some(line_index);
            }
        }
        if count != 1 {
            return Err(format!(
                "Step-30 transcript contains marker {marker:?} {count} times; expected exactly once"
            ));
        }
        let position =
            position.ok_or_else(|| format!("Step-30 transcript is missing {marker:?}"))?;
        if let Some(previous) = previous
            && position <= previous
        {
            return Err(format!(
                "Step-30 proof markers are out of causal order at {marker:?}: previous={previous}, current={position}"
            ));
        }
        previous = Some(position);
    }
    for forbidden in FORBIDDEN_PREFIXES {
        if transcript.lines().any(|line| line.starts_with(forbidden)) {
            return Err(format!(
                "Step-30 transcript contains forbidden/fail-closed boundary {forbidden:?}"
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
            .map_err(|error| format!("read Step-30 QEMU {label}: {error}"))?;
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
                return Err(format!("poll Step-30 AArch64 QEMU ({cpus} vCPU): {error}"));
            }
        }
        if start.elapsed() >= timeout {
            let kill_error = child.kill().err();
            let _ = child.wait();
            return Err(match kill_error {
                Some(error) => format!(
                    "Step-30 AArch64 QEMU ({cpus} vCPU) exceeded {}s; kill failed: {error}",
                    timeout.as_secs_f64()
                ),
                None => format!(
                    "Step-30 AArch64 QEMU ({cpus} vCPU) exceeded {}s and was killed",
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
        .map_err(|_| format!("Step-30 QEMU {label} reader panicked"))?
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
        Some(super::AARCH64_QEMU_SUCCESS_STATUS) => Ok(()),
        Some(code) => Err(format!(
            "Step-30 AArch64 QEMU ({cpus} vCPU) exited with status {code}; transcript:\n{transcript}"
        )),
        None => Err(format!(
            "Step-30 AArch64 QEMU ({cpus} vCPU) terminated by signal; transcript:\n{transcript}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_transcript() -> String {
        let mut transcript = String::from("boot\n");
        for marker in REQUIRED_MARKERS {
            transcript.push_str(marker);
            transcript.push('\n');
        }
        transcript
    }

    #[test]
    fn marker_gate_requires_every_boundary_once_and_in_order() {
        require_process_runtime_markers(&valid_transcript()).unwrap();
        for missing in REQUIRED_MARKERS {
            let transcript = valid_transcript()
                .lines()
                .filter(|line| *line != missing)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(require_process_runtime_markers(&transcript).is_err());
        }
        assert!(
            require_process_runtime_markers(&format!(
                "{FOREGROUND_MARKER}\n{BACKGROUND_MARKER}\n{FD_EXEC_MARKER}\n{FD_EXEC_MARKER}\n{NORMAL_WAIT_MARKER}\n{SIGNAL_WAIT_MARKER}\n{RESTART_MARKER}\n{SIGNAL_FRAME_MARKER}\n{JOB_CONTROL_MARKER}\n{SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
        assert!(
            require_process_runtime_markers(&format!(
                "{BACKGROUND_MARKER}\n{FOREGROUND_MARKER}\n{FD_EXEC_MARKER}\n{NORMAL_WAIT_MARKER}\n{SIGNAL_WAIT_MARKER}\n{RESTART_MARKER}\n{SIGNAL_FRAME_MARKER}\n{JOB_CONTROL_MARKER}\n{SUCCESS_MARKER}\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn marker_error_annotation_preserves_verdict_and_bounds_transcript_tail() {
        let transcript = (0..40)
            .map(|index| format!("runtime line {index}"))
            .chain(["KERNAL/S30: FAIL foreground reap".to_string()])
            .collect::<Vec<_>>()
            .join("\n");
        let verdict = require_process_runtime_markers(&transcript).unwrap_err();
        let annotated = annotate_marker_error(verdict.clone(), &transcript);
        assert!(annotated.starts_with(&verdict));
        assert!(annotated.contains("KERNAL/S30: FAIL foreground reap"));
        assert!(annotated.contains("runtime line 17"));
        assert!(!annotated.contains("runtime line 16\n"));
        assert!(annotated.contains("last 24 of 41 lines"));
    }

    #[test]
    fn marker_gate_rejects_explicit_failure_boundaries() {
        let mut transcript = valid_transcript();
        transcript.push_str("KERNAL/S30: FAIL synthetic\n");
        assert!(require_process_runtime_markers(&transcript).is_err());
    }

    #[test]
    fn fault_field_extraction_uses_last_exact_hex_value() {
        let transcript = "elr=0x1 lr=0x2\nKERNAL/S30T non-irq-fatal elr=0xffffffff8025b9ac lr=0xffffffff8025b96c";
        assert_eq!(
            extract_hex_field(transcript, "elr"),
            Some(0xffff_ffff_8025_b9ac)
        );
        assert_eq!(
            extract_hex_field(transcript, "lr"),
            Some(0xffff_ffff_8025_b96c)
        );
        assert_eq!(extract_hex_field(transcript, "far"), None);
    }

    #[test]
    fn elf_lookup_address_normalizes_protected_ttbr1_alias() {
        assert_eq!(
            elf_lookup_address(0xffff_ffff_8025_b9ac),
            0x0000_0000_4025_b9ac
        );
        assert_eq!(
            elf_lookup_address(0xffff_ffff_8020_0000),
            0x0000_0000_4020_0000
        );
        assert_eq!(elf_lookup_address(0x0000_0000_4025_b9ac), 0x4025_b9ac);
    }

    #[test]
    fn elf_symbolizer_rejects_non_elf_input() {
        let path =
            std::env::temp_dir().join(format!("kernal-step30-non-elf-{}", std::process::id()));
        fs::write(&path, b"not an elf").unwrap();
        let result = nearest_elf_function(&path, 0x1000);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn newc_writer_is_deterministic_and_aligned() {
        let mut one = Vec::new();
        append_newc(&mut one, 1, "bin", 0o040755, &[]).unwrap();
        let mut two = Vec::new();
        append_newc(&mut two, 1, "bin", 0o040755, &[]).unwrap();
        assert_eq!(one, two);
        assert_eq!(one.len() % 4, 0);
        assert!(one.starts_with(b"070701"));
    }

    #[test]
    fn eintr_sender_stays_live_until_the_parent_can_enter_futex_wait() {
        let start = GUEST_SOURCE
            .find("static void prove_eintr_restart(void)")
            .expect("missing EINTR/SA_RESTART guest proof");
        let tail = &GUEST_SOURCE[start..];
        let end = tail
            .find("static void prove_bad_signal_frame(void)")
            .expect("missing next guest proof boundary");
        let proof = &tail[..end];

        assert!(
            proof.contains("for (;;)") && proof.contains("kill(parent, SIGUSR1)"),
            "the EINTR sender must keep producing SIGUSR1 until one can interrupt FUTEX_WAIT; a one-shot pre-wait signal is racy"
        );
        assert!(
            proof.contains("kill(sender, SIGTERM)") && proof.contains("WIFSIGNALED(status)"),
            "the parent must terminate and reap the persistent signal sender after FUTEX_WAIT reports EINTR"
        );
    }
}
