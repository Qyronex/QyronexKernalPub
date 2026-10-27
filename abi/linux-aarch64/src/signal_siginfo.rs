// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;

use crate::KERNEL_SIGINFO_BYTES;

pub const SI_USER: i32 = 0;
pub const SI_TKILL: i32 = -6;
pub const SI_KERNEL: i32 = 0x80;

pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

const SIGCHLD: u8 = 17;
const SIGCONT: u8 = 18;
const SI_SIGNO_OFFSET: usize = 0;
const SI_ERRNO_OFFSET: usize = 4;
const SI_CODE_OFFSET: usize = 8;
const SI_PID_OFFSET: usize = 16;
const SI_UID_OFFSET: usize = 20;
const SI_STATUS_OFFSET: usize = 24;

/// Linux/AArch64 signal siginfo for sender- and child-generated signals.
///
/// The encoded PID/UID/status values are observations only and never become Process, credential,
/// wait or scheduler authority. All unspecified union/padding bytes are deterministic zeroes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderSignalSiginfo {
    bytes: [u8; KERNEL_SIGINFO_BYTES],
}

impl SenderSignalSiginfo {
    /// `kill(2)` / process-directed user signal (`SI_USER`).
    pub fn process_directed(signal: u8, sender_pid: NonZeroU32, sender_uid: u32) -> Option<Self> {
        Self::new(signal, SI_USER, sender_pid, sender_uid)
    }

    /// `tkill(2)` / `tgkill(2)` thread-directed user signal (`SI_TKILL`).
    pub fn thread_directed(signal: u8, sender_pid: NonZeroU32, sender_uid: u32) -> Option<Self> {
        Self::new(signal, SI_TKILL, sender_pid, sender_uid)
    }

    /// Generic kernel-origin signal (`SI_KERNEL`) with zero sender identity fields.
    pub fn kernel_directed(signal: u8) -> Option<Self> {
        if signal == 0 || signal > 64 {
            return None;
        }
        let mut bytes = [0u8; KERNEL_SIGINFO_BYTES];
        write_i32(&mut bytes, SI_SIGNO_OFFSET, i32::from(signal));
        write_i32(&mut bytes, SI_ERRNO_OFFSET, 0);
        write_i32(&mut bytes, SI_CODE_OFFSET, SI_KERNEL);
        Some(Self { bytes })
    }

    /// Kernel-generated SIGCHLD for a child that exited normally (`CLD_EXITED`).
    pub fn child_exited(child_pid: NonZeroU32, child_uid: u32, exit_status: u8) -> Self {
        Self::child(CLD_EXITED, child_pid, child_uid, i32::from(exit_status))
    }

    /// Kernel-generated SIGCHLD for a child terminated by a signal (`CLD_KILLED`/`CLD_DUMPED`).
    pub fn child_signaled(
        child_pid: NonZeroU32,
        child_uid: u32,
        termination_signal: u8,
        core_dumped: bool,
    ) -> Option<Self> {
        if termination_signal == 0 || termination_signal > 64 {
            return None;
        }
        let code = if core_dumped { CLD_DUMPED } else { CLD_KILLED };
        Some(Self::child(
            code,
            child_pid,
            child_uid,
            i32::from(termination_signal),
        ))
    }

    /// Kernel-generated SIGCHLD for a real child job-control stop (`CLD_STOPPED`).
    pub fn child_stopped(child_pid: NonZeroU32, child_uid: u32, stop_signal: u8) -> Option<Self> {
        if stop_signal == 0 || stop_signal > 64 {
            return None;
        }
        Some(Self::child(
            CLD_STOPPED,
            child_pid,
            child_uid,
            i32::from(stop_signal),
        ))
    }

    /// Kernel-generated SIGCHLD for a real child continue completion (`CLD_CONTINUED`).
    pub fn child_continued(child_pid: NonZeroU32, child_uid: u32) -> Self {
        Self::child(CLD_CONTINUED, child_pid, child_uid, i32::from(SIGCONT))
    }

    pub const fn as_bytes(&self) -> &[u8; KERNEL_SIGINFO_BYTES] {
        &self.bytes
    }

    pub const fn into_bytes(self) -> [u8; KERNEL_SIGINFO_BYTES] {
        self.bytes
    }

    fn new(signal: u8, code: i32, sender_pid: NonZeroU32, sender_uid: u32) -> Option<Self> {
        if signal == 0 || signal > 64 {
            return None;
        }
        let mut bytes = [0u8; KERNEL_SIGINFO_BYTES];
        write_i32(&mut bytes, SI_SIGNO_OFFSET, i32::from(signal));
        write_i32(&mut bytes, SI_ERRNO_OFFSET, 0);
        write_i32(&mut bytes, SI_CODE_OFFSET, code);
        write_u32(&mut bytes, SI_PID_OFFSET, sender_pid.get());
        write_u32(&mut bytes, SI_UID_OFFSET, sender_uid);
        Some(Self { bytes })
    }

    fn child(code: i32, child_pid: NonZeroU32, child_uid: u32, status: i32) -> Self {
        let mut bytes = [0u8; KERNEL_SIGINFO_BYTES];
        write_i32(&mut bytes, SI_SIGNO_OFFSET, i32::from(SIGCHLD));
        write_i32(&mut bytes, SI_ERRNO_OFFSET, 0);
        write_i32(&mut bytes, SI_CODE_OFFSET, code);
        write_u32(&mut bytes, SI_PID_OFFSET, child_pid.get());
        write_u32(&mut bytes, SI_UID_OFFSET, child_uid);
        write_i32(&mut bytes, SI_STATUS_OFFSET, status);
        Self { bytes }
    }
}

fn write_i32(bytes: &mut [u8; KERNEL_SIGINFO_BYTES], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8; KERNEL_SIGINFO_BYTES], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_i32(bytes: &[u8; KERNEL_SIGINFO_BYTES], offset: usize) -> i32 {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[offset..offset + 4]);
        i32::from_ne_bytes(word)
    }

    fn read_u32(bytes: &[u8; KERNEL_SIGINFO_BYTES], offset: usize) -> u32 {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[offset..offset + 4]);
        u32::from_ne_bytes(word)
    }

    #[test]
    fn kernel_siginfo_uses_si_kernel_and_zero_sender_identity() {
        let info = SenderSignalSiginfo::kernel_directed(11).unwrap();
        assert_eq!(read_i32(info.as_bytes(), SI_SIGNO_OFFSET), 11);
        assert_eq!(read_i32(info.as_bytes(), SI_ERRNO_OFFSET), 0);
        assert_eq!(read_i32(info.as_bytes(), SI_CODE_OFFSET), SI_KERNEL);
        assert_eq!(read_u32(info.as_bytes(), SI_PID_OFFSET), 0);
        assert_eq!(read_u32(info.as_bytes(), SI_UID_OFFSET), 0);
    }

    #[test]
    fn kill_siginfo_uses_si_user_and_sender_identity() {
        let sender = NonZeroU32::new(23).unwrap();
        let info = SenderSignalSiginfo::process_directed(15, sender, 1000).unwrap();
        let bytes = info.as_bytes();

        assert_eq!(bytes.len(), KERNEL_SIGINFO_BYTES);
        assert_eq!(read_i32(bytes, SI_SIGNO_OFFSET), 15);
        assert_eq!(read_i32(bytes, SI_ERRNO_OFFSET), 0);
        assert_eq!(read_i32(bytes, SI_CODE_OFFSET), SI_USER);
        assert_eq!(read_u32(bytes, SI_PID_OFFSET), 23);
        assert_eq!(read_u32(bytes, SI_UID_OFFSET), 1000);
        assert!(bytes[24..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn tgkill_siginfo_uses_si_tkill() {
        let sender = NonZeroU32::new(31).unwrap();
        let info = SenderSignalSiginfo::thread_directed(10, sender, 7).unwrap();
        assert_eq!(read_i32(info.as_bytes(), SI_CODE_OFFSET), SI_TKILL);
        assert_eq!(read_u32(info.as_bytes(), SI_PID_OFFSET), 31);
        assert_eq!(read_u32(info.as_bytes(), SI_UID_OFFSET), 7);
    }

    #[test]
    fn child_exit_siginfo_uses_cld_exited_and_truthful_status() {
        let child = NonZeroU32::new(41).unwrap();
        let info = SenderSignalSiginfo::child_exited(child, 1000, 23);
        let bytes = info.as_bytes();
        assert_eq!(read_i32(bytes, SI_SIGNO_OFFSET), i32::from(SIGCHLD));
        assert_eq!(read_i32(bytes, SI_ERRNO_OFFSET), 0);
        assert_eq!(read_i32(bytes, SI_CODE_OFFSET), CLD_EXITED);
        assert_eq!(read_u32(bytes, SI_PID_OFFSET), 41);
        assert_eq!(read_u32(bytes, SI_UID_OFFSET), 1000);
        assert_eq!(read_i32(bytes, SI_STATUS_OFFSET), 23);
        assert!(bytes[28..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn child_signal_siginfo_distinguishes_killed_and_dumped() {
        let child = NonZeroU32::new(43).unwrap();
        let killed = SenderSignalSiginfo::child_signaled(child, 7, 15, false).unwrap();
        assert_eq!(read_i32(killed.as_bytes(), SI_CODE_OFFSET), CLD_KILLED);
        assert_eq!(read_i32(killed.as_bytes(), SI_STATUS_OFFSET), 15);
        assert!(killed.as_bytes()[28..].iter().all(|byte| *byte == 0));

        let dumped = SenderSignalSiginfo::child_signaled(child, 7, 11, true).unwrap();
        assert_eq!(read_i32(dumped.as_bytes(), SI_CODE_OFFSET), CLD_DUMPED);
        assert_eq!(read_i32(dumped.as_bytes(), SI_STATUS_OFFSET), 11);
        assert!(dumped.as_bytes()[28..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn child_job_control_siginfo_uses_linux_cld_codes_and_statuses() {
        let child = NonZeroU32::new(47).unwrap();
        let stopped = SenderSignalSiginfo::child_stopped(child, 1000, 19).unwrap();
        assert_eq!(
            read_i32(stopped.as_bytes(), SI_SIGNO_OFFSET),
            i32::from(SIGCHLD)
        );
        assert_eq!(read_i32(stopped.as_bytes(), SI_CODE_OFFSET), CLD_STOPPED);
        assert_eq!(read_u32(stopped.as_bytes(), SI_PID_OFFSET), 47);
        assert_eq!(read_u32(stopped.as_bytes(), SI_UID_OFFSET), 1000);
        assert_eq!(read_i32(stopped.as_bytes(), SI_STATUS_OFFSET), 19);

        let continued = SenderSignalSiginfo::child_continued(child, 1000);
        assert_eq!(
            read_i32(continued.as_bytes(), SI_SIGNO_OFFSET),
            i32::from(SIGCHLD)
        );
        assert_eq!(
            read_i32(continued.as_bytes(), SI_CODE_OFFSET),
            CLD_CONTINUED
        );
        assert_eq!(read_u32(continued.as_bytes(), SI_PID_OFFSET), 47);
        assert_eq!(read_u32(continued.as_bytes(), SI_UID_OFFSET), 1000);
        assert_eq!(
            read_i32(continued.as_bytes(), SI_STATUS_OFFSET),
            i32::from(SIGCONT)
        );
        assert!(continued.as_bytes()[28..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_signal_numbers_are_rejected() {
        let sender = NonZeroU32::new(1).unwrap();
        assert_eq!(SenderSignalSiginfo::process_directed(0, sender, 0), None);
        assert_eq!(SenderSignalSiginfo::thread_directed(65, sender, 0), None);
        assert_eq!(SenderSignalSiginfo::kernel_directed(0), None);
        assert_eq!(SenderSignalSiginfo::kernel_directed(65), None);
        assert_eq!(
            SenderSignalSiginfo::child_signaled(sender, 0, 0, false),
            None
        );
        assert_eq!(
            SenderSignalSiginfo::child_signaled(sender, 0, 65, false),
            None
        );
        assert_eq!(SenderSignalSiginfo::child_stopped(sender, 0, 0), None);
        assert_eq!(SenderSignalSiginfo::child_stopped(sender, 0, 65), None);
    }
}
