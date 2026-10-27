// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;

/// Linux UAPI `siginfo_t` is fixed at 128 bytes on AArch64.
pub const KERNEL_SIGINFO_BYTES: usize = 128;

const SIGCHLD: i32 = 17;
const SIGCONT: i32 = 18;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;

// AArch64 follows the generic 64-bit siginfo layout: three leading i32 values followed by an
// 8-byte-aligned `__sifields` union. The SIGCHLD view starts at byte 16.
const SI_SIGNO_OFFSET: usize = 0;
const SI_CODE_OFFSET: usize = 8;
const SI_PID_OFFSET: usize = 16;
const SI_UID_OFFSET: usize = 20;
const SI_STATUS_OFFSET: usize = 24;

/// Already encoded AArch64 Linux `siginfo_t` for the `waitid(2)` SIGCHLD result surface.
///
/// This is an ABI value only. PID/UID/status fields are copied observations and confer no Process,
/// credential or lifecycle authority. The structure deliberately keeps all unspecified/padding/time
/// fields zero so WNOHANG and deterministic regression comparisons never expose uninitialized bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitIdSiginfo {
    bytes: [u8; KERNEL_SIGINFO_BYTES],
}

impl WaitIdSiginfo {
    /// Linux/POSIX WNOHANG no-status result. Linux zeros at least si_pid/si_signo; zeroing the complete
    /// fixed-size object is deterministic and stronger without changing the visible contract.
    pub const fn empty() -> Self {
        Self {
            bytes: [0; KERNEL_SIGINFO_BYTES],
        }
    }

    /// Encodes one normally exited child (`CLD_EXITED`).
    pub fn exited(pid: NonZeroU32, real_uid: u32, status: u8) -> Self {
        Self::child(pid, real_uid, CLD_EXITED, i32::from(status))
    }

    /// Encodes one signal-terminated child (`CLD_KILLED` / `CLD_DUMPED`).
    ///
    /// Linux signal numbers in wait status occupy seven bits. Zero is not a termination signal.
    pub fn signaled(pid: NonZeroU32, real_uid: u32, signal: u8, core_dumped: bool) -> Option<Self> {
        if signal == 0 || signal > 0x7f {
            return None;
        }
        Some(Self::child(
            pid,
            real_uid,
            if core_dumped { CLD_DUMPED } else { CLD_KILLED },
            i32::from(signal),
        ))
    }

    /// Encodes one child stopped by a Linux signal (`CLD_STOPPED`).
    ///
    /// The signal is copied observation metadata only; it cannot authorize signal or scheduler state.
    pub fn stopped(pid: NonZeroU32, real_uid: u32, signal: u8) -> Option<Self> {
        if signal == 0 || signal > 0x7f {
            return None;
        }
        Some(Self::child(pid, real_uid, CLD_STOPPED, i32::from(signal)))
    }

    /// Encodes one previously stopped child resumed by `SIGCONT` (`CLD_CONTINUED`).
    pub fn continued(pid: NonZeroU32, real_uid: u32) -> Self {
        Self::child(pid, real_uid, CLD_CONTINUED, SIGCONT)
    }

    pub const fn as_bytes(&self) -> &[u8; KERNEL_SIGINFO_BYTES] {
        &self.bytes
    }

    pub const fn into_bytes(self) -> [u8; KERNEL_SIGINFO_BYTES] {
        self.bytes
    }

    fn child(pid: NonZeroU32, real_uid: u32, code: i32, status: i32) -> Self {
        let mut encoded = Self::empty();
        write_i32(&mut encoded.bytes, SI_SIGNO_OFFSET, SIGCHLD);
        write_i32(&mut encoded.bytes, SI_CODE_OFFSET, code);
        write_u32(&mut encoded.bytes, SI_PID_OFFSET, pid.get());
        write_u32(&mut encoded.bytes, SI_UID_OFFSET, real_uid);
        write_i32(&mut encoded.bytes, SI_STATUS_OFFSET, status);
        encoded
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
    fn empty_waitid_siginfo_is_exactly_128_zero_bytes() {
        let empty = WaitIdSiginfo::empty();
        assert_eq!(empty.as_bytes().len(), KERNEL_SIGINFO_BYTES);
        assert!(empty.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn exited_child_matches_aarch64_sigchld_layout() {
        let pid = NonZeroU32::new(23).unwrap();
        let info = WaitIdSiginfo::exited(pid, 1000, 7);
        let bytes = info.as_bytes();

        assert_eq!(read_i32(bytes, SI_SIGNO_OFFSET), SIGCHLD);
        assert_eq!(read_i32(bytes, SI_CODE_OFFSET), CLD_EXITED);
        assert_eq!(read_u32(bytes, SI_PID_OFFSET), 23);
        assert_eq!(read_u32(bytes, SI_UID_OFFSET), 1000);
        assert_eq!(read_i32(bytes, SI_STATUS_OFFSET), 7);
        assert!(bytes[28..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn signaled_child_distinguishes_killed_and_core_dumped() {
        let pid = NonZeroU32::new(31).unwrap();
        let killed = WaitIdSiginfo::signaled(pid, 7, 15, false).unwrap();
        let dumped = WaitIdSiginfo::signaled(pid, 7, 11, true).unwrap();

        assert_eq!(read_i32(killed.as_bytes(), SI_CODE_OFFSET), CLD_KILLED);
        assert_eq!(read_i32(killed.as_bytes(), SI_STATUS_OFFSET), 15);
        assert_eq!(read_i32(dumped.as_bytes(), SI_CODE_OFFSET), CLD_DUMPED);
        assert_eq!(read_i32(dumped.as_bytes(), SI_STATUS_OFFSET), 11);
        assert_eq!(WaitIdSiginfo::signaled(pid, 7, 0, false), None);
        assert_eq!(WaitIdSiginfo::signaled(pid, 7, 128, false), None);
    }

    #[test]
    fn stopped_child_uses_cld_stopped_and_preserves_stop_signal() {
        let pid = NonZeroU32::new(41).unwrap();
        let stopped = WaitIdSiginfo::stopped(pid, 1001, 19).unwrap();
        let bytes = stopped.as_bytes();

        assert_eq!(read_i32(bytes, SI_SIGNO_OFFSET), SIGCHLD);
        assert_eq!(read_i32(bytes, SI_CODE_OFFSET), CLD_STOPPED);
        assert_eq!(read_u32(bytes, SI_PID_OFFSET), 41);
        assert_eq!(read_u32(bytes, SI_UID_OFFSET), 1001);
        assert_eq!(read_i32(bytes, SI_STATUS_OFFSET), 19);
        assert_eq!(WaitIdSiginfo::stopped(pid, 1001, 0), None);
        assert_eq!(WaitIdSiginfo::stopped(pid, 1001, 128), None);
    }

    #[test]
    fn continued_child_uses_cld_continued_and_sigcont_status() {
        let pid = NonZeroU32::new(43).unwrap();
        let continued = WaitIdSiginfo::continued(pid, 1002);
        let bytes = continued.as_bytes();

        assert_eq!(read_i32(bytes, SI_SIGNO_OFFSET), SIGCHLD);
        assert_eq!(read_i32(bytes, SI_CODE_OFFSET), CLD_CONTINUED);
        assert_eq!(read_u32(bytes, SI_PID_OFFSET), 43);
        assert_eq!(read_u32(bytes, SI_UID_OFFSET), 1002);
        assert_eq!(read_i32(bytes, SI_STATUS_OFFSET), SIGCONT);
    }
}
