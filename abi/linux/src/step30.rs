// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;

use crate::{Errno, linux_signed_int, linux_unsigned_int};

/// Linux wait option bits shared by `wait4` and raw `waitid`.
pub const WNOHANG: u32 = 0x0000_0001;
pub const WUNTRACED: u32 = 0x0000_0002;
pub const WSTOPPED: u32 = WUNTRACED;
pub const WEXITED: u32 = 0x0000_0004;
pub const WCONTINUED: u32 = 0x0000_0008;
pub const WNOWAIT: u32 = 0x0100_0000;
pub const WNOTHREAD: u32 = 0x2000_0000;
pub const WALL: u32 = 0x4000_0000;
pub const WCLONE: u32 = 0x8000_0000;

const WAIT4_OPTION_MASK: u32 = WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WALL | WCLONE;
const WAITID_OPTION_MASK: u32 =
    WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | WNOTHREAD | WALL | WCLONE;
const WAITID_STATE_MASK: u32 = WSTOPPED | WEXITED | WCONTINUED;

/// Linux `wait4`/`waitpid` child selector after consuming the low 32-bit `pid_t` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wait4Selector {
    AnyChild,
    Pid(NonZeroU32),
    SameProcessGroup,
    ProcessGroup(NonZeroU32),
}

/// Linux raw `waitid` idtype values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitIdType {
    All,
    Pid,
    ProcessGroup,
    PidFd,
}

/// Linux signal-number argument shared by `kill(2)` and `tgkill(2)`.
///
/// Signal zero is a real UAPI operation: it performs target existence/permission checks without
/// queueing a signal. Keeping it distinct prevents later runtime code from manufacturing a Signal 0
/// object or accidentally returning success without permission checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalNumber {
    Probe,
    Signal(u8),
}

impl SignalNumber {
    pub const fn value(self) -> u8 {
        match self {
            Self::Probe => 0,
            Self::Signal(signal) => signal,
        }
    }

    pub const fn is_probe(self) -> bool {
        matches!(self, Self::Probe)
    }
}

/// Linux `kill(pid, sig)` target selector after signed 32-bit `pid_t` decoding.
///
/// These scalar selectors are observations only. In particular, a positive PID/PGID is not Process
/// authority and must be resolved through the canonical Linux identity owner before any signal state
/// can be observed or mutated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KillSelector {
    Pid(NonZeroU32),
    SameProcessGroup,
    AllPermitted,
    ProcessGroup(NonZeroU32),
}

/// Positive thread-group/thread tuple accepted by `tgkill(2)` before identity resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TgkillTarget {
    tgid: NonZeroU32,
    tid: NonZeroU32,
}

impl TgkillTarget {
    pub const fn tgid(self) -> NonZeroU32 {
        self.tgid
    }

    pub const fn tid(self) -> NonZeroU32 {
        self.tid
    }
}

/// Validated Linux wait option word. Validation here checks only the Linux UAPI bit contract; the
/// runtime may support a narrower state-observation subset and must not pretend an unsupported
/// stopped/continued/thread-scope mode succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitOptions(u32);

impl WaitOptions {
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn nohang(self) -> bool {
        self.0 & WNOHANG != 0
    }

    pub const fn nowait(self) -> bool {
        self.0 & WNOWAIT != 0
    }

    pub const fn exited(self) -> bool {
        self.0 & WEXITED != 0
    }

    pub const fn stopped(self) -> bool {
        self.0 & WSTOPPED != 0
    }

    pub const fn continued(self) -> bool {
        self.0 & WCONTINUED != 0
    }

    pub const fn linux_thread_scope_bits(self) -> u32 {
        self.0 & (WNOTHREAD | WALL | WCLONE)
    }
}

/// Decodes Linux wait4's signed `pid_t` selector without turning the scalar into Process authority.
pub fn decode_wait4_selector(raw_pid: u64) -> Result<Wait4Selector, Errno> {
    let pid = linux_signed_int(raw_pid);
    match pid {
        -1 => Ok(Wait4Selector::AnyChild),
        0 => Ok(Wait4Selector::SameProcessGroup),
        1.. => Ok(Wait4Selector::Pid(
            NonZeroU32::new(pid as u32).expect("positive pid_t is nonzero"),
        )),
        i32::MIN => Err(Errno::ESRCH),
        _ => Ok(Wait4Selector::ProcessGroup(
            NonZeroU32::new((-pid) as u32).expect("negative pid_t below -1 has nonzero magnitude"),
        )),
    }
}

pub const fn decode_waitid_type(raw: u64) -> Option<WaitIdType> {
    match linux_unsigned_int(raw) {
        0 => Some(WaitIdType::All),
        1 => Some(WaitIdType::Pid),
        2 => Some(WaitIdType::ProcessGroup),
        3 => Some(WaitIdType::PidFd),
        _ => None,
    }
}

/// Decodes Linux's signed 32-bit signal argument. Zero is preserved as a permission/existence probe;
/// 1..=64 are normal Linux signals and every negative/out-of-range value is `EINVAL`.
pub const fn decode_signal_number(raw: u64) -> Result<SignalNumber, Errno> {
    let signal = linux_signed_int(raw);
    match signal {
        0 => Ok(SignalNumber::Probe),
        1..=64 => Ok(SignalNumber::Signal(signal as u8)),
        _ => Err(Errno::EINVAL),
    }
}

/// Decodes all four Linux `kill(2)` PID selector modes without resolving any target.
pub fn decode_kill_selector(raw_pid: u64) -> KillSelector {
    let pid = linux_signed_int(raw_pid);
    match pid {
        1.. => KillSelector::Pid(NonZeroU32::new(pid as u32).expect("positive pid_t is nonzero")),
        0 => KillSelector::SameProcessGroup,
        -1 => KillSelector::AllPermitted,
        _ => KillSelector::ProcessGroup(
            NonZeroU32::new(pid.unsigned_abs()).expect("pid below -1 has nonzero magnitude"),
        ),
    }
}

/// Decodes `tgkill(2)`'s exact positive thread-group and thread IDs.
///
/// Linux rejects non-positive TGID/TID values with `EINVAL`; the returned scalar tuple is still only
/// lookup input and must be cross-checked by the canonical Process/TID owner before signal mutation.
pub fn decode_tgkill_target(raw_tgid: u64, raw_tid: u64) -> Result<TgkillTarget, Errno> {
    let tgid = linux_signed_int(raw_tgid);
    let tid = linux_signed_int(raw_tid);
    if tgid <= 0 || tid <= 0 {
        return Err(Errno::EINVAL);
    }
    Ok(TgkillTarget {
        tgid: NonZeroU32::new(tgid as u32).expect("positive tgid is nonzero"),
        tid: NonZeroU32::new(tid as u32).expect("positive tid is nonzero"),
    })
}

/// Validates the raw wait4 option word against the Linux syscall's accepted option bits.
pub const fn decode_wait4_options(raw: u64) -> Result<WaitOptions, Errno> {
    let bits = linux_unsigned_int(raw);
    if bits & !WAIT4_OPTION_MASK != 0 {
        Err(Errno::EINVAL)
    } else {
        Ok(WaitOptions(bits))
    }
}

/// Validates raw waitid options and Linux's requirement that at least one state class be requested.
pub const fn decode_waitid_options(raw: u64) -> Result<WaitOptions, Errno> {
    let bits = linux_unsigned_int(raw);
    if bits & !WAITID_OPTION_MASK != 0 || bits & WAITID_STATE_MASK == 0 {
        Err(Errno::EINVAL)
    } else {
        Ok(WaitOptions(bits))
    }
}

/// Architecture-neutral Linux process-runtime operations introduced by Step 30.
///
/// These variants preserve raw Linux-visible scalar register values only. They carry no Process,
/// Thread, scheduler, VFS, FD, ELF, signal, credential, or usercopy authority. Architecture adapters
/// classify syscall numbers into this contract; the final AArch64 integration owner must delegate
/// semantics to the already accepted canonical owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step30RuntimeCall {
    Execve {
        filename: u64,
        argv: u64,
        envp: u64,
    },
    Execveat {
        dirfd: u64,
        pathname: u64,
        argv: u64,
        envp: u64,
        flags: u64,
    },
    WaitId {
        which: u64,
        id: u64,
        infop: u64,
        options: u64,
        rusage: u64,
    },
    Wait4 {
        pid: u64,
        status: u64,
        options: u64,
        rusage: u64,
    },
    SetTidAddress {
        tidptr: u64,
    },
    SetRobustList {
        head: u64,
        len: u64,
    },
    Kill {
        pid: u64,
        signal: u64,
    },
    Tgkill {
        tgid: u64,
        tid: u64,
        signal: u64,
    },
    RtSigaction {
        signal: u64,
        action: u64,
        old_action: u64,
        sigset_size: u64,
    },
    RtSigprocmask {
        how: u64,
        set: u64,
        old_set: u64,
        sigset_size: u64,
    },
    RtSigreturn,
    Setpgid {
        pid: u64,
        pgid: u64,
    },
    Getpgid {
        pid: u64,
    },
    Getsid {
        pid: u64,
    },
    Setsid,
    Prctl {
        option: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    },
    Getppid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait4_selector_preserves_linux_pid_semantics() {
        assert_eq!(decode_wait4_selector(u64::MAX), Ok(Wait4Selector::AnyChild));
        assert_eq!(
            decode_wait4_selector(0),
            Ok(Wait4Selector::SameProcessGroup)
        );
        assert_eq!(
            decode_wait4_selector(23),
            Ok(Wait4Selector::Pid(NonZeroU32::new(23).unwrap()))
        );
        assert_eq!(
            decode_wait4_selector((-23i32 as u32) as u64),
            Ok(Wait4Selector::ProcessGroup(NonZeroU32::new(23).unwrap()))
        );
        assert_eq!(
            decode_wait4_selector((i32::MIN as u32) as u64),
            Err(Errno::ESRCH)
        );
    }

    #[test]
    fn wait_option_decoders_match_linux_uapi_bits() {
        assert_eq!(decode_wait4_options(0).unwrap().bits(), 0);
        assert!(decode_wait4_options(u64::from(WNOHANG | WCONTINUED)).is_ok());
        assert_eq!(decode_wait4_options(u64::from(WEXITED)), Err(Errno::EINVAL));

        let exited_nowait = decode_waitid_options(u64::from(WEXITED | WNOHANG | WNOWAIT)).unwrap();
        assert!(exited_nowait.exited());
        assert!(exited_nowait.nohang());
        assert!(exited_nowait.nowait());
        assert!(!exited_nowait.stopped());
        assert!(!exited_nowait.continued());
        assert_eq!(exited_nowait.linux_thread_scope_bits(), 0);
        assert_eq!(decode_waitid_options(0), Err(Errno::EINVAL));
        assert_eq!(decode_waitid_options(0x10), Err(Errno::EINVAL));
    }

    #[test]
    fn waitid_types_match_linux_uapi() {
        assert_eq!(decode_waitid_type(0), Some(WaitIdType::All));
        assert_eq!(decode_waitid_type(1), Some(WaitIdType::Pid));
        assert_eq!(decode_waitid_type(2), Some(WaitIdType::ProcessGroup));
        assert_eq!(decode_waitid_type(3), Some(WaitIdType::PidFd));
        assert_eq!(decode_waitid_type(4), None);
    }

    #[test]
    fn signal_number_decoder_preserves_probe_and_rejects_invalid_values() {
        assert_eq!(decode_signal_number(0), Ok(SignalNumber::Probe));
        assert_eq!(decode_signal_number(1), Ok(SignalNumber::Signal(1)));
        assert_eq!(decode_signal_number(64), Ok(SignalNumber::Signal(64)));
        assert_eq!(decode_signal_number(65), Err(Errno::EINVAL));
        assert_eq!(decode_signal_number(u64::MAX), Err(Errno::EINVAL));
        assert_eq!(
            decode_signal_number((-64i32 as u32) as u64),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn kill_selector_preserves_all_signed_pid_modes() {
        assert_eq!(
            decode_kill_selector(23),
            KillSelector::Pid(NonZeroU32::new(23).unwrap())
        );
        assert_eq!(decode_kill_selector(0), KillSelector::SameProcessGroup);
        assert_eq!(decode_kill_selector(u64::MAX), KillSelector::AllPermitted);
        assert_eq!(
            decode_kill_selector((-23i32 as u32) as u64),
            KillSelector::ProcessGroup(NonZeroU32::new(23).unwrap())
        );
        assert_eq!(
            decode_kill_selector((i32::MIN as u32) as u64),
            KillSelector::ProcessGroup(NonZeroU32::new(1u32 << 31).unwrap())
        );
    }

    #[test]
    fn tgkill_target_requires_positive_tgid_and_tid() {
        let target = decode_tgkill_target(23, 29).unwrap();
        assert_eq!(target.tgid(), NonZeroU32::new(23).unwrap());
        assert_eq!(target.tid(), NonZeroU32::new(29).unwrap());
        assert_eq!(decode_tgkill_target(0, 29), Err(Errno::EINVAL));
        assert_eq!(decode_tgkill_target(23, 0), Err(Errno::EINVAL));
        assert_eq!(decode_tgkill_target(u64::MAX, 29), Err(Errno::EINVAL));
        assert_eq!(decode_tgkill_target(23, u64::MAX), Err(Errno::EINVAL));
    }
}
