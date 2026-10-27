// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Step30RuntimeCall, SyscallRequest};

/// Linux arm64 has 64 kernel-visible signals, so the raw realtime-signal syscall ABI exchanges one
/// 64-bit kernel signal-set word. This is deliberately the kernel UAPI width, not libc's larger
/// user-space `sigset_t` wrapper type.
pub const KERNEL_SIGSET_BYTES: u64 = 8;

/// AArch64 defines `SA_RESTORER`, so the native kernel `struct sigaction` is four native 64-bit
/// fields: handler, flags, restorer and the one-word kernel signal mask.
pub const KERNEL_SIGACTION_BYTES: usize = 32;

/// Raw Linux/AArch64 `struct sigaction` value after usercopy has already succeeded.
///
/// This is an ABI value only. Handler/restorer addresses are not executable authority, flags are not
/// validated here, and the signal mask still requires canonical `SignalSet` sanitization by the
/// accepted signal-policy owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

impl KernelSigaction {
    pub const fn new(handler: u64, flags: u64, restorer: u64, mask: u64) -> Self {
        Self {
            handler,
            flags,
            restorer,
            mask,
        }
    }

    pub fn from_ne_bytes(bytes: [u8; KERNEL_SIGACTION_BYTES]) -> Self {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[0..8]);
        let handler = u64::from_ne_bytes(word);
        word.copy_from_slice(&bytes[8..16]);
        let flags = u64::from_ne_bytes(word);
        word.copy_from_slice(&bytes[16..24]);
        let restorer = u64::from_ne_bytes(word);
        word.copy_from_slice(&bytes[24..32]);
        let mask = u64::from_ne_bytes(word);
        Self::new(handler, flags, restorer, mask)
    }

    pub fn to_ne_bytes(self) -> [u8; KERNEL_SIGACTION_BYTES] {
        let mut bytes = [0u8; KERNEL_SIGACTION_BYTES];
        bytes[0..8].copy_from_slice(&self.handler.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.restorer.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.mask.to_ne_bytes());
        bytes
    }

    pub const fn handler(self) -> u64 {
        self.handler
    }

    pub const fn flags(self) -> u64 {
        self.flags
    }

    pub const fn restorer(self) -> u64 {
        self.restorer
    }

    pub const fn mask(self) -> u64 {
        self.mask
    }
}

/// Linux `sigprocmask` / `rt_sigprocmask` selector values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigmaskHow {
    Block,
    Unblock,
    SetMask,
}

/// Decodes only the Linux scalar `how` argument. User pointers and signal-set mutation remain owned
/// by the final runtime's audited usercopy and canonical SignalTable paths.
pub const fn decode_sigmask_how(raw: u64) -> Option<SigmaskHow> {
    match raw {
        0 => Some(SigmaskHow::Block),
        1 => Some(SigmaskHow::Unblock),
        2 => Some(SigmaskHow::SetMask),
        _ => None,
    }
}

/// Both Linux `rt_sigaction` and `rt_sigprocmask` require the architecture's exact kernel signal-set
/// size. Keeping the check here prevents magic-number copies in trap/runtime integration.
pub const fn valid_rt_sigset_size(size: u64) -> bool {
    size == KERNEL_SIGSET_BYTES
}

/// Linux arm64 syscall-number anchors for the audited Step-30 process-runtime integration surface.
pub mod nr {
    pub const WAITID: u64 = 95;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const KILL: u64 = 129;
    pub const TGKILL: u64 = 131;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGRETURN: u64 = 139;
    pub const SETPGID: u64 = 154;
    pub const GETPGID: u64 = 155;
    pub const GETSID: u64 = 156;
    pub const SETSID: u64 = 157;
    pub const PRCTL: u64 = 167;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const WAIT4: u64 = 260;
    pub const EXECVEAT: u64 = 281;
}

/// Classifies the audited Step-30 Linux arm64 process-runtime surface.
///
/// No argument is validated or dereferenced here. Raw register bits are retained for the accepted
/// exec, wait, signal, identity, credential, robust-list and usercopy owners to interpret. Scalar
/// PID/TID values are observation/selection inputs only; exact-generation authority is revalidated
/// by the semantic owner before any state mutation.
pub fn classify_step30_runtime(request: SyscallRequest) -> Option<Step30RuntimeCall> {
    let a = request.args;
    match request.number {
        super::nr::EXECVE => Some(Step30RuntimeCall::Execve {
            filename: a[0],
            argv: a[1],
            envp: a[2],
        }),
        nr::EXECVEAT => Some(Step30RuntimeCall::Execveat {
            dirfd: a[0],
            pathname: a[1],
            argv: a[2],
            envp: a[3],
            flags: a[4],
        }),
        nr::WAITID => Some(Step30RuntimeCall::WaitId {
            which: a[0],
            id: a[1],
            infop: a[2],
            options: a[3],
            rusage: a[4],
        }),
        nr::WAIT4 => Some(Step30RuntimeCall::Wait4 {
            pid: a[0],
            status: a[1],
            options: a[2],
            rusage: a[3],
        }),
        nr::SET_TID_ADDRESS => Some(Step30RuntimeCall::SetTidAddress { tidptr: a[0] }),
        nr::SET_ROBUST_LIST => Some(Step30RuntimeCall::SetRobustList {
            head: a[0],
            len: a[1],
        }),
        nr::KILL => Some(Step30RuntimeCall::Kill {
            pid: a[0],
            signal: a[1],
        }),
        nr::TGKILL => Some(Step30RuntimeCall::Tgkill {
            tgid: a[0],
            tid: a[1],
            signal: a[2],
        }),
        nr::RT_SIGACTION => Some(Step30RuntimeCall::RtSigaction {
            signal: a[0],
            action: a[1],
            old_action: a[2],
            sigset_size: a[3],
        }),
        nr::RT_SIGPROCMASK => Some(Step30RuntimeCall::RtSigprocmask {
            how: a[0],
            set: a[1],
            old_set: a[2],
            sigset_size: a[3],
        }),
        nr::RT_SIGRETURN => Some(Step30RuntimeCall::RtSigreturn),
        nr::SETPGID => Some(Step30RuntimeCall::Setpgid {
            pid: a[0],
            pgid: a[1],
        }),
        nr::GETPGID => Some(Step30RuntimeCall::Getpgid { pid: a[0] }),
        nr::GETSID => Some(Step30RuntimeCall::Getsid { pid: a[0] }),
        nr::SETSID => Some(Step30RuntimeCall::Setsid),
        nr::PRCTL => Some(Step30RuntimeCall::Prctl {
            option: a[0],
            arg2: a[1],
            arg3: a[2],
            arg4: a[3],
            arg5: a[4],
        }),
        nr::GETPPID => Some(Step30RuntimeCall::Getppid),
        nr::GETUID => Some(Step30RuntimeCall::Getuid),
        nr::GETEUID => Some(Step30RuntimeCall::Geteuid),
        nr::GETGID => Some(Step30RuntimeCall::Getgid),
        nr::GETEGID => Some(Step30RuntimeCall::Getegid),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_kernel_sigaction_roundtrips_without_layout_ambiguity() {
        let action = KernelSigaction::new(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334_3536_3738,
        );
        assert_eq!(KERNEL_SIGACTION_BYTES, 32);
        let encoded = action.to_ne_bytes();
        let decoded = KernelSigaction::from_ne_bytes(encoded);
        assert_eq!(decoded, action);
        assert_eq!(decoded.handler(), action.handler());
        assert_eq!(decoded.flags(), action.flags());
        assert_eq!(decoded.restorer(), action.restorer());
        assert_eq!(decoded.mask(), action.mask());
    }

    #[test]
    fn arm64_realtime_signal_scalar_contract_is_exact() {
        assert_eq!(KERNEL_SIGSET_BYTES, 8);
        assert!(valid_rt_sigset_size(8));
        assert!(!valid_rt_sigset_size(0));
        assert!(!valid_rt_sigset_size(16));
        assert_eq!(decode_sigmask_how(0), Some(SigmaskHow::Block));
        assert_eq!(decode_sigmask_how(1), Some(SigmaskHow::Unblock));
        assert_eq!(decode_sigmask_how(2), Some(SigmaskHow::SetMask));
        assert_eq!(decode_sigmask_how(3), None);
        assert_eq!(decode_sigmask_how(u64::MAX), None);
    }

    #[test]
    fn arm64_step30_numbers_match_linux_asm_generic() {
        assert_eq!(nr::WAITID, 95);
        assert_eq!(nr::SET_TID_ADDRESS, 96);
        assert_eq!(nr::SET_ROBUST_LIST, 99);
        assert_eq!(nr::KILL, 129);
        assert_eq!(nr::TGKILL, 131);
        assert_eq!(nr::RT_SIGACTION, 134);
        assert_eq!(nr::RT_SIGPROCMASK, 135);
        assert_eq!(nr::RT_SIGRETURN, 139);
        assert_eq!(nr::SETPGID, 154);
        assert_eq!(nr::GETPGID, 155);
        assert_eq!(nr::GETSID, 156);
        assert_eq!(nr::SETSID, 157);
        assert_eq!(nr::PRCTL, 167);
        assert_eq!(nr::GETPPID, 173);
        assert_eq!(nr::GETUID, 174);
        assert_eq!(nr::GETEUID, 175);
        assert_eq!(nr::GETGID, 176);
        assert_eq!(nr::GETEGID, 177);
        assert_eq!(nr::WAIT4, 260);
        assert_eq!(nr::EXECVEAT, 281);
        assert_eq!(super::super::nr::EXECVE, 221);
    }

    #[test]
    fn classifiers_preserve_raw_argument_order_without_semantics() {
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(
                super::super::nr::EXECVE,
                [1, 2, 3, 4, 5, 6],
            )),
            Some(Step30RuntimeCall::Execve {
                filename: 1,
                argv: 2,
                envp: 3,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::EXECVEAT, [7, 8, 9, 10, 11, 12])),
            Some(Step30RuntimeCall::Execveat {
                dirfd: 7,
                pathname: 8,
                argv: 9,
                envp: 10,
                flags: 11,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::WAITID, [13, 14, 15, 16, 17, 18])),
            Some(Step30RuntimeCall::WaitId {
                which: 13,
                id: 14,
                infop: 15,
                options: 16,
                rusage: 17,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::WAIT4, [19, 20, 21, 22, 23, 24])),
            Some(Step30RuntimeCall::Wait4 {
                pid: 19,
                status: 20,
                options: 21,
                rusage: 22,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(
                nr::SET_TID_ADDRESS,
                [25, 0, 0, 0, 0, 0]
            )),
            Some(Step30RuntimeCall::SetTidAddress { tidptr: 25 })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(
                nr::SET_ROBUST_LIST,
                [26, 27, 0, 0, 0, 0]
            )),
            Some(Step30RuntimeCall::SetRobustList { head: 26, len: 27 })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::KILL, [28, 29, 0, 0, 0, 0])),
            Some(Step30RuntimeCall::Kill {
                pid: 28,
                signal: 29,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::TGKILL, [30, 31, 32, 0, 0, 0])),
            Some(Step30RuntimeCall::Tgkill {
                tgid: 30,
                tid: 31,
                signal: 32,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(
                nr::RT_SIGACTION,
                [33, 34, 35, 36, 0, 0]
            )),
            Some(Step30RuntimeCall::RtSigaction {
                signal: 33,
                action: 34,
                old_action: 35,
                sigset_size: 36,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(
                nr::RT_SIGPROCMASK,
                [37, 38, 39, 40, 0, 0],
            )),
            Some(Step30RuntimeCall::RtSigprocmask {
                how: 37,
                set: 38,
                old_set: 39,
                sigset_size: 40,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::RT_SIGRETURN, [u64::MAX; 6])),
            Some(Step30RuntimeCall::RtSigreturn)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::SETPGID, [41, 42, 0, 0, 0, 0])),
            Some(Step30RuntimeCall::Setpgid { pid: 41, pgid: 42 })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETPGID, [43, 0, 0, 0, 0, 0])),
            Some(Step30RuntimeCall::Getpgid { pid: 43 })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETSID, [44, 0, 0, 0, 0, 0])),
            Some(Step30RuntimeCall::Getsid { pid: 44 })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::SETSID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Setsid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::PRCTL, [45, 46, 47, 48, 49, 50])),
            Some(Step30RuntimeCall::Prctl {
                option: 45,
                arg2: 46,
                arg3: 47,
                arg4: 48,
                arg5: 49,
            })
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETPPID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Getppid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETUID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Getuid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETEUID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Geteuid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETGID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Getgid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(nr::GETEGID, [u64::MAX; 6])),
            Some(Step30RuntimeCall::Getegid)
        );
        assert_eq!(
            classify_step30_runtime(SyscallRequest::new(u64::MAX, [u64::MAX; 6])),
            None
        );
    }
}
