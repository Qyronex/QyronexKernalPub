// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const ABI_VERSION: u32 = 1;
pub const MAX_SYSCALL_ARGS: usize = 6;

pub mod syscall {
    pub const ABI_QUERY: u32 = 0;
    pub const THREAD_YIELD: u32 = 1;
    pub const THREAD_EXIT: u32 = 2;
    pub const IPC_SEND: u32 = 3;
    pub const IPC_RECV: u32 = 4;
    pub const IPC_CALL: u32 = 5;
    pub const CAP_DERIVE: u32 = 6;
    pub const CAP_REVOKE: u32 = 7;
    pub const ADDRESS_MAP: u32 = 8;
    pub const ADDRESS_UNMAP: u32 = 9;
    pub const NOTIFY_SIGNAL: u32 = 10;
    pub const NOTIFY_WAIT: u32 = 11;
}

#[repr(i64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    InvalidArgument = -1,
    InvalidCapability = -2,
    AccessDenied = -3,
    WouldBlock = -4,
    NoMemory = -5,
    NotSupported = -6,
    Interrupted = -7,
    BadState = -8,
    Overflow = -9,
}

impl Status {
    pub const fn as_i64(self) -> i64 {
        self as i64
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallFrame {
    pub number: u32,
    pub abi_version: u32,
    pub args: [u64; MAX_SYSCALL_ARGS],
}

impl SyscallFrame {
    pub const fn new(number: u32, args: [u64; MAX_SYSCALL_ARGS]) -> Self {
        Self {
            number,
            abi_version: ABI_VERSION,
            args,
        }
    }

    pub const fn is_compatible(&self) -> bool {
        self.abi_version == ABI_VERSION
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub max_message_words: u16,
    pub reserved: u16,
    pub feature_bits: u64,
}

impl AbiInfo {
    pub const fn v1(max_message_words: u16, feature_bits: u64) -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            max_message_words,
            reserved: 0,
            feature_bits,
        }
    }
}

pub mod feature {
    pub const CAPABILITIES: u64 = 1 << 0;
    pub const RENDEZVOUS_IPC: u64 = 1 << 1;
    pub const NOTIFICATIONS: u64 = 1 << 2;
    pub const SHARED_MEMORY: u64 = 1 << 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_frame_rejects_unknown_abi_version() {
        let mut frame = SyscallFrame::new(syscall::THREAD_YIELD, [0; 6]);
        assert!(frame.is_compatible());
        frame.abi_version = ABI_VERSION + 1;
        assert!(!frame.is_compatible());
    }

    #[test]
    fn status_codes_are_stable_negative_errors() {
        assert_eq!(Status::Ok.as_i64(), 0);
        assert!(Status::AccessDenied.as_i64() < 0);
        assert_ne!(
            Status::InvalidArgument.as_i64(),
            Status::InvalidCapability.as_i64()
        );
    }
}
