// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_linux_abi::Errno;

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

/// Authority-free Step-15 subset of the Linux futex operation contract.
///
/// This type deliberately owns no usercopy, FutexTable, scheduler or wake-mailbox authority. It
/// only validates the raw Linux scalar operation needed by the unchanged musl pthread proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimumFutexCall {
    /// Process-private wait with no timeout. The runtime must atomically compare the futex word to
    /// `expected` immediately before `FutexTable::prepare_wait` under its external serialization.
    WaitPrivate { expected: u32 },
    /// Process-private wake of at most `maximum` matching waiters.
    WakePrivate { maximum: u32 },
}

/// Decodes the raw Linux `futex` operation/value pair into the deliberately narrow Step-15 subset.
///
/// Only `FUTEX_WAIT_PRIVATE` with a null timeout and `FUTEX_WAKE_PRIVATE` are accepted. Shared
/// futexes, timed waits, CLOCK_REALTIME, PI, requeue and bitset operations remain outside Step 15 and
/// fail with `ENOSYS` instead of silently approximating Linux semantics.
pub const fn decode_minimum(
    operation: u64,
    value: u64,
    timeout_or_value2: u64,
) -> Result<MinimumFutexCall, Errno> {
    match operation {
        op if op == FUTEX_WAIT_PRIVATE as u64 => {
            if timeout_or_value2 != 0 {
                return Err(Errno::ENOSYS);
            }
            Ok(MinimumFutexCall::WaitPrivate {
                expected: value as u32,
            })
        }
        op if op == FUTEX_WAKE_PRIVATE as u64 => {
            // Linux treats the wake count as a signed int internally. Step 15 rejects values that
            // would become negative rather than widening the contract around nonsensical counts.
            if value > i32::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            Ok(MinimumFutexCall::WakePrivate {
                maximum: value as u32,
            })
        }
        _ => Err(Errno::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_private_operation_numbers_match_uapi() {
        assert_eq!(FUTEX_WAIT, 0);
        assert_eq!(FUTEX_WAKE, 1);
        assert_eq!(FUTEX_PRIVATE_FLAG, 128);
        assert_eq!(FUTEX_CLOCK_REALTIME, 256);
        assert_eq!(FUTEX_WAIT_PRIVATE, 128);
        assert_eq!(FUTEX_WAKE_PRIVATE, 129);
    }

    #[test]
    fn private_untimed_wait_preserves_expected_u32() {
        assert_eq!(
            decode_minimum(FUTEX_WAIT_PRIVATE as u64, 0x1_7856_3412, 0),
            Ok(MinimumFutexCall::WaitPrivate {
                expected: 0x7856_3412
            })
        );
    }

    #[test]
    fn timed_wait_is_not_silently_approximated() {
        assert_eq!(
            decode_minimum(FUTEX_WAIT_PRIVATE as u64, 7, 0x1000),
            Err(Errno::ENOSYS)
        );
    }

    #[test]
    fn private_wake_accepts_nonnegative_signed_count_domain() {
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, 1, u64::MAX),
            Ok(MinimumFutexCall::WakePrivate { maximum: 1 })
        );
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, i32::MAX as u64, 0),
            Ok(MinimumFutexCall::WakePrivate {
                maximum: i32::MAX as u32
            })
        );
        assert_eq!(
            decode_minimum(FUTEX_WAKE_PRIVATE as u64, i32::MAX as u64 + 1, 0),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn shared_and_broader_futex_operations_remain_out_of_scope() {
        for operation in [
            FUTEX_WAIT as u64,
            FUTEX_WAKE as u64,
            (FUTEX_WAIT_PRIVATE | FUTEX_CLOCK_REALTIME) as u64,
            3,
            u64::MAX,
        ] {
            assert_eq!(decode_minimum(operation, 0, 0), Err(Errno::ENOSYS));
        }
    }
}
