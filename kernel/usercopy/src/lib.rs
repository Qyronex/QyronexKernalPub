// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_vm::{USER_MAX_EXCLUSIVE, USER_MIN};

/// Keep one privileged user-access window short enough that IRQ latency cannot grow without bound.
/// Larger logical transfers must be split by their caller into independently validated chunks.
pub const MAX_USERCOPY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NullGuard,
    OutsideUserRange,
    Overflow,
    TooLarge,
    Fault,
    PanUnavailable,
    PanStateLeak,
    FaultHandlerUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserRange {
    start: u64,
    len: usize,
    end: u64,
}

impl UserRange {
    pub fn new(start: u64, len: usize) -> Result<Self, Error> {
        if len > MAX_USERCOPY_BYTES {
            return Err(Error::TooLarge);
        }
        if start < USER_MIN {
            return Err(Error::NullGuard);
        }
        if start >= USER_MAX_EXCLUSIVE {
            return Err(Error::OutsideUserRange);
        }
        let len_u64 = u64::try_from(len).map_err(|_| Error::Overflow)?;
        let end = start.checked_add(len_u64).ok_or(Error::Overflow)?;
        if end > USER_MAX_EXCLUSIVE {
            return Err(Error::OutsideUserRange);
        }
        Ok(Self { start, len, end })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn contains_address(self, address: u64) -> bool {
        if self.len == 0 {
            false
        } else {
            address >= self.start && address < self.end
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_user_ranges() {
        let range = UserRange::new(USER_MIN, 32).unwrap();
        assert_eq!(range.start(), USER_MIN);
        assert_eq!(range.len(), 32);
        assert_eq!(range.end(), USER_MIN + 32);
        assert!(range.contains_address(USER_MIN));
        assert!(range.contains_address(USER_MIN + 31));
        assert!(!range.contains_address(USER_MIN + 32));
    }

    #[test]
    fn zero_length_is_allowed_only_at_a_valid_user_address() {
        let range = UserRange::new(USER_MIN, 0).unwrap();
        assert!(range.is_empty());
        assert_eq!(range.end(), USER_MIN);
        assert!(!range.contains_address(USER_MIN));
        assert_eq!(UserRange::new(0, 0), Err(Error::NullGuard));
        assert_eq!(
            UserRange::new(USER_MAX_EXCLUSIVE, 0),
            Err(Error::OutsideUserRange)
        );
    }

    #[test]
    fn rejects_null_guard_and_kernel_half() {
        assert_eq!(UserRange::new(0, 1), Err(Error::NullGuard));
        assert_eq!(UserRange::new(USER_MIN - 1, 1), Err(Error::NullGuard));
        assert_eq!(
            UserRange::new(USER_MAX_EXCLUSIVE, 1),
            Err(Error::OutsideUserRange)
        );
        assert_eq!(
            UserRange::new(0xffff_8000_0000_0000, 1),
            Err(Error::OutsideUserRange)
        );
    }

    #[test]
    fn rejects_end_crossing_user_boundary() {
        assert_eq!(
            UserRange::new(USER_MAX_EXCLUSIVE - 8, 16),
            Err(Error::OutsideUserRange)
        );
        let last = UserRange::new(USER_MAX_EXCLUSIVE - 8, 8).unwrap();
        assert_eq!(last.end(), USER_MAX_EXCLUSIVE);
    }

    #[test]
    fn rejects_unbounded_single_copy() {
        assert_eq!(
            UserRange::new(USER_MIN, MAX_USERCOPY_BYTES + 1),
            Err(Error::TooLarge)
        );
    }
}
