// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::Errno;

pub const CLOCK_MONOTONIC: u64 = 1;
pub const LINUX_TIMESPEC64_BYTES: usize = 16;

/// Step-15 Linux clock IDs supported by the current minimum runtime.
///
/// `CLOCK_REALTIME` is deliberately not fabricated from the monotonic generic timer. Additional
/// clock domains may be added only when Kernal has an authoritative source for them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxClockId {
    Monotonic,
}

impl LinuxClockId {
    pub const fn from_raw(raw: u64) -> Result<Self, Errno> {
        match raw {
            CLOCK_MONOTONIC => Ok(Self::Monotonic),
            _ => Err(Errno::EINVAL),
        }
    }
}

/// Linux arm64 `struct timespec` layout used by `clock_gettime`.
///
/// Common time normalization remains owned by `kernal-time`; this type owns only the Linux LP64
/// field representation and byte encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxTimespec64 {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl LinuxTimespec64 {
    pub fn from_monotonic_ns(nanoseconds: u64) -> Result<Self, kernal_time::Error> {
        let timespec = kernal_time::ns_to_timespec(nanoseconds)?;
        Ok(Self {
            tv_sec: timespec.tv_sec,
            tv_nsec: timespec.tv_nsec,
        })
    }

    /// Encodes the LP64 Linux arm64 timespec explicitly as little-endian bytes, avoiding any
    /// alignment, padding or privileged direct-pointer assumptions in the semantic layer.
    pub fn to_le_bytes(self) -> [u8; LINUX_TIMESPEC64_BYTES] {
        let seconds = self.tv_sec.to_le_bytes();
        let nanoseconds = self.tv_nsec.to_le_bytes();
        let mut bytes = [0_u8; LINUX_TIMESPEC64_BYTES];
        bytes[..8].copy_from_slice(&seconds);
        bytes[8..].copy_from_slice(&nanoseconds);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_authoritative_monotonic_clock_is_accepted() {
        assert_eq!(
            LinuxClockId::from_raw(CLOCK_MONOTONIC),
            Ok(LinuxClockId::Monotonic)
        );
        for unsupported in [0, 2, 4, u64::MAX] {
            assert_eq!(LinuxClockId::from_raw(unsupported), Err(Errno::EINVAL));
        }
    }

    #[test]
    fn monotonic_nanoseconds_use_canonical_time_normalization() {
        assert_eq!(
            LinuxTimespec64::from_monotonic_ns(1_234_567_890).unwrap(),
            LinuxTimespec64 {
                tv_sec: 1,
                tv_nsec: 234_567_890,
            }
        );
        let expected = kernal_time::ns_to_timespec(u64::MAX).unwrap();
        assert_eq!(
            LinuxTimespec64::from_monotonic_ns(u64::MAX).unwrap(),
            LinuxTimespec64 {
                tv_sec: expected.tv_sec,
                tv_nsec: expected.tv_nsec,
            }
        );
    }

    #[test]
    fn arm64_timespec_encoding_is_exactly_two_little_endian_i64_fields() {
        let timespec = LinuxTimespec64 {
            tv_sec: 0x0102_0304_0506_0708,
            tv_nsec: 0x1112_1314_1516_1718,
        };
        assert_eq!(
            timespec.to_le_bytes(),
            [
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11,
            ]
        );
    }
}
