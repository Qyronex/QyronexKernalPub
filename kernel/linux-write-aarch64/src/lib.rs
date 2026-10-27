// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_linux_abi::Errno;
use kernal_usercopy::{Error as UsercopyError, UserRange};

/// Keep each privileged user-access window small and independently validated.
pub const WRITE_CHUNK_BYTES: usize = 256;

/// Bound one synchronous Step-14 bootstrap-console syscall.
///
/// Linux permits `write` to complete partially. Capping the early serial/console path prevents an
/// attacker-controlled `count` from monopolizing the lower-EL synchronous handler for an
/// unbounded number of usercopy and polling-console iterations. Broader asynchronous/file I/O is a
/// later roadmap concern and must not be pulled into Step 14.
pub const MAX_BOOTSTRAP_WRITE_BYTES: u64 = 4 * 1024;

/// Separates Linux request failures from kernel user-access invariant failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    Errno(Errno),
    UserAccessInvariant(UsercopyError),
}

/// Copies one Linux write buffer from the active AArch64 EL0 address space and emits it to an
/// existing kernel-owned output sink.
///
/// Descriptor policy remains in `kernal-linux-bootstrap`; this helper owns only the architecture
/// usercopy mechanics. Logical writes are split into independently validated bounded chunks, as
/// required by the accepted Step-10 usercopy contract, and this early synchronous console path
/// completes at most [`MAX_BOOTSTRAP_WRITE_BYTES`] per syscall. A larger Linux request therefore
/// returns a valid short-write count. The sink callback must not retain the borrowed scratch slice.
pub fn write_from_user<E>(user_buffer: u64, count: u64, mut emit: E) -> Result<u64, WriteError>
where
    E: FnMut(&[u8]),
{
    let mut copy = kernal_usercopy_aarch64::copy_from_user;
    write_with(user_buffer, count, &mut copy, &mut emit)
}

fn write_with<C, E>(
    user_buffer: u64,
    count: u64,
    copy: &mut C,
    emit: &mut E,
) -> Result<u64, WriteError>
where
    C: FnMut(&mut [u8], u64) -> Result<(), UsercopyError>,
    E: FnMut(&[u8]),
{
    // Linux permits a zero-length write without touching the user buffer. The common dispatcher
    // has already validated fd 1/2 before this runtime helper is called.
    if count == 0 {
        return Ok(0);
    }

    let target = core::cmp::min(count, MAX_BOOTSTRAP_WRITE_BYTES);
    let mut scratch = [0_u8; WRITE_CHUNK_BYTES];
    let mut written = 0_u64;
    while written < target {
        let remaining = target - written;
        let chunk_u64 = core::cmp::min(remaining, WRITE_CHUNK_BYTES as u64);
        let chunk_len = usize::try_from(chunk_u64).map_err(|_| WriteError::Errno(Errno::EINVAL))?;
        let source = match user_buffer.checked_add(written) {
            Some(source) => source,
            None => return request_failure(UsercopyError::Overflow, written),
        };

        // Validate every privileged access window independently.
        if let Err(error) = UserRange::new(source, chunk_len) {
            return request_failure(error, written);
        }

        let chunk = &mut scratch[..chunk_len];
        match copy(chunk, source) {
            Ok(()) => {
                emit(chunk);
                written += chunk_u64;
            }
            Err(error) if is_request_error(error) => return request_failure(error, written),
            Err(error) => return Err(WriteError::UserAccessInvariant(error)),
        }
    }

    Ok(written)
}

fn request_failure(error: UsercopyError, written: u64) -> Result<u64, WriteError> {
    if written == 0 {
        Err(map_usercopy_error(error))
    } else {
        Ok(written)
    }
}

const fn is_request_error(error: UsercopyError) -> bool {
    matches!(
        error,
        UsercopyError::NullGuard
            | UsercopyError::OutsideUserRange
            | UsercopyError::Overflow
            | UsercopyError::TooLarge
            | UsercopyError::Fault
    )
}

const fn map_usercopy_error(error: UsercopyError) -> WriteError {
    match error {
        UsercopyError::TooLarge => WriteError::Errno(Errno::EINVAL),
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::Fault => WriteError::Errno(Errno::EFAULT),
        UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => WriteError::UserAccessInvariant(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_BASE: u64 = 0x0000_0000_0001_0000;
    const USER_MAX_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

    #[test]
    fn zero_count_never_touches_pointer_or_sink() {
        let mut copies = 0_usize;
        let mut emitted = 0_usize;
        let result = write_with(
            0,
            0,
            &mut |_: &mut [u8], _: u64| {
                copies += 1;
                Ok(())
            },
            &mut |bytes: &[u8]| emitted += bytes.len(),
        );

        assert_eq!(result, Ok(0));
        assert_eq!(copies, 0);
        assert_eq!(emitted, 0);
    }

    #[test]
    fn invalid_ranges_fail_before_copy_or_output() {
        for (pointer, count) in [(0, 1), (USER_MAX_EXCLUSIVE - 8, 16)] {
            let mut copies = 0_usize;
            let mut output = Vec::new();
            let result = write_with(
                pointer,
                count,
                &mut |_: &mut [u8], _: u64| {
                    copies += 1;
                    Ok(())
                },
                &mut |bytes: &[u8]| output.extend_from_slice(bytes),
            );

            assert_eq!(result, Err(WriteError::Errno(Errno::EFAULT)));
            assert_eq!(copies, 0);
            assert!(output.is_empty());
        }
    }

    #[test]
    fn bounded_buffer_is_copied_and_emitted_in_small_chunks() {
        let source: Vec<u8> = (0..600).map(|index| (index % 251) as u8).collect();
        let mut calls = 0_usize;
        let mut output = Vec::new();

        let result = write_with(
            USER_BASE,
            source.len() as u64,
            &mut |destination: &mut [u8], address: u64| {
                calls += 1;
                let offset = usize::try_from(address - USER_BASE).unwrap();
                destination.copy_from_slice(&source[offset..offset + destination.len()]);
                Ok(())
            },
            &mut |bytes: &[u8]| output.extend_from_slice(bytes),
        );

        assert_eq!(result, Ok(600));
        assert_eq!(calls, 3);
        assert_eq!(output, source);
    }

    #[test]
    fn oversized_logical_write_returns_bounded_short_count() {
        let requested = MAX_BOOTSTRAP_WRITE_BYTES + 1;
        let mut copied = 0_u64;
        let mut emitted = 0_u64;
        let result = write_with(
            USER_BASE,
            requested,
            &mut |destination: &mut [u8], _: u64| {
                copied += destination.len() as u64;
                destination.fill(b'L');
                Ok(())
            },
            &mut |bytes: &[u8]| emitted += bytes.len() as u64,
        );

        assert_eq!(result, Ok(MAX_BOOTSTRAP_WRITE_BYTES));
        assert_eq!(copied, MAX_BOOTSTRAP_WRITE_BYTES);
        assert_eq!(emitted, MAX_BOOTSTRAP_WRITE_BYTES);
    }

    #[test]
    fn hostile_max_count_is_bounded_without_pointer_wrap() {
        let mut copied = 0_u64;
        let result = write_with(
            USER_BASE,
            u64::MAX,
            &mut |destination: &mut [u8], _: u64| {
                copied += destination.len() as u64;
                Ok(())
            },
            &mut |_: &[u8]| {},
        );

        assert_eq!(result, Ok(MAX_BOOTSTRAP_WRITE_BYTES));
        assert_eq!(copied, MAX_BOOTSTRAP_WRITE_BYTES);
    }

    #[test]
    fn first_user_fault_returns_efault_without_output() {
        let mut output = Vec::new();
        let result = write_with(
            USER_BASE,
            16,
            &mut |_: &mut [u8], _: u64| Err(UsercopyError::Fault),
            &mut |bytes: &[u8]| output.extend_from_slice(bytes),
        );

        assert_eq!(result, Err(WriteError::Errno(Errno::EFAULT)));
        assert!(output.is_empty());
    }

    #[test]
    fn later_user_fault_returns_completed_partial_write() {
        let mut calls = 0_usize;
        let mut output = Vec::new();
        let result = write_with(
            USER_BASE,
            (WRITE_CHUNK_BYTES + 8) as u64,
            &mut |destination: &mut [u8], _: u64| {
                calls += 1;
                if calls == 1 {
                    destination.fill(b'K');
                    Ok(())
                } else {
                    Err(UsercopyError::Fault)
                }
            },
            &mut |bytes: &[u8]| output.extend_from_slice(bytes),
        );

        assert_eq!(result, Ok(WRITE_CHUNK_BYTES as u64));
        assert_eq!(output, vec![b'K'; WRITE_CHUNK_BYTES]);
    }

    #[test]
    fn pan_or_fault_handler_failure_is_not_downgraded_to_linux_errno() {
        for error in [
            UsercopyError::PanUnavailable,
            UsercopyError::PanStateLeak,
            UsercopyError::FaultHandlerUnavailable,
        ] {
            let result = write_with(
                USER_BASE,
                1,
                &mut |_: &mut [u8], _: u64| Err(error),
                &mut |_: &[u8]| {},
            );
            assert_eq!(result, Err(WriteError::UserAccessInvariant(error)));
        }
    }
}
