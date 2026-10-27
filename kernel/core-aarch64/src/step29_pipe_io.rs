// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::Errno;
use kernal_linux_pipe::{Endpoint, Error as PipeError, PIPE_BUF, PipeTable};
use kernal_usercopy::Error as UsercopyError;

const LARGE_WRITE_PROBE: usize = PIPE_BUF + 1;

/// Result boundary for the Step-29 ARM64 pipe transfer helper.
///
/// Descriptor/object dispatch stays with the canonical FD/OFD owner. This module receives an
/// already-resolved pipe endpoint plus the descriptor's shared O_NONBLOCK state and therefore never
/// creates a numeric-fd shadow map or falls back to stdout/stderr based on a descriptor number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Linux(Errno),
    BlockingWaitRequired,
    Invariant,
}

/// Transfers bytes from one canonical pipe read endpoint into userspace.
///
/// Each prepared chunk is copied completely before the pipe owner is committed. A user fault in the
/// current chunk therefore leaves that chunk unconsumed; only earlier fully committed chunks may be
/// returned as positive short progress. Empty blocking reads fail closed until the Step-30 owner
/// composes this `BlockingWaitRequired` boundary with the scheduler rather than busy-spinning inside
/// the synchronous SVC window.
pub(super) fn read<const N: usize, const CAP: usize>(
    pipes: &mut PipeTable<N, CAP>,
    endpoint: Endpoint,
    user_buffer: u64,
    count: u64,
    nonblocking: bool,
) -> Result<u64, Error> {
    if count == 0 {
        let plan = pipes.read_plan(endpoint, 0).map_err(map_pipe_error)?;
        pipes.commit_read(plan, 0).map_err(map_pipe_error)?;
        return Ok(0);
    }

    let mut completed = 0u64;
    let mut scratch = [0u8; PIPE_BUF];
    while completed < count {
        let remaining = count - completed;
        let requested = usize::try_from(core::cmp::min(remaining, PIPE_BUF as u64))
            .map_err(|_| Error::Invariant)?;
        let plan = match pipes.read_plan(endpoint, requested) {
            Ok(plan) => plan,
            Err(PipeError::WouldBlock) if completed != 0 => return Ok(completed),
            Err(PipeError::WouldBlock) if nonblocking => return Err(Error::Linux(Errno::EAGAIN)),
            Err(PipeError::WouldBlock) => return Err(Error::BlockingWaitRequired),
            Err(error) => return Err(map_pipe_error(error)),
        };

        // A zero-length plan with a non-zero request is canonical EOF: the writer lease is gone and
        // all buffered data has been drained.
        if plan.is_empty() {
            return Ok(completed);
        }

        let copied = pipes
            .copy_read(plan, &mut scratch[..plan.len()])
            .map_err(map_pipe_error)?;
        if copied != plan.len() {
            return Err(Error::Invariant);
        }

        let Some(address) = user_buffer.checked_add(completed) else {
            return if completed != 0 {
                Ok(completed)
            } else {
                Err(Error::Linux(Errno::EFAULT))
            };
        };
        match kernal_usercopy_aarch64::copy_to_user(address, &scratch[..copied]) {
            Ok(()) => {
                pipes.commit_read(plan, copied).map_err(map_pipe_error)?;
                let copied = u64::try_from(copied).map_err(|_| Error::Invariant)?;
                completed = completed.checked_add(copied).ok_or(Error::Invariant)?;
            }
            Err(error) => {
                // Validate/abort this exact plan without consuming any current-chunk bytes. Earlier
                // committed chunks are the only legal positive short result.
                pipes.commit_read(plan, 0).map_err(map_pipe_error)?;
                return match map_usercopy_error(error) {
                    Error::Linux(Errno::EFAULT) if completed != 0 => Ok(completed),
                    mapped => Err(mapped),
                };
            }
        }

        // A short plan means the pipe did not contain another complete requested chunk at this
        // instant. Returning now preserves positive-short semantics without inventing a wait path.
        if plan.len() < requested {
            return Ok(completed);
        }
    }
    Ok(completed)
}

/// Transfers bytes from userspace into one canonical pipe write endpoint.
///
/// Requests up to PIPE_BUF preserve the pipe owner's all-or-wait atomicity. Larger requests probe
/// one byte beyond PIPE_BUF so the owner may expose a legal currently-available prefix. Usercopy is
/// completed before commit, therefore bytes from a faulting current chunk never reach the ring.
/// Scheduler wake publication is deliberately left to the descriptor adapter after its Runtime/FD/
/// Pipe borrow has ended.
pub(super) fn write<const N: usize, const CAP: usize>(
    pipes: &mut PipeTable<N, CAP>,
    endpoint: Endpoint,
    user_buffer: u64,
    count: u64,
    nonblocking: bool,
) -> Result<u64, Error> {
    if count == 0 {
        let plan = if nonblocking {
            pipes.prepare_nonblocking_write(endpoint, 0)
        } else {
            pipes.prepare_write(endpoint, 0)
        }
        .map_err(map_pipe_error)?;
        pipes.commit_write(plan, &[]).map_err(map_pipe_error)?;
        return Ok(0);
    }

    let mut completed = 0u64;
    let mut scratch = [0u8; LARGE_WRITE_PROBE];
    while completed < count {
        let remaining = count - completed;
        let requested = if remaining <= PIPE_BUF as u64 {
            usize::try_from(remaining).map_err(|_| Error::Invariant)?
        } else {
            usize::try_from(core::cmp::min(remaining, LARGE_WRITE_PROBE as u64))
                .map_err(|_| Error::Invariant)?
        };

        let plan = match if nonblocking {
            pipes.prepare_nonblocking_write(endpoint, requested)
        } else {
            pipes.prepare_write(endpoint, requested)
        } {
            Ok(plan) => plan,
            Err(PipeError::WouldBlock) if completed != 0 => return Ok(completed),
            Err(PipeError::WouldBlock) if nonblocking => return Err(Error::Linux(Errno::EAGAIN)),
            Err(PipeError::WouldBlock) => return Err(Error::BlockingWaitRequired),
            Err(PipeError::BrokenPipe) if completed != 0 => return Ok(completed),
            // SIGPIPE delivery is a later process/signal-owner concern; Step 29 pins the syscall
            // return boundary to EPIPE when no byte from this call has been committed.
            Err(PipeError::BrokenPipe) => return Err(Error::Linux(Errno::EPIPE)),
            Err(error) => return Err(map_pipe_error(error)),
        };

        if plan.is_empty() {
            pipes.commit_write(plan, &[]).map_err(map_pipe_error)?;
            return Ok(completed);
        }

        let Some(address) = user_buffer.checked_add(completed) else {
            return if completed != 0 {
                Ok(completed)
            } else {
                Err(Error::Linux(Errno::EFAULT))
            };
        };
        let target = &mut scratch[..plan.len()];
        if let Err(error) = kernal_usercopy_aarch64::copy_from_user(target, address) {
            // Empty commit is a validated abort. Earlier completed chunks remain valid positive
            // short-write progress; the faulting current chunk remains wholly unpublished.
            pipes.commit_write(plan, &[]).map_err(map_pipe_error)?;
            return match map_usercopy_error(error) {
                Error::Linux(Errno::EFAULT) if completed != 0 => Ok(completed),
                mapped => Err(mapped),
            };
        }

        pipes.commit_write(plan, target).map_err(map_pipe_error)?;
        let written = u64::try_from(plan.len()).map_err(|_| Error::Invariant)?;
        completed = completed.checked_add(written).ok_or(Error::Invariant)?;
        if plan.len() < requested {
            return Ok(completed);
        }
    }
    Ok(completed)
}

fn map_pipe_error(error: PipeError) -> Error {
    match error {
        PipeError::BadEndpoint => Error::Linux(Errno::EBADF),
        PipeError::WouldBlock => Error::Linux(Errno::EAGAIN),
        PipeError::BrokenPipe => Error::Linux(Errno::EPIPE),
        PipeError::TableFull => Error::Linux(Errno::ENFILE),
        PipeError::StaleEndpoint
        | PipeError::StalePlan
        | PipeError::InvalidLength
        | PipeError::CapacityZero
        | PipeError::EpochExhausted => Error::Invariant,
    }
}

fn map_usercopy_error(error: UsercopyError) -> Error {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::TooLarge
        | UsercopyError::Fault => Error::Linux(Errno::EFAULT),
        UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Error::Invariant,
    }
}
