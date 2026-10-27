// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::linux_signed_int;
use kernal_linux_fd::OpenObjectKind;
use kernal_linux_pipe::{Error as PipeError, PIPE_BUF, PipeId, ReadState};
use kernal_scheduler_cpu::Error as SchedulerError;
use kernal_scheduler_smp::GlobalThreadId;

use super::pipe_wait::{self, WaitCommit};

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_NONBLOCK: u64 = 0x800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareReadWait {
    Retry,
    Prepared(PipeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevalidateReadWait {
    Retry,
    StillBlocking,
}

/// Resume-side result for a pipe read that previously proved it had to block.
///
/// `Retry` means normal pipe readiness won and the caller must rerun the canonical FD/pipe read
/// transaction. The other variants mean Core already resolved a signal-owned interruption. In both
/// cases the caller must return from the current syscall dispatcher without fabricating a read result;
/// either the trapped PC was rewound or a handler frame now owns the return path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockingReadOutcome {
    Retry,
    Restarted,
    SignalFrameCommitted,
}

/// Revalidates an empty blocking pipe and publishes one exact Prepared waiter while the canonical
/// FD/Pipe runtime owner is still borrowed.
///
/// The first Step-29 read observation is intentionally not trusted across owner release. This helper
/// re-resolves the descriptor/OFD endpoint and observes `WouldBlock` under the sole PipeTable owner,
/// then publishes only Prepared waiter state. It deliberately releases the waiter serializer before
/// returning so the caller can drop the Runtime borrow and perform the mandatory second observation
/// before acquiring scheduler-sleep authority.
fn prepare_read_wait(
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    current: GlobalThreadId,
) -> Result<PrepareReadWait, ()> {
    if count == 0 {
        return Ok(PrepareReadWait::Retry);
    }
    let fd = linux_signed_int(raw_fd);
    let requested = usize::try_from(core::cmp::min(count, PIPE_BUF as u64)).map_err(|_| ())?;

    super::super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        if fds.object_kind(fd).map_err(|_| ())? != OpenObjectKind::Pipe {
            return Ok(PrepareReadWait::Retry);
        }
        let status = fds.status_flags(fd).map_err(|_| ())?;
        if status & O_ACCMODE != O_RDONLY || status & O_NONBLOCK != 0 {
            return Ok(PrepareReadWait::Retry);
        }
        let endpoint = fds.pipe_endpoint(fd).map_err(|_| ())?;
        match pipes.prepare_read(endpoint, requested) {
            Ok(ReadState::Ready(_) | ReadState::Eof) => Ok(PrepareReadWait::Retry),
            Err(PipeError::WouldBlock) => {
                // SAFETY: the synchronous SVC owns this PE with local IRQ re-entry excluded. The
                // Pipe waiter serializer is independent of the mutable FD/Pipe runtime borrow. Only
                // Prepared state is published here; commit happens after canonical revalidation.
                unsafe { pipe_wait::prepare(endpoint.pipe(), current) }.map_err(|_| ())?;
                Ok(PrepareReadWait::Prepared(endpoint.pipe()))
            }
            Err(_) => Err(()),
        }
    })
    .map_err(|_| ())?
}

/// Performs the required second canonical FD/OFD/Pipe observation after waiter publication.
///
/// Descriptor replacement, nonblocking/access-mode changes, a different Pipe generation, data
/// readiness, or EOF all force a retry of the ordinary syscall path. Only the same live generation
/// still reporting `WouldBlock` is eligible for waiter commit.
fn revalidate_read_wait(
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    expected_pipe: PipeId,
) -> Result<RevalidateReadWait, ()> {
    if count == 0 {
        return Ok(RevalidateReadWait::Retry);
    }
    let fd = linux_signed_int(raw_fd);
    let requested = usize::try_from(core::cmp::min(count, PIPE_BUF as u64)).map_err(|_| ())?;

    super::super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        if fds.object_kind(fd).map_err(|_| ())? != OpenObjectKind::Pipe {
            return Ok(RevalidateReadWait::Retry);
        }
        let status = fds.status_flags(fd).map_err(|_| ())?;
        if status & O_ACCMODE != O_RDONLY || status & O_NONBLOCK != 0 {
            return Ok(RevalidateReadWait::Retry);
        }
        let endpoint = fds.pipe_endpoint(fd).map_err(|_| ())?;
        if endpoint.pipe() != expected_pipe {
            return Ok(RevalidateReadWait::Retry);
        }
        match pipes.prepare_read(endpoint, requested) {
            Ok(ReadState::Ready(_) | ReadState::Eof) => Ok(RevalidateReadWait::Retry),
            Err(PipeError::WouldBlock) => Ok(RevalidateReadWait::StillBlocking),
            Err(_) => Err(()),
        }
    })
    .map_err(|_| ())?
}

fn resolve_prepared_without_sleep(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<BlockingReadOutcome, ()> {
    // A signal may have won while the Prepared waiter was published. Interrupted state is retained
    // and cancellation must not erase it; resolve that owner before allowing ordinary readiness to
    // win. Otherwise exact cancellation contains Prepared/Notified state and the syscall re-observes.
    // SAFETY: this exact generation owns the IRQ-masked SVC and no Runtime/FD/Pipe borrow is live.
    if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
        return resolve_after_resume(frame, current);
    }
    match unsafe { pipe_wait::cancel(current) } {
        Ok(true) | Ok(false) => Ok(BlockingReadOutcome::Retry),
        Err(pipe_wait::Error::InvalidWaiterState) => {
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                resolve_after_resume(frame, current)
            } else {
                Err(())
            }
        }
        Err(_) => Err(()),
    }
}

/// Blocks the exact current scheduler generation for one canonical pipe read.
///
/// Publication and commit intentionally straddle a second canonical FD/OFD/Pipe observation:
/// `prepare -> drop waiter serializer/runtime borrow -> revalidate -> commit`. This closes both sides
/// of the lost-wake window without moving descriptor or PipeTable authority into Core.
pub(crate) fn block_read(
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    frame: &mut ExceptionFrame,
) -> Result<BlockingReadOutcome, ()> {
    let current_cpu = super::super::super::current_cpu_index();
    let scheduler = super::super::super::CPU_SCHEDULERS
        .get(current_cpu)
        .ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns the IRQ-masked scheduler window for this PE.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }

    let pipe = match prepare_read_wait(process, raw_fd, count, current)? {
        PrepareReadWait::Retry => return Ok(BlockingReadOutcome::Retry),
        PrepareReadWait::Prepared(pipe) => pipe,
    };

    match revalidate_read_wait(process, raw_fd, count, pipe)? {
        RevalidateReadWait::Retry => return resolve_prepared_without_sleep(frame, current),
        RevalidateReadWait::StillBlocking => {}
    }

    // No Runtime/FD/Pipe borrow survives this commit. A readiness/signal race between revalidation
    // and commit is retained by the waiter owner and returned as AlreadyWoken instead of sleeping.
    // SAFETY: exact current generation owns the local IRQ-masked scheduler window.
    match unsafe { pipe_wait::commit(current) }.map_err(|_| ())? {
        WaitCommit::AlreadyWoken => {
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                return resolve_after_resume(frame, current);
            }
            return Ok(BlockingReadOutcome::Retry);
        }
        WaitCommit::Sleep => {}
    }

    // All canonical Runtime/FD/Pipe borrows ended above. Only exact scheduler identity plus the live
    // exception frame owned by this suspended SVC remains across the context switch.
    // SAFETY: waiter commit and local owner quiescence are retained continuously into the block.
    let switched = unsafe {
        scheduler.bootstrap_block_current_and_switch_with_destination_address_space(
            current,
            super::super::activate_step30_scheduler_destination,
        )
    };

    match switched {
        Ok(resumed) if resumed == current => resolve_after_resume(frame, current),
        Ok(_) => Err(()),
        Err(SchedulerError::NoRunnableThread) => {
            // A signal owner may have claimed the committed waiter during the failed block attempt.
            // SAFETY: current remains the exact running generation on this documented pre-switch path.
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                return resolve_after_resume(frame, current);
            }
            // A normal readiness publication may instead have consumed the waiter before the
            // scheduler reported no peer. False therefore means retry, not corruption.
            // SAFETY: exact current generation still owns this failed block path.
            match unsafe { pipe_wait::cancel(current) }.map_err(|_| ())? {
                false => Ok(BlockingReadOutcome::Retry),
                true => Err(()),
            }
        }
        Err(_) => {
            // Containment only. If signal ownership already linearized, cancellation correctly fails
            // and the original privileged scheduler error still propagates fail-closed.
            // SAFETY: the resumed/current owner window still excludes local re-entry.
            let _ = unsafe { pipe_wait::cancel(current) };
            Err(())
        }
    }
}

fn resolve_after_resume(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<BlockingReadOutcome, ()> {
    // SAFETY: the exact generation is current again in the same IRQ-masked SVC owner window.
    if !unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
        return Ok(BlockingReadOutcome::Retry);
    }

    // The pipe path never staged provisional x0 success, so x0..x5 still contain the original read
    // syscall arguments. Reuse the already-audited interrupted-wait signal transaction directly: it
    // either rewinds the trapped SVC or installs one handler frame containing EINTR/SA_RESTART state.
    match super::super::signal_delivery::deliver_interrupted_futex(frame, current)? {
        super::super::signal_delivery::InterruptedFutexDelivery::Restarted => {
            Ok(BlockingReadOutcome::Restarted)
        }
        super::super::signal_delivery::InterruptedFutexDelivery::SignalFrameCommitted => {
            Ok(BlockingReadOutcome::SignalFrameCommitted)
        }
    }
}

fn wake_exact(target: GlobalThreadId) -> Result<(), ()> {
    let target_index = usize::from(target.cpu.0);
    let target_scheduler = super::super::super::CPU_SCHEDULERS
        .get(target_index)
        .ok_or(())?;
    let current_cpu = super::super::super::current_cpu_index();
    if target_index == current_cpu {
        // SAFETY: exact target came from the generation-safe Pipe waiter owner while this PE retains
        // the scheduler quiescence window. This only transitions the matching blocked generation.
        unsafe { target_scheduler.bootstrap_wake_local_exact(target) }.map_err(|_| ())
    } else {
        super::super::remote_wake_with_reschedule(target_scheduler, target).map_err(|_| ())
    }
}

/// Publishes one normal pipe-read readiness transition after bytes have committed and after the
/// caller has released every Runtime/FD/Pipe borrow.
pub(crate) fn notify_after_write(pipe: PipeId) -> Result<(), ()> {
    // SAFETY: caller is the synchronous post-commit owner with local IRQ re-entry excluded and no
    // canonical Runtime/FD/Pipe borrow live.
    let (_report, target) = unsafe { pipe_wait::notify_one(pipe) }.map_err(|_| ())?;
    if let Some(target) = target {
        wake_exact(target)?;
    }
    Ok(())
}

/// Publishes EOF readiness after the final writer endpoint lease is released. Every matching reader
/// is notified because no future writer can make progress for this Pipe generation.
pub(crate) fn notify_after_writer_close(pipe: PipeId) -> Result<(), ()> {
    // SAFETY: caller has completed the canonical FD/OFD release and PipeTable close transaction and
    // dropped those borrows before entering this wake phase.
    let (targets, _report) = unsafe { pipe_wait::notify_all(pipe) }.map_err(|_| ())?;
    for target in targets.into_iter().flatten() {
        wake_exact(target)?;
    }
    Ok(())
}
