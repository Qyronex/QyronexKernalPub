// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::{Errno, SyscallReturn};
use kernal_linux_bootstrap::{BootstrapContext, OutputFd};
use kernal_linux_bootstrap_aarch64::{TrapOutcome, dispatch_linux_syscall};
use kernal_linux_write_aarch64::{WriteError, write_from_user};

use super::Pl011;

struct LiveBootstrapContext {
    serial: Pl011,
    pid: NonZeroU32,
    tid: NonZeroU32,
}

impl BootstrapContext for LiveBootstrapContext {
    fn write(&mut self, _fd: OutputFd, user_buffer: u64, count: u64) -> Result<u64, Errno> {
        match write_from_user(user_buffer, count, |bytes| {
            // Preserve the Linux userspace stream byte-for-byte. `write_str` injects CR before LF,
            // so the accepted Step-14 output owner emits raw bytes here instead.
            for byte in bytes {
                self.serial.write_byte(*byte);
            }
        }) {
            Ok(written) => Ok(written),
            Err(WriteError::Errno(errno)) => Err(errno),
            Err(WriteError::UserAccessInvariant(_)) => super::super::fatal_with_serial(
                &self.serial,
                "KERNAL/ARM64: Step 15 write usercopy invariant failed\n",
            ),
        }
    }

    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn tid(&self) -> NonZeroU32 {
        self.tid
    }
}

/// Executes live AArch64 `write(2)` through the accepted Step-14 trap/return boundary.
///
/// The exact current scheduler generation, Linux PID/TID and opaque `ActiveProcess` witness are
/// resolved inside one synchronous borrow of the persistent Step-15 runtime. The write path is
/// bounded and non-scheduling, so the witness remains valid through `dispatch_linux_syscall`, which
/// alone commits the validated Linux return to the exception frame.
pub(super) fn handle(frame: &mut ExceptionFrame) -> bool {
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        return false;
    };
    // SAFETY: this lower-EL synchronous SVC owns the current PE's IRQ-masked scheduler window.
    let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
        Ok(current) => current,
        Err(_) => return false,
    };
    let Some(serial) = super::step15_svc_serial() else {
        return false;
    };

    let dispatched = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _, _, identities, _) = state.initial_leader_parts();
        let pid = identities.bound_pid(&*process).map_err(|_| ())?;
        let tid = identities
            .bound_tid_for_scheduler_thread(&*process, current)
            .map_err(|_| ())?;
        let active = address_space.current_owner(&*process).map_err(|_| ())?;
        let mut context = LiveBootstrapContext { serial, pid, tid };

        dispatch_linux_syscall(&active, frame, &mut context).map_err(|_| ())
    });

    matches!(dispatched, Ok(Ok(TrapOutcome::Returned)))
}

/// Executes a live serial write for an already-authorized External stdout/stderr object.
///
/// Unlike [`handle`], this entry deliberately does not decode `frame.x[0]` as a bootstrap numeric
/// descriptor. Step-29 first resolves the generation-safe canonical FD/OFD object and only then maps
/// `External(Stdout|Stderr)` to an [`OutputFd`]. This preserves aliases such as duplicated stdout on
/// fd 3 while preventing a closed or reused scalar fd 1/2 from resurrecting serial authority.
///
/// Scheduler-thread identity, Linux PID/TID, current address-space ownership, bounded usercopy and
/// fail-closed PAN/usercopy invariant handling are identical to the accepted Step-15 writer. Once an
/// External object reaches this entry, internal failures are returned as `Err(())`; callers must not
/// reinterpret that as permission to fall back to the legacy numeric descriptor path.
pub(super) fn handle_bound_output(frame: &mut ExceptionFrame, output: OutputFd) -> Result<(), ()> {
    if frame.x[8] != 64 {
        return Err(());
    }

    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: this lower-EL synchronous SVC owns the current PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    let serial = super::step15_svc_serial().ok_or(())?;

    let result = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _, _, identities, _) = state.initial_leader_parts();
        let pid = identities.bound_pid(&*process).map_err(|_| ())?;
        let tid = identities
            .bound_tid_for_scheduler_thread(&*process, current)
            .map_err(|_| ())?;
        // Preserve the accepted live address-space ownership check even though the descriptor
        // authority was already resolved by the Step-29 FD owner. Keep the witness live across the
        // synchronous output transaction.
        let _active = address_space.current_owner(&*process).map_err(|_| ())?;
        let mut context = LiveBootstrapContext { serial, pid, tid };

        match context.write(output, frame.x[1], frame.x[2]) {
            Ok(written) => {
                let written = i64::try_from(written).map_err(|_| ())?;
                SyscallReturn::success(written).ok_or(())
            }
            Err(errno) => Ok(SyscallReturn::error(errno)),
        }
    })
    .map_err(|_| ())??;

    frame.x[0] = result.as_u64_bits();
    Ok(())
}
