// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_bootstrap::ExitScope;
use kernal_linux_exit_lifecycle::Completion;

use super::{Pl011, initial, runtime};

/// Finishes the final Step-15/28/29/30 Linux process after `exit_group(94)` switched back to the BSP
/// idle context and returns the exact finalized Linux exit status.
///
/// The live leader cannot tear down its own scheduler context or Process authority. The SVC path
/// therefore persists the canonical ThreadGroup ticket and performs only the non-returning current
/// exit. This function runs after the old BSP stack resumes, deactivates the user TTBR0, obtains the
/// exact scheduler reap proof, consumes Process/CSpace + Linux identity authority, and only then
/// returns the initial-user stack to the protected Core pool.
///
/// # Safety
/// Must run on BSP/CPU0 immediately after the `bootstrap_yield` returns from the final Linux leader,
/// with local IRQs masked, irq_depth=0 and preempt_count=0. No other owner may mutate the persistent
/// Process, scheduler, activation registry or initial-user stack during this transaction.
pub(super) unsafe fn finalize_after_resume(serial: &Pl011) -> Result<u32, ()> {
    let scheduler = &super::super::CPU_SCHEDULERS[0];

    let scheduler_owner = match scheduler.owner() {
        Ok(owner) => owner,
        Err(_) => {
            serial.write_str("KERNAL/S30F finalize scheduler-owner unavailable\n");
            return Err(());
        }
    };
    if usize::from(scheduler_owner.0) != 0 {
        serial.write_str("KERNAL/S30F finalize scheduler-owner wrong-cpu\n");
        return Err(());
    }
    let exited =
        match runtime::with_linux_runtime(|state| state.pending_thread_exit(scheduler_owner)) {
            Ok(Some(exited)) => exited,
            Ok(None) => {
                serial.write_str("KERNAL/S30F finalize pending-exit missing\n");
                return Err(());
            }
            Err(_) => {
                serial.write_str("KERNAL/S30F finalize runtime unavailable\n");
                return Err(());
            }
        };
    if exited.cpu != scheduler_owner {
        serial.write_str("KERNAL/S30F finalize exited-owner mismatch\n");
        return Err(());
    }

    // SAFETY: delegated BSP owner/quiescence contract.
    let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
        Ok(current) => current,
        Err(_) => {
            serial.write_str("KERNAL/S30F finalize current-generation unavailable\n");
            return Err(());
        }
    };
    if current == exited {
        serial.write_str("KERNAL/S30F finalize current-still-exited\n");
        return Err(());
    }

    // The Process remains Live until the proof-carrying lifecycle finalizer below. Retire its hardware
    // and logical AArch64 current-owner binding first so destroying the address-space object can never
    // leave a stale TTBR0/activation registry entry behind.
    // SAFETY: BSP owns the address-space switch window and the final Linux generation has already
    // switched away; no EL0 execution can race this deactivation.
    unsafe {
        kernal_process_aarch64::BoundProcessAddressSpace::<{ runtime::STEP15_RUNTIME_VMAS }>::deactivate()
    }
    .map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 final Linux TTBR0 deactivated\n");

    // The initial-user stack is permanently mapped protected pool storage, so no dynamic stack-page
    // teardown is needed before the canonical scheduler reap.
    // SAFETY: `exited` is the exact retained group-exit generation and `current.local` is the BSP
    // generation that resumed on this owner CPU after the non-returning leader switch.
    let (initial_stack, proof) = unsafe {
        scheduler.bootstrap_reap_exited_after_teardown_with_proof(exited.local, current.local)
    }
    .map_err(|_| ())?;

    let finalized = runtime::with_linux_runtime(move |state| {
        state.finalize_pending_thread_exit(
            exited,
            |ticket, exits, process, objects, bindings, identities| {
                let thread_handle = bindings
                    .authority_for_reaped_proof(objects, process.id(), &proof)
                    .map_err(kernal_process::Error::ThreadBinding)?;
                let completion = kernal_linux_exit_lifecycle::finalize_reaped_thread(
                    ticket,
                    exits,
                    process,
                    objects,
                    bindings,
                    proof,
                    thread_handle,
                )?;
                match completion {
                    Completion::ProcessExited {
                        scope: ExitScope::ThreadGroup,
                        ..
                    } => {}
                    _ => return Err(kernal_linux_exit_lifecycle::Error::ExitRequestMismatch),
                }
                identities.retire_process(process)?;
                Ok(completion)
            },
        )
    });
    let completion = match finalized {
        Ok(Ok(completion)) => completion,
        Ok(Err(_)) | Err(_) => {
            // Scheduler reap consumed the one-shot generation proof. Never recycle the stack when
            // Process/identity finalization failed; leaving it allocated is the fail-closed outcome.
            let _ = initial_stack;
            return Err(());
        }
    };

    // SAFETY: `initial_stack` is the exact descriptor returned by the successful leader scheduler
    // reap, and the matching proof was consumed by successful Process/identity finalization above.
    unsafe { kernal_core_aarch64::reclaim_initial_user_core_stack(initial_stack) }
        .map_err(|_| ())?;

    let Completion::ProcessExited { status, .. } = completion else {
        return Err(());
    };
    serial.write_str("KERNAL/ARM64: Step 15 exit_group finalized status=");
    serial.write_u64(status as u64);
    serial.write_str(" initial-stack=reclaimed\n");

    #[cfg(feature = "step29-fs-breadth-qemu-proof")]
    {
        if status != 0 {
            serial.write_str(
                "KERNAL/ARM64: Step 29 mutable filesystem fixture returned non-zero status\n",
            );
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str(
                "KERNAL/ARM64: Step 29 mutable filesystem loader proof-state incomplete\n",
            );
            return Err(());
        }

        // The static positive fixture prints its success marker only after the complete cwd,
        // create/write/pwrite/link/symlink/rename/unlink/metadata lifecycle. This kernel marker is
        // strictly later: exit_group returned to BSP idle, the exact Process/Thread generation was
        // finalized, and the protected initial-user stack was reclaimed above.
        serial.write_str("KERNAL/S29FS: mutable filesystem fixture finalized status=0\n");
    }

    #[cfg(feature = "step29-fs-breadth-negative-qemu-proof")]
    {
        if status != 0 {
            serial.write_str(
                "KERNAL/ARM64: Step 29 negative filesystem fixture returned non-zero status\n",
            );
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str(
                "KERNAL/ARM64: Step 29 negative filesystem loader proof-state incomplete\n",
            );
            return Err(());
        }

        // As above, userspace owns the errno/confinement assertions while this marker proves that
        // the same successful fixture generation crossed the canonical lifecycle finalization edge.
        serial.write_str("KERNAL/S29FSN: negative filesystem fixture finalized status=0\n");
    }

    #[cfg(feature = "step29-fd-pipe-qemu-proof")]
    {
        if status != 0 {
            serial.write_str("KERNAL/ARM64: Step 29 fd-pipe fixture returned non-zero status\n");
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 29 fd-pipe loader proof-state incomplete\n");
            return Err(());
        }

        // The unchanged static Linux fixture emits its own alias and roundtrip markers only after
        // exercising the live descriptor/pipe syscalls. This final kernel marker is later than its
        // success marker by construction: the userspace process has returned, exit_group has switched
        // back to BSP idle, and the exact Process/Thread generation has been finalized above.
        serial.write_str("KERNAL/S29IO: fd-pipe fixture finalized status=0\n");
    }

    #[cfg(feature = "step29-directory-qemu-proof")]
    {
        if status != 0 {
            serial.write_str("KERNAL/ARM64: Step 29 BusyBox ls returned non-zero status\n");
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 29 directory loader proof-state incomplete\n");
            return Err(());
        }
        if !super::step29_fd::directory_proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 29 directory/getdents proof-state incomplete\n");
            return Err(());
        }

        // These lines are emitted only after a real directory FD generation has committed at least
        // one fully copied getdents64 record, the same generation has delivered a symlink record, and
        // that exact generation has subsequently closed. The unchanged BusyBox process has also been
        // reaped/finalized with status zero above.
        serial.write_str("KERNAL/S29D: unchanged static ARM64 BusyBox ls selected\n");
        serial.write_str("KERNAL/S29D: committed getdents64 directory listing observed\n");
        serial.write_str("KERNAL/S29D: symlink dirent observed and directory fd closed\n");
        serial.write_str("KERNAL/S29D: BusyBox ls finalized status=0\n");
    }

    #[cfg(feature = "step30-final-qemu-proof")]
    {
        if status != 0 {
            serial.write_str(
                "KERNAL/ARM64: Step 30 process-runtime guest returned non-zero status\n",
            );
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial
                .write_str("KERNAL/ARM64: Step 30 process-runtime loader proof-state incomplete\n");
            return Err(());
        }
        // Every required KERNAL/S30 userspace marker is emitted before exit_group only after its
        // Linux-visible assertion succeeds. This later kernel line proves the same initial Process
        // generation crossed the canonical non-returning exit, scheduler reap, Process/identity
        // finalization and protected-stack reclamation edge with status zero.
        serial.write_str("KERNAL/ARM64: Step 30 process-runtime guest finalized status=0\n");
    }

    #[cfg(all(
        feature = "step29-qemu-proof",
        not(feature = "step30-final-qemu-proof"),
        not(feature = "step29-directory-qemu-proof"),
        not(feature = "step29-fd-pipe-qemu-proof"),
        not(feature = "step29-fs-breadth-qemu-proof"),
        not(feature = "step29-fs-breadth-negative-qemu-proof")
    ))]
    {
        if status != 0 {
            serial.write_str("KERNAL/ARM64: Step 29 BusyBox date returned non-zero status\n");
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 29 BusyBox loader proof-state incomplete\n");
            return Err(());
        }
        if !super::step29_fd::proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 29 path/fd proof-state incomplete\n");
            return Err(());
        }

        // The deterministic Step-29 archive makes /etc/localtime a relative symlink to the separately
        // pinned UTC TZif target. The generation-bound path/FD proof below can therefore complete only
        // after the shared component resolver followed that fixture and the unchanged applet observed
        // the target through its normal open/stat/read/close sequence.
        serial.write_str("KERNAL/S29: unchanged static ARM64 BusyBox date selected\n");
        serial.write_str("KERNAL/S29: relative localtime symlink followed to pinned UTC target\n");
        serial.write_str("KERNAL/S29: immutable initramfs open-stat-read-close sequence passed\n");
        serial.write_str("KERNAL/S29: BusyBox date finalized status=0\n");
    }

    #[cfg(all(feature = "step28-qemu-proof", not(feature = "step29-qemu-proof")))]
    {
        if status != 0 {
            serial.write_str("KERNAL/ARM64: Step 28 BusyBox true returned non-zero status\n");
            return Err(());
        }
        if !initial::step28_proof_complete() {
            serial.write_str("KERNAL/ARM64: Step 28 proof-state incomplete at finalization\n");
            return Err(());
        }

        // These feature-scoped acceptance markers are emitted only after the monotonic Step-28
        // proof state has recorded both earlier boundaries and the process has finalized with status
        // zero. The external harness requires every line exactly once and in this causal order.
        serial.write_str("KERNAL/S28: CPIO archive accepted; executable bin/busybox selected\n");
        serial.write_str("KERNAL/S28: canonical ARM64 ELF leader loaded\n");
        serial.write_str("KERNAL/S28: unchanged static ARM64 BusyBox true finalized status=0\n");
    }

    Ok(u32::from(status))
}
