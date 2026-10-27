// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::ptr::NonNull;

/// Executes one live Linux `exit(2)` for the current Step-15 pthread.
///
/// The lifecycle ticket is committed to the persistent process runtime before the current kernel
/// stack can be abandoned. The accepted AArch64 clone-exit owner then performs generation-owned
/// CLONE_CHILD_CLEARTID usercopy, canonical private-futex wake delivery and the non-returning
/// scheduler switch. Normal reap/finalization is deliberately left to a successor transaction so the
/// exact `ReapedThreadProof` can flow through `finalize_reaped_thread_with_identity` before this
/// protected Core stack is reusable.
pub(super) fn handle_thread_exit(raw_status: u64) -> bool {
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        if let Some(serial) = super::step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 exit scheduler owner unavailable\n");
        }
        return false;
    };

    // SAFETY: this lower-EL synchronous SVC runs in the current PE's IRQ-masked scheduler-owner
    // window, with irq_depth=0 and preempt_count=0 until the canonical exit switch below.
    let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
        Ok(current) => current,
        Err(_) => {
            if let Some(serial) = super::step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 15 exit current generation unavailable\n");
            }
            return false;
        }
    };

    // Persist the exact lifecycle ticket outside the exiting stack, but retain only stable raw owner
    // pointers across the subsequent context switch. The runtime borrow is fully released before the
    // clear-child-tid/futex/scheduler composition may wake or switch another pthread.
    let owners = super::runtime::with_linux_runtime(|state| {
        state.prepare_thread_exit(current, raw_status as u8)?;
        let (process, address_space, tid) = state.process_parts_for_scheduler_thread(current)?;
        Ok::<_, super::runtime::Error>((
            NonNull::from(process),
            NonNull::from(address_space),
            tid.get(),
        ))
    });
    let Ok(Ok((process, address_space, exiting_tid))) = owners else {
        if let Some(serial) = super::step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 exit lifecycle prepare failed\n");
        }
        return false;
    };

    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 15 thread exit prepared slot=");
        serial.write_u64(current.local.slot as u64);
        serial.write_str(" generation=");
        serial.write_u64(current.local.generation as u64);
        serial.write_str(" status=");
        serial.write_u64((raw_status as u8) as u64);
        serial.write_str("\n");
    }

    // SAFETY: the raw process/address-space pointers name pinned persistent Step-15 runtime owners;
    // no Rust Process/address-space reference survives the runtime-cell borrow above or crosses the
    // context switch below. The delegated SVC contract retains exact scheduler ownership and current
    // TTBR0 binding. Same-CPU clear-child-tid wake delivery is synchronous; only foreign exact
    // identities reach this router. The destination callback revalidates and activates the exact
    // selected Process/AddressSpace before the successor stack becomes current.
    let dispatched = unsafe {
        kernal_linux_clone_exit_aarch64::exit_current_with_clear_child_tid_raw_with_destination_address_space_and_transition(
            process,
            address_space,
            scheduler,
            super::futex::futexes(),
            exiting_tid,
            super::activate_step30_scheduler_destination,
            |exited| {
                let wakes = super::runtime::with_linux_runtime(|state| {
                    state.notify_wait_exit_transition_for_scheduler_thread(exited)
                })
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                let Some(wakes) = wakes else {
                    return Ok(());
                };
                for target in wakes.iter() {
                    let target_index = usize::from(target.cpu.0);
                    if target_index == current_cpu {
                        // SAFETY: Running->Exited is committed and scheduler table borrows are gone;
                        // the cleanup owner window remains quiescent until successor selection.
                        unsafe { scheduler.bootstrap_wake_local_exact(target) }
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    } else {
                        let target_scheduler = super::super::CPU_SCHEDULERS
                            .get(target_index)
                            .ok_or(kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                        super::remote_wake_with_reschedule(target_scheduler, target)
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    }
                }
                Ok(())
            },
            |target| {
                let target_index = usize::from(target.cpu.0);
                if target_index == current_cpu {
                    return Err(kernal_scheduler_cpu::Error::WrongOwner);
                }
                let target_scheduler = super::super::CPU_SCHEDULERS
                    .get(target_index)
                    .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                super::remote_wake_with_reschedule(target_scheduler, target)
            },
        )
    };

    // A successful current-thread exit switches to a different generation and can never resume this
    // Exited stack. Any return therefore represents a fatal invariant or delivery failure and must
    // not be translated into an errno or ERET back to the exiting pthread.
    let _ = dispatched;
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 15 thread exit returned unexpectedly\n");
    }
    false
}

/// Executes the final Linux `exit_group(2)` for the Step-15 process leader.
///
/// The process-wide lifecycle ticket is persisted before the non-returning scheduler transition.
/// This uses exactly the same raw Process/address-space exit owner as `exit(2)`: no Process or
/// address-space Rust reference remains live on the leader stack while the scheduler switches back
/// to the suspended BSP idle context. The BSP later consumes the retained ticket with the exact
/// leader `ReapedThreadProof` and performs Process/identity/stack teardown.
pub(super) fn handle_group_exit(raw_status: u64) -> bool {
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        if let Some(serial) = super::step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 exit_group scheduler owner unavailable\n");
        }
        return false;
    };

    // SAFETY: this lower-EL synchronous SVC owns the current PE's IRQ-masked scheduler window.
    let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
        Ok(current) => current,
        Err(_) => {
            if let Some(serial) = super::step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 15 exit_group current unavailable\n");
            }
            return false;
        }
    };

    let owners = super::runtime::with_linux_runtime(|state| {
        state.prepare_group_exit(current, raw_status as u8)?;
        let (process, address_space, tid) = state.process_parts_for_scheduler_thread(current)?;
        Ok::<_, super::runtime::Error>((
            NonNull::from(process),
            NonNull::from(address_space),
            tid.get(),
        ))
    });
    let Ok(Ok((process, address_space, exiting_tid))) = owners else {
        if let Some(serial) = super::step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 exit_group lifecycle prepare failed\n");
        }
        return false;
    };

    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 15 exit_group prepared slot=");
        serial.write_u64(current.local.slot as u64);
        serial.write_str(" generation=");
        serial.write_u64(current.local.generation as u64);
        serial.write_str(" status=");
        serial.write_u64((raw_status as u8) as u64);
        serial.write_str("\n");
    }

    // SAFETY: identical owner/quiescence contract to the accepted thread-exit path. `process` and
    // `address_space` are pinned raw handles; the runtime-cell borrow ended before this call. The
    // final leader has no expected clear-child-tid obligation, but using the canonical helper keeps
    // the generation-owned cleanup check and fail-closed behavior intact. The destination callback
    // activates either the exact retained successor Process or canonical kernel/idle token zero.
    let dispatched = unsafe {
        kernal_linux_clone_exit_aarch64::exit_current_with_clear_child_tid_raw_with_destination_address_space_and_transition(
            process,
            address_space,
            scheduler,
            super::futex::futexes(),
            exiting_tid,
            super::activate_step30_scheduler_destination,
            |exited| {
                let wakes = super::runtime::with_linux_runtime(|state| {
                    state.notify_wait_exit_transition_for_scheduler_thread(exited)
                })
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                let Some(wakes) = wakes else {
                    return Ok(());
                };
                for target in wakes.iter() {
                    let target_index = usize::from(target.cpu.0);
                    if target_index == current_cpu {
                        // SAFETY: Running->Exited is committed and scheduler table borrows are gone;
                        // the cleanup owner window remains quiescent until successor selection.
                        unsafe { scheduler.bootstrap_wake_local_exact(target) }
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    } else {
                        let target_scheduler = super::super::CPU_SCHEDULERS
                            .get(target_index)
                            .ok_or(kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                        super::remote_wake_with_reschedule(target_scheduler, target)
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    }
                }
                Ok(())
            },
            |target| {
                let target_index = usize::from(target.cpu.0);
                if target_index == current_cpu {
                    return Err(kernal_scheduler_cpu::Error::WrongOwner);
                }
                let target_scheduler = super::super::CPU_SCHEDULERS
                    .get(target_index)
                    .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                super::remote_wake_with_reschedule(target_scheduler, target)
            },
        )
    };

    let _ = dispatched;
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 15 exit_group returned unexpectedly\n");
    }
    false
}

/// Terminates the exact current Linux generation for a destructively committed fatal default signal.
///
/// SignalTable receipt consumption has already happened before this function is entered. Therefore
/// every failure from this point is fail-closed and non-returning: no error can escape to the EL0
/// generation whose fatal signal was consumed. The lifecycle cause is persisted through the existing
/// ExitCoordinator and the same clone-exit/clear-child-tid/futex/scheduler owner path used above.
pub(super) fn handle_fatal_signal(signal: u8, core_dumped: bool) -> ! {
    let current_cpu = super::super::current_cpu_index();
    let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) else {
        fatal_signal_fail_closed(
            "KERNAL/ARM64: Step 30 fatal signal scheduler owner unavailable\n",
        );
    };

    // SAFETY: fatal delivery runs synchronously in the same lower-EL return window that consumed the
    // exact SignalTable receipt, with the current PE still owning the IRQ-masked scheduler window.
    let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
        Ok(current) if usize::from(current.cpu.0) == current_cpu => current,
        Ok(_) | Err(_) => fatal_signal_fail_closed(
            "KERNAL/ARM64: Step 30 fatal signal current generation unavailable\n",
        ),
    };

    let owners = super::runtime::with_linux_runtime(|state| {
        state.prepare_signal_termination(current, signal, core_dumped)?;
        let (process, address_space, tid) = state.process_parts_for_scheduler_thread(current)?;
        Ok::<_, super::runtime::Error>((
            NonNull::from(process),
            NonNull::from(address_space),
            tid.get(),
        ))
    });
    let Ok(Ok((process, address_space, exiting_tid))) = owners else {
        fatal_signal_fail_closed("KERNAL/ARM64: Step 30 fatal signal lifecycle prepare failed\n");
    };

    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 30 fatal signal prepared slot=");
        serial.write_u64(current.local.slot as u64);
        serial.write_str(" generation=");
        serial.write_u64(current.local.generation as u64);
        serial.write_str(" signal=");
        serial.write_u64(signal as u64);
        serial.write_str(" core=");
        serial.write_u64(core_dumped as u64);
        serial.write_str("\n");
    }

    // SAFETY: identical raw-owner/quiescence contract to `handle_thread_exit`/`handle_group_exit`.
    // The runtime borrow ended before this call, TTBR0 remains bound to the exact current Process,
    // clear-child-tid/futex cleanup remains generation-owned, and destination activation revalidates
    // the selected Process/AddressSpace before the successor stack becomes current.
    let dispatched = unsafe {
        kernal_linux_clone_exit_aarch64::exit_current_with_clear_child_tid_raw_with_destination_address_space_and_transition(
            process,
            address_space,
            scheduler,
            super::futex::futexes(),
            exiting_tid,
            super::activate_step30_scheduler_destination,
            |exited| {
                let wakes = super::runtime::with_linux_runtime(|state| {
                    state.notify_wait_exit_transition_for_scheduler_thread(exited)
                })
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?
                .map_err(|_| kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                let Some(wakes) = wakes else {
                    return Ok(());
                };
                for target in wakes.iter() {
                    let target_index = usize::from(target.cpu.0);
                    if target_index == current_cpu {
                        // SAFETY: Running->Exited is committed and scheduler table borrows are gone;
                        // the cleanup owner window remains quiescent until successor selection.
                        unsafe { scheduler.bootstrap_wake_local_exact(target) }
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    } else {
                        let target_scheduler = super::super::CPU_SCHEDULERS
                            .get(target_index)
                            .ok_or(kernal_linux_clone_exit_aarch64::ExitError::Invariant)?;
                        super::remote_wake_with_reschedule(target_scheduler, target)
                            .map_err(kernal_linux_clone_exit_aarch64::ExitError::Scheduler)?;
                    }
                }
                Ok(())
            },
            |target| {
                let target_index = usize::from(target.cpu.0);
                if target_index == current_cpu {
                    return Err(kernal_scheduler_cpu::Error::WrongOwner);
                }
                let target_scheduler = super::super::CPU_SCHEDULERS
                    .get(target_index)
                    .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                super::remote_wake_with_reschedule(target_scheduler, target)
            },
        )
    };

    let _ = dispatched;
    fatal_signal_fail_closed("KERNAL/ARM64: Step 30 fatal signal exit returned unexpectedly\n")
}

fn fatal_signal_fail_closed(message: &str) -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str(message);
    }
    loop {
        core::hint::spin_loop();
    }
}
