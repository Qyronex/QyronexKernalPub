// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Errno, SyscallReturn};
use kernal_linux_bootstrap::time::{LINUX_TIMESPEC64_BYTES, LinuxClockId, LinuxTimespec64};
use kernal_usercopy::{Error as UsercopyError, UserRange};

/// Separates Linux request failures from privileged time/user-access invariant failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockGettimeError {
    Errno(Errno),
    TimerInvariant(kernal_timer_aarch64::MonotonicError),
    TimespecInvariant,
    UserAccessInvariant(UsercopyError),
}

/// Executes the Step-15 AArch64 `clock_gettime` runtime operation without owning syscall-number or
/// trap dispatch.
///
/// The generic virtual counter is converted through `kernal-time` by `kernal-timer-aarch64`; the
/// resulting Linux arm64 `timespec` is written only through the accepted Step-10 PAN/usercopy path.
/// Unsupported clock IDs and bad user pointers are normal Linux request failures. A broken kernel
/// time source, failed canonical timespec conversion, unavailable PAN, leaked PAN state or missing
/// usercopy fault handler remains a kernel invariant failure for the caller's existing fatal path.
#[cfg(target_arch = "aarch64")]
pub fn clock_gettime(
    clock_id: u64,
    user_timespec: u64,
) -> Result<SyscallReturn, ClockGettimeError> {
    let mut now = kernal_timer_aarch64::monotonic_now_ns;
    let mut copy =
        |address: u64, bytes: &[u8]| kernal_usercopy_aarch64::copy_to_user(address, bytes);
    clock_gettime_with(clock_id, user_timespec, &mut now, &mut copy)
}

fn clock_gettime_with<N, C>(
    clock_id: u64,
    user_timespec: u64,
    now: &mut N,
    copy: &mut C,
) -> Result<SyscallReturn, ClockGettimeError>
where
    N: FnMut() -> Result<u64, kernal_timer_aarch64::MonotonicError>,
    C: FnMut(u64, &[u8]) -> Result<(), UsercopyError>,
{
    LinuxClockId::from_raw(clock_id).map_err(ClockGettimeError::Errno)?;

    // Reject malformed ranges before touching the privileged time source. The real copy remains
    // fault-safe because mappings can still change after this structural validation.
    UserRange::new(user_timespec, LINUX_TIMESPEC64_BYTES).map_err(map_usercopy_error)?;

    let nanoseconds = now().map_err(ClockGettimeError::TimerInvariant)?;
    let timespec = LinuxTimespec64::from_monotonic_ns(nanoseconds)
        .map_err(|_| ClockGettimeError::TimespecInvariant)?;
    let bytes = timespec.to_le_bytes();
    copy(user_timespec, &bytes).map_err(map_usercopy_error)?;

    Ok(SyscallReturn::success(0).expect("zero is a valid Linux syscall success"))
}

const fn map_usercopy_error(error: UsercopyError) -> ClockGettimeError {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::Fault => ClockGettimeError::Errno(Errno::EFAULT),
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => ClockGettimeError::UserAccessInvariant(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_BASE: u64 = 0x0000_0000_0001_0000;
    const USER_MAX_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

    #[test]
    fn unsupported_clock_fails_before_timer_or_usercopy() {
        let mut now_calls = 0;
        let mut copy_calls = 0;
        let result = clock_gettime_with(
            0,
            USER_BASE,
            &mut || {
                now_calls += 1;
                Ok(1)
            },
            &mut |_, _| {
                copy_calls += 1;
                Ok(())
            },
        );

        assert_eq!(result, Err(ClockGettimeError::Errno(Errno::EINVAL)));
        assert_eq!(now_calls, 0);
        assert_eq!(copy_calls, 0);
    }

    #[test]
    fn malformed_pointer_fails_before_timer_or_usercopy() {
        for pointer in [0, USER_MAX_EXCLUSIVE - 8, u64::MAX] {
            let mut now_calls = 0;
            let mut copy_calls = 0;
            let result = clock_gettime_with(
                1,
                pointer,
                &mut || {
                    now_calls += 1;
                    Ok(1)
                },
                &mut |_, _| {
                    copy_calls += 1;
                    Ok(())
                },
            );

            assert_eq!(result, Err(ClockGettimeError::Errno(Errno::EFAULT)));
            assert_eq!(now_calls, 0);
            assert_eq!(copy_calls, 0);
        }
    }

    #[test]
    fn monotonic_time_writes_exact_linux_arm64_timespec() {
        let mut copied_address = 0;
        let mut copied = [0_u8; LINUX_TIMESPEC64_BYTES];
        let result = clock_gettime_with(
            1,
            USER_BASE,
            &mut || Ok(1_234_567_890),
            &mut |address, bytes| {
                copied_address = address;
                copied.copy_from_slice(bytes);
                Ok(())
            },
        );

        assert_eq!(result, Ok(SyscallReturn::success(0).unwrap()));
        assert_eq!(copied_address, USER_BASE);
        assert_eq!(i64::from_le_bytes(copied[..8].try_into().unwrap()), 1);
        assert_eq!(
            i64::from_le_bytes(copied[8..].try_into().unwrap()),
            234_567_890
        );
    }

    #[test]
    fn user_fault_maps_to_efault() {
        let result = clock_gettime_with(1, USER_BASE, &mut || Ok(1), &mut |_, _| {
            Err(UsercopyError::Fault)
        });
        assert_eq!(result, Err(ClockGettimeError::Errno(Errno::EFAULT)));
    }

    #[test]
    fn impossible_fixed_size_and_pan_failures_are_not_downgraded_to_linux_errno() {
        for error in [
            UsercopyError::TooLarge,
            UsercopyError::PanUnavailable,
            UsercopyError::PanStateLeak,
            UsercopyError::FaultHandlerUnavailable,
        ] {
            let result = clock_gettime_with(1, USER_BASE, &mut || Ok(1), &mut |_, _| Err(error));
            assert_eq!(result, Err(ClockGettimeError::UserAccessInvariant(error)));
        }
    }

    #[test]
    fn broken_time_source_is_not_fabricated_into_userspace() {
        let timer_error = kernal_timer_aarch64::monotonic_ns_from_sample(0, 1).unwrap_err();
        let mut copy_calls = 0;
        let result = clock_gettime_with(1, USER_BASE, &mut || Err(timer_error), &mut |_, _| {
            copy_calls += 1;
            Ok(())
        });

        assert_eq!(result, Err(ClockGettimeError::TimerInvariant(timer_error)));
        assert_eq!(copy_calls, 0);
    }
}

// These Step-30.7 structural contracts deliberately live in a library-only test module. Keeping
// them out of `kernel/core-aarch64/tests/` prevents host `cargo test --tests` from asking Cargo to
// build the freestanding ELF binary for the macOS host while preserving the same source assertions.
#[cfg(test)]
mod step30_contract_oracles {
    const SCHEDULER_CPU: &str = include_str!("../../scheduler-cpu/src/lib.rs");
    const CORE_MAIN: &str = include_str!("../../core-aarch64/src/main.rs");
    const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
    const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
    const OWNER: &str = include_str!("../../core-aarch64/src/step15_runtime.rs");
    const INTEGRATED_OWNER: &str =
        include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
    const DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");

    #[test]
    fn aarch64_scheduler_owner_can_drain_remote_wake_mailbox_from_irq() {
        assert!(SCHEDULER_CPU.contains("drain_remote_wakes_from_irq"));
        let marker = SCHEDULER_CPU
            .find("drain_remote_wakes_from_irq")
            .expect("missing owner drain");
        let window = &SCHEDULER_CPU
            [marker.saturating_sub(320)..core::cmp::min(SCHEDULER_CPU.len(), marker + 1800)];
        assert!(window.contains("aarch64") || !window.contains("target_arch = \"x86_64\""));
        assert!(window.contains("irq_depth") && window.contains("preempt_count"));
    }

    #[test]
    fn foreign_wake_route_pairs_mailbox_publish_with_reschedule_sgi() {
        assert!(QEMU.contains("remote_wake"));
        assert!(QEMU.contains("send_sgi1") || QEMU.contains("RESCHEDULE_SGI"));
    }

    #[test]
    fn primary_irq_path_balances_irq_depth_and_drains_before_safe_point() {
        assert!(CORE_MAIN.contains("enter_irq"));
        assert!(CORE_MAIN.contains("exit_irq"));
        assert!(CORE_MAIN.contains("drain_remote_wakes_from_irq"));
    }

    #[test]
    fn irq_return_consumes_need_reschedule_at_scheduler_safe_point() {
        assert!(CORE_MAIN.contains("need_reschedule"));
        assert!(CORE_MAIN.contains("clear_reschedule"));
        assert!(
            CORE_MAIN.contains("bootstrap_reschedule_with_job_control_destination_address_space")
        );
    }

    #[test]
    fn cross_process_safe_point_preserves_destination_address_space_activation() {
        let combined = [CORE_MAIN, QEMU].concat();
        assert!(
            combined.contains("destination_address_space")
                || combined.contains("activate_step30_scheduler_destination")
        );
    }

    #[test]
    fn existing_futex_and_exit_foreign_wakes_share_the_canonical_route() {
        assert!(QEMU.contains("remote_wake_with_reschedule"));
        let exit = include_str!("../../core-aarch64/src/step15_exit.rs");
        assert!(exit.contains("remote_wake_with_reschedule"));
    }

    #[test]
    fn blocking_wait_no_longer_falls_back_to_not_handled() {
        assert!(!RUNTIME.contains("WaitOutcome::WouldBlock => Ok(Outcome::NotHandled)"));
        assert!(RUNTIME.contains("resolve_blocking_wait"));
    }

    #[test]
    fn core_uses_only_the_canonical_wait_receipt_protocol() {
        assert!(OWNER.contains("prepare_wait_sleep_for_scheduler_thread"));
        assert!(INTEGRATED_OWNER.contains("commit_wait_sleep_signal_aware"));
        assert!(OWNER.contains("cancel_wait_sleep"));
        assert!(RUNTIME.contains("WaitPrepareOutcome::Sleep"));
        assert!(RUNTIME.contains("WaitSignalCommitOutcome::AlreadyWoken"));
        assert!(RUNTIME.contains("WaitSignalCommitOutcome::Interrupted"));
    }

    #[test]
    fn committed_wait_enters_the_destination_aware_scheduler_block() {
        assert!(
            RUNTIME.contains("bootstrap_block_current_and_switch_with_destination_address_space")
        );
        assert!(RUNTIME.contains("activate_step30_scheduler_destination"));
        assert!(RUNTIME.contains("NoRunnableThread"));
        assert!(RUNTIME.contains("cancel_blocking_wait"));
    }

    #[test]
    fn child_exit_wake_is_early_but_result_is_zombie_after_proof_finalization() {
        let exit = include_str!("../../core-aarch64/src/step15_exit.rs");
        let qemu = include_str!("../../core-aarch64/src/step15_qemu.rs");
        let clone_exit = include_str!("../../linux-clone-exit-aarch64/src/lib.rs");
        assert!(exit.contains("notify_wait_exit_transition_for_scheduler_thread"));
        assert!(clone_exit.contains("exit_transition(exited)?"));
        assert!(qemu.contains("finalize_step30_pending_exit_after_resume"));
        assert!(qemu.contains("complete_process_exit_wait_after_lifecycle"));
    }

    #[test]
    fn every_successful_svc_return_uses_one_common_delivery_hook() {
        assert!(QEMU.contains("step15_lower_el_dispatch("));
        assert!(QEMU.contains("signal_frame_committed"));
        assert!(QEMU.contains("deliver_step30_signal_on_return(frame)"));
        assert!(QEMU.contains("fn step15_lower_el_dispatch"));
    }

    #[test]
    fn delivery_is_prepare_usercopy_commit_then_frame_mutation() {
        let helper = DELIVERY.find("fn prepare_handler_frame").unwrap();
        let copy = helper
            + DELIVERY[helper..]
                .find("copy_to_user(placement.frame_base(), &bytes)")
                .unwrap();
        let delivery = DELIVERY.find("pub(super) fn deliver_on_return").unwrap();
        let prepare = delivery
            + DELIVERY[delivery..]
                .find("prepare_delivery_for_thread")
                .unwrap();
        let build = prepare + DELIVERY[prepare..].find("prepare_handler_frame(").unwrap();
        let commit = build + DELIVERY[build..].find("commit_prepared_delivery").unwrap();
        let apply = commit + DELIVERY[commit..].find(".apply(").unwrap();
        let apply_tail = &DELIVERY[apply..];
        assert!(helper < copy);
        assert!(prepare < build && build < commit && commit < apply);
        assert!(apply_tail.contains("&mut frame.x"));
        assert!(apply_tail.contains("&mut frame.sp_el0"));
        assert!(apply_tail.contains("&mut frame.elr_el1"));
    }

    #[test]
    fn current_process_address_space_and_entry_generation_are_revalidated() {
        assert!(OWNER.contains("with_current_signal_delivery"));
        assert!(OWNER.contains("current_owner(process)"));
        assert!(OWNER.contains("validate_entry_switch_generation(entry_switch_generation)"));
    }

    #[test]
    fn complete_minimal_frame_preserves_live_fpsimd_and_user_sender_provenance() {
        assert!(DELIVERY.contains("capture_current_el0_fpsimd"));
        assert!(DELIVERY.contains("MinimalAarch64RtSignalFrame"));
        assert!(DELIVERY.contains("SignalProvenance::User"));
        assert!(DELIVERY.contains("SignalProvenance::Tkill"));
        assert!(DELIVERY.contains("SenderSignalSiginfo::process_directed"));
        assert!(DELIVERY.contains("SenderSignalSiginfo::thread_directed"));
    }

    #[test]
    fn unavailable_altstack_falls_back_and_missing_restorer_uses_mapped_trampoline() {
        assert!(!DELIVERY.contains("handler.flags() & SA_ONSTACK"));
        let restorer = DELIVERY.find(".restorer()").unwrap();
        let fallback = restorer
            + DELIVERY[restorer..]
                .find("unwrap_or(AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE)")
                .unwrap();
        let placement = fallback
            + DELIVERY[fallback..]
                .find("place_minimal_signal_frame(snapshot.sp_el0)")
                .unwrap();
        let handler_commit = placement
            + DELIVERY[placement..]
                .find("commit_prepared_delivery")
                .unwrap();
        assert!(restorer < fallback && fallback < placement && placement < handler_commit);
    }
}
