// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Step-30.7 structural regression oracle for Linux group/broadcast kill composition.
//!
//! This test intentionally lives in the lib-only signal-owner crate. Putting the same oracle under
//! `kernel/core-aarch64/tests/` makes Cargo build the freestanding AArch64 Core binary while running
//! host integration tests; Darwin's host assembler cannot consume that ELF/AArch64 startup assembly.
//! The oracle itself is authority-free: it only reads the accepted Core integration sources as text.

const STEP30: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");

fn kill_arm() -> &'static str {
    let marker = "Step30RuntimeCall::Kill";
    let start = STEP30.find(marker).expect("missing explicit kill arm");
    let tail = &STEP30[start..];
    let end = tail[marker.len()..]
        .find("\n        Step30RuntimeCall::")
        .map(|offset| marker.len() + offset)
        .unwrap_or(tail.len());
    &tail[..end]
}

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = ["\nfn ", "\npub(super) fn ", "\npub(crate) fn ", "\npub fn "]
        .into_iter()
        .filter_map(|next| body.find(next).map(|offset| marker.len() + offset))
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn bounded_target_observation_reuses_retained_process_and_identity_owners() {
    assert!(RUNTIME.contains("struct SignalTargetPidBatch"));
    assert!(RUNTIME.contains("fn signal_target_pids"));
    assert!(RUNTIME.contains("RuntimeProcessSlot::validate"));
    assert!(RUNTIME.contains("getpgid(process)"));
    assert!(RUNTIME.contains("bound_pid(process)"));
    assert!(RUNTIME.contains("ProcessState::Live"));
    assert!(RUNTIME.contains("wait_publication.is_none()"));
    assert!(!RUNTIME.contains("process_group_registry"));
    assert!(!RUNTIME.contains("kill_pid_registry"));
}

#[test]
fn every_linux_kill_selector_shape_is_explicit() {
    let kill = kill_arm();
    assert!(kill.contains("KillSelector::Pid"));
    assert!(kill.contains("KillSelector::SameProcessGroup"));
    assert!(kill.contains("KillSelector::ProcessGroup"));
    assert!(kill.contains("KillSelector::AllPermitted"));
}

#[test]
fn observed_group_targets_reenter_exact_signal_owner_and_permission_policy() {
    let kill = kill_arm();
    assert!(kill.contains("signal_target_pids"));
    assert!(kill.contains("with_process_signal_target_for_pid"));
    assert!(kill.contains("may_signal"));
    assert!(kill.contains("SIGCONT"));
    assert!(kill.contains("queue_signal_with_provenance"));
}

#[test]
fn kill_minus_one_excludes_caller_and_pid_one() {
    let kill = kill_arm();
    assert!(kill.contains("target == sender_pid"));
    assert!(kill.contains("target.get() == 1"));
    assert!(kill.contains("KillSelector::AllPermitted"));
}

#[test]
fn group_result_aggregation_preserves_linux_errno_and_partial_success() {
    let kill = kill_arm();
    assert!(kill.contains("delivered"));
    assert!(kill.contains("permission_denied"));
    assert!(kill.contains("pending_capacity"));
    assert!(kill.contains("Errno::ESRCH"));
    assert!(kill.contains("Errno::EPERM"));
    assert!(kill.contains("Errno::EAGAIN"));
    assert!(kill.contains("SyscallReturn::success(0)"));
}

#[test]
fn signal_zero_group_probe_never_constructs_signal_zero() {
    let kill = kill_arm();
    assert!(kill.contains("SignalNumber::Probe => SignalSendResult::ProbeSuccess"));
    assert!(kill.contains("SignalNumber::Signal(number)"));
    assert!(kill.contains("Signal::new(number)"));
    assert!(
        !kill
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains("Signal::new(0)"))
    );
}

#[test]
fn sa_onstack_without_altstack_falls_back_to_current_user_stack() {
    assert!(SIGNAL_DELIVERY.contains("place_minimal_signal_frame(snapshot.sp_el0)"));
    assert!(SIGNAL_DELIVERY.contains("Aarch64SignalStack::new(0, SS_DISABLE, 0)"));
    assert!(!SIGNAL_DELIVERY.contains("handler.flags() & SA_ONSTACK"));
}

#[test]
fn successful_signal_receipt_commit_mismatch_is_non_returning() {
    let delivery = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_on_return");

    // Ignore, terminate, stop, continue, bad-handler-frame and ready-handler-frame each consume one
    // exact PreparedSignal receipt. Any successful commit that returns a different Delivery is
    // destructive and must cross the non-returning boundary.
    assert_eq!(delivery.matches("commit_prepared_delivery").count(), 6);
    for mismatch in [
        "ignored signal delivery changed after commit",
        "fatal signal delivery changed after commit",
        "stop delivery changed after signal commit",
        "continue delivery changed after signal commit",
        "bad handler signal changed after commit",
        "handler signal delivery changed after commit",
    ] {
        assert!(
            delivery.contains(mismatch),
            "missing fail-closed mismatch class after PreparedSignal commit: {mismatch}"
        );
    }
    assert!(
        delivery.matches("fail_closed_after_signal_commit(").count() >= 6,
        "every successful mismatch must fail closed; additional post-commit scheduler failures may share the same boundary"
    );
    assert!(!delivery.contains("effective_mask: match committed"));
    assert!(SIGNAL_DELIVERY.contains("fn fail_closed_after_signal_commit(message: &str) -> !"));
    assert!(SIGNAL_DELIVERY.contains("core::hint::spin_loop()"));

    let handler = delivery
        .find("Delivery::Handler { .. } =>")
        .expect("missing normal handler-delivery arm");
    let handler = &delivery[handler..];
    assert_eq!(handler.matches("commit_prepared_delivery").count(), 2);
    assert!(handler.matches("fail_closed_after_signal_commit(").count() >= 2);
    assert!(handler.contains("Err(SignalError::PreparedDeliveryStale) => Ok(())"));
}

#[test]
fn handler_restorer_is_proven_executable_before_signal_receipt_commit() {
    let prepared = function_window(SIGNAL_DELIVERY, "fn prepare_handler_frame");
    assert!(prepared.contains("let restorer = handler"));
    assert!(prepared.contains("user_vma_at"));
    assert!(prepared.contains("handler_executable"));
    assert!(prepared.contains("restorer_executable"));
    assert!(prepared.contains("vma.perms.executable()"));
    assert!(prepared.contains("if !entry_points_executable"));
    assert!(prepared.contains("process.address_space_handle()"));

    let delivery = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_on_return");
    let handler = delivery
        .find("Delivery::Handler { .. } =>")
        .expect("missing normal handler-delivery arm");
    let build = delivery[handler..]
        .find("prepare_handler_frame")
        .map(|offset| handler + offset)
        .expect("handler/restorer mapping proof must run before commit");
    let commit = delivery[handler..]
        .find("commit_prepared_delivery")
        .map(|offset| handler + offset)
        .expect("missing handler receipt commit");
    let apply = delivery[commit..]
        .find(".apply(")
        .map(|offset| commit + offset)
        .expect("live handler entry must apply only after receipt commit");
    let apply_tail = &delivery[apply..];
    assert!(apply_tail.contains("&mut frame.x"));
    assert!(apply_tail.contains("&mut frame.sp_el0"));
    assert!(apply_tail.contains("&mut frame.elr_el1"));
    assert!(handler < build && build < commit && commit < apply);
}
