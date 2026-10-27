// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const SIGNAL_OWNER: &str = include_str!("../src/lib.rs");

fn window<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).expect("missing start marker");
    let tail = &source[begin..];
    let finish = tail.find(end).unwrap_or(tail.len());
    &tail[..finish]
}

#[test]
fn sigcont_generation_cancels_opposite_pending_state_in_signal_owner() {
    assert!(SIGNAL_OWNER.contains("SIGCONT"));
    assert!(
        SIGNAL_OWNER.contains("cancel_job_control_pending"),
        "canonical SignalTable must own Stop/Continue pending-state cancellation before Core scheduler side effects"
    );
}

#[test]
fn kill_sigcont_uses_process_transaction_after_signal_generation() {
    let kill = window(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Kill",
        "Step30RuntimeCall::Tgkill",
    );
    for required in [
        "SIGCONT",
        "begin_process_job_control_transaction",
        "JobControlCommand::Continue",
        "dispatch_process_job_control",
        "finish_process_job_control_dispatch",
    ] {
        assert!(kill.contains(required), "kill(SIGCONT) missing: {required}");
    }
    assert!(
        !kill.contains("bootstrap_job_control_continue"),
        "kill(SIGCONT) must never mutate a RunQueue directly"
    );
}

#[test]
fn tgkill_sigcont_resumes_the_exact_target_process_not_only_one_thread() {
    let tgkill = window(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Tgkill",
        "Step30RuntimeCall::RtSigaction",
    );
    for required in [
        "SIGCONT",
        "job_control_targets_for_pid",
        "begin_process_job_control_transaction",
        "JobControlCommand::Continue",
        "dispatch_process_job_control",
        "finish_process_job_control_dispatch",
    ] {
        assert!(
            tgkill.contains(required),
            "tgkill(SIGCONT) missing: {required}"
        );
    }
    assert!(
        !tgkill.contains("bootstrap_job_control_continue"),
        "tgkill(SIGCONT) must use the process transaction instead of resuming one scheduler generation directly"
    );
}
