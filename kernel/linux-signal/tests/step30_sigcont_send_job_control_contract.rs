// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing start marker: {start}"))
        .1;
    tail.split_once(end)
        .unwrap_or_else(|| panic!("missing end marker: {end}"))
        .0
}

#[test]
fn kill_sigcont_commits_signal_before_process_continue_and_finishes_outside_runtime_owner() {
    let kill = between(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Kill",
        "Step30RuntimeCall::Tgkill",
    );

    for required in [
        "SIGCONT",
        "queue_signal_with_provenance",
        "job_control_targets_for_pid",
        "begin_process_job_control_transaction",
        "JobControlCommand::Continue",
        "dispatch_process_job_control",
        "finish_process_job_control_dispatch",
    ] {
        assert!(kill.contains(required), "kill(SIGCONT) missing: {required}");
    }

    let queue = kill.find("queue_signal_with_provenance").unwrap();
    let begin = kill.find("begin_process_job_control_transaction").unwrap();
    let dispatch = kill.find("dispatch_process_job_control").unwrap();
    assert!(
        queue < begin && begin < dispatch,
        "SIGCONT must commit SignalTable state, then begin the exact process transaction, then mutate scheduler owners"
    );
}

#[test]
fn tgkill_sigcont_has_the_same_process_wide_continue_side_effect() {
    let tgkill = between(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Tgkill",
        "Step30RuntimeCall::RtSigaction",
    );

    for required in [
        "target.tgid()",
        "queue_thread_signal_with_provenance",
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

    let queue = tgkill.find("queue_thread_signal_with_provenance").unwrap();
    let begin = tgkill
        .find("begin_process_job_control_transaction")
        .unwrap();
    let dispatch = tgkill.find("dispatch_process_job_control").unwrap();
    assert!(
        queue < begin && begin < dispatch,
        "thread-directed SIGCONT must queue first but resume the complete target Process before scheduler dispatch"
    );
}

#[test]
fn return_time_default_continue_consumes_only_and_never_starts_a_second_resume_transaction() {
    let continued = between(
        SIGNAL_DELIVERY,
        "action: DefaultAction::Continue",
        "Delivery::Handler",
    );
    assert!(
        continued.contains("commit_prepared_delivery"),
        "default Continue still has to consume its exact pending signal receipt"
    );
    assert!(
        !continued.contains("begin_process_job_control_transaction")
            && !continued.contains("dispatch_process_job_control")
            && !continued.contains("JobControlCommand::Continue"),
        "SIGCONT resume authority belongs only to successful send-time generation; return-time delivery must not duplicate it"
    );
}
