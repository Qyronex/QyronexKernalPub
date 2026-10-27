// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// SIGCONT has a process-wide job-control side effect even when kill(2) selects a process group or
// the all-permitted set. Pin the common per-target send edge so a narrow kill(pid, SIGCONT) fix cannot
// leave kill(0/-pgid/-1, SIGCONT) merely queueing a signal to stopped processes that cannot return.

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("missing start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("missing end marker");
    &tail[..end]
}

fn kill_window() -> &'static str {
    between(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Kill",
        "Step30RuntimeCall::Tgkill",
    )
}

fn tgkill_window() -> &'static str {
    between(
        STEP30_RUNTIME,
        "Step30RuntimeCall::Tgkill",
        "Step30RuntimeCall::RtSigaction",
    )
}

fn common_send_window() -> &'static str {
    between(kill_window(), "let send = |target", "let send_selected =")
}

fn selected_send_window() -> &'static str {
    between(kill_window(), "let send_selected =", "match selector")
}

#[test]
fn common_per_process_send_owns_the_sigcont_continue_transaction() {
    let send = common_send_window();

    for required in [
        "queue_signal_with_provenance",
        "SIGCONT",
        "job_control_targets_for_pid",
        "begin_process_job_control_transaction",
        "JobControlCommand::Continue",
        "dispatch_process_job_control",
        "finish_process_job_control_dispatch",
    ] {
        assert!(
            send.contains(required),
            "common kill target send path is missing SIGCONT process-continue edge: {required}"
        );
    }

    let queued = send
        .find("queue_signal_with_provenance")
        .expect("missing signal queue commit");
    let begin = send
        .find("begin_process_job_control_transaction")
        .expect("missing SIGCONT transaction begin");
    let dispatch = send
        .find("dispatch_process_job_control")
        .expect("missing scheduler dispatch");
    let finish = send
        .find("finish_process_job_control_dispatch")
        .expect("missing durable completion/safe-point finish");
    assert!(
        queued < begin && begin < dispatch && dispatch < finish,
        "SIGCONT must queue first, then begin/dispatch/finish the exact process transaction"
    );

    let real_signal = send
        .find("SignalNumber::Signal(number)")
        .expect("missing nonzero signal branch");
    let sigcont = send[real_signal..begin]
        .find("SIGCONT")
        .expect("SIGCONT guard must be inside the real-signal path");
    assert!(sigcont < begin - real_signal);
}

#[test]
fn every_group_selector_reuses_the_common_per_target_send_path() {
    let selected = selected_send_window();
    assert!(
        selected.contains("for target in targets.iter()") && selected.contains("send(target)?"),
        "group/all kill selectors must route every selected Process through the common send edge"
    );

    let kill = kill_window();
    for (marker, next) in [
        (
            "KillSelector::SameProcessGroup",
            "KillSelector::ProcessGroup",
        ),
        ("KillSelector::ProcessGroup", "KillSelector::AllPermitted"),
    ] {
        let arm = between(kill, marker, next);
        assert!(
            arm.contains("send_selected"),
            "{marker} must reuse the common selected-target send loop"
        );
    }

    let all = kill
        .split_once("KillSelector::AllPermitted")
        .expect("missing all-permitted selector")
        .1;
    assert!(
        all.contains("send_selected"),
        "kill(-1, SIGCONT) must reuse the common selected-target send loop"
    );
}

#[test]
fn committed_sigcont_finishes_process_resume_before_fallible_wait_wake_routing() {
    let selected = selected_send_window();
    let queued_arm = between(
        selected,
        "SignalSendResult::Queued(targets) => {",
        "SignalSendResult::MissingTarget",
    );
    let selected_finish = queued_arm
        .find("finish_continue(continue_dispatch)")
        .expect("group SIGCONT path must finish the process Continue transaction");
    let selected_wake = queued_arm
        .find("interrupt_and_wake_process_wait_after_signal")
        .expect("group signal path must retain normal wait/futex interruption routing");
    assert!(
        selected_finish < selected_wake,
        "after a committed group SIGCONT, process Continue must finish before fallible wait/futex wake routing"
    );

    let pid = between(
        kill_window(),
        "KillSelector::Pid(target)",
        "KillSelector::SameProcessGroup",
    );
    let pid_finish = pid
        .find("finish_continue(continue_dispatch)")
        .expect("kill(pid, SIGCONT) must finish the process Continue transaction");
    let pid_wake = pid
        .find("interrupt_and_wake_process_wait_after_signal")
        .expect("kill(pid) must retain normal wait/futex interruption routing");
    assert!(
        pid_finish < pid_wake,
        "after a committed kill(pid, SIGCONT), process Continue must finish before fallible wait/futex wake routing"
    );

    let tgkill = tgkill_window();
    let tgkill_dispatch = tgkill
        .find("dispatch_process_job_control")
        .expect("tgkill(SIGCONT) must dispatch the process-wide Continue transaction");
    let tgkill_finish = tgkill
        .find("finish_process_job_control_dispatch")
        .expect("tgkill(SIGCONT) must finish the process-wide Continue transaction");
    let tgkill_wake = tgkill
        .find("interrupt_and_wake_thread_wait_after_signal")
        .expect("tgkill must retain exact thread wait/futex interruption routing");
    assert!(
        tgkill_dispatch < tgkill_finish && tgkill_finish < tgkill_wake,
        "after committed tgkill(SIGCONT), process Continue must finish before fallible thread wait/futex wake routing"
    );
}

#[test]
fn sigcont_group_fix_must_not_bypass_the_canonical_scheduler_owner() {
    let send = common_send_window();
    assert!(
        !send.contains("bootstrap_job_control_continue") && !send.contains("job_control_continue("),
        "signal send must use the generation-bound Process transaction, never direct RunQueue authority"
    );
}
