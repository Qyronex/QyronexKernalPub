// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Step-30.7 structural regression oracle for prompt delivery of already-queued signals to a
//! running remote EL0 target.
//!
//! The oracle is authority-free: it only reads the accepted owners as source text. Keeping it in
//! the lib-only signal crate avoids making host `cargo test --workspace --tests` build the
//! freestanding AArch64 Core binary.

const IDENTITY: &str = include_str!("../../linux-identity/src/lib.rs");
const STEP30: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn runtime_arm(marker: &str) -> &'static str {
    let start = STEP30
        .find(marker)
        .unwrap_or_else(|| panic!("missing Step-30 runtime arm: {marker}"));
    let tail = &STEP30[start..];
    let end = tail[marker.len()..]
        .find("\n        Step30RuntimeCall::")
        .map(|offset| marker.len() + offset)
        .unwrap_or(tail.len());
    &tail[..end]
}

fn source_window<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing source marker: {start_marker}"));
    let tail = &source[start..];
    let end = tail
        .find(end_marker)
        .unwrap_or_else(|| panic!("missing source end marker: {end_marker}"));
    &tail[..end]
}

fn documented_method_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing method marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = body
        .find("\n    ///")
        .map(|offset| marker.len() + offset)
        .unwrap_or(tail.len());
    &tail[..end]
}

fn compact(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn identity_exposes_only_bounded_exact_process_thread_observations() {
    let observer = documented_method_window(IDENTITY, "pub fn bound_scheduler_thread_at");
    assert!(observer.contains("live_linux_process(process)"));
    assert!(observer.contains("record.process == process_id"));
    assert!(observer.contains("record.key.scheduler_thread"));
    assert!(!observer.contains("allocator.allocate"));
}

#[test]
fn process_signal_targets_are_snapshotted_only_after_queue_commit() {
    let kill = runtime_arm("Step30RuntimeCall::Kill");
    let queue = kill
        .find("queue_signal_with_provenance")
        .expect("process-directed signal must use canonical queue owner");
    let observe = kill
        .find("process_signal_notify_targets(process, identities)")
        .expect("queued process signal must retain exact bound thread observations");
    let queued = kill[observe..]
        .find("SignalSendResult::Queued(targets)")
        .map(|offset| observe + offset)
        .expect("queue success must carry only the post-commit exact target snapshot");
    assert!(queue < observe && observe < queued);
    assert!(STEP30.contains("bound_scheduler_thread_at(process, ordinal)"));
}

#[test]
fn exact_tgkill_retains_only_the_exact_thread_after_queue_commit() {
    let tgkill = compact(runtime_arm("Step30RuntimeCall::Tgkill"));
    assert!(tgkill.contains("scheduler_thread_for_tid"));
    assert!(tgkill.contains("bound_tid_for_scheduler_thread"));
    let queue = tgkill
        .find("queue_thread_signal_with_provenance")
        .expect("tgkill must use canonical exact-thread queue owner");
    let tail = &tgkill[queue..];
    let single = tail
        .find("SignalNotifyTargets::single(thread)")
        .expect("tgkill queue success must retain its exact target generation");
    let queued = tail[..single]
        .rfind("SignalSendResult::Queued(")
        .expect("exact target must be wrapped in the queued notification result");
    assert!(queued < single);
}

#[test]
fn signal_zero_probe_branches_never_create_notification_targets() {
    for arm in [
        runtime_arm("Step30RuntimeCall::Kill"),
        runtime_arm("Step30RuntimeCall::Tgkill"),
    ] {
        let arm = compact(arm);
        let probe = arm
            .find("SignalNumber::Probe=>SignalSendResult::ProbeSuccess")
            .expect("signal-zero probe branch must remain explicit");
        let tail = &arm[probe..];
        let real = tail
            .find("SignalNumber::Signal(number)=>")
            .expect("real signal branch must follow probe branch");
        let probe_branch = &tail[..real];
        assert!(!probe_branch.contains("SignalSendResult::Queued"));
        assert!(!probe_branch.contains("send_sgi1"));
    }
}

#[test]
fn notification_plan_deduplicates_per_remote_cpu_and_skips_sender_cpu() {
    assert!(STEP30.contains("cpus: [bool; super::super::MAX_PROOF_CPUS]"));
    let plan = source_window(
        STEP30,
        "impl SignalNotifyPlan",
        "fn process_signal_notify_targets",
    );
    assert!(plan.contains("let target_cpu = usize::from(thread.cpu.0)"));
    assert!(plan.contains("self.cpus.get_mut(target_cpu)"));
    assert!(plan.contains("target_cpu != current_cpu"));
    assert!(plan.contains("*notify = true"));
}

#[test]
fn remote_notification_is_pure_sgi_routing_without_scheduler_wake_authority() {
    let plan = source_window(
        STEP30,
        "impl SignalNotifyPlan",
        "fn process_signal_notify_targets",
    );
    let deliver = source_window(plan, "fn deliver(self)", "\n    }\n}");
    assert!(deliver.contains("CPU_MPIDRS"));
    assert!(deliver.contains("RESCHEDULE_SGI_DEFAULT"));
    assert!(deliver.contains("send_sgi1"));
    assert!(deliver.contains("if !notify"));
    assert!(deliver.contains("continue"));

    // This path is an interrupt notification only. Scheduler/wait authority remains elsewhere.
    assert!(!deliver.contains("remote_wake("));
    assert!(!deliver.contains("bootstrap_wake_local_exact"));
    assert!(!deliver.contains("request_reschedule"));
    assert!(!deliver.contains("make_ready"));
    assert!(!deliver.contains("bootstrap_block"));
}

#[test]
fn group_and_pid_success_route_post_commit_notifications_before_linux_success() {
    let kill = compact(runtime_arm("Step30RuntimeCall::Kill"));
    assert!(kill.contains("notifications.include_targets(current_cpu,targets)?"));
    assert!(kill.contains("notifications.deliver()?"));

    let pid_start = kill
        .find("KillSelector::Pid(target)=>{")
        .expect("missing exact-PID kill selector arm");
    let pid_tail = &kill[pid_start..];
    let pid_end = pid_tail
        .find("KillSelector::SameProcessGroup")
        .unwrap_or(pid_tail.len());
    let pid = &pid_tail[..pid_end];

    let send = pid
        .find("let(result,continue_dispatch)=send(target)?;")
        .expect(
            "exact-PID signal send must retain the queue result plus SIGCONT completion receipt",
        );
    let continue_done = pid.find("finish_continue(continue_dispatch);").expect(
        "exact-PID send must finish committed SIGCONT scheduling before later fallible work",
    );
    let wake = pid
        .find("interrupt_and_wake_process_wait_after_signal(target,)?;")
        .expect("queued exact-PID send must route the canonical post-commit wait wake");
    let finish_pid = pid
        .find("finish_signal_send_result(result,current_cpu)")
        .expect("exact-PID send must finish through post-commit notification handling");
    assert!(send < continue_done && continue_done < wake && wake < finish_pid);

    let finish = compact(source_window(
        STEP30,
        "fn finish_signal_send_result",
        "fn encode_signal_send_result",
    ));
    let queued = finish
        .find("SignalSendResult::Queued(targets)")
        .expect("real queued signal must have a post-commit completion path");
    let deliver = finish
        .find("notifications.deliver()?")
        .expect("queued signal must deliver its SGI plan");
    let success = finish
        .find("SyscallReturn::success(0)")
        .expect("Linux success must be returned only after notification");
    assert!(queued < deliver && deliver < success);
}

#[test]
fn queued_signal_cannot_bypass_post_commit_notification_path() {
    let encoder = source_window(
        STEP30,
        "fn encode_signal_send_result",
        "fn decode_sigaction_action",
    );
    assert!(encoder.contains("SignalSendResult::Queued(_) => Err(())"));
    assert!(encoder.contains("SignalError::PendingCapacity"));
    assert!(encoder.contains("Errno::EAGAIN"));
}
