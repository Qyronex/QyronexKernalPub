// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Pins the Step-30.7 post-scheduler Job-Control publication chain. This deliberately does not claim
// that Default Stop/SIGCONT transaction orchestration or the RESCHEDULE IRQ mailbox drain is complete;
// those remain the preceding owner seam. The contract prevents future work from collapsing exact
// scheduler completion back into aggregate counters or publishing Wait state from scheduler code.

const RUNTIME_OWNER: &str =
    include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");
const CORE_ROUTE: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");
const CPU_JOB_CONTROL: &str = include_str!("../../scheduler-cpu/src/exit_split/job_control.rs");
const SMP: &str = include_str!("../../scheduler-smp/src/lib.rs");

fn window<'a>(source: &'a str, marker: &str, next: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing marker: {marker}"));
    let tail = &source[start..];
    let end = tail.find(next).unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn remote_transport_retains_exact_generation_qualified_completion_evidence() {
    for required in [
        "pub struct JobControlGeneration",
        "pub struct JobControlCompletion",
        "pub struct JobControlCompletionBatch",
        "pub enum JobControlAppliedOutcome",
        "pub fn completed_batch",
        "pub fn acknowledge",
    ] {
        assert!(
            SMP.contains(required),
            "missing exact Job-Control transport owner: {required}"
        );
    }
    assert!(SMP.contains("StaleJobControlGeneration"));
    assert!(SMP.contains("ConflictingJobControlGeneration"));
    assert!(SMP.contains("StaleJobControlCompletion"));
}

#[test]
fn owner_irq_drain_returns_exact_completions_not_only_aggregate_counters() {
    let drain = window(
        CPU_JOB_CONTROL,
        "pub unsafe fn drain_remote_job_control_exact_from_irq",
        "pub unsafe fn bootstrap_reschedule_with_job_control_destination_address_space",
    );
    assert!(drain.contains("JobControlDrainResult"));
    assert!(drain.contains("claim_pending"));
    assert!(drain.contains("complete_pending"));
    assert!(drain.contains("completed_batch"));
    assert!(
        !drain.contains("acknowledge("),
        "owner IRQ drain must retain completion evidence until Core/Runtime accepts it"
    );
}

#[test]
fn runtime_revalidates_process_targets_before_one_wait_publication() {
    let publish = window(
        RUNTIME_OWNER,
        "pub(super) fn publish_process_job_control_completion",
        "pub(super) fn prepare_process_exit_wait_plan",
    );
    assert!(publish.contains("self.job_control_targets_for_pid(targets.pid())"));
    assert!(publish.contains("if current_targets != targets"));
    assert!(publish.contains("publish_stopped_with_wakes"));
    assert!(publish.contains("publish_continued_with_wakes"));
    assert!(publish.contains("SA_NOCLDSTOP"));
    assert!(publish.contains("ChildSignalProvenance::stopped"));
    assert!(publish.contains("ChildSignalProvenance::continued"));

    let wait_stop = publish.find("publish_stopped_with_wakes").unwrap();
    let signal_queue = publish.find("queue_signal_with_provenance").unwrap();
    assert!(
        wait_stop < signal_queue,
        "real scheduler completion must make Wait visibility independent of later SIGCHLD capacity/policy"
    );
}

#[test]
fn core_routes_only_post_commit_wakes_and_signal_notifications() {
    let route = window(
        CORE_ROUTE,
        "fn route_process_job_control_publication",
        "pub(super) fn service_process_job_control_completions",
    );
    assert!(route.contains("wake_wait_exit_batch"));
    assert!(route.contains("publication.signal_targets()"));
    assert!(route.contains("notifications.deliver()"));
    assert!(
        !route.contains("job_control_stop(") && !route.contains("job_control_continue("),
        "post-commit routing must not mutate scheduler state a second time"
    );

    let compatibility = window(
        CORE_ROUTE,
        "pub(super) fn complete_process_job_control_after_scheduler",
        "pub(super) fn complete_process_exit_wait_after_lifecycle",
    );
    assert!(compatibility.contains("publish_process_job_control_completion(targets, event)"));
    assert!(
        compatibility.contains("route_process_job_control_publication(publication, current_cpu)")
    );
    assert!(
        !compatibility.contains("job_control_stop(")
            && !compatibility.contains("job_control_continue("),
        "compatibility completion path must compose publication then delegate routing only"
    );
}
