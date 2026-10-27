// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 structural contract for Linux job-control observations. This test owns no wait,
// scheduler or signal authority; it only prevents final integration from turning scheduler Stop/
// Continue into a green build while the canonical Wait owner still exposes exit-only semantics.

const WAIT_OWNER: &str = include_str!("../src/lib.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn window<'a>(source: &'a str, marker: &str, next: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing marker: {marker}"));
    let tail = &source[start..];
    let end = tail
        .find(next)
        .unwrap_or_else(|| panic!("missing boundary after {marker}: {next}"));
    &tail[..end]
}

fn contains_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| source.contains(needle))
}

fn without_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[test]
fn wait_owner_encodes_linux_stopped_and_continued_statuses() {
    assert!(
        contains_any(WAIT_OWNER, &["fn stopped(", "fn stopped_status("]),
        "canonical WaitStatus needs a stopped-status constructor"
    );
    assert!(
        contains_any(WAIT_OWNER, &["fn continued(", "fn continued_status("]),
        "canonical WaitStatus needs a continued-status constructor"
    );
    assert!(
        WAIT_OWNER.contains("0x7f"),
        "stopped status must retain the Linux 0x7f low byte"
    );
    assert!(
        WAIT_OWNER.contains("0xffff"),
        "continued status must retain the Linux 0xffff encoding"
    );
}

#[test]
fn child_lifecycle_keeps_job_control_observation_separate_from_zombie_state() {
    assert!(WAIT_OWNER.contains("Zombie(WaitStatus)"));
    let child = window(WAIT_OWNER, "struct ChildRecord", "enum WaiterState");
    assert!(
        child.contains("state: ChildState"),
        "terminal child lifecycle state must remain a distinct owner field"
    );
    assert!(
        child.contains("pending_job_control: Option<PendingObservation>"),
        "Stop/Continue must remain a separate generation-bound observation instead of converting a live child into Zombie"
    );

    let compact = without_whitespace(WAIT_OWNER);
    assert!(
        compact.contains("record.pending_job_control=Some(PendingObservation{"),
        "job-control publication must write the dedicated pending observation owner"
    );
    assert!(
        compact.contains("record.state=ChildState::Zombie(status);")
            && compact.contains("record.pending_job_control=None;"),
        "terminal publication must transition to Zombie and retire any transient job-control observation"
    );
}

#[test]
fn blocking_waiter_and_linear_receipt_retain_requested_event_classes() {
    let waiter = window(WAIT_OWNER, "struct WaiterRecord", "/// Linear receipt");
    assert!(
        contains_any(waiter, &["interest", "events", "classes", "observations"]),
        "WaiterRecord must retain whether this wait accepts Exit, Stop and/or Continue"
    );

    let receipt = window(
        WAIT_OWNER,
        "pub struct WaitSleepReceipt",
        "impl WaitSleepReceipt",
    );
    assert!(
        contains_any(receipt, &["interest", "events", "classes", "observations"]),
        "the generation-bound sleep receipt must bind the same event-class selection as its waiter"
    );
}

#[test]
fn wait_owner_has_non_destructive_stop_and_continue_publication_edges() {
    assert!(
        contains_any(
            WAIT_OWNER,
            &[
                "publish_stopped",
                "publish_stop",
                "publish_job_control_stop"
            ]
        ),
        "missing canonical stopped-child publication edge"
    );
    assert!(
        contains_any(
            WAIT_OWNER,
            &[
                "publish_continued",
                "publish_continue",
                "publish_job_control_continue"
            ]
        ),
        "missing canonical continued-child publication edge"
    );
    assert!(
        WAIT_OWNER.contains("WaitWakeBatch"),
        "job-control publication must return exact scheduler wake generations through the existing Wait owner batch"
    );
}

#[test]
fn wait_options_distinguish_exit_stop_and_continue_without_reusing_nowait() {
    let options = window(
        WAIT_OWNER,
        "pub struct WaitOptions",
        "/// Linux-visible child observation",
    );
    for class in ["exited", "stopped", "continued"] {
        assert!(
            options.contains(class),
            "WaitOptions must preserve requested {class} observations independently of WNOHANG/WNOWAIT"
        );
    }
    assert!(options.contains("nowait"));
}

#[test]
fn runtime_planners_compose_wuntraced_and_wcontinued_instead_of_rejecting_them() {
    let waitid = window(
        RUNTIME,
        "fn waitid_observation_plan",
        "fn encode_waitid_siginfo",
    );
    assert!(waitid.contains("options.stopped()"));
    assert!(waitid.contains("options.continued()"));
    let waitid_compact = without_whitespace(waitid);
    assert!(
        !waitid_compact.contains("options.stopped()||options.continued()"),
        "waitid must not reject WSTOPPED/WCONTINUED once the Wait owner can represent them"
    );

    let wait4 = window(
        RUNTIME,
        "fn wait4_observation_plan",
        "fn map_wait_usercopy_error",
    );
    assert!(wait4.contains("options.stopped()"));
    assert!(wait4.contains("options.continued()"));
    let wait4_compact = without_whitespace(wait4);
    assert!(
        !wait4_compact.contains("options.stopped()||options.continued()"),
        "wait4 must not reject WUNTRACED/WCONTINUED once the Wait owner can represent them"
    );
}
