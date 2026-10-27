// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const CHILD_EXIT_OWNER: &str =
    include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");

fn process_exit_plan() -> &'static str {
    let start = CHILD_EXIT_OWNER
        .find("pub(super) fn prepare_process_exit_wait_plan")
        .expect("missing process-exit Wait/SIGCHLD owner");
    let tail = &CHILD_EXIT_OWNER[start..];
    let end = tail
        .find("pub(super) fn commit_process_auto_reap_reclaiming_frames")
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn caught_sigchld_snapshots_exact_child_identity_credentials_and_cause_before_queue_commit() {
    let owner = process_exit_plan();
    for required in [
        ".child_pid()",
        ".ruid()",
        "cause: kernal_linux_exit_lifecycle::ExitCause",
        "let child_provenance = match cause",
        "queue_signal_with_provenance",
        "SignalProvenance::Child",
    ] {
        assert!(
            owner.contains(required),
            "missing truthful SIGCHLD child snapshot edge: {required}"
        );
    }
    assert!(
        !owner.contains("ThreadIdentityCompletion"),
        "Wait/SIGCHLD publication must consume owner-neutral Completion + ExitCause evidence"
    );

    let child_pid = owner
        .find(".child_pid()")
        .expect("missing retained child PID snapshot");
    let child_uid = owner
        .find(".ruid()")
        .expect("missing child credential snapshot");
    let cause = owner
        .find("let child_provenance = match cause")
        .expect("missing resolved ExitCause provenance mapping");
    let queue = owner
        .find("queue_signal_with_provenance")
        .expect("missing canonical signal provenance queue");
    assert!(
        child_pid < queue && child_uid < queue && cause < queue,
        "SIGCHLD child PID, UID and resolved ExitCause must be snapshotted before queue commit"
    );

    if let Some(retire) = owner.find("retire_process") {
        assert!(
            queue < retire,
            "SIGCHLD child provenance must be committed before any process identity retirement"
        );
    }
}
