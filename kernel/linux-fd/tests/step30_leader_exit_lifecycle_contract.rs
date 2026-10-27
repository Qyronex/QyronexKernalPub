// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const CHILD_EXIT: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");
const CHILD_EXIT_OWNER: &str =
    include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");
const LIFECYCLE: &str = include_str!("../../linux-exit-lifecycle/src/lib.rs");

fn window<'a>(source: &'a str, marker: &str, next: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing marker: {marker}"));
    let tail = &source[start..];
    let end = tail.find(next).unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn lifecycle_identity_finalizer_remains_non_leader_pthread_only() {
    let finalizer = window(
        LIFECYCLE,
        "pub fn finalize_reaped_thread_with_identity",
        "fn complete_released_thread",
    );
    assert!(
        finalizer.contains("release_reaped_thread_identity(process, objects, bindings, proof)"),
        "non-leader pthreads must retain the proof-carrying Linux TID retirement owner"
    );
    assert!(
        !finalizer.contains("if linux_tid == linux_pid"),
        "process-leader classification belongs in Step30/Core composition, not the pthread lifecycle API"
    );
    assert!(
        !finalizer.contains("identities.retire_process(process)"),
        "the pthread-only lifecycle API must not acquire process-identity retirement authority"
    );
}

#[test]
fn generic_lifecycle_finalization_returns_the_cause_from_its_private_ticket_resolution() {
    let mut found = false;
    for candidate in LIFECYCLE.split("pub fn ").skip(1) {
        let candidate = candidate.split("\npub fn ").next().unwrap_or(candidate);
        if candidate.contains("resolve_ticket(ticket, process)?")
            && candidate.contains("let cause = ticket.cause();")
            && candidate.contains("process.release_reaped_thread(")
            && candidate.contains("complete_released_thread(")
            && !candidate.contains("release_reaped_thread_identity")
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "the generic leader-capable lifecycle owner must return metadata from the same private resolve_ticket -> generic reap-proof consumption linearization; Core must not reconstruct ExitCause"
    );
}

#[test]
fn core_splits_leader_and_pthread_before_consuming_the_reap_proof() {
    let finalizer = window(
        QEMU,
        "pub(super) fn finalize_step30_pending_exit_after_resume",
        "pub(super) fn drain_step30_pending_exits_before_wait",
    );

    let pid = finalizer
        .find("bound_pid(process)")
        .expect("Core must classify against the canonical bound Process PID");
    let tid = finalizer
        .find("bound_tid_for_scheduler_thread(process, proof.thread())")
        .expect("Core must classify the exact reaped scheduler generation's bound TID");
    let leader = finalizer
        .find("if linux_tid == linux_pid")
        .expect("Core must derive process-leader identity from canonical TID == PID");
    let pthread_finalize = finalizer
        .find("finalize_reaped_thread_with_identity")
        .expect("non-leader pthread path must keep the existing identity finalizer");
    let leader_branch = &finalizer[leader..pthread_finalize];

    let authority = leader_branch
        .find("authority_for_reaped_proof")
        .expect("leader path must recover process-local Thread authority from the reap proof");
    let lifecycle_finalize = leader_branch
        .find("kernal_linux_exit_lifecycle::finalize_reaped_thread")
        .expect("leader path must consume the reap proof through a generic lifecycle finalizer");
    assert!(authority < lifecycle_finalize);
    assert!(
        !leader_branch.contains("release_reaped_thread_identity"),
        "a Process leader must never enter the pthread-only identity retirement owner"
    );
    assert!(
        !leader_branch.contains("ticket.cause()"),
        "leader Wait/SIGCHLD cause must come from the lifecycle-resolved finalization result, not a pre-resolution ticket copy"
    );
    assert!(
        !leader_branch.contains("ExitRequestMismatch"),
        "a valid non-final leader completion must retain Process identity rather than fail closed"
    );

    let process_exit = finalizer[pthread_finalize..]
        .find("Completion::ProcessExited")
        .map(|offset| pthread_finalize + offset)
        .expect("ProcessExited must be observed after the leader/pthread branches converge");
    let retire_process = finalizer[process_exit..]
        .find("identities.retire_process(process)")
        .map(|offset| process_exit + offset)
        .expect("final Process completion must retire process-scoped Linux identity exactly once");

    assert!(pid < leader && tid < leader);
    assert!(leader < pthread_finalize);
    assert!(pthread_finalize < process_exit && process_exit < retire_process);
}

#[test]
fn futex_wait_resume_reuses_the_canonical_pending_exit_finalizer() {
    let futex = window(QEMU, "if request.number == 98", "if request.number == 113");
    assert!(
        futex.contains("finalize_step30_pending_exit_after_resume(current_cpu)"),
        "successful FUTEX_WAIT resume must delegate pending-exit ownership to the canonical Step30 finalizer"
    );
    assert!(
        !futex.contains("finalize_reaped_thread_with_identity"),
        "FUTEX_WAIT must not retain a second pthread-only reap/lifecycle implementation"
    );
    assert!(
        !futex.contains("bootstrap_reap_exited_after_teardown_with_proof"),
        "the canonical pending-exit finalizer must be the sole proof-consuming reap owner after FUTEX_WAIT resume"
    );
}

#[test]
fn wait_sigchld_tail_consumes_owner_neutral_completion_and_cause() {
    let child_exit = window(
        CHILD_EXIT,
        "pub(super) fn complete_process_exit_wait_after_lifecycle",
        "pub(super) fn complete_process_job_control_after_scheduler",
    );
    assert!(
        child_exit.contains("kernal_linux_exit_lifecycle::Completion")
            && child_exit.contains("kernal_linux_exit_lifecycle::ExitCause"),
        "post-lifecycle child publication must consume only Completion + ExitCause evidence"
    );
    assert!(
        !child_exit.contains("ThreadIdentityCompletion"),
        "post-lifecycle child publication must not require the pthread-only identity wrapper"
    );

    let owner = window(
        CHILD_EXIT_OWNER,
        "pub(super) fn prepare_process_exit_wait_plan",
        "pub(super) fn commit_process_auto_reap_reclaiming_frames",
    );
    assert!(
        owner.contains("kernal_linux_exit_lifecycle::Completion")
            && owner.contains("kernal_linux_exit_lifecycle::ExitCause"),
        "Wait/SIGCHLD policy must consume owner-neutral completion/cause evidence"
    );
    assert!(
        !owner.contains("ThreadIdentityCompletion"),
        "Wait/SIGCHLD policy must not manufacture a pthread identity completion for a leader"
    );
    assert!(
        owner.contains("ExitCause::Exited") && owner.contains("ExitCause::Signaled"),
        "ordinary and signaled Process exits must retain truthful Wait/SIGCHLD provenance"
    );
}
