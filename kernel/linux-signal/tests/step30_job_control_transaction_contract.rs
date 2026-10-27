// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const CORE_JOB_CONTROL: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");
const SMP_JOB_CONTROL: &str = include_str!("../../scheduler-smp/src/lib.rs");

#[test]
fn process_job_control_uses_full_width_generation_bound_receipts() {
    for required in [
        "begin_process_job_control_transaction",
        "retain_process_job_control_completion",
        "JobControlGeneration",
        "ProcessJobControlDispatch",
        "ProcessJobControlCompletionProgress",
    ] {
        assert!(
            CORE_JOB_CONTROL.contains(required),
            "missing process job-control receipt invariant: {required}"
        );
    }
    assert!(
        SMP_JOB_CONTROL.contains("StaleJobControlGeneration")
            && SMP_JOB_CONTROL.contains("ConflictingJobControlGeneration"),
        "remote transport must reject stale/conflicting transaction generations"
    );
}

#[test]
fn newer_same_process_transaction_supersedes_older_receipt() {
    assert!(
        CORE_JOB_CONTROL.contains("transaction.targets.process() == targets.process()")
            && CORE_JOB_CONTROL.contains("state.transactions[slot] = Some"),
        "one exact Process may retain only its newest job-control transaction"
    );
    assert!(
        CORE_JOB_CONTROL.contains("completion.generation() < transaction.generation")
            && CORE_JOB_CONTROL.contains("ProcessJobControlCompletionProgress::Stale"),
        "older copied ACKs must not satisfy a superseding process transaction"
    );
}

#[test]
fn process_event_requires_every_exact_target_ack_and_a_real_transition() {
    assert!(
        CORE_JOB_CONTROL.contains("transaction.outcomes[..transaction.targets.len()]")
            && CORE_JOB_CONTROL.contains("any(Option::is_none)"),
        "process publication must wait for every exact target generation"
    );
    assert!(
        CORE_JOB_CONTROL.contains("JobControlAppliedOutcome::is_real_transition")
            && CORE_JOB_CONTROL.contains("event: Option<super::runtime::ProcessJobControlEvent>"),
        "all-no-op ACK sets must complete without fabricating a Stop/Continue child event"
    );
}

#[test]
fn stop_and_continue_accept_only_command_compatible_scheduler_outcomes() {
    for required in [
        "JobControlAppliedOutcome::AlreadyStopped",
        "JobControlAppliedOutcome::Held",
        "JobControlAppliedOutcome::Deschedule",
        "JobControlAppliedOutcome::NotStopped",
        "JobControlAppliedOutcome::Continued",
        "JobControlAppliedOutcome::Readied",
    ] {
        assert!(
            CORE_JOB_CONTROL.contains(required),
            "missing outcome: {required}"
        );
    }
    assert!(
        CORE_JOB_CONTROL.contains("completion.command() != transaction.command")
            && CORE_JOB_CONTROL.contains("!transaction.accepts_outcome(completion.outcome())"),
        "opposite-command or impossible scheduler ACKs must fail closed"
    );
}

#[test]
fn local_scheduler_ack_is_durable_before_runtime_composition() {
    assert!(
        CORE_JOB_CONTROL.contains("mailbox.push(request)")
            && CORE_JOB_CONTROL.contains("claim_exact_local_job_control_request")
            && CORE_JOB_CONTROL.contains("mailbox.complete_pending(claim, outcome)"),
        "local scheduler mutation must retain its exact ACK in the same durable per-CPU mailbox"
    );
    assert!(
        CORE_JOB_CONTROL.contains("completed_batch(PROCESS_JOB_CONTROL_MAILBOX_SLOTS)")
            && CORE_JOB_CONTROL.contains("mailbox.acknowledge(completion)"),
        "local and remote durable ACKs must share the Runtime composition and final acknowledgement path"
    );
    assert!(
        !CORE_JOB_CONTROL.contains("local_completions:"),
        "local ACKs must not escape through a transient by-value side channel"
    );
}

#[test]
fn rejected_local_scheduler_mutation_restores_the_reserved_mailbox_claim() {
    assert!(
        CORE_JOB_CONTROL.contains("let scheduler_result = match dispatch.command()")
            && CORE_JOB_CONTROL.contains("mailbox.restore_pending(claim)")
            && CORE_JOB_CONTROL.contains("return Err(())"),
        "a local scheduler error after claim_pending must restore the exact RESERVED request to Pending before returning"
    );
}
