// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const SIGNAL_OWNER: &str = include_str!("../src/lib.rs");
const WAIT_OWNER: &str = include_str!("../../linux-wait/src/lib.rs");
const SCHEDULER_OWNER: &str = include_str!("../../scheduler/src/lib.rs");
const SMP_JOB_CONTROL: &str = include_str!("../../scheduler-smp/src/lib.rs");
const CPU_JOB_CONTROL: &str = include_str!("../../scheduler-cpu/src/exit_split/job_control.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const JOB_CONTROL_TRANSACTION: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");

#[test]
fn canonical_scheduler_owner_retains_stop_hold_and_deferred_real_wake() {
    for required in ["job_control_stop", "job_control_continue", "deferred_ready"] {
        assert!(
            SCHEDULER_OWNER.contains(required),
            "missing canonical scheduler job-control invariant: {required}"
        );
    }
}

#[test]
fn cpu_scheduler_exposes_owner_checked_generation_bound_job_control_bridge() {
    assert!(
        CPU_JOB_CONTROL.contains("bootstrap_job_control_stop"),
        "CpuSchedulerCell must expose the canonical RunQueue stop operation under owner/quiescence"
    );
    assert!(
        CPU_JOB_CONTROL.contains("bootstrap_job_control_continue"),
        "CpuSchedulerCell must expose the canonical RunQueue continue operation under owner/quiescence"
    );
    assert!(
        CPU_JOB_CONTROL.contains("GlobalThreadId")
            && CPU_JOB_CONTROL.contains("PublicationState::Published"),
        "job-control mutation must remain exact-generation and published-context scoped"
    );
    assert!(
        CPU_JOB_CONTROL.contains("drain_remote_job_control_from_irq")
            && CPU_JOB_CONTROL
                .contains("bootstrap_reschedule_with_job_control_destination_address_space"),
        "remote stop/continue must drain only on the owner IRQ and switch at the owner safe point"
    );
}

#[test]
fn remote_job_control_retains_transaction_generation_and_exact_completion_authority() {
    for required in [
        "JobControlGeneration",
        "JobControlCompletion",
        "JobControlCompletionBatch",
        "JobControlAppliedOutcome",
        "drain_exact_into",
    ] {
        assert!(
            SMP_JOB_CONTROL.contains(required),
            "remote job-control must retain exact completion evidence: {required}"
        );
    }
    assert!(
        SMP_JOB_CONTROL.contains("StaleJobControlGeneration")
            && SMP_JOB_CONTROL.contains("ConflictingJobControlGeneration"),
        "older/conflicting pending transactions must not overwrite a newer exact command"
    );

    for required in [
        "drain_remote_job_control_exact_from_irq",
        "claim_pending",
        "PublicationState::Published",
        "complete_pending",
        "completed_batch",
    ] {
        assert!(
            CPU_JOB_CONTROL.contains(required),
            "owner IRQ drain must revalidate and durably complete exact generation authority: {required}"
        );
    }
    assert!(
        SMP_JOB_CONTROL.contains("completions.push(JobControlCompletion::new(request, outcome))"),
        "durable transport owner must construct the generation-qualified completion from the retained request only after CPU owner completion"
    );
    assert!(
        CPU_JOB_CONTROL.contains("AlreadyStopped")
            && CPU_JOB_CONTROL.contains("NotStopped")
            && CPU_JOB_CONTROL.contains("completions"),
        "no-op outcomes must remain report-only rather than becoming Linux-visible completion authority"
    );
}

#[test]
fn wait_owner_represents_stopped_and_continued_child_events() {
    assert!(
        WAIT_OWNER.contains("fn stopped(") || WAIT_OWNER.contains("fn stopped_status("),
        "wait owner needs Linux WIFSTOPPED-compatible status construction"
    );
    assert!(
        WAIT_OWNER.contains("fn continued(") || WAIT_OWNER.contains("fn continued_status("),
        "wait owner needs Linux WIFCONTINUED-compatible status construction"
    );
    assert!(
        WAIT_OWNER.contains("0x7f"),
        "stopped wait status must preserve the Linux 0x7f low-byte encoding"
    );
    assert!(
        WAIT_OWNER.contains("0xffff"),
        "continued wait status must preserve the Linux 0xffff encoding"
    );
}

#[test]
fn process_job_control_transaction_is_the_only_core_scheduler_bridge() {
    for required in [
        "begin_process_job_control_transaction",
        "dispatch_process_job_control",
        "retain_process_job_control_completion",
        "publish_process_job_control_completion",
    ] {
        assert!(
            JOB_CONTROL_TRANSACTION.contains(required),
            "missing generation-bound process job-control transaction edge: {required}"
        );
    }
}

#[test]
fn committed_default_stop_uses_process_transaction_before_wait_publication() {
    assert!(SIGNAL_DELIVERY.contains("DefaultAction::Stop"));
    assert!(
        SIGNAL_DELIVERY.contains("begin_process_job_control_transaction")
            && SIGNAL_DELIVERY.contains("JobControlCommand::Stop"),
        "a committed default stop must start the exact Process transaction instead of mutating a RunQueue directly"
    );
    assert!(
        SIGNAL_DELIVERY.contains("dispatch_process_job_control"),
        "default stop must dispatch the transaction to local/remote scheduler owners"
    );
}

#[test]
fn sigcont_send_uses_immediate_process_transaction_for_stopped_targets() {
    assert!(SIGNAL_OWNER.contains("SIGCONT"));
    assert!(STEP30_RUNTIME.contains("SIGCONT"));
    assert!(
        STEP30_RUNTIME.contains("begin_process_job_control_transaction")
            && STEP30_RUNTIME.contains("JobControlCommand::Continue"),
        "SIGCONT cannot wait for return-time delivery; successful generation must start the exact Process continue transaction immediately"
    );
    assert!(
        STEP30_RUNTIME.contains("dispatch_process_job_control"),
        "SIGCONT resume must dispatch through the canonical Process transaction to local/remote scheduler owners"
    );
}
