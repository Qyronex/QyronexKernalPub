// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const CORE_JOB_CONTROL: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");

fn dispatch_window() -> &'static str {
    CORE_JOB_CONTROL
        .split_once("pub(super) fn dispatch_process_job_control")
        .expect("process job-control dispatch must exist")
        .1
        .split_once("/// Drains only the current PE's exact remote Job-Control requests")
        .expect("remote Job-Control drain must follow dispatch")
        .0
}

#[test]
fn local_scheduler_failure_restores_reserved_mailbox_claim() {
    let dispatch = dispatch_window();

    assert!(
        dispatch.contains("claim_exact_local_job_control_request"),
        "local scheduler mutation must first reserve the exact durable mailbox request"
    );
    assert!(
        dispatch.contains("mailbox.complete_pending(claim, outcome)"),
        "successful local scheduler mutation must durably complete the exact reserved request"
    );
    assert!(
        dispatch.contains("mailbox.restore_pending(claim)"),
        "a local scheduler error after claim must restore the RESERVED slot to Pending before returning; otherwise one failed local Stop/Continue permanently leaks mailbox capacity"
    );
}
