// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const CORE_MAIN: &str = include_str!("../../core-aarch64/src/main.rs");
const LIVE_SVC: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const JOB_CONTROL_OWNER: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

#[test]
fn reschedule_sgi_drains_both_remote_wakes_and_exact_job_control_requests() {
    let irq = section(
        CORE_MAIN,
        "if interrupt.intid == RESCHEDULE_SGI_DEFAULT as u32",
        "RESCHEDULE_IRQS[index].fetch_add(1, Ordering::AcqRel);",
    );

    assert!(
        irq.contains("drain_remote_wakes_from_irq"),
        "accepted remote wake drain must remain in the reschedule SGI path"
    );
    assert!(
        irq.contains("job_control"),
        "the real reschedule SGI path must also drain exact remote job-control requests"
    );
    assert!(
        LIVE_SVC.contains("drain_process_job_control_from_irq")
            || LIVE_SVC.contains("drain_step30_job_control_from_irq"),
        "Core must expose the canonical step30_child_exit IRQ drain through the live SVC owner"
    );
    assert!(
        JOB_CONTROL_OWNER.contains("drain_process_job_control_from_irq")
            && JOB_CONTROL_OWNER.contains("drain_remote_job_control_exact_from_irq"),
        "job-control IRQ mutation must remain delegated to the exact scheduler owner"
    );
}

#[test]
fn durable_job_control_completions_are_serviced_only_after_irq_owner_mutation_ends() {
    assert!(
        JOB_CONTROL_OWNER.contains("service_process_job_control_completions"),
        "durable remote ACKs need a retryable post-IRQ Runtime/Wait publication edge"
    );
    assert!(
        LIVE_SVC.contains("service_process_job_control_completions")
            || LIVE_SVC.contains("service_step30_job_control_completions"),
        "live Core must expose the post-IRQ completion service without reaching into child owner state"
    );

    let handler = section(
        CORE_MAIN,
        "extern \"C\" fn aarch64_exception_handler",
        "fn handle_interrupt",
    );
    let first_exit = handler
        .find("local.exit_irq()")
        .expect("real IRQ handler must leave irq_depth before post-IRQ composition");
    let first_completion = handler
        .find("service_step30_job_control_safe_point")
        .expect("real IRQ handler must service durable job-control completion evidence");
    let last_exit = handler
        .rfind("local.exit_irq()")
        .expect("normal IRQ path must leave irq_depth before post-IRQ composition");
    let last_completion = handler
        .rfind("service_step30_job_control_safe_point")
        .expect("normal IRQ path must service durable job-control completion evidence");

    assert!(
        first_exit < first_completion && last_exit < last_completion,
        "every live IRQ return path must service Runtime/Wait job-control publication only after exit_irq"
    );
    assert!(
        handler
            .matches("service_step30_job_control_safe_point")
            .count()
            >= 2,
        "both spurious/no-ack and acknowledged IRQ return paths must service durable completions"
    );
}

#[test]
fn post_eoi_safe_point_switches_a_stopped_current_without_yield_running() {
    let safe_point = section(
        CORE_MAIN,
        "fn service_reschedule_safe_point",
        "fn current_cpu_index",
    );

    assert!(
        safe_point.contains("bootstrap_reschedule_with_job_control_destination_address_space"),
        "a Running->Stop transition leaves current held-Ready, so the live safe point must use the job-control-aware switch owner"
    );
    assert!(
        !safe_point.contains("bootstrap_yield_with_destination_address_space("),
        "the ordinary yield path starts with yield_running(current) and is invalid after current was already stopped"
    );
}
