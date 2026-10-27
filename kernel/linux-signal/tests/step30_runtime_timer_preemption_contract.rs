// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 regression contract: the bootstrap IRQ proof deliberately disarms the virtual timer
// after its bounded delivery proof. The live process runtime must arm it again and every runtime
// timer IRQ must request the existing post-IRQ scheduler safe point. Otherwise a CPU-bound fork
// child can monopolize a one-vCPU guest forever and the SIGSTOP/SIGCONT lifecycle cannot progress.

const MAIN: &str = include_str!("../../core-aarch64/src/main.rs");

#[test]
fn live_runtime_rearms_the_timer_after_the_bounded_irq_proof() {
    let runtime = MAIN
        .split_once("#[cfg(all(feature = \"qemu-proof\", feature = \"step15-qemu-proof\"))]")
        .expect("missing live qemu runtime block")
        .1;
    let resume = runtime
        .find("step15_qemu::resume_initial_linux")
        .expect("missing initial Linux resume");
    let before_resume = &runtime[..resume];

    assert!(
        before_resume.contains("kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS)"),
        "the BSP runtime timer must be armed after the bounded IRQ proof and before userspace resumes"
    );
}

#[test]
fn runtime_timer_irq_requests_the_existing_scheduler_safe_point() {
    let handler = MAIN
        .split_once("fn handle_interrupt(interrupt: AcknowledgedInterrupt)")
        .expect("missing interrupt dispatcher")
        .1;
    let timer = handler
        .split_once("if interrupt.intid == timer_intid")
        .expect("missing virtual timer branch")
        .1;
    let timer = timer
        .split_once("if interrupt.intid == RESCHEDULE_SGI_DEFAULT")
        .expect("missing reschedule-SGI branch after timer branch")
        .0;

    for required in [
        "PROOF_DONE[index].load(Ordering::Acquire)",
        "kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS)",
        "local.request_reschedule()",
    ] {
        assert!(
            timer.contains(required),
            "runtime timer branch must retain periodic preemption ownership: {required}"
        );
    }

    assert!(
        MAIN.contains("service_reschedule_safe_point(local)"),
        "timer IRQ must continue to delegate switching to the post-EOI/post-exit_irq safe point"
    );
}
