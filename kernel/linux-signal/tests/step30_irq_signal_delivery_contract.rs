// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 structural oracle: pending signals must be considered at every asynchronous lower-EL
// IRQ return boundary, not only after SVC dispatch. Exact Job-Control may already have stopped the
// interrupted generation inside the owner IRQ, so the post-IRQ scheduler safe point is allowed to
// switch first. Its owner contract must restore this exact generation before this frame is touched
// again; only then may ordinary signal-on-return consume the generation-bound ExceptionFrame.

const MAIN: &str = include_str!("../../core-aarch64/src/main.rs");
const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const JOB_CONTROL: &str = include_str!("../../scheduler-cpu/src/exit_split/job_control.rs");

fn irq_handler() -> &'static str {
    let start = MAIN
        .find("extern \"C\" fn aarch64_exception_handler")
        .expect("canonical AArch64 IRQ handler must remain present");
    let tail = &MAIN[start..];
    let end = tail
        .find("\nfn handle_interrupt")
        .expect("IRQ handler must end before interrupt dispatch helper");
    &tail[..end]
}

fn delivery_offset(text: &str) -> Option<usize> {
    text.find("deliver_step30_signal_on_return(frame)")
        .or_else(|| text.find("deliver_signal_on_irq_return(frame)"))
}

#[test]
fn acknowledged_lower_el_irq_resumes_exact_generation_before_signal_delivery() {
    let handler = irq_handler();
    assert!(
        handler.contains("ExceptionSource::LowerElAarch64"),
        "IRQ policy must distinguish a userspace return from current-EL proof/runtime IRQs"
    );

    let normal_start = handler
        .find("handle_interrupt(interrupt)")
        .expect("canonical acknowledged-IRQ body must remain present");
    let epilogue = &handler[normal_start..];
    let exit_irq = epilogue
        .find("local.exit_irq()")
        .expect("IRQ depth must be released before the scheduler/signal return owners can run");
    let reschedule = epilogue
        .find("service_reschedule_safe_point(local)")
        .expect("canonical post-IRQ reschedule safe point must remain present");
    let delivery = delivery_offset(epilogue)
        .expect("acknowledged lower-EL IRQ return must invoke canonical Step-30 signal delivery");
    assert!(
        exit_irq < reschedule && reschedule < delivery,
        "exact Job-Control reschedule must run after exit_irq and restore this generation before its ExceptionFrame is used for signal delivery"
    );
}

#[test]
fn no_ack_lower_el_irq_uses_the_same_exact_resume_boundary() {
    let handler = irq_handler();
    let Some(no_ack_start) = handler.find("let Some(interrupt)") else {
        // A refactor that removes the early no-ack return and converges on one common epilogue is
        // acceptable; the acknowledged-path test above then pins the common ordering.
        return;
    };
    let normal_start = handler
        .find("handle_interrupt(interrupt)")
        .expect("canonical acknowledged-IRQ body must remain present");
    let no_ack = &handler[no_ack_start..normal_start];
    if !no_ack.contains("return;") {
        // No early return means this path converges on the common epilogue pinned above.
        return;
    }

    let exit_irq = no_ack
        .find("local.exit_irq()")
        .expect("no-ack return must release irq_depth");
    let reschedule = no_ack
        .find("service_reschedule_safe_point(local)")
        .expect("no-ack IRQ return must retain the canonical reschedule safe point");
    let delivery = delivery_offset(no_ack)
        .expect("an early lower-EL no-ack IRQ return must also run Step-30 signal delivery");
    let ret = no_ack
        .rfind("return;")
        .expect("this branch was classified as an early return");
    assert!(
        exit_irq < reschedule && reschedule < delivery && delivery < ret,
        "no-ack IRQ return must restore the exact generation before signal delivery and before returning from the exception"
    );
}

#[test]
fn job_control_reschedule_returns_only_after_the_original_generation_is_current_again() {
    assert!(
        MAIN.contains("bootstrap_reschedule_with_job_control_destination_address_space"),
        "Core must use the Job-Control-aware post-IRQ scheduler owner"
    );
    let start = JOB_CONTROL
        .find("pub unsafe fn bootstrap_reschedule_with_job_control_destination_address_space")
        .expect("missing Job-Control-aware AArch64 reschedule owner");
    let tail = &JOB_CONTROL[start..];
    let end = tail
        .find("\n    #[cfg(all(target_arch = \"aarch64\", target_os = \"none\"))]\n    unsafe fn bootstrap_switch_stopped_current")
        .expect("missing stopped-current scheduler helper boundary");
    let reschedule = &tail[..end];
    assert!(
        reschedule
            .contains("self.bootstrap_yield_with_destination_address_space(activate_destination)")
            && reschedule.contains("self.bootstrap_switch_stopped_current(activate_destination)"),
        "ordinary reschedule must retain yield semantics while stopped-current uses the exact specialized switch owner"
    );

    let stopped = JOB_CONTROL
        .split_once("unsafe fn bootstrap_switch_stopped_current")
        .expect("missing stopped-current switch owner")
        .1;
    let switch = stopped
        .find("switch_context(old_sp_ptr, next_sp)")
        .expect("stopped-current path must perform the canonical context switch");
    let resumed = &stopped[switch..];
    for required in [
        "let observed = unpack_thread(local.current_thread())",
        "if observed != current",
        "ThreadState::Running",
        "job_control_stopped(current)",
    ] {
        assert!(
            resumed.contains(required),
            "scheduler return must revalidate the exact resumed generation before returning to its saved IRQ frame: {required}"
        );
    }
}

#[test]
fn irq_return_bridge_delegates_to_the_existing_signal_owner() {
    let has_bridge = QEMU.contains("pub(super) fn deliver_step30_signal_on_return")
        || QEMU.contains("pub(super) fn deliver_signal_on_irq_return");
    assert!(
        has_bridge,
        "Core needs only a narrow bridge; do not create a second signal-delivery implementation in main.rs"
    );
    assert!(QEMU.contains("signal_delivery::deliver_on_return(frame)"));
}
