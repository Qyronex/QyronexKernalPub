// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");

fn pending_exit_drain() -> &'static str {
    let start = QEMU
        .find("pub(super) fn drain_step30_pending_exits_before_wait")
        .expect("missing Step-30 pre-Wait pending-exit drain");
    let tail = &QEMU[start..];
    let end = tail
        .find("\nfn step15_svc_serial")
        .expect("missing boundary after Step-30 pending-exit drain");
    &tail[..end]
}

fn lower_el_dispatch() -> &'static str {
    let start = QEMU
        .find("fn step15_lower_el_dispatch")
        .expect("missing lower-EL syscall dispatcher");
    let tail = &QEMU[start..];
    let end = tail
        .find("\nconst fn is_classified_minimum_number")
        .expect("missing boundary after lower-EL syscall dispatcher");
    &tail[..end]
}

#[test]
fn pre_wait_drain_finalizes_all_retained_exits_with_a_finite_owner_bound() {
    let drain = pending_exit_drain();
    assert!(
        drain.contains("runtime::STEP15_RUNTIME_THREADS"),
        "pending-exit drain must be bounded by the runtime thread capacity"
    );
    assert!(
        drain.contains("pending_thread_exit"),
        "pending-exit drain must observe the canonical runtime pending-exit owner"
    );
    assert!(
        drain.contains("finalize_step30_pending_exit_after_resume"),
        "pending-exit drain must delegate each retained generation to the canonical proof-carrying finalizer"
    );
    assert!(
        drain.contains("if !finalize_step30_pending_exit_after_resume(current_cpu)?"),
        "bounded drain must stop when the progress-reporting finalizer observes an empty owner queue"
    );
    assert!(
        drain.contains("pending.is_some()"),
        "bounded drain must fail closed if capacity is exhausted with work remaining"
    );
}

#[test]
fn wait4_and_waitid_drain_pending_exits_before_runtime_wait_observation() {
    let dispatch = lower_el_dispatch();
    let classifier = dispatch
        .find("classify_step30_runtime(request)")
        .expect("live dispatcher must classify the Step-30 wait call");
    assert!(
        dispatch.contains("Step30RuntimeCall::Wait4")
            && dispatch.contains("Step30RuntimeCall::WaitId"),
        "both wait4 and waitid must share the pre-Wait pending-exit drain"
    );
    let drain = dispatch
        .find("drain_step30_pending_exits_before_wait")
        .expect("live Wait dispatch must drain retained child exits");
    let runtime_wait = dispatch
        .find("step30_runtime::handle(request, frame)")
        .expect("normal Step-30 runtime dispatcher must remain present");
    assert!(
        classifier < drain && drain < runtime_wait,
        "retained child exits must become canonical Wait events before Wait4/WaitId observe the runtime"
    );
}
