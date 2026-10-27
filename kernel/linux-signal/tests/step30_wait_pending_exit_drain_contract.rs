// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Gate-5 regression contract for the exact wait4 deadlock observed after two children had already
// completed scheduler exit before the parent's first wait observation. The fix must publish retained
// lifecycle completions through the existing canonical finalizer; Core must not synthesize Wait state.

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn window<'a>(source: &'a str, marker: &str, next: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing marker: {marker}"));
    let tail = &source[start..];
    let end = tail.find(next).unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn current_pe_pending_exit_drain_is_bounded_and_reuses_canonical_finalizer() {
    let drain = window(
        STEP15_QEMU,
        "pub(super) fn drain_step30_pending_exits_before_wait",
        "fn step15_svc_serial",
    );

    assert!(
        drain.contains("runtime::STEP15_RUNTIME_THREADS"),
        "pending-exit draining must be bounded by the retained Step-30 thread capacity"
    );
    assert!(
        drain.contains("finalize_step30_pending_exit_after_resume(current_cpu)"),
        "the drain must repeatedly consume the existing proof-carrying lifecycle finalizer"
    );
    assert!(
        drain.contains("pending_thread_exit"),
        "after exhausting the bound the drain must re-observe canonical pending-exit ownership"
    );
    assert!(
        drain.contains("Err(())"),
        "a still-pending exit after the bounded drain must fail closed"
    );
}

#[test]
fn lower_el_svc_drains_completed_children_before_step30_wait_observation() {
    let svc = window(
        STEP15_QEMU,
        "fn step15_lower_el_dispatch",
        "const fn is_classified_minimum_number",
    );

    let classify = svc
        .find("classify_step30_runtime(request)")
        .expect("Step-30 SVC path must classify the runtime call before selective draining");
    let drain = svc
        .find("drain_step30_pending_exits_before_wait(current_cpu)")
        .expect("Wait4/WaitId SVC path must drain retained child exits");
    let step30 = svc
        .find("match step30_runtime::handle(request, frame)")
        .expect("missing Step-30 runtime dispatch");
    assert!(svc.contains("Step30RuntimeCall::Wait4"));
    assert!(svc.contains("Step30RuntimeCall::WaitId"));
    assert!(
        classify < drain && drain < step30,
        "completed child lifecycle tickets must reach Wait ownership before WaitId/Wait4 can observe WouldBlock"
    );
}

#[test]
fn blocking_wait_resume_uses_the_same_bounded_exit_drain() {
    let blocking = &STEP30_RUNTIME[STEP30_RUNTIME
        .find("fn block_until_wait_ready")
        .expect("missing blocking wait owner")..];

    assert!(
        blocking.contains("super::drain_step30_pending_exits_before_wait(current_cpu)"),
        "blocking wait resume must drain every retained current-PE child exit before re-observation"
    );
    assert!(
        !blocking.contains("super::finalize_step30_pending_exit_after_resume(current_cpu)"),
        "blocking wait resume must not regress to a one-shot pending-exit finalizer"
    );
}
