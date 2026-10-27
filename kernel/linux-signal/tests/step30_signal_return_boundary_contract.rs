// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = ["\nfn ", "\npub(super) fn ", "\npub(crate) fn ", "\npub fn "]
        .into_iter()
        .filter_map(|next| body.find(next).map(|offset| marker.len() + offset))
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

fn compact(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn finalized_step30_signal_frame_cannot_fall_through_unconditional_return_hook() {
    let fallback = function_window(STEP15_QEMU, "extern \"C\" fn step15_lower_el_fallback");
    let fallback = compact(fallback);

    assert!(fallback.contains("step15_lower_el_dispatch"));
    assert!(fallback.contains("deliver_step30_signal_on_return(frame)"));
    assert!(
        !fallback.contains(
            "if!step15_lower_el_dispatch(frame){returnfalse;}deliver_step30_signal_on_return(frame).is_ok()"
        ),
        "a Step-30 syscall that already finalized a signal frame must have an explicit return boundary that skips ordinary deliver_on_return"
    );
}

#[test]
fn trap_dispatch_propagates_the_interrupted_wait_finalized_frame_outcome() {
    assert!(
        STEP15_QEMU.contains("step30_runtime::Outcome::SignalFrameCommitted"),
        "the trap layer must distinguish an interrupted-wait handler frame from ordinary FrameCommitted returns",
    );

    let fallback = function_window(STEP15_QEMU, "extern \"C\" fn step15_lower_el_fallback");
    assert!(
        fallback.contains("deliver_step30_signal_on_return"),
        "ordinary handled syscalls still require the normal signal return hook",
    );
}

#[test]
fn bad_handler_frame_sigsegv_is_linearized_after_the_exact_signal_receipt() {
    let preparation = function_window(SIGNAL_DELIVERY, "fn prepare_handler_frame");
    assert!(
        !preparation.contains("terminate_bad_handler_frame("),
        "frame preparation is non-destructive: bad user state must be returned to the caller so the exact PreparedSignal receipt can be revalidated before forced SIGSEGV",
    );

    let interrupted = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_interrupted_wait");
    let interrupted_handler = interrupted
        .find("Delivery::Handler { handler, .. } => {")
        .expect("interrupted wait must retain an explicit caught-handler arm");
    let interrupted_handler = &interrupted[interrupted_handler..];
    let interrupted_commit = interrupted_handler
        .find("commit_interrupted_wait_signal")
        .expect("bad interrupted-wait handler state must revalidate/commit the exact signal+wait receipt");
    let interrupted_sigsegv = interrupted_handler
        .find("terminate_bad_handler_frame")
        .expect(
            "a still-current bad interrupted-wait handler frame must terminate as forced SIGSEGV",
        );
    assert!(
        interrupted_commit < interrupted_sigsegv,
        "ChildWon/SignalStale must win before a bad handler frame may force SIGSEGV",
    );
    assert!(interrupted_handler.contains("InterruptedWaitSignalCommit::ChildWon"));
    assert!(interrupted_handler.contains("InterruptedWaitSignalCommit::SignalStale"));

    let ordinary = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_on_return");
    let ordinary_handler = ordinary
        .find("Delivery::Handler { .. } => {")
        .expect("ordinary return delivery must retain an explicit caught-handler arm");
    let ordinary_handler = &ordinary[ordinary_handler..];
    let ordinary_commit = ordinary_handler.find("commit_prepared_delivery").expect(
        "ordinary bad handler state must revalidate/commit its exact PreparedSignal receipt",
    );
    let ordinary_sigsegv = ordinary_handler
        .find("terminate_bad_handler_frame")
        .expect("a still-current bad ordinary handler frame must terminate as forced SIGSEGV");
    assert!(
        ordinary_commit < ordinary_sigsegv,
        "a stale process-pending receipt must not kill this thread because frame preparation failed",
    );
}
