// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 host-safe structural oracle for the private-FUTEX signal-resume transaction. The
// canonical futex owner retains Interrupted until Core has revalidated canonical SignalTable policy;
// this test pins ordering only and introduces no runtime owner or scheduler behavior.

const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const FUTEX_BRIDGE: &str = include_str!("../../core-aarch64/src/step15_futex.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let top_level = body.find("\n///");
    let nested = body.find("\n    ///");
    let end = match (top_level, nested) {
        (Some(left), Some(right)) => marker.len() + core::cmp::min(left, right),
        (Some(offset), None) | (None, Some(offset)) => marker.len() + offset,
        (None, None) => tail.len(),
    };
    &tail[..end]
}

#[test]
fn resumed_futex_proves_retained_marker_before_signal_revalidation() {
    let delivery = function_window(SIGNAL_DELIVERY, "fn deliver_interrupted_futex");
    let prove = delivery
        .find("prove_interrupted_futex_marker(current)")
        .expect("resume must prove the exact retained futex marker first");
    let prepare = delivery
        .find("prepare_delivery_for_thread")
        .expect("resume must revalidate canonical SignalTable delivery");
    assert!(prove < prepare);
    assert!(
        !delivery[..prepare].contains("consume_interrupted_after_signal"),
        "the futex marker must remain retained while SignalTable is prepared"
    );
}

#[test]
fn retry_resolution_consumes_exact_marker_before_rewinding_svc() {
    let retry = function_window(
        SIGNAL_DELIVERY,
        "fn restart_interrupted_futex_after_retry_resolution",
    );
    let consume = retry
        .find("consume_interrupted_futex_marker_for_retry(current)")
        .expect("retry must retire the exact retained interruption claim");
    let restart = retry
        .find("restart_interrupted_futex(frame)")
        .expect("retry must rewind only after marker retirement");
    assert!(consume < restart);

    let delivery = function_window(SIGNAL_DELIVERY, "fn deliver_interrupted_futex");
    assert!(delivery.contains("let Some(prepared) = prepared else"));
    assert!(delivery.contains("restart_interrupted_futex_after_retry_resolution(frame, current)"));
    assert!(delivery.contains("SignalError::PreparedDeliveryStale"));
}

#[test]
fn committed_signal_consumes_marker_only_through_fail_closed_post_commit_edge() {
    let consume = function_window(
        SIGNAL_DELIVERY,
        "fn consume_interrupted_futex_marker_after_signal_commit",
    );
    assert!(consume.contains("super::futex::consume_interrupted_after_signal(current)"));
    assert!(consume.contains("Ok(true)"));
    assert!(consume.contains("fail_closed_after_signal_commit"));

    let restart = function_window(
        SIGNAL_DELIVERY,
        "fn restart_interrupted_futex_after_signal_commit",
    );
    let marker = restart
        .find("consume_interrupted_futex_marker_after_signal_commit")
        .expect("post-commit retry must consume the marker");
    let rewind = restart
        .find("restart_interrupted_futex(frame)")
        .expect("post-commit retry must rewind only after marker consumption");
    assert!(marker < rewind);
}

#[test]
fn handler_and_fatal_paths_do_not_apply_effect_before_marker_resolution() {
    let delivery = function_window(SIGNAL_DELIVERY, "fn deliver_interrupted_futex");
    assert!(delivery.contains("commit_prepared_current_signal"));
    assert!(delivery.contains("consume_interrupted_futex_marker_after_signal_commit"));

    let handler_consume = delivery
        .rfind("consume_interrupted_futex_marker_after_signal_commit")
        .expect("handler commit must resolve the futex marker");
    let handler_apply = delivery
        .rfind("prepared_frame.entry.apply")
        .expect("handler frame must be applied only after the transaction commits");
    assert!(handler_consume < handler_apply);

    let fatal = delivery
        .find("super::exit::handle_fatal_signal")
        .expect("fatal default signal must use the canonical lifecycle owner");
    let consume_before_fatal = delivery[..fatal]
        .rfind("consume_interrupted_futex_marker_after_signal_commit")
        .expect("fatal signal commit must resolve the retained futex marker before exit");
    assert!(consume_before_fatal < fatal);
}

#[test]
fn core_futex_bridge_exposes_observe_then_consume_without_signal_shadow_state() {
    let observe = function_window(FUTEX_BRIDGE, "fn interruption_pending_after_resume");
    assert!(observe.contains("futexes().interruption_pending(target)"));
    assert!(!observe.contains("SignalTable"));

    let consume = function_window(FUTEX_BRIDGE, "fn consume_interrupted_after_signal");
    assert!(consume.contains("futexes().consume_interrupted(target)"));
    assert!(!consume.contains("SignalTable"));
    assert!(!consume.contains("bootstrap_wake_local_exact"));
    assert!(!consume.contains("remote_wake"));
}
