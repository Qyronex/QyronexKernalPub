// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const CORE_SVC: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const FUTEX_TRAP: &str = include_str!("../../linux-futex-trap-aarch64/src/lib.rs");

#[test]
fn live_futex_wait_uses_signal_aware_dispatch_and_reuses_canonical_signal_delivery() {
    for required in [
        "dispatch_private_futex_raw_with_destination_address_space_signal_aware",
        "DispatchOutcome::SignalInterrupted",
        "deliver_interrupted_futex",
        "InterruptedFutexDelivery::SignalFrameCommitted",
    ] {
        assert!(
            CORE_SVC.contains(required),
            "missing live FUTEX_WAIT signal-composition edge: {required}"
        );
    }

    assert!(
        SIGNAL_DELIVERY.contains("pub(super) fn deliver_interrupted_futex"),
        "Core must reuse the canonical signal delivery transaction for interrupted FUTEX_WAIT"
    );
    assert!(
        SIGNAL_DELIVERY.contains("interruption_pending_after_resume")
            && SIGNAL_DELIVERY.contains("consume_interrupted_after_signal"),
        "the signal transaction must prove the retained futex marker and consume it only after policy resolution"
    );
    assert!(
        FUTEX_TRAP.contains("DispatchOutcome::SignalInterrupted")
            || FUTEX_TRAP.contains("SignalInterrupted(GlobalThreadId)"),
        "the futex trap owner must retain and return exact signal interruption authority"
    );

    let delivery_start = SIGNAL_DELIVERY
        .find("pub(super) fn deliver_interrupted_futex")
        .expect("missing canonical interrupted-futex delivery entry");
    let delivery = &SIGNAL_DELIVERY[delivery_start..];
    let commit = delivery
        .find("commit_prepared_current_signal(")
        .expect("live interrupted-futex delivery must commit canonical signal policy");
    let consume = delivery
        .find("consume_interrupted_futex_marker_after_signal_commit(")
        .expect("live interrupted-futex delivery must consume the exact marker after commit");
    assert!(
        commit < consume,
        "the retained FUTEX_WAIT marker must be consumed only after canonical signal policy has a commit edge"
    );
}

#[test]
fn committed_futex_handler_frame_suppresses_the_second_return_hook_delivery() {
    assert!(
        CORE_SVC.contains("InterruptedFutexDelivery::SignalFrameCommitted")
            && CORE_SVC.contains("*signal_frame_committed = true"),
        "an interrupted futex handler frame must cross the same no-second-signal return boundary as interrupted wait"
    );
}
