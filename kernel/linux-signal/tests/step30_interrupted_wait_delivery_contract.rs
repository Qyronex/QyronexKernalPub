// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

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

#[test]
fn interrupted_wait_handler_builds_before_linear_commit_and_applies_after_it() {
    let delivery = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_interrupted_wait");

    let build = delivery
        .find("prepare_handler_frame")
        .expect("handler frame must be fully prepared before the linear commit");
    let commit = delivery[build..]
        .find("commit_interrupted_wait_signal")
        .map(|offset| build + offset)
        .expect("prepared signal and exact wait interruption need one commit edge");
    let apply = delivery[commit..]
        .find(".apply(")
        .map(|offset| commit + offset)
        .expect("live exception frame may change only after the linear commit");
    let apply_tail = &delivery[apply..];

    assert!(build < commit);
    assert!(commit < apply);
    assert!(apply_tail.contains("&mut frame.x"));
    assert!(apply_tail.contains("&mut frame.sp_el0"));
    assert!(apply_tail.contains("&mut frame.elr_el1"));
    assert!(delivery.contains("InterruptedWaitSignalCommit::ChildWon"));
    assert!(delivery.contains("InterruptedWaitSignalCommit::SignalStale"));
    assert!(delivery.contains("InterruptedWaitDelivery::Reobserve"));
    assert!(delivery.contains("InterruptedWaitDelivery::SignalFrameCommitted"));
}

#[test]
fn resumed_delivery_is_reprepared_from_the_current_generation() {
    let delivery = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_interrupted_wait");

    assert!(delivery.contains("current_user_switch_generation"));
    assert!(delivery.contains("prepare_delivery_for_thread"));
    assert!(delivery.contains("InterruptedWaitContext::Restart"));
    assert!(delivery.contains("InterruptedWaitContext::ReturnEintr"));
    assert!(delivery.contains("SA_RESTART"));
}

#[test]
fn resumed_switch_generation_witness_is_sampled_inside_runtime_owner_for_prepare_and_commit() {
    for marker in [
        "pub(super) fn deliver_interrupted_wait",
        "pub(super) fn commit_interrupted_wait_signal",
    ] {
        let window = function_window(SIGNAL_DELIVERY, marker);
        let runtime = window
            .find("with_linux_runtime")
            .unwrap_or_else(|| panic!("{marker} must re-enter the sole Linux runtime owner"));
        let generation = window
            .find("current_user_switch_generation")
            .unwrap_or_else(|| panic!("{marker} must sample the resumed switch generation"));
        let owner = window
            .find("with_current_signal_delivery")
            .unwrap_or_else(|| {
                panic!("{marker} must consume the witness through the canonical signal owner")
            });

        assert!(
            runtime < generation,
            "{marker}: generation witness must be sampled after entering RuntimeCell ownership"
        );
        assert!(
            generation < owner,
            "{marker}: witness must be sampled before signal-owner validation"
        );
    }
}
