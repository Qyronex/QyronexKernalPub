// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Step-30.7 regression contract for blocking pipe reads interrupted by a handled signal.
//!
//! The blocking owner has three distinct resume outcomes. In particular,
//! `SignalFrameCommitted` means one handler frame already owns this kernel-to-user return and the
//! ordinary lower-EL return signal hook must not run again with the original pre-block entry witness.

const STEP29_FD: &str = include_str!("../../core-aarch64/src/step29_fd.rs");
const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");

#[test]
fn blocking_pipe_restart_and_committed_signal_frame_must_remain_distinct() {
    let collapsed = "super::futex::pipe_blocking::BlockingReadOutcome::Restarted\n                    | super::futex::pipe_blocking::BlockingReadOutcome::SignalFrameCommitted";
    assert!(
        !STEP29_FD.contains(collapsed),
        "Step29 must not collapse Restarted and SignalFrameCommitted into the same plain handled result"
    );
}

#[test]
fn step29_fd_must_expose_a_typed_committed_signal_frame_outcome() {
    let typed_owner = STEP29_FD.contains("enum HandleOutcome")
        || STEP29_FD.contains("enum DispatchOutcome")
        || STEP29_FD.contains("enum Outcome");
    assert!(
        typed_owner && STEP29_FD.contains("SignalFrameCommitted"),
        "Step29 FD dispatch needs a typed SignalFrameCommitted result instead of bool-only ownership"
    );
}

#[test]
fn step15_dispatch_must_receive_the_step29_committed_frame_outcome() {
    let typed_match = STEP15_QEMU.contains("step29_fd::HandleOutcome::SignalFrameCommitted")
        || STEP15_QEMU.contains("step29_fd::DispatchOutcome::SignalFrameCommitted")
        || STEP15_QEMU.contains("step29_fd::Outcome::SignalFrameCommitted");
    assert!(
        typed_match,
        "Step15 must receive Step29 SignalFrameCommitted explicitly so it can suppress the ordinary return hook"
    );
}

#[test]
fn outer_return_path_keeps_the_existing_committed_frame_suppression_contract() {
    assert!(
        STEP15_QEMU.contains("if signal_frame_committed")
            && STEP15_QEMU.contains("deliver_step30_signal_on_return(frame)"),
        "the regression oracle depends on the existing one-frame-per-return suppression boundary"
    );
}
