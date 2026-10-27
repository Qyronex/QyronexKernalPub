// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Regression contract for the Step-30 SA_RESTART pipe-read return owner.
//!
//! The final filesystem adapter must not pre-claim read(2): the canonical Step-29 FD owner is the
//! only path that can preserve the typed `SignalFrameCommitted` outcome all the way to Step15.

const OPENAT2_OPS: &str = include_str!("../../core-aarch64/src/step29_final_fs/openat2_ops.rs");
const STEP29_FD: &str = include_str!("../../core-aarch64/src/step29_fd.rs");

#[test]
fn final_fs_adapter_must_not_intercept_blocking_pipe_read() {
    assert!(
        !OPENAT2_OPS.contains("pipe_blocking::block_read"),
        "final_fs/openat2_ops must not pre-claim blocking read(2); doing so collapses the typed committed-frame outcome"
    );
}

#[test]
fn canonical_step29_read_owner_keeps_committed_frame_typed() {
    assert!(
        STEP29_FD.contains("PathFdCall::Read")
            && STEP29_FD.contains("return handle_read(process, fd, user_buffer, count, frame)")
            && STEP29_FD.contains("BlockingReadOutcome::SignalFrameCommitted")
            && STEP29_FD.contains("HandleOutcome::SignalFrameCommitted"),
        "Step29 read dispatch must remain the canonical typed owner for committed signal frames"
    );
}

#[test]
fn restarted_and_committed_frame_outcomes_remain_distinct() {
    let collapsed = "BlockingReadOutcome::Restarted\n                    | super::futex::pipe_blocking::BlockingReadOutcome::SignalFrameCommitted";
    assert!(
        !STEP29_FD.contains(collapsed),
        "Restarted and SignalFrameCommitted must never collapse into one plain handled outcome"
    );
}
