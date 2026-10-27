// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const PATH_FD: &str = include_str!("../../core-aarch64/src/step29_fd.rs");
const PIPE_BLOCKING: &str = include_str!("../../core-aarch64/src/step30_pipe_blocking.rs");
const PIPE_IO: &str = include_str!("../../core-aarch64/src/step29_pipe_io.rs");

#[test]
fn blocking_pipe_read_hands_off_to_scheduler_owner() {
    assert!(
        PATH_FD.contains("pipe_blocking::block_read"),
        "PathFd read(2) must hand BlockingWaitRequired to the Step-30 scheduler owner"
    );
    assert!(
        PATH_FD.contains("BlockingReadOutcome::Retry"),
        "normal pipe readiness must retry the canonical FD/Pipe read transaction"
    );
    assert!(
        PATH_FD.contains("BlockingReadOutcome::Restarted")
            && PATH_FD.contains("BlockingReadOutcome::SignalFrameCommitted"),
        "signal-owned wakeups must return through the existing restart/signal-frame path"
    );
}

#[test]
fn blocking_boundary_is_not_collapsed_into_invariant() {
    assert!(PIPE_IO.contains("BlockingWaitRequired"));
    assert!(
        !PATH_FD.contains(
            "super::step29_pipe_io::Error::BlockingWaitRequired\n        | super::step29_pipe_io::Error::Invariant => Error::Invariant"
        ),
        "BlockingWaitRequired is a scheduler handoff, not an invariant failure"
    );
}

#[test]
fn wake_helpers_remain_post_commit_and_generation_exact() {
    assert!(PIPE_BLOCKING.contains("pub(crate) fn notify_after_write(pipe: PipeId)"));
    assert!(PIPE_BLOCKING.contains("pub(crate) fn notify_after_writer_close(pipe: PipeId)"));
    assert!(PIPE_BLOCKING.contains("fn wake_exact(target: GlobalThreadId)"));
}
