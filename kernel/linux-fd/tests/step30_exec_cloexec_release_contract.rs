// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const STEP29_FD_IO: &str = include_str!("../../core-aarch64/src/step29_fd_io.rs");

#[test]
fn live_exec_releases_every_object_returned_by_cloexec_commit() {
    assert!(
        STEP30_RUNTIME.contains("commit_close_on_exec"),
        "live exec must first consume the generation-bound CLOEXEC snapshot"
    );
    assert!(
        STEP30_RUNTIME.contains("ReleasedObject"),
        "CLOEXEC commit receipts are linear resource authority and must not be silently dropped"
    );
    assert!(
        STEP30_RUNTIME.contains("fd_pipe_overlay_parts"),
        "exec must release closed descriptor backing through the existing selected Process pipe/overlay owners"
    );
    for required in [
        "ReleasedObject::Pipe",
        "ReleasedObject::RetainedDirectory",
        "ReleasedObject::RetainedReadOnly",
        "ReleasedObject::WritableRegular",
        "pipes.close",
        "release_directory",
        "release_open",
        "release_retained_regular",
    ] {
        assert!(
            STEP30_RUNTIME.contains(required),
            "live exec CLOEXEC cleanup missing canonical release edge: {required}"
        );
    }
}

#[test]
fn exec_cloexec_release_matches_the_accepted_step29_release_owner_pattern() {
    for required in [
        "ReleasedObject::Pipe",
        "ReleasedObject::RetainedDirectory",
        "ReleasedObject::RetainedReadOnly",
        "ReleasedObject::WritableRegular",
        "pipes.close",
        "release_directory",
        "release_open",
        "release_retained_regular",
    ] {
        assert!(
            STEP29_FD_IO.contains(required),
            "Step29 accepted release template changed unexpectedly: {required}"
        );
    }
}
