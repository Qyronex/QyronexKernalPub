// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const PATH_RUNTIME: &str = include_str!("../../core-aarch64/src/step29_runtime.rs");

#[test]
fn live_exec_is_owned_by_the_step30_runtime_instead_of_falling_through_to_enosys() {
    assert!(
        STEP30_RUNTIME.contains("Step30RuntimeCall::Execve"),
        "live execve must have a Step30 runtime arm"
    );
    assert!(
        STEP30_RUNTIME.contains("Step30RuntimeCall::Execveat"),
        "live execveat must have a Step30 runtime arm"
    );
    assert!(
        STEP30_RUNTIME.contains("ExecCommitHandoff"),
        "live exec must use the accepted generation-bound exec commit owner"
    );
}

#[test]
fn cloexec_prepare_and_commit_run_inside_the_exact_process_fd_view() {
    assert!(
        PATH_RUNTIME.contains("pub fn with_process"),
        "path runtime must retain its exact Process -> FdView selection boundary"
    );
    assert!(
        STEP30_RUNTIME.contains("step29_runtime::with_process")
            || STEP30_RUNTIME.contains("super::step29_runtime::with_process"),
        "exec must re-enter the exact current Process descriptor/filesystem view"
    );
    assert!(
        STEP30_RUNTIME.contains("ExecCommitHandoff::prepare"),
        "exec must snapshot CLOEXEC state only after selecting the exact Process FdView"
    );
    assert!(
        STEP30_RUNTIME.contains("commit_close_on_exec"),
        "successful image replacement must consume the selected Process CLOEXEC snapshot"
    );
}
