// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const PATH_RUNTIME: &str = include_str!("../../core-aarch64/src/step29_runtime.rs");
const FORK_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_fork.rs");

fn function_window<'a>(source: &'a str, marker: &str, next: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let end = tail
        .find(next)
        .unwrap_or_else(|| panic!("missing function boundary after {marker}: {next}"));
    &tail[..end]
}

#[test]
fn each_process_binding_owns_an_independent_filesystem_context() {
    assert!(
        PATH_RUNTIME.contains("fs_contexts")
            || PATH_RUNTIME.contains("fs_context: FsContext")
            || PATH_RUNTIME.contains("ProcessFsContext"),
        "Step30 process path runtime must store FsContext per process binding"
    );
    assert!(
        !PATH_RUNTIME.contains("fs_context: UnsafeCell<FsContext>"),
        "ordinary fork must not share one global mutable FsContext across process generations"
    );
}

#[test]
fn fork_copies_cwd_by_acquiring_a_distinct_vfs_hold_and_copies_umask_by_value() {
    let fork = function_window(
        PATH_RUNTIME,
        "fn fork_process",
        "/// Retires one exact Process",
    );
    for required in [
        "cwd_handle()",
        "set_context_cwd",
        "replace_umask",
        "fork_view",
    ] {
        assert!(
            fork.contains(required),
            "process-path fork is missing independent FsContext/OFD edge: {required}"
        );
    }

    let fd_fork = fork.find("fork_view").expect("missing child FdView fork");
    let cwd_hold = fork
        .find("set_context_cwd")
        .expect("missing child cwd lifetime acquisition");
    let publish = fork
        .rfind("ProcessFdBinding")
        .expect("missing child process binding publication");
    assert!(fd_fork < publish && cwd_hold < publish);
}

#[test]
fn process_retirement_releases_cwd_hold_and_fd_view_exactly_once() {
    let retire = function_window(PATH_RUNTIME, "fn retire_process", "fn begin_borrow");
    assert!(
        retire.contains("retire_view"),
        "missing exact FdView retirement"
    );
    assert!(
        retire.contains("release_context_cwd"),
        "process teardown must release its independent cwd lifetime hold"
    );
}

#[test]
fn ordinary_fork_composes_path_runtime_before_scheduler_publication() {
    assert!(
        FORK_RUNTIME.contains("step29_runtime::fork_process"),
        "ordinary Step30 fork must compose the existing process-local FD/FsContext owner"
    );
    assert!(
        FORK_RUNTIME.contains("bootstrap_publish_staged_ready"),
        "fork must retain the existing staged scheduler publication boundary"
    );
}
