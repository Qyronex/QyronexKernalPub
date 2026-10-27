// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 structural oracle for the process-local Step29 path/FD view handoff during fork.
// It owns no runtime authority; it only pins ordering across the existing canonical owners.

const FORK: &str = include_str!("../../core-aarch64/src/step30_fork.rs");
const PATH_RUNTIME: &str = include_str!("../../core-aarch64/src/step29_runtime.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = body
        .find("\n///")
        .map(|offset| marker.len() + offset)
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn step29_owner_forks_shared_ofd_and_process_local_fs_context() {
    let fork = function_window(PATH_RUNTIME, "fn fork_process(&self");
    assert!(fork.contains("fds.fork_view(parent_binding.view)"));
    assert!(fork.contains("FsContext::new(INITRAMFS_ROOT_ID)"));
    assert!(fork.contains("replace_umask(parent_umask)"));
    assert!(fork.contains("set_context_cwd(&mut child_context"));
    assert!(fork.contains("process: child"));
}

#[test]
fn unpublished_fork_binds_step29_view_only_after_process_slot_installation() {
    let stage = function_window(
        FORK,
        "pub(super) unsafe fn stage_unpublished_fork_transaction",
    );
    let install = stage
        .find("runtime.install_additional_process(child, child_space)")
        .expect("child Process/AddressSpace slot must be installed first");
    let parent = stage
        .find("with_fork_snapshot_parent(current")
        .expect("parent must be reselected through exact runtime authority");
    let fork_view = stage
        .find("super::step29_runtime::fork_process(parent_process, child_process)")
        .expect("Step29 process-local path/FD view must be inherited");
    let receipt = stage
        .find("Ok(UnpublishedForkReceipt")
        .expect("receipt must escape only after all process-local owners are staged");
    assert!(install < parent);
    assert!(parent < fork_view);
    assert!(fork_view < receipt);
}

#[test]
fn failed_step29_fork_cannot_leave_unpublished_process_authority_behind() {
    let stage = function_window(
        FORK,
        "pub(super) unsafe fn stage_unpublished_fork_transaction",
    );
    let failure = stage
        .find("if path_bound.is_err()")
        .expect("Step29 fork failure needs a canonical rollback branch");
    let tail = &stage[failure..];
    let cancel_wait = tail
        .find("cancel_unpublished_fork_child_wait(wait_publication)")
        .expect("rollback must remove the unpublished Wait token");
    let take_child = tail
        .find("take_unpublished_additional_process(runtime_slot, child_process)")
        .expect("rollback must recover the exact Process/AddressSpace slot");
    let abort = tail
        .find("abort_completed_fork_staging")
        .expect("rollback must reuse the canonical snapshot/identity cleanup transaction");
    assert!(cancel_wait < take_child);
    assert!(take_child < abort);
}

#[test]
fn later_unpublished_rollback_retires_step29_view_before_identity_retirement() {
    let rollback = function_window(
        FORK,
        "pub(super) unsafe fn rollback_unpublished_fork_transaction",
    );
    let retire_path = rollback
        .find("super::step29_runtime::retire_process(child_process)")
        .expect("successful staged fork must retire its Step29 view on rollback");
    let take_process = rollback
        .find("take_unpublished_additional_process(runtime_slot, child_process)")
        .expect("exact retained Process slot must still be recovered");
    let retire_identity = rollback
        .find("retire_unpublished_fork_child_identity(&mut child)")
        .expect("Linux identity retirement remains the final child authority edge");
    assert!(retire_path < take_process);
    assert!(take_process < retire_identity);
}

#[test]
fn fork_module_does_not_duplicate_fd_or_filesystem_state() {
    assert!(!FORK.contains("FdTable<"));
    assert!(!FORK.contains("FdTableSet<"));
    assert!(!FORK.contains("FsContext {"));
    assert!(!FORK.contains("OpenFileSlot"));
}
