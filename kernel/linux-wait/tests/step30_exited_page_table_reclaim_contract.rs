// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 regression oracle for the repeated-fork Gate-5 failure. A destructively reaped
// Process must return not only anonymous data frames but also its now-unreachable TTBR0 page-table
// hierarchy to the canonical live Backend owner. Otherwise the bounded RuntimeTablePool is consumed
// monotonically by successful fork/reap cycles.

const EXIT_RECLAIM: &str = include_str!("../../process-aarch64/src/exec_discard.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
const AUTO_REAP: &str = include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");
const ADDRESS_SPACE_AARCH64: &str = include_str!("../../address-space-aarch64/src/lib.rs");
const PAGE_TABLE_AARCH64: &str = include_str!("../../page-table-aarch64/src/implementation.rs");

fn function_window<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing start marker: {start_marker}"));
    let tail = &source[start..];
    let end = tail
        .find(end_marker)
        .unwrap_or_else(|| panic!("missing end marker after {start_marker}: {end_marker}"));
    &tail[..end]
}

#[test]
fn exited_process_reclaim_returns_empty_ttbr0_tree_after_leaf_frames_are_drained() {
    let reclaim = function_window(
        EXIT_RECLAIM,
        "pub unsafe fn reclaim_exited_empty_page_table_tree",
        "\n    }\n}",
    );
    assert!(reclaim.contains("ProcessState::Exited"));
    assert!(reclaim.contains("self.space.vmas().get(0).is_some()"));
    assert!(reclaim.contains("self.poisoned = true"));
    assert!(reclaim.contains("reclaim_empty_page_table_tree"));

    let wait_reap = function_window(
        RUNTIME,
        "pub(super) fn commit_wait_reap_reclaiming_frames",
        "\n}\n\nimpl Step15LinuxRuntime",
    );
    let leaf_drain = wait_reap
        .find("reclaim_exited_anonymous_user_frames")
        .expect("wait reap must drain the exact exited child's data frames");
    let tree_reclaim = wait_reap
        .find("reclaim_exited_empty_page_table_tree")
        .expect("wait reap must return the exited child's empty TTBR0 hierarchy");
    let destructive_wait = wait_reap
        .find("commit_wait_reap_for_scheduler_thread")
        .expect("wait reap must retain the canonical destructive WaitTable commit");

    assert!(
        leaf_drain < tree_reclaim,
        "empty TTBR0 reclamation must happen only after all user leaves/data frames are drained"
    );
    assert!(
        tree_reclaim < destructive_wait,
        "table pages must be returned while the exact zombie Process/AddressSpace owner is retained"
    );
}

#[test]
fn auto_reap_returns_empty_ttbr0_tree_before_wait_and_slot_destruction() {
    let auto_reap = function_window(
        AUTO_REAP,
        "pub(super) fn commit_process_auto_reap_reclaiming_frames",
        "/// Observes one child status",
    );
    let leaf_drain = auto_reap
        .find("reclaim_exited_anonymous_user_frames")
        .expect("auto-reap must drain the exited child's data frames");
    let tree_reclaim = auto_reap
        .find("reclaim_exited_empty_page_table_tree")
        .expect("auto-reap must return the exited child's empty TTBR0 hierarchy");
    let wait_remove = auto_reap
        .find("auto_reap_exit_with_wakes")
        .expect("auto-reap must retain the canonical WaitTable removal");
    let slot_remove = auto_reap
        .rfind(".take()")
        .expect("auto-reap must release the exact retained runtime slot");

    assert!(leaf_drain < tree_reclaim);
    assert!(tree_reclaim < wait_remove);
    assert!(wait_remove < slot_remove);
}

#[test]
fn terminal_address_space_reclaim_reaches_backend_release_for_children_and_root() {
    let address_space = function_window(
        ADDRESS_SPACE_AARCH64,
        "unsafe fn reclaim_empty_page_table_tree<B: Backend>(",
        "fn validate_mapping",
    );
    assert!(
        address_space.contains("reclaim_empty_tree"),
        "address-space terminal reclaim must delegate to the canonical page-table owner"
    );

    let mapper = function_window(
        PAGE_TABLE_AARCH64,
        "pub unsafe fn reclaim_empty_tree(&mut self)",
        "fn ensure_leaf_table_inner",
    );
    let verify = mapper
        .find("verify_empty_tree")
        .expect("tree reclaim must verify emptiness before release");
    let children = mapper
        .find("reclaim_empty_children")
        .expect("tree reclaim must release detached child tables");
    let root = mapper
        .find("release_table(self.root)")
        .expect("tree reclaim must release the root table itself");

    assert!(verify < children && children < root);
}
