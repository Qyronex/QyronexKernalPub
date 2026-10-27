// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 successful-exec robust-futex ordering contract.
//
// The registered robust-list head points into the old userspace image. Successful exec must therefore
// finish every ordinary reversible staging step first, observe the exact current generation's robust
// metadata, complete the canonical owner-death walk while the old TTBR0 is still current, and only
// then cross the irreversible AddressSpace replacement boundary. The scheduler's generation-bound
// exec-state commit consumes the same observed head after the root swap and clears stale metadata/TLS.

const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const SCHEDULER_EXEC: &str = include_str!("../../scheduler-cpu/src/exit_split.rs");
const ROBUST_OWNER: &str = include_str!("../../linux-clone-exit-aarch64/src/lib.rs");

#[test]
fn scheduler_exec_metadata_owner_is_generation_bound_and_receipt_checked() {
    assert!(
        SCHEDULER_EXEC.contains("bootstrap_current_exec_robust_list_head")
            && SCHEDULER_EXEC.contains("pending_robust_list_head"),
        "exec must observe robust metadata through the exact current scheduler generation"
    );
    assert!(
        SCHEDULER_EXEC.contains("bootstrap_commit_current_exec_user_state")
            && SCHEDULER_EXEC.contains("expected_robust_head")
            && SCHEDULER_EXEC.contains("commit_published_exec_user_state"),
        "post-swap exec metadata commit must consume the exact robust-head observation instead of clearing blindly"
    );
}

#[test]
fn exec_reuses_the_canonical_robust_owner_death_walker() {
    assert!(
        ROBUST_OWNER.contains("pub unsafe fn cleanup_robust_list"),
        "the accepted bounded robust-futex cleanup owner must remain the sole userspace walk implementation"
    );
    assert!(
        ROBUST_OWNER.contains("ROBUST_LIST_LIMIT")
            && ROBUST_OWNER.contains("FUTEX_OWNER_DIED")
            && ROBUST_OWNER.contains("ROBUST_FUTEX_WAKE_COUNT"),
        "exec must reuse the bounded owner-death + canonical futex wake policy rather than duplicate it in Core"
    );
}

#[test]
fn live_exec_finishes_robust_user_memory_cleanup_before_root_replacement() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist");
    let tail = &RUNTIME[exec..];

    let staged = tail
        .find("stage_exec_image")
        .expect("exec must fully stage the replacement image before final precommit cleanup");
    let observe = tail
        .find("bootstrap_current_exec_robust_list_head")
        .expect("exec must observe the exact current generation's robust head");
    let cleanup = tail
        .find("cleanup_robust_list")
        .expect("exec must run canonical robust owner-death cleanup while old userspace is active");
    let replacement = tail
        .find("commit_exec_address_space_replacement")
        .expect("exec must commit the retained AddressSpace replacement");
    let metadata_commit = tail
        .find("bootstrap_commit_current_exec_user_state")
        .expect(
            "exec must consume/reset the old generation's userspace metadata after root commit",
        );

    assert!(
        staged < observe && observe < cleanup && cleanup < replacement,
        "robust-list user memory may be touched only after reversible image staging and before the irreversible root swap"
    );
    assert!(
        replacement < metadata_commit,
        "the scheduler metadata/TLS reset belongs to the committed new image, after replacement activation"
    );
    assert!(
        !tail[replacement..].contains("cleanup_robust_list"),
        "no old robust-list userspace walk is permitted after the new TTBR0 becomes authoritative"
    );
}
