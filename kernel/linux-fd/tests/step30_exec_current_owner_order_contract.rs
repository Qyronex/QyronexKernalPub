// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const STEP15_RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime.rs");
const STEP15_INTEGRATED: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");

fn function_body<'a>(source: &'a str, signature: &str, next_signature: &str) -> &'a str {
    let start = source.find(signature).expect("missing function signature");
    let tail = &source[start..];
    let end = tail.find(next_signature).unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn live_exec_reuses_existing_exact_current_owner_instead_of_inventing_identity_authority() {
    assert!(
        !STEP15_INTEGRATED.contains("prepare_current_exec_identity"),
        "Step30 must not add a second exec identity-selection owner"
    );

    let exec = function_body(
        STEP30_RUNTIME,
        "fn handle_live_exec",
        "fn prepare_exec_cloexec",
    );
    let single_thread = exec
        .find("exact_current_is_only_bound_process_thread(current)")
        .expect("live exec must prove the existing bounded single-thread condition");
    let entropy = exec
        .find("with_exec_at_random")
        .expect("missing canonical AT_RANDOM transaction");
    let process_parts = exec
        .find("process_parts_for_scheduler_thread(current)")
        .expect("successful staging must re-observe the canonical Process/TID owner");

    assert!(
        single_thread < entropy && entropy < process_parts,
        "exact-current single-thread proof must precede reversible staging; Process/TID re-observation belongs after successful staging"
    );
}

#[test]
fn live_exec_validates_return_state_before_irreversible_precommit_owners() {
    let exec = function_body(
        STEP30_RUNTIME,
        "fn handle_live_exec",
        "fn prepare_exec_cloexec",
    );
    let return_state = exec
        .find("El0ReturnState::new")
        .expect("missing canonical EL0 return-state validation");
    let cloexec = exec
        .find("prepare_exec_cloexec")
        .expect("missing exact-process CLOEXEC preparation");
    let robust = exec
        .find("bootstrap_current_exec_robust_list_head")
        .expect("missing robust-list observation");
    let replacement = exec
        .find("commit_exec_address_space_replacement")
        .expect("missing AddressSpace replacement commit");

    assert!(
        return_state < cloexec && cloexec < robust && robust < replacement,
        "EL0 return-state validation and fallible owner preparation must finish before the irreversible root swap"
    );
}

#[test]
fn irreversible_exec_commit_order_matches_the_canonical_owner_handoff() {
    let exec = function_body(
        STEP30_RUNTIME,
        "fn handle_live_exec",
        "fn prepare_exec_cloexec",
    );

    let root = exec
        .find("commit_exec_address_space_replacement")
        .expect("missing root replacement");
    let rebind = exec
        .find("rebind_entry_switch_generation")
        .expect("missing ExceptionFrame generation rebind");
    let brk = exec
        .find("replace_process_break_for_exec")
        .expect("missing atomic process break replacement");
    let cloexec = exec
        .find("commit_exec_cloexec")
        .expect("missing CLOEXEC commit");
    let signals = exec
        .find("commit_exec_signal_reset")
        .expect("missing signal reset");
    let user_state = exec
        .find("bootstrap_commit_current_exec_user_state")
        .expect("missing scheduler exec user-state reset");
    let identity = exec
        .find("commit_exec_identity_marker")
        .expect("missing canonical mark_execed owner");
    let registers = exec
        .find("frame.x.fill(0)")
        .expect("missing fresh register image");
    let reclaim = exec
        .find("reclaim_exec_superseded")
        .expect("missing superseded-image reclaim");
    let committed = exec
        .find("Outcome::FrameCommitted")
        .expect("missing committed frame outcome");

    assert!(
        root < rebind
            && rebind < brk
            && brk < cloexec
            && cloexec < signals
            && signals < user_state
            && user_state < identity
            && identity < registers
            && registers < reclaim
            && reclaim < committed,
        "irreversible exec owners must remain strictly ordered after the root swap"
    );
}

#[test]
fn superseded_exec_reclaim_uses_the_exec_owner_bridge_not_the_fork_selector() {
    let reclaim = function_body(
        STEP30_RUNTIME,
        "fn reclaim_exec_superseded",
        "fn exec_fail_closed",
    );
    assert!(
        reclaim.contains("with_exec_current_owner"),
        "post-swap reclaim must re-enter the exact-current Exec owner"
    );
    assert!(
        !reclaim.contains("with_fork_snapshot_parent"),
        "fork-only selector must not own post-swap Exec reclaim"
    );

    assert!(
        STEP15_RUNTIME.contains("fn with_exec_current_owner"),
        "canonical exact-current Exec owner bridge must remain the single authority"
    );
}
