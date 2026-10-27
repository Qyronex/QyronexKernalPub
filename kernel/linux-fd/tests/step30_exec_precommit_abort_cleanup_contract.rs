// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 successful-staging transaction-boundary contract.
//
// All ordinary recoverable Exec work, including typed image staging, belongs to the reversible
// AT_RANDOM transaction. Once typed staging succeeds, entropy commits and every later owner edge is
// invariant/fail-stop-only. A second authority that discards a successfully staged image would reopen
// the old image after the commit boundary and is therefore forbidden.

const EXEC_INPUT: &str = include_str!("../../core-aarch64/src/step30_exec_input.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

#[test]
fn successful_typed_staging_is_the_last_recoverable_exec_boundary() {
    assert!(
        EXEC_INPUT.contains("stage_exec_image_with_core_frames"),
        "the canonical typed reversible staging owner must remain present"
    );
    assert!(
        EXEC_INPUT.contains("successful typed staging result is the AT_RANDOM")
            && EXEC_INPUT.contains("final ordinary recoverable exec failure boundary"),
        "the staging Safety contract must document successful typed staging as the entropy/errno boundary"
    );
    assert!(
        !EXEC_INPUT.contains("discard_prepared_exec_image"),
        "no second authority may discard an already-successful staged image after the AT_RANDOM commit boundary"
    );
}

#[test]
fn live_exec_next_red_crosses_from_staging_into_irreversible_owner_order() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist");
    let tail = &RUNTIME[exec..];
    let stage = tail
        .find("stage_exec_image_with_core_frames")
        .expect("live exec must complete typed reversible image staging");
    let robust = tail
        .find("cleanup_robust_list")
        .expect("robust owner-death cleanup must run on the old TTBR0 after staging commits");
    let swap = tail
        .find("commit_exec_address_space_replacement")
        .expect("successful exec must cross the retained AddressSpace point of no return");

    assert!(
        stage < robust && robust < swap,
        "successful staging must precede robust cleanup, which must precede root replacement"
    );
    assert!(
        !tail[stage..].contains("discard_prepared_exec_image"),
        "the irreversible live Exec tail must not reopen a successful staged-image abort path"
    );
}
