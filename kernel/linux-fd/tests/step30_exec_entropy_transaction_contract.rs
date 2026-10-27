// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 live-exec entropy transaction contract.
//
// The initial image consumes grant 0 once. Live exec owns grant 1 through the reversible
// `with_exec_at_random` transaction so a Linux-visible failure during pathname/argv/env/ELF staging
// cannot permanently consume the process's only replacement-image AT_RANDOM payload.

const ENTROPY: &str = include_str!("../../core-aarch64/src/step15_entropy.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

#[test]
fn entropy_owner_retains_the_exec_grant_across_reversible_staging_failure() {
    let transaction = ENTROPY
        .find("pub fn with_exec_at_random")
        .expect("missing reversible live-exec AT_RANDOM owner");
    let tail = &ENTROPY[transaction..];

    assert!(
        tail.contains("with_second_transaction(operation)"),
        "live exec must reuse the second-grant transaction instead of inventing another entropy owner"
    );
    assert!(
        ENTROPY.contains("self.state.store(SECOND_READY, Ordering::Release)")
            && ENTROPY.contains("self.state.store(EXHAUSTED, Ordering::Release)"),
        "failed staging must republish the exact second grant while successful staging consumes it"
    );
}

#[test]
fn live_exec_stages_the_replacement_inside_the_reversible_entropy_transaction() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist");
    let tail = &RUNTIME[exec..];

    let entropy = tail
        .find("with_exec_at_random")
        .expect("live exec must borrow the reversible second AT_RANDOM grant");
    let staging = tail
        .find("stage_exec_image")
        .expect("live exec must stage the complete replacement image before commit");
    let replacement = tail
        .find("commit_exec_address_space_replacement")
        .expect("live exec must eventually commit the staged replacement binding");

    assert!(
        entropy < staging && staging < replacement,
        "AT_RANDOM must cover reversible image staging and finish before the irreversible root swap"
    );
    assert!(
        !tail[..replacement].contains("take_at_random"),
        "live exec must not irreversibly consume the second grant before replacement staging succeeds"
    );
}
