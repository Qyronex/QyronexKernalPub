// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 live-exec errno boundary.
//
// The canonical loader already preserves its exact semantic failure until every staging frame has
// been returned. Core must not erase that cause to `()` before the syscall owner can classify a
// recoverable pre-commit failure. Normal Linux errno mapping ends at the replacement-root commit;
// after that point any unexpected failure is internal/fail-stop rather than rollback or errno.

const LOADER_FRAMES: &str = include_str!("../../core-aarch64/src/step15_loader_frames.rs");
const LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn function_window_for_any<'a>(source: &'a str, needles: &[&str]) -> &'a str {
    let marker = needles
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
        .expect("missing function marker");
    let prefix = &source[..marker];
    let start = [
        "\npub(super) unsafe fn ",
        "\npub(super) fn ",
        "\n    pub unsafe fn ",
        "\n    pub fn ",
        "\nunsafe fn ",
        "\nfn ",
        "\n    unsafe fn ",
        "\n    fn ",
    ]
    .into_iter()
    .filter_map(|boundary| prefix.rfind(boundary))
    .max()
    .map(|offset| offset + 1)
    .unwrap_or(marker);
    let tail = &source[start..];
    let end = [
        "\npub(super) unsafe fn ",
        "\npub(super) fn ",
        "\n    pub unsafe fn ",
        "\n    pub fn ",
        "\nunsafe fn ",
        "\nfn ",
        "\n    unsafe fn ",
        "\n    fn ",
    ]
    .into_iter()
    .filter_map(|boundary| tail[1..].find(boundary).map(|offset| offset + 1))
    .min()
    .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn canonical_loader_retains_the_semantic_failure_until_frame_reclaim_completes() {
    assert!(
        LOADER_FRAMES.contains("struct ExecLoadFailure")
            && LOADER_FRAMES.contains("error: Error")
            && LOADER_FRAMES.contains("fn reclaim_remaining"),
        "the loader must retain one exact semantic error alongside the linear staging-frame journal"
    );
    let reclaim = function_window_for_any(LOADER_FRAMES, &["fn reclaim_remaining"]);
    let returns_original_error = reclaim.contains("Ok(self.error)")
        || (reclaim.contains("let Self { error") && reclaim.contains("Ok(error)"));
    assert!(
        returns_original_error,
        "the original loader cause must be returned only after the remaining frame journal is empty"
    );
}

#[test]
fn live_staging_must_not_erase_the_recovered_loader_cause_to_unit() {
    let stage = function_window_for_any(LIVE_VM, &["stage_exec_image"]);
    assert!(
        stage.contains("reclaim_remaining"),
        "live exec staging must recover the canonical loader cause after exact rollback"
    );
    assert!(
        !stage.contains("let _semantic_error") && !stage.contains("Result<StagedExecImage, ()>"),
        "stage_exec_image must preserve a typed pre-commit failure; discarding the cause or returning only () loses ENOEXEC/ENOMEM truth"
    );
    assert!(
        LIVE_VM.contains("ExecStageError::Linux(Errno::ENOEXEC)")
            && LIVE_VM.contains("ExecStageError::Linux(Errno::ENOMEM)"),
        "the live-VM staging owner must retain the concrete recoverable ELF/resource errno classification"
    );
}

#[test]
fn exec_errno_classification_occurs_before_the_irreversible_root_swap() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist before errno ordering can be accepted");
    let tail = &RUNTIME[exec..];
    let swap = tail
        .find("commit_exec_address_space_replacement")
        .expect("live exec must use the generation-safe retained AddressSpace replacement owner");
    let precommit = &tail[..swap];

    assert!(
        precommit.contains("stage_exec_image_with_core_frames"),
        "the syscall owner must enter the canonical reversible exec preparation boundary before root replacement"
    );

    let typed_linux_boundary = if precommit.contains("ReversibleExecError") {
        precommit.contains("ExecInputError::Linux")
            && precommit.contains("ExecSourceError::Linux")
            && precommit.contains("ExecStageError::Linux")
    } else {
        precommit.contains("ExecInputError::Linux")
    };
    assert!(
        typed_linux_boundary && precommit.contains("SyscallReturn::error"),
        "typed recoverable preparation errno must pass through unchanged while the old image is still current"
    );

    let typed_invariant_boundary = if precommit.contains("ReversibleExecError") {
        precommit.contains("ReversibleExecError::Invariant")
            || precommit.contains("ExecInputError::Invariant")
            || precommit.contains("ExecSourceError::Invariant")
            || precommit.contains("ExecStageError::Invariant")
    } else {
        precommit.contains("ExecInputError::Invariant") || precommit.contains("Invariant")
    };
    assert!(
        typed_invariant_boundary,
        "reversible preparation invariants must remain distinct from Linux-visible errno"
    );
}
