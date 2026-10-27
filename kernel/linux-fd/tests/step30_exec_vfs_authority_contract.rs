// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const QEMU_RUNTIME: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const EXEC_SOURCE: &str = include_str!("../../core-aarch64/src/step30_exec_source.rs");
const EXEC_INPUT: &str = include_str!("../../core-aarch64/src/step30_exec_input.rs");

fn compact_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn staged_exec_function() -> &'static str {
    let start = EXEC_INPUT
        .find("pub(super) unsafe fn stage_exec_image_with_core_frames")
        .expect("missing canonical staged exec helper");
    let tail = &EXEC_INPUT[start..];
    let end = tail.find("\nfn stage_one_vector").unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn live_exec_modules_are_compiled_only_as_part_of_the_real_runtime_path() {
    for module in ["step30_exec_source.rs", "step30_exec_input.rs"] {
        assert!(
            QEMU_RUNTIME.contains(module),
            "live Step-30 runtime must compile the accepted exec helper module: {module}"
        );
    }
}

#[test]
fn executable_selection_reenters_the_process_local_step29_vfs_owner() {
    let compact = compact_whitespace(EXEC_SOURCE);
    for required in [
        "select_exec_image_source",
        "step29_runtime::with_process",
        "runtime.overlay()",
        "runtime.fs_context()",
        "runtime.fds()",
        "ReadOnlyFile",
        "root_id",
    ] {
        assert!(
            compact.contains(required),
            "missing generation-qualified exec source authority: {required}"
        );
    }
    assert!(
        compact.contains("with_image_bytes"),
        "selected executable bytes must be exposed only through the generation-qualified source receipt"
    );
}

#[test]
fn argv_envp_are_owned_before_the_old_image_can_be_replaced() {
    for required in [
        "stage_exec_vectors",
        "ExecStringVector",
        "copy_from_user",
        "StagedExecVectors",
        "with_linux_start",
    ] {
        assert!(
            EXEC_INPUT.contains(required),
            "missing bounded exec input staging edge: {required}"
        );
    }
}

#[test]
fn staged_exec_owns_vfs_and_vectors_before_fresh_image_staging() {
    let staged = staged_exec_function();
    let vectors = staged
        .find("stage_exec_vectors")
        .expect("staged exec must own argv/envp while the old image is current");
    let source = staged.find("select_exec_image_source").expect(
        "staged exec must select the executable through the Step29 process-local VFS owner",
    );
    let image_bytes = staged
        .find("with_image_bytes")
        .expect("staged exec must re-enter the generation-qualified executable source receipt");
    let fresh_image = staged
        .find("super::live_vm::stage_exec_image")
        .expect("missing fresh AddressSpace image staging");

    assert!(
        vectors < fresh_image && source < fresh_image && image_bytes < fresh_image,
        "copied argv/envp, exact VFS source and image receipt must all precede fresh AddressSpace staging"
    );
}

#[test]
fn live_exec_composes_the_staged_helper_before_irreversible_owners() {
    let exec = STEP30_RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("missing live Execve arm");
    let tail = &STEP30_RUNTIME[exec..];

    let entropy = tail
        .find("with_exec_at_random")
        .expect("live exec must enter the canonical second AT_RANDOM transaction");
    let staged = tail
        .find("stage_exec_image_with_core_frames")
        .expect("live exec must invoke the bounded staged exec helper");
    let robust = tail
        .find("kernal_linux_clone_exit_aarch64::cleanup_robust_list(")
        .expect("live exec must use the canonical robust-list owner before root replacement");
    let replacement = tail
        .find("commit_exec_address_space_replacement")
        .expect("live exec must commit the staged AddressSpace replacement");

    assert!(
        entropy < staged && staged < robust && robust < replacement,
        "live exec order must be AT_RANDOM -> full typed staging -> robust cleanup -> AddressSpace replacement"
    );
    assert!(
        !STEP30_RUNTIME.contains("Archive::parse(") && !STEP30_RUNTIME.contains("ProtectedInitrd"),
        "Step30 runtime must not duplicate initramfs/CPIO authority outside the selected VFS receipt"
    );
}
