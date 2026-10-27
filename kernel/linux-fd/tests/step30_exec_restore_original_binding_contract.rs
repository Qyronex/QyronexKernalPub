// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");

fn stage_exec_window() -> &'static str {
    LIVE_VM
        .split_once("pub(super) unsafe fn stage_exec_image")
        .expect("missing live exec staging owner")
        .1
        .split_once("/// Core-side exec orchestration")
        .expect("missing end of live exec staging owner")
        .0
}

#[test]
fn exec_staging_restores_the_original_binding_before_success_or_recoverable_failure() {
    let stage = stage_exec_window();

    assert!(
        stage.contains("|process, active_space, objects|")
            || stage.contains("|process, old_space, objects|")
            || stage.contains("|process, original_space, objects|"),
        "exec staging must retain the exact original Process binding instead of discarding it as `_active_space`"
    );

    let load = [
        stage.find("load_initial_linux_elf_with_core_frames"),
        stage.find("load_exec_linux_elf_with_core_frames"),
        stage.find("load_exec_image_with_core_frames"),
    ]
    .into_iter()
    .flatten()
    .min()
    .expect("missing canonical exec image loader");

    let restore = [
        stage.find("active_space.activate_owner"),
        stage.find("old_space.activate_owner"),
        stage.find("original_space.activate_owner"),
        stage.find("restore_exec_active_binding"),
        stage.find("reactivate_exec_original_binding"),
        stage.find("restore_original_exec_binding"),
    ]
    .into_iter()
    .flatten()
    .min()
    .expect("exec staging must explicitly restore/prove the original binding current");

    let success = stage
        .find("Ok(StagedExecImage")
        .expect("missing successful staged-image publication");
    let discard = stage
        .find("discard_exec_staging_anonymous_user_frames")
        .expect("failed fresh exec staging must drain through the canonical discard owner");

    assert!(
        load < restore && restore < success,
        "the original retained binding must be current again before a successfully staged replacement is returned to the exec commit owner"
    );
    assert!(
        restore < discard,
        "the original binding must be current before the staging discard owner may reclaim a failed replacement"
    );
}
