// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 live-exec rollback contract.
//
// The accepted boot loader is intentionally fail-stop: after opaque loader failure it poisons the
// target binding and quarantines the allocated frame batch. Live exec cannot stop there before its
// point of no return, because the old image is still the current valid process image and a failed exec
// must leave it usable. The live staging wrapper therefore needs a discard-only cleanup edge for the
// fresh same-Process binding, including the case where the lower loader already poisoned staging.

const LOADER_FRAMES: &str = include_str!("../../core-aarch64/src/step15_loader_frames.rs");
const LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");
const PROCESS_ROOT: &str = include_str!("../../process-aarch64/src/lib.rs");
const EXEC_DISCARD: &str = include_str!("../../process-aarch64/src/exec_discard.rs");

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
fn boot_quarantine_policy_is_not_the_complete_live_exec_rollback_policy() {
    let boot = function_window_for_any(LOADER_FRAMES, &["load_initial_linux_elf_with_core_frames"]);
    assert!(
        boot.contains("LoaderFramesQuarantined") && boot.contains("space.poison()"),
        "the historical boot loader must remain explicitly fail-stop/quarantine on opaque loader failure"
    );
    assert!(
        LIVE_VM.contains("stage_exec_image"),
        "live exec must stage its fresh same-Process image through the dedicated live-VM wrapper"
    );
}

#[test]
fn discard_owner_is_compiled_and_can_drain_already_poisoned_staging() {
    assert!(
        PROCESS_ROOT.contains("mod exec_discard;"),
        "process-aarch64 must compile the discard-only exec staging owner"
    );
    assert!(
        EXEC_DISCARD.contains("discard_exec_staging_anonymous_user_frames"),
        "missing discard-only owner for a never-committed exec staging binding"
    );

    let discard = function_window_for_any(
        EXEC_DISCARD,
        &["discard_exec_staging_anonymous_user_frames"],
    );
    assert!(
        discard.contains("ProcessState::Live") || discard.contains("process.state()"),
        "exec staging discard must stay bound to a live Process generation"
    );
    assert!(
        discard.contains("active_space.current_owner(process)"),
        "the old current binding must prove exact current ownership before a different staging binding is drained"
    );
    assert!(
        discard.contains("binding_id") && discard.contains("address_space_object"),
        "discard must prove a distinct logical binding for the same exact AddressSpace object"
    );
    assert!(
        discard.contains("self.poison()") || discard.contains("self.poisoned = true"),
        "discard authority must monotonically quarantine the staging binding before destructive cleanup"
    );
    assert!(
        !discard.contains("if self.is_poisoned() {\n            return Err(Error::Poisoned)"),
        "discard-only cleanup must remain usable after the lower loader already poisoned staging"
    );
}

#[test]
fn live_exec_staging_discards_failed_fresh_image_and_returns_frames() {
    let stage = function_window_for_any(LIVE_VM, &["stage_exec_image"]);
    assert!(
        stage.contains("load_exec_linux_elf_with_core_frames")
            || stage.contains("load_initial_linux_elf_with_core_frames")
            || stage.contains("load_aarch64_linux_elf"),
        "live exec staging must still use the canonical ELF/Linux-stack loader owner"
    );
    assert!(
        stage.contains("discard_exec_staging_anonymous_user_frames"),
        "loader failure must re-enter the process-aarch64 discard owner rather than stopping at boot-style quarantine"
    );
    assert!(
        stage.contains("frame_pool")
            && (stage.contains("reclaim(") || stage.contains("free(") || stage.contains("release")),
        "discarded staging frames must return to the sole live frame-pool owner before failed exec returns"
    );
}

#[test]
fn side_effect_free_exec_preflight_precedes_fresh_root_allocation() {
    let stage = function_window_for_any(LIVE_VM, &["stage_exec_image"]);
    let preflight = [
        "preflight_exec_linux_image",
        "preflight_exec_linux_load",
        "plan_exec_linux_load",
        "plan_initial_linux_load",
    ]
    .into_iter()
    .filter_map(|marker| stage.find(marker))
    .min()
    .expect("live exec must run canonical side-effect-free ELF/stack preflight explicitly");
    let create = stage
        .find("BoundProcessAddressSpace::<")
        .or_else(|| stage.find("BoundProcessAddressSpace::create"))
        .expect("live exec must create a fresh replacement binding only after preflight");
    assert!(
        preflight < create,
        "malformed/preflight-rejected exec must consume zero RuntimeTablePool root pages"
    );
}
