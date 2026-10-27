// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 structural contract for the live exec image transaction. The accepted linux-exec owner
// already pins CLOEXEC generation safety; this oracle prevents final integration from satisfying that
// descriptor contract while still returning ENOSYS or changing descriptors before a replacement
// AArch64 image is completely staged.

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const PROCESS_AARCH64: &str = include_str!("../../process-aarch64/src/activation.rs");

fn contains_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| source.contains(needle))
}

fn method_window_for_any<'a>(source: &'a str, needles: &[&str]) -> &'a str {
    let marker = needles
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
        .expect("missing method marker");
    let start = source[..marker]
        .rfind("\n    pub ")
        .map(|offset| offset + 1)
        .unwrap_or(marker);
    let tail = &source[start..];
    let end = tail[1..]
        .find("\n    pub ")
        .map(|offset| offset + 1)
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn exec_preparation_modules_are_part_of_the_live_qemu_core_graph() {
    assert!(
        STEP15_QEMU.contains("#[path = \"step30_exec_input.rs\"]")
            && STEP15_QEMU.contains("mod step30_exec_input;"),
        "bounded user argv/envp/path preparation must be compiled into the live AArch64 Core"
    );
    assert!(
        STEP15_QEMU.contains("#[path = \"step30_exec_source.rs\"]")
            && STEP15_QEMU.contains("mod step30_exec_source;"),
        "generation-safe immutable executable source selection must be compiled into the live AArch64 Core"
    );
}

#[test]
fn live_exec_stages_a_fresh_bound_address_space_before_fd_commit() {
    assert!(STEP30_RUNTIME.contains("Step30RuntimeCall::Execve"));
    assert!(STEP30_RUNTIME.contains("Step30RuntimeCall::Execveat"));
    assert!(
        contains_any(
            STEP30_RUNTIME,
            &[
                "BoundProcessAddressSpace::create",
                "stage_exec_address_space",
                "prepare_exec_image",
                "stage_exec_image"
            ]
        ),
        "exec must stage a fresh same-Process AArch64 binding instead of overwriting the active image in place"
    );
    assert!(
        contains_any(
            STEP30_RUNTIME,
            &[
                "stage_exec_image",
                "load_initial_linux_elf_with_core_frames",
                "load_aarch64_linux_elf",
                "load_exec_image"
            ]
        ),
        "exec must enter the canonical AArch64 ELF/image staging owner before committing CLOEXEC"
    );
}

#[test]
fn successful_image_replacement_consumes_cloexec_and_marks_exec_after_staging() {
    let exec = STEP30_RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("missing live exec dispatch");
    let tail = &STEP30_RUNTIME[exec..];
    let staged = [
        tail.find("stage_exec_image"),
        tail.find("load_initial_linux_elf_with_core_frames"),
        tail.find("load_aarch64_linux_elf"),
        tail.find("load_exec_image"),
    ]
    .into_iter()
    .flatten()
    .min()
    .expect("missing exec image staging");
    let cloexec = tail
        .find("commit_close_on_exec")
        .expect("missing selected-view CLOEXEC commit");
    let mark_execed = tail
        .find("mark_execed")
        .expect("missing canonical Linux identity exec marker");
    assert!(
        staged < cloexec && staged < mark_execed,
        "no descriptor/identity exec commit may occur before the replacement image is ready"
    );
}

#[test]
fn superseded_live_process_binding_has_a_narrow_inactive_reclaim_or_quarantine_edge() {
    const CLEANUP_NAMES: [&str; 5] = [
        "reclaim_superseded",
        "reclaim_inactive",
        "reclaim_replaced",
        "quarantine_superseded",
        "quarantine_inactive",
    ];
    assert!(
        contains_any(PROCESS_AARCH64, &CLEANUP_NAMES),
        "exec needs a live-Process inactive-binding cleanup edge; reclaim_exited_anonymous_user_frames cannot be reused for a still-live Process"
    );

    let cleanup = method_window_for_any(PROCESS_AARCH64, &CLEANUP_NAMES);
    assert!(
        cleanup.contains("ProcessState::Live"),
        "superseded-binding cleanup must reject a non-live Process generation"
    );
    assert!(
        cleanup.contains("self.owner_process") || cleanup.contains("authorize_owner"),
        "superseded-binding cleanup must stay bound to the exact Process ObjectId"
    );
    assert!(
        cleanup.contains("self.address_space_object") || cleanup.contains("authorize_owner"),
        "superseded-binding cleanup must stay bound to the exact AddressSpace ObjectId"
    );
    assert!(
        cleanup.contains("unsafe fn")
            || cleanup.contains("activation::current_read")
            || cleanup.contains("current_owner(")
            || cleanup.contains("current_user_ttbr0"),
        "a live-Process cleanup edge must prove the superseded binding inactive or require an explicit unsafe quiescence contract"
    );
    if cleanup.contains("quarantine") {
        assert!(
            cleanup.contains("poison"),
            "a quarantine edge must monotonically poison the superseded binding"
        );
    }
}

#[test]
fn exec_reenters_the_existing_process_local_path_and_fd_owner() {
    assert!(
        STEP30_RUNTIME.contains("step29_runtime::with_process")
            || STEP30_RUNTIME.contains("super::step29_runtime::with_process"),
        "exec pathname/OFD/CLOEXEC work must stay inside the existing Process-selected Step29 owner"
    );
    assert!(STEP30_RUNTIME.contains("ExecCommitHandoff::prepare"));
}
