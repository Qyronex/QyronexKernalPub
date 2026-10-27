// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

#[test]
fn exec_selects_replacement_binding_before_irreversible_process_commits() {
    let exec = STEP30_RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("missing live Execve arm");
    let tail = &STEP30_RUNTIME[exec..];

    let staged = [
        tail.find("stage_exec_image"),
        tail.find("load_exec_linux_elf_with_core_frames"),
        tail.find("stage_exec_linux_elf_with_core_frames"),
        tail.find("load_exec_image_with_core_frames"),
        tail.find("stage_exec_image_with_core_frames"),
        tail.find("load_initial_linux_elf_with_core_frames"),
        tail.find("load_aarch64_linux_elf"),
        tail.find("load_exec_image"),
    ]
    .into_iter()
    .flatten()
    .min()
    .expect("missing replacement image staging");
    let replacement = tail
        .find("commit_exec_address_space_replacement")
        .expect("missing exact retained Process/address-space replacement commit");
    let cloexec = tail
        .find("commit_close_on_exec")
        .expect("missing selected-view CLOEXEC commit");
    let signal_reset = tail
        .find("reset_caught_handlers_for_exec")
        .expect("missing canonical SignalTable exec reset");
    let thread_reset = tail
        .find("bootstrap_commit_current_exec_user_state")
        .expect("missing canonical current-thread exec reset");
    let mark_execed = tail
        .find("mark_execed")
        .expect("missing canonical Linux identity exec marker");

    assert!(
        staged < replacement,
        "the fresh AddressSpace must be fully staged before the active Process binding is switched"
    );
    assert!(
        replacement < cloexec
            && replacement < signal_reset
            && replacement < thread_reset
            && replacement < mark_execed,
        "CLOEXEC, signal reset, thread/TLS reset and did_exec are irreversible and must not commit before replacement activation succeeds"
    );
}
