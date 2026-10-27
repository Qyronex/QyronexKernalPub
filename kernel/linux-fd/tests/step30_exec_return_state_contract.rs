// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const LOADER: &str = include_str!("../../core-aarch64/src/step15_loader_frames.rs");
const CONTEXT_OWNER: &str = include_str!("../../thread-context/src/lib.rs");
const CPU_CONTEXT_BRIDGE: &str = include_str!("../../scheduler-cpu/src/exit_split.rs");

#[test]
fn successful_exec_returns_to_the_loaded_entry_and_initial_stack_with_fresh_registers() {
    assert!(LOADER.contains("pub struct LoadedInitialLinuxImage"));
    assert!(LOADER.contains("pub loaded: LoadedImage"));

    let exec = STEP30_RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("missing live Execve dispatch");
    let tail = &STEP30_RUNTIME[exec..];

    assert!(
        tail.contains(".entry") && tail.contains(".initial_sp"),
        "successful exec must derive EL0 PC and SP from the newly loaded image"
    );
    assert!(
        tail.contains("frame.elr_el1") || tail.contains("El0ReturnState::new"),
        "exec must install a new architectural return PC rather than resume the syscall PC"
    );
    assert!(
        tail.contains("frame.sp_el0") || tail.contains("El0ReturnState::new"),
        "exec must install the new Linux initial stack pointer"
    );
    assert!(
        tail.contains("frame.x = [0; 31]")
            || tail.contains("frame.x.fill(0)")
            || tail.contains("reset_exec_exception_frame")
            || tail.contains("install_exec_return_frame"),
        "old general-purpose user registers must not leak into the replacement image"
    );
}

#[test]
fn successful_exec_resets_thread_owned_linux_user_state_and_live_tls() {
    for required in [
        "commit_published_exec_user_state",
        "pending_robust_list_head = None",
        "pending_clear_child_tid = None",
        "user_thread_pointer = 0",
    ] {
        assert!(
            CONTEXT_OWNER.contains(required),
            "missing canonical thread-context exec reset edge: {required}"
        );
    }
    assert!(
        CPU_CONTEXT_BRIDGE.contains("bootstrap_commit_current_exec_user_state")
            && CPU_CONTEXT_BRIDGE.contains("install_el0_thread_pointer(0)"),
        "the owner-PE exec bridge must commit context reset and clear TPIDR_EL0"
    );
    assert!(
        STEP30_RUNTIME.contains("bootstrap_commit_current_exec_user_state"),
        "live exec must consume the canonical current-thread exec reset bridge before returning to EL0"
    );
}

#[test]
fn successful_exec_resets_caught_signal_handlers_before_new_image_return() {
    let exec = STEP30_RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("missing live Execve dispatch");
    let tail = &STEP30_RUNTIME[exec..];

    assert!(
        tail.contains("reset_caught_handlers_for_exec"),
        "successful exec must consume the canonical SignalTable exec reset so caught handlers do not leak into the replacement image"
    );
}
