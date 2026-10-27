// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Structural Step-30.7 contract for the already-implemented exec commit owners. This test does not
// claim that execve/execveat dispatch is complete; it prevents the irreversible commit chain from
// regressing while the final VFS/image-staging composition is still being wired.

const ABI: &str = include_str!("../../../abi/linux/src/lib.rs");
const LINUX_STACK: &str = include_str!("../../user-elf/src/linux_stack.rs");
const STEP29_FD: &str = include_str!("../../core-aarch64/src/step29_fd.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
const THREAD_CONTEXT: &str = include_str!("../../thread-context/src/lib.rs");
const CPU_EXIT_SPLIT: &str = include_str!("../../scheduler-cpu/src/exit_split.rs");
const SIGNAL_OWNER: &str = include_str!("../../linux-signal/src/lib.rs");
const IDENTITY_OWNER: &str = include_str!("../../linux-identity/src/lib.rs");

#[test]
fn exec_errno_and_stack_limits_have_one_canonical_owner() {
    assert!(ABI.contains("pub const E2BIG: Self = Self(7);"));
    assert!(ABI.contains("pub const ENOEXEC: Self = Self(8);"));

    for required in [
        "pub const MAX_ARGV0_BYTES: usize = 127;",
        "pub const MAX_ARGC: usize = 16;",
        "pub const MAX_ENVC: usize = 16;",
        "pub const MAX_STRING_BYTES: usize = 2048;",
    ] {
        assert!(
            LINUX_STACK.contains(required),
            "exec must reuse the canonical Linux initial-stack limit: {required}"
        );
    }
}

#[test]
fn execveat_empty_path_requires_the_explicit_step29_usercopy_edge() {
    assert!(STEP29_FD.contains("fn copy_user_path_allow_empty("));
    assert!(STEP29_FD.contains("copy_user_path_with_allow_empty(user_path, allow_empty"));
    assert!(STEP29_FD.contains("if index == 0 && !allow_empty"));
    assert!(
        STEP29_FD.contains("Err(Error::Linux(Errno::ENOENT))"),
        "ordinary empty path must stay ENOENT while AT_EMPTY_PATH opts in explicitly"
    );
}

#[test]
fn address_space_swap_is_generation_selected_and_linear_after_activation() {
    let marker = "fn commit_exec_address_space_replacement";
    let start = RUNTIME
        .find(marker)
        .expect("missing retained Process/address-space exec swap owner");
    let tail = &RUNTIME[start..];
    let end = tail
        .find("// Additional Step-30 child-exit composition")
        .unwrap_or(tail.len());
    let swap = &tail[..end];

    for required in [
        "process_object_for_scheduler_thread(current)",
        "bound_tid_for_scheduler_thread(selected, current)",
        "current_owner(selected)",
        "replacement.activate_owner",
        "core::mem::replace",
    ] {
        assert!(
            swap.contains(required),
            "missing exec swap invariant: {required}"
        );
    }
    assert!(
        swap.find("replacement.activate_owner").unwrap() < swap.find("core::mem::replace").unwrap(),
        "hardware/logical activation must precede the immediate retained-binding swap"
    );
}

#[test]
fn thread_exec_reset_is_atomic_in_the_context_owner_and_scheduler_bridge() {
    let marker = "pub fn commit_published_exec_user_state";
    let start = THREAD_CONTEXT
        .find(marker)
        .expect("missing atomic ContextTable exec-user-state reset");
    let tail = &THREAD_CONTEXT[start..];
    for required in [
        "expected_robust_head",
        "pending_robust_list_head = None",
        "pending_clear_child_tid = None",
        "user_thread_pointer = 0",
    ] {
        assert!(
            tail.contains(required),
            "missing ContextTable exec reset: {required}"
        );
    }

    assert!(CPU_EXIT_SPLIT.contains("bootstrap_current_exec_robust_list_head"));
    assert!(CPU_EXIT_SPLIT.contains("bootstrap_commit_current_exec_user_state"));
    assert!(CPU_EXIT_SPLIT.contains("commit_published_exec_user_state"));
    assert!(CPU_EXIT_SPLIT.contains("install_el0_thread_pointer(0)"));
}

#[test]
fn process_exec_commit_reuses_signal_and_identity_owners() {
    assert!(
        SIGNAL_OWNER.contains("pub fn reset_caught_handlers_for_exec"),
        "successful exec must reset caught handlers without replacing SignalTable"
    );
    assert!(
        IDENTITY_OWNER.contains("pub fn mark_execed"),
        "successful exec must publish did_exec in the canonical LinuxIdentity ProcessRecord"
    );
}
