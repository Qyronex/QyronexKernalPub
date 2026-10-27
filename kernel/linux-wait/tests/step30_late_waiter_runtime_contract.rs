// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 regression oracle for the late-waiter exit-publication race. This is authority-free:
// it only checks that canonical Core uses the wake-aware WaitTable edge, routes exact generations
// after the runtime borrow ends, and cannot strand a consumed waiter behind fallible stack reclaim.

const WAIT: &str = include_str!("../src/lib.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const CHILD_EXIT: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");

fn pending_exit_finalizer() -> &'static str {
    let start = QEMU
        .find("pub(super) fn finalize_step30_pending_exit_after_resume")
        .expect("Step-30 pending-exit finalizer must remain present");
    let tail = &QEMU[start..];
    let end = tail.find("\nfn step15_svc_serial").unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn final_zombie_publication_uses_the_wake_aware_wait_owner_edge() {
    assert!(WAIT.contains("pub fn publish_exit_with_wakes"));
    assert!(
        RUNTIME.contains("publish_exit_with_wakes"),
        "late committed waiters must be consumed atomically with zombie publication"
    );
    assert!(
        !RUNTIME.contains("wait.publish_exit(publication"),
        "compatibility publish_exit rejects a matching late waiter with WaiterWakeRequired"
    );
}

#[test]
fn late_wait_generations_are_routed_only_after_the_runtime_borrow_ends() {
    let finalizer = pending_exit_finalizer();
    let completion = finalizer
        .find("step30_child_exit::complete_process_exit_wait_after_lifecycle")
        .expect(
            "pending-exit finalizer must enter the canonical child-exit Wait composition helper",
        );
    let wake = finalizer.find("wake_wait_exit_batch").expect(
        "late exact Wait generations must still be routed after child-exit composition returns",
    );
    assert!(
        completion < wake,
        "scheduler wake routing must remain outside and after the child-exit Runtime owner transaction"
    );

    let helper_start = CHILD_EXIT
        .find("pub(super) fn complete_process_exit_wait_after_lifecycle")
        .expect("missing canonical post-lifecycle child-exit Wait helper");
    let helper = &CHILD_EXIT[helper_start..];
    assert!(
        helper.contains("runtime::with_linux_runtime(|state|")
            && helper.contains("prepare_process_exit_wait_plan(process_id, completion, cause)"),
        "Wait publication policy must remain inside the canonical LinuxRuntime owner borrow with neutral Completion + ExitCause evidence"
    );
    assert!(
        helper.contains("ProcessExitWaitDisposition::ZombiePublished(wakes) => Ok(Some(wakes))"),
        "the helper must return only the exact wake batch by value after the Runtime borrow ends"
    );
}

#[test]
fn consumed_waiters_are_woken_before_fallible_stack_reclaim() {
    let finalizer = pending_exit_finalizer();
    let wake = finalizer
        .find("wake_wait_exit_batch(current_cpu, scheduler, wakes)")
        .expect("late wait wake routing must remain present");
    let reclaim = finalizer
        .find("reclaim_reaped_clone_core_stack(retired_stack)")
        .expect("retired clone stack reclaim must remain present");
    assert!(
        wake < reclaim,
        "a waiter consumed by zombie publication must be delivered before fallible stack reclaim"
    );
}
