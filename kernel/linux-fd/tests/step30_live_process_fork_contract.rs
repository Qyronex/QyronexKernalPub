// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP15_LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");
const STEP30_FORK: &str = include_str!("../../core-aarch64/src/step30_fork.rs");

fn clone_syscall_window() -> &'static str {
    let start = STEP15_QEMU
        .find("if request.number == 220")
        .expect("missing live clone(220) dispatch window");
    let tail = &STEP15_QEMU[start..];
    let end = tail
        .find("match step30_runtime::handle")
        .expect("missing boundary after live clone(220) dispatch window");
    &tail[..end]
}

fn process_fork_orchestration() -> &'static str {
    let start = STEP15_LIVE_VM
        .find("pub(super) unsafe fn fork_process")
        .expect("missing live private-fork orchestration helper");
    let tail = &STEP15_LIVE_VM[start..];
    let end = tail
        .find("/// Proves the bounded Step-30 exec precondition")
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn live_clone_dispatch_splits_process_fork_before_pthread_clone() {
    let clone = clone_syscall_window();
    let classifier = clone
        .find("ProcessClonePlan::validate")
        .expect("clone(220) must enter the canonical process-clone classifier first");
    let fork_kind = clone
        .find("ProcessCloneKind::Fork")
        .expect("live clone(220) must distinguish private process fork");
    let process_fork = clone
        .find("live_vm::fork_process")
        .expect("live clone(220) must route fork-shaped requests through the Step30 process-fork orchestration helper");
    let pthread = clone
        .find("dispatch_clone_with_core_stacks")
        .expect("accepted pthread clone dispatcher must remain present");
    assert!(
        classifier < fork_kind && fork_kind < process_fork && process_fork < pthread,
        "ProcessClonePlan::Fork must be classified and routed through the private-fork helper before the pthread-only ClonePlan dispatcher"
    );
}

#[test]
fn live_process_fork_returns_pid_only_after_final_scheduler_publication() {
    let fork = process_fork_orchestration();
    let staged = fork
        .find("step30_fork::stage_unpublished_fork_transaction")
        .expect("live fork helper must first create the reversible unpublished Process snapshot");
    let scheduler = fork
        .find("step30_fork::stage_fork_scheduler_generation")
        .expect("live fork helper must transfer the unpublished stack into one staged scheduler generation");
    let authority = fork
        .find("step30_fork::stage_fork_leader_authority")
        .expect("live fork helper must bind Process/Thread/TID authority before Ready publication");
    let published = fork
        .find("step30_fork::publish_staged_fork_leader")
        .expect("live fork helper must publish only after all reversible setup is complete");
    assert!(
        staged < scheduler && scheduler < authority && authority < published,
        "private-fork orchestration must preserve snapshot -> scheduler staging -> leader authority -> Ready+Published order"
    );

    let clone = clone_syscall_window();
    let helper = clone
        .find("live_vm::fork_process")
        .expect("missing private-fork orchestration call");
    let parent_x0 = clone[helper..]
        .find("frame.x[0] = u64::from(published.child_pid().get())")
        .map(|offset| offset + helper)
        .expect("parent x0 must be written only from the published fork receipt");
    assert!(helper < parent_x0);
    assert!(
        !clone[..helper].contains("frame.x[0] =") && !clone[..helper].contains("frame.x[0]="),
        "parent-visible x0 must not publish child identity before private-fork orchestration returns a PublishedForkLeaderReceipt"
    );
}

#[test]
fn process_fork_owner_uses_the_canonical_process_clone_classifier() {
    assert!(
        STEP30_FORK.contains("ProcessClonePlan"),
        "Step30 fork owner must use the canonical ProcessClonePlan classifier"
    );
    assert!(
        STEP30_FORK.contains("ProcessCloneKind::Fork"),
        "Step30 fork owner must reject non-fork process-clone kinds"
    );
    assert!(
        STEP30_FORK.contains("require_private_fork_plan"),
        "Step30 fork owner must preserve the private-fork policy boundary"
    );
    assert!(
        STEP30_FORK.contains("PublishedForkLeaderReceipt"),
        "Step30 fork owner must keep a distinct final publication receipt"
    );
}
