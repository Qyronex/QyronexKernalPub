// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const LIVE_SVC: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");

fn clone_220_block() -> &'static str {
    LIVE_SVC
        .split_once("if request.number == 220")
        .expect("live clone(220) dispatch block must exist")
        .1
        .split_once("match step30_runtime::handle")
        .expect("Step-30 runtime dispatch must follow clone(220)")
        .0
}

#[test]
fn process_fork_is_classified_before_pthread_dispatch_and_parent_pid_publication() {
    let clone = clone_220_block();
    let classify = clone
        .find("ProcessClonePlan::validate")
        .expect("process-family clone must be classified explicitly");
    let fork = clone
        .find("ProcessCloneKind::Fork")
        .expect("exact private fork kind must be handled");
    let route = clone
        .find("live_vm::fork_process(")
        .expect("fork must enter the canonical live owner transaction");
    let publish_parent = clone
        .find("frame.x[0] = u64::from(published.child_pid().get())")
        .expect("parent x0 must come from the final published fork receipt");
    let pthread = clone
        .find("dispatch_clone_with_core_stacks")
        .expect("existing pthread clone dispatcher must remain available");

    assert!(classify < fork);
    assert!(fork < route);
    assert!(route < publish_parent);
    assert!(publish_parent < pthread);
}

#[test]
fn malformed_process_family_arguments_fail_closed_before_pthread_fallback() {
    let clone = clone_220_block();
    let classify = clone
        .find("ProcessClonePlan::validate")
        .expect("process-family clone must be classified explicitly");
    let pthread = clone
        .find("dispatch_clone_with_core_stacks")
        .expect("pthread fallback must remain present");
    let classify_to_pthread = &clone[classify..pthread];

    assert!(
        !classify_to_pthread.contains("if let Ok(plan)"),
        "validation errors must not all collapse into pthread fallback"
    );
    assert!(
        classify_to_pthread.contains("kernal_linux_clone::Error::UnsupportedFlags"),
        "only a true non-process clone shape may continue to pthread classification"
    );
    assert!(
        classify_to_pthread.contains("Errno::EINVAL"),
        "malformed fork/vfork-shaped pointer or stack arguments must fail closed"
    );
}

#[test]
fn vfork_remains_explicitly_fail_closed_instead_of_falling_into_pthread_clone() {
    let clone = clone_220_block();
    let vfork = clone
        .find("ProcessCloneKind::Vfork")
        .expect("vfork must be recognized as a distinct process-family shape");
    let rejected = clone.find("vfork remains unsupported").expect(
        "vfork must remain explicitly unsupported until it has a shared-AS owner transaction",
    );
    let pthread = clone
        .find("dispatch_clone_with_core_stacks")
        .expect("pthread fallback must remain present");

    assert!(vfork < rejected);
    assert!(rejected < pthread);
}

#[test]
fn live_fork_wrapper_keeps_the_complete_owner_publication_chain() {
    for required in [
        "stage_unpublished_fork_transaction",
        "stage_fork_scheduler_generation",
        "stage_fork_leader_authority",
        "publish_staged_fork_leader",
    ] {
        assert!(
            LIVE_VM.contains(required),
            "live fork wrapper lost required owner stage: {required}"
        );
    }
}
