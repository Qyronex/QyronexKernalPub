// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const FORK: &str = include_str!("../../core-aarch64/src/step30_fork.rs");
const EXIT_OWNER: &str = include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");

fn compact(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn fork_inherits_break_before_the_child_can_be_published() {
    let source = compact(FORK);
    let bind = source
        .find("runtime.bind_unpublished_fork_child_identity(current,&child)")
        .expect("fork must bind the exact child Linux identity");
    let inherit = source
        .find("inherit_unpublished_fork_break(runtime,current,&child)")
        .expect("fork must inherit the exact parent program break");
    let install = source
        .find("runtime.install_additional_process(child,child_space)")
        .expect("fork must retain the child before scheduler publication");

    assert!(bind < inherit);
    assert!(inherit < install);
    assert!(source.contains("vm.inherit_process_break(parent_process,child_process)"));
}

#[test]
fn every_reversible_fork_cleanup_releases_the_child_break_slot() {
    let source = compact(FORK);
    let rollback = source
        .find("fnrollback_unpublished_fork_transaction")
        .expect("missing canonical unpublished fork rollback");
    let rollback_tail = &source[rollback..];
    assert!(rollback_tail.contains("retire_unpublished_fork_break(runtime,child_process)?"));

    let abort = source
        .find("fnabort_completed_fork_staging")
        .expect("missing completed fork staging abort");
    let abort_tail = &source[abort..];
    assert!(abort_tail.contains("retire_unpublished_fork_break(runtime,child.id())"));
}

#[test]
fn exited_children_release_break_state_for_zombie_and_auto_reap_paths() {
    let source = compact(EXIT_OWNER);
    assert!(source.contains("fnretire_exited_process_break"));
    assert!(source.contains("self.vm.remove_process_break(process_id)"));
    assert!(source.contains("Err(kernal_linux_vm::Error::MissingBreakState)=>Ok(())"));

    let auto_reap = source
        .find("ifauto_reap{")
        .expect("missing auto-reap branch");
    let auto_tail = &source[auto_reap..];
    let auto_retire = auto_tail
        .find("self.retire_exited_process_break(process_id)?")
        .expect("auto-reap must release the exited child break slot");
    let auto_return = auto_tail
        .find("ProcessExitWaitDisposition::AutoReap(process_id)")
        .expect("missing auto-reap disposition");
    assert!(auto_retire < auto_return);

    let zombie_publish = source
        .find("self.publish_process_exit_wait_status(process_id,status)?")
        .expect("missing zombie Wait publication");
    let zombie_tail = &source[zombie_publish..];
    let zombie_retire = zombie_tail
        .find("self.retire_exited_process_break(process_id)?")
        .expect("zombie publication must release the exited child break slot");
    let zombie_return = zombie_tail
        .find("ProcessExitWaitDisposition::ZombiePublished(wakes)")
        .expect("missing zombie disposition");
    assert!(zombie_retire < zombie_return);
}
