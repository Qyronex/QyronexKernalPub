// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const RUNTIME_OWNER: &str =
    include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");
const CORE_FINALIZER: &str = include_str!("../../core-aarch64/src/step30_child_exit.rs");
const QEMU_RUNTIME: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const WAIT_OWNER: &str = include_str!("../../linux-wait/src/lib.rs");

#[test]
fn sigchld_exit_policy_reenters_canonical_parent_and_signal_owners() {
    for required in [
        "process_object_for_pid(parent_pid)",
        "kernal_linux_signal::Disposition::Ignore",
        "kernal_linux_signal::SA_NOCLDWAIT",
        "cause: kernal_linux_exit_lifecycle::ExitCause",
        "queue_signal_with_provenance",
        "kernal_linux_signal::SignalProvenance::Child",
        "publish_process_exit_wait_status(process_id, status)",
    ] {
        assert!(
            RUNTIME_OWNER.contains(required),
            "missing SIGCHLD owner invariant: {required}"
        );
    }
    assert!(
        !RUNTIME_OWNER.contains("signals.queue_signal(parent, sigchld)"),
        "caught SIGCHLD must retain truthful child provenance instead of generic SI_KERNEL"
    );
}

#[test]
fn auto_reap_keeps_resource_owner_order_and_wait_owner_authority() {
    let auto_reap_start = CORE_FINALIZER
        .find("ProcessExitWaitDisposition::AutoReap(process_id) => {")
        .expect("missing AutoReap finalizer arm");
    let auto_reap = &CORE_FINALIZER[auto_reap_start..];
    let page_tables = auto_reap
        .find("RuntimeTablePool::with_live")
        .expect("missing live page-table owner in AutoReap arm");
    let frame_pool = auto_reap
        .find("memory::with_live_frame_pool")
        .expect("missing live frame-pool owner in AutoReap arm");
    let runtime = auto_reap
        .find("runtime::with_linux_runtime")
        .expect("missing destructive runtime owner in AutoReap arm");
    assert!(page_tables < frame_pool && frame_pool < runtime);

    assert!(RUNTIME_OWNER.contains("commit_process_auto_reap_reclaiming_frames"));
    assert!(RUNTIME_OWNER.contains("reclaim_exited_anonymous_user_frames"));
    assert!(WAIT_OWNER.contains("auto_reap_exit_with_wakes"));
    assert!(WAIT_OWNER.contains("self.children[publication.slot] = None"));
}

#[test]
fn every_process_exit_resume_path_uses_one_shared_sigchld_finalizer() {
    assert_eq!(
        QEMU_RUNTIME
            .matches("step30_child_exit::complete_process_exit_wait_after_lifecycle")
            .count(),
        1,
        "the shared pending-exit finalizer must be the sole direct Wait/SIGCHLD publication edge"
    );
    assert!(
        QEMU_RUNTIME.contains("&& finalize_step30_pending_exit_after_resume(current_cpu).is_err()"),
        "FUTEX_WAIT resume must delegate to the shared pending-exit finalizer instead of duplicating reap/publication logic"
    );
    assert_eq!(
        QEMU_RUNTIME
            .matches("publish_process_exit_completion_wait(process_id, &completion)")
            .count(),
        0,
        "QEMU finalizers must not bypass the SIGCHLD/auto-reap policy wrapper"
    );
}
