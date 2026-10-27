// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const SIGNAL_OWNER: &str = include_str!("../src/lib.rs");
const CHILD_EXIT_OWNER: &str =
    include_str!("../../core-aarch64/src/step30_child_exit_runtime_owner.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const AARCH64_SIGINFO: &str = include_str!("../../../abi/linux-aarch64/src/signal_siginfo.rs");

#[test]
fn canonical_pending_signal_retains_child_exit_provenance_until_delivery() {
    assert!(
        SIGNAL_OWNER.contains("Child(ChildSignalProvenance)")
            && SIGNAL_OWNER.contains("struct PendingSignal")
            && SIGNAL_OWNER.contains("provenance: SignalProvenance"),
        "SIGCHLD child PID/UID/status must live in the canonical pending-signal receipt, not a Core sidecar"
    );
    assert!(
        CHILD_EXIT_OWNER.contains("queue_signal_with_provenance"),
        "child exit must queue SIGCHLD with its exact child provenance instead of a provenance-free kernel signal"
    );
    assert!(
        !CHILD_EXIT_OWNER.contains("signals.queue_signal(parent, sigchld)"),
        "plain kernel SIGCHLD queueing loses CLD_* / si_pid / si_uid / si_status"
    );
}

#[test]
fn aarch64_handler_frame_encodes_truthful_child_siginfo_from_prepared_receipt() {
    for required in [
        "CLD_EXITED",
        "CLD_KILLED",
        "CLD_DUMPED",
        "child_exited",
        "child_signaled",
    ] {
        assert!(
            AARCH64_SIGINFO.contains(required),
            "missing AArch64 child siginfo encoder contract: {required}"
        );
    }

    assert!(
        SIGNAL_DELIVERY.contains("SignalProvenance::Child") || SIGNAL_DELIVERY.contains("Child {"),
        "prepared SIGCHLD delivery must distinguish child provenance"
    );
    assert!(
        SIGNAL_DELIVERY.contains("SenderSignalSiginfo::child_exited")
            || SIGNAL_DELIVERY.contains("SenderSignalSiginfo::child_signaled"),
        "handler frame must encode child provenance with the dedicated CLD_* siginfo helper"
    );
}
