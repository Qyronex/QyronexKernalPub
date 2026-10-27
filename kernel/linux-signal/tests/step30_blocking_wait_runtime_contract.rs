// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const SYSCALL_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const LINUX_RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = ["\nfn ", "\npub(super) fn ", "\npub(crate) fn ", "\npub fn "]
        .into_iter()
        .filter_map(|next| body.find(next).map(|offset| marker.len() + offset))
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn blocking_wait_commit_preserves_the_canonical_signal_interruption_state() {
    let blocking = function_window(SYSCALL_RUNTIME, "fn block_until_wait_ready");

    assert!(blocking.contains("commit_wait_sleep_signal_aware"));
    assert!(blocking.contains("WaitSignalCommitOutcome::Interrupted"));
    assert!(!blocking.contains("state.commit_wait_sleep(&receipt)"));
}

#[test]
fn interrupted_wait_receiver_uses_the_atomic_signal_delivery_transaction() {
    assert!(
        SYSCALL_RUNTIME.contains("signal_delivery::deliver_interrupted_wait"),
        "blocking wait interruption must enter the shared interrupted-wait signal transaction",
    );
    assert!(
        SYSCALL_RUNTIME.contains("InterruptedWaitDelivery::Reobserve"),
        "child-won or stale signal races must return to canonical wait observation",
    );
    assert!(
        SYSCALL_RUNTIME.contains("InterruptedWaitDelivery::SignalFrameCommitted"),
        "a committed interrupted-wait signal frame needs an explicit finalized return boundary",
    );
}

#[test]
fn pending_signal_is_primed_after_wait_registration_before_sleep_commit() {
    let blocking = function_window(SYSCALL_RUNTIME, "fn block_until_wait_ready");
    let prepare = blocking
        .find("prepare_wait_sleep_for_scheduler_thread")
        .expect("blocking wait must first register the exact Prepared receipt");
    let prime = blocking
        .find("prime_wait_signal_interruption(current)")
        .expect("already-pending deliverable signals must mark the exact Prepared waiter");
    let commit = blocking
        .find("commit_wait_sleep_signal_aware(&receipt)")
        .expect("the signal-aware owner commit must observe any primed interruption");

    assert!(prepare < prime);
    assert!(prime < commit);

    let primer = function_window(SYSCALL_RUNTIME, "fn prime_wait_signal_interruption");
    let classify = primer
        .find("signal_syscall_interruption_for_thread")
        .expect("primer must consult the canonical signal owner");
    let interrupt = primer
        .find("interrupt_wait_for_signal")
        .expect("only a deliverable interrupting signal may mark the Wait owner");
    assert!(classify < interrupt);
}

#[test]
fn resumed_wait_signal_generation_is_sampled_inside_the_runtime_owner_window() {
    let delivery = function_window(SIGNAL_DELIVERY, "pub(super) fn deliver_interrupted_wait");
    let runtime_borrow = delivery
        .find("with_linux_runtime")
        .expect("resumed signal work must re-enter the sole Linux runtime owner");
    let generation = delivery
        .find("current_user_switch_generation")
        .expect("resumed signal work must sample the fresh AArch64 switch generation");
    let signal_boundary = delivery.find("with_current_signal_delivery").expect(
        "fresh generation must be consumed by the canonical signal-delivery owner boundary",
    );

    assert!(runtime_borrow < generation);
    assert!(generation < signal_boundary);

    let owner = function_window(LINUX_RUNTIME, "pub(super) fn with_current_signal_delivery");
    assert!(owner.contains("process_parts_for_scheduler_thread"));
    assert!(owner.contains("current_owner"));
    assert!(owner.contains("validate_entry_switch_generation"));
}
