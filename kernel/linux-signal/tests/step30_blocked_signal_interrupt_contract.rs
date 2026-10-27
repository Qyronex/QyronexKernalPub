// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 host-safe structural oracle for the blocked wait/futex signal-interruption owner split.
// It deliberately proves only the already-leased Wait + Signal/Runtime half. Futex reason ownership
// remains governance-blocked until the canonical futex paths are leased.

const WAIT: &str = include_str!("../../linux-wait/src/lib.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step15_runtime_integrated.rs");
const SIGNAL_DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const SYSCALL_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let top_level = body.find("\n///");
    let nested = body.find("\n    ///");
    let end = match (top_level, nested) {
        (Some(left), Some(right)) => marker.len() + core::cmp::min(left, right),
        (Some(offset), None) | (None, Some(offset)) => marker.len() + offset,
        (None, None) => tail.len(),
    };
    &tail[..end]
}

fn section_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_offset = source
        .find(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"));
    let tail = &source[start_offset..];
    let end_offset = tail
        .find(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"));
    &tail[..end_offset]
}

#[test]
fn wait_owner_retains_signal_interruption_in_the_existing_waiter_record() {
    assert!(WAIT.contains("WaiterState::Interrupted"));
    assert!(WAIT.contains("pub enum WaitInterruptOutcome"));
    assert!(WAIT.contains("pub enum WaitSignalCommitOutcome"));
    assert!(!WAIT.contains("interrupted_waiters:"));

    let interrupt = function_window(WAIT, "pub fn interrupt_sleep_for_thread");
    assert!(interrupt.contains("thread: GlobalThreadId"));
    assert!(interrupt.contains("WaiterState::Prepared"));
    assert!(interrupt.contains("WaiterState::Committed"));
    assert!(interrupt.contains("state: WaiterState::Interrupted"));
    assert!(interrupt.contains("WaitInterruptOutcome::InterruptedNoWake"));
    assert!(interrupt.contains("WaitInterruptOutcome::Wake(current.thread)"));
    assert!(interrupt.contains("WaitInterruptOutcome::ChildNotified"));
    assert!(!interrupt.contains("make_ready"));
    assert!(!interrupt.contains("remote_wake"));
}

#[test]
fn prepared_interruption_cannot_race_through_the_compatibility_commit() {
    let commit = function_window(WAIT, "pub fn commit_sleep(&mut self");
    assert!(commit.contains("WaiterState::Interrupted => Err(Error::WaiterInterrupted)"));

    let aware = function_window(WAIT, "pub fn commit_sleep_signal_aware");
    assert!(aware.contains("WaiterState::Interrupted"));
    assert!(aware.contains("WaitSignalCommitOutcome::Interrupted"));
    assert!(aware.contains("WaiterState::Notified"));
    assert!(aware.contains("WaitSignalCommitOutcome::AlreadyWoken"));
}

#[test]
fn child_notification_remains_distinct_from_signal_interruption() {
    let publish = function_window(WAIT, "pub fn publish_exit_with_wakes");
    assert!(publish.contains("finish_terminal_waiters(record)"));

    let finish = function_window(WAIT, "fn finish_terminal_waiters");
    assert!(finish.contains("WaiterState::Prepared | WaiterState::Interrupted"));
    assert!(finish.contains("state: WaiterState::Notified"));
    assert!(finish.contains("WaiterState::Committed"));
    assert!(finish.contains("wakes.push(waiter.thread)"));

    let consume = function_window(WAIT, "pub fn consume_interrupted_sleep");
    assert!(consume.contains("WaiterState::Interrupted"));
    assert!(consume.contains("WaiterState::Notified"));
    assert!(consume.contains("Ok(true)"));
    assert!(consume.contains("Ok(false)"));
}

#[test]
fn runtime_revalidates_identity_before_wait_owner_interruption() {
    let interrupt = function_window(RUNTIME, "fn interrupt_wait_for_signal");
    let identity = interrupt
        .find("process_object_for_scheduler_thread")
        .expect("exact scheduler generation must re-enter canonical identity owner");
    let wait = interrupt
        .find("interrupt_sleep_for_thread")
        .expect("runtime must delegate interruption to canonical WaitTable owner");
    assert!(identity < wait);
    assert!(!interrupt.contains("bootstrap_wake_local_exact"));
    assert!(!interrupt.contains("remote_wake"));

    let commit = function_window(RUNTIME, "fn commit_wait_sleep_signal_aware");
    assert!(commit.contains("process_object_for_scheduler_thread(receipt.thread())"));
    assert!(commit.contains("commit_sleep_signal_aware"));

    let consume = function_window(RUNTIME, "fn consume_interrupted_wait_for_signal");
    assert!(consume.contains("process_object_for_scheduler_thread(receipt.thread())"));
    assert!(consume.contains("consume_interrupted_sleep"));
}

#[test]
fn process_directed_signal_selects_at_most_one_actual_next_delivery_target() {
    let target = function_window(RUNTIME, "fn process_signal_wait_interrupt_target");
    assert!(target.contains("with_process_signal_target_for_pid"));
    assert!(target.contains("bound_scheduler_thread_at"));
    assert!(target.contains("prepare_delivery_for_thread"));
    assert!(target.contains("DefaultAction::Ignore"));
    assert!(target.contains("DefaultAction::Continue"));
    assert!(target.contains("DefaultAction::Stop"));
    assert!(target.contains("DefaultAction::Terminate"));
    assert!(target.contains("SA_RESTART"));
    assert!(target.contains("return Ok(Some((thread, interruption)))"));
    assert!(!target.contains("interrupt_wait_for_signal"));
    assert!(!target.contains("bootstrap_wake_local_exact"));
    assert!(!target.contains("remote_wake"));
    assert!(!target.contains("thread_mask"));
}

#[test]
fn post_queue_helpers_return_only_exact_wait_wake_obligations() {
    let process = function_window(SIGNAL_DELIVERY, "fn interrupt_process_wait_after_signal");
    assert!(process.contains("process_signal_wait_interrupt_target"));
    assert!(process.contains("interrupt_wait_for_signal"));
    assert!(process.contains("exact_wait_route"));
    assert!(process.contains("finish_wait_interrupt_route"));
    assert!(!process.contains("bootstrap_wake_local_exact"));
    assert!(!process.contains("remote_wake"));

    let thread = function_window(SIGNAL_DELIVERY, "fn interrupt_thread_wait_after_signal");
    assert!(thread.contains("signal_syscall_interruption_for_thread"));
    assert!(thread.contains("interrupt_wait_for_signal"));
    assert!(thread.contains("exact_wait_route"));
    assert!(thread.contains("finish_wait_interrupt_route"));
    assert!(!thread.contains("bootstrap_wake_local_exact"));
    assert!(!thread.contains("remote_wake"));

    let exact = function_window(SIGNAL_DELIVERY, "fn exact_wait_route");
    assert!(exact.contains("WaitInterruptOutcome::Wake(thread) if thread == expected"));
    assert!(exact.contains("WaitInterruptOutcome::Wake(_) => Err(())"));
    assert!(exact.contains("WaitInterruptOutcome::NotWaiting"));
    assert!(exact.contains("SignalWaitInterruptRoute::Futex(expected)"));
    assert!(exact.contains("WaitInterruptOutcome::InterruptedNoWake"));
    assert!(exact.contains("WaitInterruptOutcome::ChildNotified"));

    let finish = function_window(SIGNAL_DELIVERY, "fn finish_wait_interrupt_route");
    assert!(finish.contains("interrupt_wait_after_signal(target)"));
    assert!(finish.contains("SignalInterruptRoute::Wake(thread) if thread == target"));
    assert!(finish.contains("SignalInterruptRoute::Wake(_) => Err(())"));
    assert!(!finish.contains("bootstrap_wake_local_exact"));
    assert!(!finish.contains("remote_wake_with_reschedule"));
}

#[test]
fn exact_wait_wake_routing_uses_existing_scheduler_owners_only() {
    let route = function_window(SIGNAL_DELIVERY, "fn route_exact_wait_wake_after_signal");
    assert!(route.contains("current_cpu_index"));
    assert!(route.contains("CPU_SCHEDULERS"));
    assert!(route.contains("bootstrap_wake_local_exact"));
    assert!(route.contains("remote_wake_with_reschedule"));
    assert!(!route.contains("make_ready("));
    assert!(!route.contains("SignalTable"));
    assert!(!route.contains("WaitTable"));

    let process = function_window(
        SIGNAL_DELIVERY,
        "fn interrupt_and_wake_process_wait_after_signal",
    );
    let interrupt = process
        .find("interrupt_process_wait_after_signal")
        .expect("process queue must commit Wait owner before scheduler wake routing");
    let wake = process
        .find("route_exact_wait_wake_after_signal")
        .expect("process queue must route only the returned exact wake obligation");
    assert!(interrupt < wake);

    let thread = function_window(
        SIGNAL_DELIVERY,
        "fn interrupt_and_wake_thread_wait_after_signal",
    );
    let interrupt = thread
        .find("interrupt_thread_wait_after_signal")
        .expect("thread queue must commit Wait owner before scheduler wake routing");
    let wake = thread
        .find("route_exact_wait_wake_after_signal")
        .expect("thread queue must route only the returned exact wake obligation");
    assert!(interrupt < wake);
}

#[test]
fn signal_send_calls_exact_wait_interruption_only_after_real_queue_success() {
    let kill = section_between(
        SYSCALL_RUNTIME,
        "Step30RuntimeCall::Kill { pid, signal }",
        "Step30RuntimeCall::Tgkill { tgid, tid, signal }",
    );
    assert!(kill.contains("SignalSendResult::Queued"));
    assert!(kill.contains("interrupt_and_wake_process_wait_after_signal"));
    assert!(!kill.contains("SignalNumber::Probe => super::signal_delivery"));

    let tgkill = section_between(
        SYSCALL_RUNTIME,
        "Step30RuntimeCall::Tgkill { tgid, tid, signal }",
        "Step30RuntimeCall::RtSigaction",
    );
    assert!(tgkill.contains("queue_thread_signal_with_provenance"));
    assert!(tgkill.contains("interrupt_and_wake_thread_wait_after_signal"));
    assert!(!tgkill.contains("SignalNumber::Probe => super::signal_delivery"));
}

#[test]
fn aarch64_interrupted_wait_snapshot_distinguishes_eintr_from_restart() {
    let snapshot = function_window(SIGNAL_DELIVERY, "fn interrupted_wait_snapshot");
    assert!(snapshot.contains("InterruptedWaitContext::ReturnEintr"));
    assert!(snapshot.contains("SyscallReturn::error(Errno::EINTR).as_u64_bits()"));
    assert!(snapshot.contains("InterruptedWaitContext::Restart"));
    assert!(snapshot.contains("elr_el1.checked_sub(4)"));
    assert!(snapshot.contains("El0ReturnState::new"));
    assert!(snapshot.contains("snapshot.elr_el1 = validated.return_pc()"));
    assert!(!snapshot.contains("ERESTART"));
}

#[test]
fn interrupted_wait_signal_commit_is_one_runtime_transaction() {
    let commit = function_window(SIGNAL_DELIVERY, "fn commit_interrupted_wait_signal");
    let wait_state = commit
        .find("commit_wait_sleep_signal_aware")
        .expect("Wait owner state must be checked first");
    let signal_commit = commit
        .find("commit_prepared_delivery")
        .expect("exact PreparedSignalDelivery must be committed");
    let wait_consume = commit
        .find("consume_interrupted_wait_for_signal")
        .expect("exact wait interruption must be consumed after signal commit");
    assert!(wait_state < signal_commit);
    assert!(signal_commit < wait_consume);
    assert!(commit.contains("WaitSignalCommitOutcome::AlreadyWoken"));
    assert!(commit.contains("InterruptedWaitSignalCommit::ChildWon"));
    assert!(commit.contains("WaitSignalCommitOutcome::Interrupted"));
    assert!(commit.contains("InterruptedWaitSignalCommit::SignalCommitted"));
    assert!(!commit.contains("bootstrap_wake_local_exact"));
    assert!(!commit.contains("remote_wake"));
}

#[test]
fn stale_prepared_signal_releases_only_exact_wait_interruption_for_reobserve() {
    let commit = function_window(SIGNAL_DELIVERY, "fn commit_interrupted_wait_signal");
    let stale = commit
        .find("SignalError::PreparedDeliveryStale")
        .expect("stale prepared delivery must have a distinct retry outcome");
    let consume = commit[stale..]
        .find("consume_interrupted_wait_for_signal(receipt)")
        .map(|offset| stale + offset)
        .expect("stale signal must release only the exact retained wait interruption");
    let retry = commit[consume..]
        .find("InterruptedWaitSignalCommit::SignalStale")
        .map(|offset| consume + offset)
        .expect("stale signal must return a reobserve/reblock result");
    assert!(stale < consume);
    assert!(consume < retry);
    assert!(!commit[stale..retry].contains("cancel_committed_wait_for_signal"));
    assert!(!commit[stale..retry].contains("bootstrap_wake_local_exact"));
    assert!(!commit[stale..retry].contains("remote_wake"));
}

#[test]
fn compatibility_cancel_still_consumes_only_exact_committed_generation() {
    let cancel = function_window(WAIT, "pub fn cancel_committed_sleep_for_thread");
    assert!(cancel.contains("thread: GlobalThreadId"));
    assert!(cancel.contains("waiter.thread == thread"));
    assert!(cancel.contains("waiter.state == WaiterState::Committed"));
    assert!(cancel.contains("self.waiters[slot] = None"));
    assert!(!cancel.contains("make_ready"));
    assert!(!cancel.contains("remote_wake"));
}

#[test]
fn signal_interruption_policy_is_read_only_and_sa_restart_aware() {
    let policy = function_window(RUNTIME, "fn signal_syscall_interruption_for_thread");
    assert!(policy.contains("prepare_delivery_for_thread"));
    assert!(!policy.contains("commit_prepared_delivery"));
    assert!(policy.contains("DefaultAction::Ignore"));
    assert!(policy.contains("DefaultAction::Continue"));
    assert!(policy.contains("DefaultAction::Stop"));
    assert!(policy.contains("DefaultAction::Terminate"));
    assert!(policy.contains("SA_RESTART"));
    assert!(policy.contains("SignalSyscallInterruption::ReturnEintr"));
    assert!(policy.contains("SignalSyscallInterruption::Restart"));
    assert!(policy.contains("SignalSyscallInterruption::FatalDelivery"));
}

#[test]
fn no_core_sidecar_interruption_registry_is_introduced_by_preparation_slice() {
    assert!(!RUNTIME.contains("SignalInterruptRegistry"));
    assert!(!RUNTIME.contains("InterruptedFutexTable"));
    assert!(!RUNTIME.contains("interrupted_waiters:"));
}
