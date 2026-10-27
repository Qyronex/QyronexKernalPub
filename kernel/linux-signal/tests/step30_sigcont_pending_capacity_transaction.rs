// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;
use kernal_linux_identity::LinuxIdentityTable;
use kernal_linux_signal::{
    Disposition, Error, SIGCONT, SIGSTOP, Signal, SignalProvenance, SignalSet, SignalTable,
};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{Personality, Process, ThreadObjectBindings};
use kernal_scheduler::RunQueue;
use kernal_scheduler_smp::GlobalThreadId;

const CPU0: CpuIndex = CpuIndex(0);

fn signal(number: u8) -> Signal {
    Signal::new(number).expect("test signal is valid")
}

fn one_thread_fixture() -> (
    ObjectTable<8>,
    Process<8>,
    ThreadObjectBindings<2>,
    RunQueue<2>,
    LinuxIdentityTable<2, 2>,
    GlobalThreadId,
) {
    let mut objects = ObjectTable::<8>::new();
    let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
    let mut bindings = ThreadObjectBindings::<2>::new();
    let mut scheduler = RunQueue::<2>::new();
    let local = scheduler.create(10).unwrap();
    let thread = GlobalThreadId::new(CPU0, local);
    let handle = process
        .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, thread)
        .unwrap();
    let mut identities = LinuxIdentityTable::<2, 2>::new();
    identities
        .bind_leader(&process, &objects, &bindings, &scheduler, CPU0, handle)
        .unwrap();
    (objects, process, bindings, scheduler, identities, thread)
}

fn provenance() -> SignalProvenance {
    SignalProvenance::User {
        sender_pid: NonZeroU32::new(77).unwrap(),
        sender_uid: 1000,
    }
}

#[test]
fn process_sigcont_capacity_failure_preserves_thread_stop_pending_state() {
    let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();
    signals
        .bind_thread(&identities, &process, thread, SignalSet::empty())
        .unwrap();

    // Fill the process-directed queue with an unrelated signal while retaining a thread-local STOP.
    signals.queue_signal(&process, signal(10)).unwrap();
    signals
        .queue_thread_signal(&identities, &process, thread, signal(SIGSTOP))
        .unwrap();
    assert_eq!(signals.pending_count(&process), Ok(1));
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1)
    );

    // Failed generation is not a commit: SIGCONT may not cancel the opposite job-control pending
    // state until its own bounded queue operation has succeeded.
    assert_eq!(
        signals.queue_signal_with_provenance(&process, signal(SIGCONT), provenance()),
        Err(Error::PendingCapacity)
    );
    assert_eq!(signals.pending_count(&process), Ok(1));
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1),
        "PendingCapacity must not partially commit SIGCONT by cancelling thread-local STOP"
    );
}

#[test]
fn thread_sigcont_capacity_failure_preserves_process_stop_pending_state() {
    let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();
    signals
        .bind_thread(&identities, &process, thread, SignalSet::empty())
        .unwrap();

    // Fill the target thread queue while retaining the opposite process-wide STOP generation.
    signals.queue_signal(&process, signal(SIGSTOP)).unwrap();
    signals
        .queue_thread_signal(&identities, &process, thread, signal(10))
        .unwrap();
    assert_eq!(signals.pending_count(&process), Ok(1));
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1)
    );

    assert_eq!(
        signals.queue_thread_signal_with_provenance(
            &identities,
            &process,
            thread,
            signal(SIGCONT),
            provenance(),
        ),
        Err(Error::PendingCapacity)
    );
    assert_eq!(
        signals.pending_count(&process),
        Ok(1),
        "PendingCapacity must not partially commit tgkill(SIGCONT) by cancelling process STOP"
    );
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1)
    );
}

#[test]
fn thread_sigcont_can_use_slot_freed_by_cancelling_target_stop() {
    let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();
    signals
        .bind_thread(&identities, &process, thread, SignalSet::empty())
        .unwrap();

    // The target queue is full, but only with the exact opposite job-control generation. Transactional
    // staging must cancel that STOP on the private target copy before checking/committing SIGCONT.
    signals
        .queue_thread_signal(&identities, &process, thread, signal(SIGSTOP))
        .unwrap();
    assert_eq!(
        signals.queue_thread_signal_with_provenance(
            &identities,
            &process,
            thread,
            signal(SIGCONT),
            provenance(),
        ),
        Ok(())
    );
    assert_eq!(signals.pending_count(&process), Ok(0));
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1),
        "opposite STOP must free the sole target slot for the committed SIGCONT"
    );
}

#[test]
fn ignored_sigcont_still_commits_opposite_job_control_cancellation() {
    let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();
    signals
        .bind_thread(&identities, &process, thread, SignalSet::empty())
        .unwrap();
    signals
        .set_disposition(&process, signal(SIGCONT), Disposition::Ignore)
        .unwrap();
    signals
        .queue_thread_signal(&identities, &process, thread, signal(SIGSTOP))
        .unwrap();

    // Linux job-control generation cancellation remains a committed side effect even when the newly
    // generated SIGCONT itself is discarded by disposition and occupies no pending slot.
    assert_eq!(
        signals.queue_signal_with_provenance(&process, signal(SIGCONT), provenance()),
        Ok(())
    );
    assert_eq!(signals.pending_count(&process), Ok(0));
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(0),
        "ignored SIGCONT must still cancel pending STOP generations"
    );
}
