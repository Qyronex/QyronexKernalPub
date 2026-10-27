// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30 signal-generation transaction contract.
//
// Linux job-control generation removes the pending opposite class as part of the successful
// generation. That cancellation must be staged on the exact target queue before capacity admission:
// when a one-slot target queue contains only the opposite signal, the cancellation itself frees the
// slot needed by the new signal. The canonical queues must still remain untouched if later staging
// fails; the sibling-capacity failure cases are pinned separately.

use core::num::NonZeroU32;
use kernal_linux_identity::LinuxIdentityTable;
use kernal_linux_signal::{SIGCONT, SIGSTOP, Signal, SignalProvenance, SignalSet, SignalTable};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{Personality, Process, ThreadObjectBindings};
use kernal_scheduler::RunQueue;
use kernal_scheduler_smp::GlobalThreadId;

const CPU0: CpuIndex = CpuIndex(0);

fn signal(number: u8) -> Signal {
    Signal::new(number).expect("test signal is valid")
}

fn provenance() -> SignalProvenance {
    SignalProvenance::User {
        sender_pid: NonZeroU32::new(77).unwrap(),
        sender_uid: 1000,
    }
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

#[test]
fn process_sigcont_replaces_process_stop_in_the_only_pending_slot() {
    let (_objects, process, _bindings, _scheduler, _identities, _thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();

    signals.queue_signal(&process, signal(SIGSTOP)).unwrap();
    assert_eq!(signals.pending_count(&process), Ok(1));

    assert_eq!(
        signals.queue_signal_with_provenance(&process, signal(SIGCONT), provenance()),
        Ok(()),
        "SIGCONT must stage-remove process SIGSTOP before checking the one-slot process queue"
    );
    assert_eq!(signals.pending_count(&process), Ok(1));
}

#[test]
fn process_stop_replaces_process_sigcont_in_the_only_pending_slot() {
    let (_objects, process, _bindings, _scheduler, _identities, _thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();

    signals.queue_signal(&process, signal(SIGCONT)).unwrap();
    assert_eq!(signals.pending_count(&process), Ok(1));

    assert_eq!(
        signals.queue_signal_with_provenance(&process, signal(SIGSTOP), provenance()),
        Ok(()),
        "STOP generation must stage-remove process SIGCONT before checking the one-slot process queue"
    );
    assert_eq!(signals.pending_count(&process), Ok(1));
}

#[test]
fn thread_stop_replaces_thread_sigcont_in_the_only_pending_slot() {
    let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
    let mut signals = SignalTable::<2, 1, 2>::new();
    signals.bind_process(&process).unwrap();
    signals
        .bind_thread(&identities, &process, thread, SignalSet::empty())
        .unwrap();

    signals
        .queue_thread_signal(&identities, &process, thread, signal(SIGCONT))
        .unwrap();
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1)
    );

    assert_eq!(
        signals.queue_thread_signal(&identities, &process, thread, signal(SIGSTOP)),
        Ok(()),
        "STOP generation must stage-remove thread SIGCONT before checking the one-slot thread queue"
    );
    assert_eq!(
        signals.thread_pending_count(&identities, &process, thread),
        Ok(1)
    );
}
