// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

mod runtime {
    pub const STEP15_RUNTIME_THREADS: usize = 16;
}

#[allow(dead_code)]
#[path = "../../core-aarch64/src/step30_pipe_wait.rs"]
mod step30_pipe_wait;

use kernal_linux_pipe::{PipeId, PipeTable};
use kernal_percpu::CpuIndex;
use kernal_scheduler::ThreadId;
use kernal_scheduler_smp::GlobalThreadId;
use step30_pipe_wait::{InterruptOutcome, PipeWaitTable, WaitCommit};

fn thread(cpu: u16, slot: u16, generation: u16) -> GlobalThreadId {
    GlobalThreadId::new(CpuIndex(cpu), ThreadId { slot, generation })
}

fn pipes() -> (PipeId, PipeId) {
    let mut owner = PipeTable::<2, 8>::new();
    let first = owner.create().unwrap().reader.pipe();
    let second = owner.create().unwrap().reader.pipe();
    (first, second)
}

#[test]
fn readiness_before_commit_is_retained_without_scheduler_wake() {
    let (pipe, _) = pipes();
    let waiter = thread(0, 3, 7);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();

    let mut output = [thread(0, 0, 1); 1];
    let report = waits.notify(pipe, 1, &mut output).unwrap();
    assert_eq!(report.consumed, 1);
    assert_eq!(report.runnable, 0);
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::AlreadyWoken));
    assert_eq!(waits.len(), 0);
}

#[test]
fn committed_readiness_grants_exactly_one_scheduler_wake() {
    let (pipe, _) = pipes();
    let waiter = thread(2, 5, 11);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::Sleep));

    let mut output = [thread(0, 0, 1); 1];
    let report = waits.notify(pipe, 1, &mut output).unwrap();
    assert_eq!(report.consumed, 1);
    assert_eq!(report.runnable, 1);
    assert_eq!(output[0], waiter);
    assert_eq!(waits.len(), 0);
}

#[test]
fn signal_before_commit_is_retained_and_never_fabricates_wake() {
    let (pipe, _) = pipes();
    let waiter = thread(1, 8, 4);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.interrupt(waiter), Ok(InterruptOutcome::Retained));
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::AlreadyWoken));
    assert_eq!(waits.interruption_pending(waiter), Ok(true));
    assert_eq!(waits.consume_interrupted(waiter), Ok(true));
    assert_eq!(waits.len(), 0);
}

#[test]
fn committed_signal_grants_one_exact_wake_and_duplicate_grants_none() {
    let (pipe, _) = pipes();
    let waiter = thread(3, 1, 9);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::Sleep));
    assert_eq!(waits.interrupt(waiter), Ok(InterruptOutcome::WakeRequired));
    assert_eq!(
        waits.interrupt(waiter),
        Ok(InterruptOutcome::AlreadyInterrupted)
    );
    assert_eq!(waits.interruption_pending(waiter), Ok(true));
}

#[test]
fn normal_pipe_wake_cannot_steal_signal_owned_interruption() {
    let (pipe, _) = pipes();
    let waiter = thread(0, 6, 12);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::Sleep));
    assert_eq!(waits.interrupt(waiter), Ok(InterruptOutcome::WakeRequired));

    let mut output = [thread(0, 0, 1); 1];
    let report = waits.notify(pipe, 1, &mut output).unwrap();
    assert_eq!(report.consumed, 0);
    assert_eq!(report.runnable, 0);
    assert_eq!(waits.interruption_pending(waiter), Ok(true));
    assert_eq!(waits.consume_interrupted(waiter), Ok(true));
}

#[test]
fn final_writer_close_uses_same_readiness_wake_contract() {
    let (pipe, _) = pipes();
    let waiter = thread(0, 9, 2);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::Sleep));

    let mut output = [thread(0, 0, 1); 1];
    let report = waits.notify(pipe, 1, &mut output).unwrap();
    assert_eq!(report.consumed, 1);
    assert_eq!(report.runnable, 1);
    assert_eq!(output[0], waiter);
}

#[test]
fn unrelated_pipe_cannot_wake_waiter() {
    let (pipe, other) = pipes();
    let waiter = thread(0, 4, 6);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, waiter).unwrap();
    assert_eq!(waits.commit(waiter), Ok(WaitCommit::Sleep));

    let mut output = [thread(0, 0, 1); 1];
    let report = waits.notify(other, 1, &mut output).unwrap();
    assert_eq!(report.consumed, 0);
    assert_eq!(report.runnable, 0);
    assert_eq!(waits.len(), 1);
}

#[test]
fn stale_thread_generation_cannot_interrupt_current_waiter() {
    let (pipe, _) = pipes();
    let current = thread(1, 7, 10);
    let stale = thread(1, 7, 9);
    let mut waits = PipeWaitTable::<4>::new();
    waits.prepare(pipe, current).unwrap();
    assert_eq!(waits.commit(current), Ok(WaitCommit::Sleep));

    assert_eq!(waits.interrupt(stale), Ok(InterruptOutcome::NotWaiting));
    assert_eq!(waits.interruption_pending(current), Ok(false));
    assert_eq!(waits.interrupt(current), Ok(InterruptOutcome::WakeRequired));
}
