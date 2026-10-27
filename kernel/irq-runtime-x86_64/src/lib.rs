// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU64, Ordering};
use kernal_apic_runtime_x86_64::RuntimeApicCell;
use kernal_apic_x86_64::{HardwareLocalApic, RuntimeApicHandle};
use kernal_arch_x86_64::CpuFeatures;
use kernal_percpu::CpuIndex;
use kernal_scheduler_cpu::CpuSchedulerCell;
use kernal_scheduler_smp::DrainReport;
use kernal_timer_runtime_x86_64::TimerCell;
use kernal_tsc_x86_64::TscFrequency;

pub const MAX_CPUS: usize = 256;

static APICS: [RuntimeApicCell; MAX_CPUS] = [const { RuntimeApicCell::new() }; MAX_CPUS];
static TIMERS: [TimerCell; MAX_CPUS] = [const { TimerCell::new() }; MAX_CPUS];
static RESCHEDULE_INTERRUPTS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuOutOfRange,
    UnsupportedHostArchitecture,
    ApicState(kernal_apic_runtime_x86_64::Error),
    Timer(kernal_timer_runtime_x86_64::Error),
    Scheduler(kernal_scheduler_cpu::Error),
    Apic(kernal_apic_x86_64::Error),
}

/// Publishes the IRQ-time Local APIC handle and configures this CPU's TSC-deadline LVT.
///
/// The owning `HardwareLocalApic` must remain alive while a legacy xAPIC runtime handle is used,
/// because its UC kmap lease backs the published MMIO virtual address. x2APIC has no such mapping.
pub fn prepare_cpu(
    cpu: CpuIndex,
    apic: &mut HardwareLocalApic<'_>,
    features: CpuFeatures,
    frequency: TscFrequency,
    timer_vector: u8,
) -> Result<(), Error> {
    let index = cpu.0 as usize;
    let apic_cell = APICS.get(index).ok_or(Error::CpuOutOfRange)?;
    let timer = TIMERS.get(index).ok_or(Error::CpuOutOfRange)?;

    timer
        .prepare(apic, features, frequency, timer_vector)
        .map_err(Error::Timer)?;
    apic_cell
        .prepare(cpu, apic.runtime_handle())
        .map_err(Error::ApicState)?;
    RESCHEDULE_INTERRUPTS[index].store(0, Ordering::Relaxed);
    Ok(())
}

pub fn apic_handle(cpu: CpuIndex) -> Result<RuntimeApicHandle, Error> {
    APICS
        .get(cpu.0 as usize)
        .ok_or(Error::CpuOutOfRange)?
        .get(cpu)
        .map_err(Error::ApicState)
}

pub fn timer_interrupt_count(cpu: CpuIndex) -> Result<u64, Error> {
    TIMERS
        .get(cpu.0 as usize)
        .ok_or(Error::CpuOutOfRange)?
        .interrupt_count()
        .map_err(Error::Timer)
}

pub fn reschedule_interrupt_count(cpu: CpuIndex) -> Result<u64, Error> {
    Ok(RESCHEDULE_INTERRUPTS
        .get(cpu.0 as usize)
        .ok_or(Error::CpuOutOfRange)?
        .load(Ordering::Acquire))
}

pub fn timer_deadline(cpu: CpuIndex) -> Result<u64, Error> {
    TIMERS
        .get(cpu.0 as usize)
        .ok_or(Error::CpuOutOfRange)?
        .last_deadline()
        .map_err(Error::Timer)
}

/// # Safety
/// Caller must execute at CPL0 on `cpu` with migration prevented.
pub unsafe fn arm_after_ns(cpu: CpuIndex, delay_ns: u64) -> Result<u64, Error> {
    let timer = TIMERS.get(cpu.0 as usize).ok_or(Error::CpuOutOfRange)?;
    // SAFETY: delegated caller contract.
    let plan = unsafe { timer.arm_after_ns(delay_ns) }.map_err(Error::Timer)?;
    Ok(plan.deadline_cycles)
}

/// # Safety
/// Same current-CPL0 CPU contract as `arm_after_ns`.
pub unsafe fn arm_if_disarmed(cpu: CpuIndex, delay_ns: u64) -> Result<Option<u64>, Error> {
    if timer_deadline(cpu)? != 0 {
        return Ok(None);
    }
    // SAFETY: delegated caller contract.
    Ok(Some(unsafe { arm_after_ns(cpu, delay_ns) }?))
}

/// Records timer delivery and sends EOI. Scheduler state is intentionally not mutated here.
pub fn handle_timer(cpu: CpuIndex, vector: u8) -> Result<u64, Error> {
    let timer = TIMERS.get(cpu.0 as usize).ok_or(Error::CpuOutOfRange)?;
    let count = timer.record_interrupt(vector).map_err(Error::Timer)?;
    apic_handle(cpu)?.end_of_interrupt().map_err(Error::Apic)?;
    Ok(count)
}

/// Drains a bounded number of already-published remote wake messages on the owning CPU, EOIs the
/// fixed reschedule IPI, then increments the delivery counter. No foreign RunQueue is mutated.
///
/// # Safety
/// Must execute at CPL0 on `cpu` from that CPU's first-level reschedule interrupt after GS CpuLocal
/// has called `enter_irq()`. IF must be clear and `scheduler` must be owned by the same CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn handle_reschedule<const THREADS: usize, const WAKES: usize>(
    cpu: CpuIndex,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    maximum_wakes: usize,
) -> Result<DrainReport, Error> {
    if scheduler.owner().map_err(Error::Scheduler)? != cpu {
        return Err(Error::Scheduler(kernal_scheduler_cpu::Error::WrongOwner));
    }
    // SAFETY: caller establishes first-level IRQ context. This dedicated path requires irq_depth=1
    // and does not reuse the thread-context scheduler guard.
    let report = unsafe { scheduler.drain_remote_wakes_from_irq(maximum_wakes) }
        .map_err(Error::Scheduler)?;
    apic_handle(cpu)?.end_of_interrupt().map_err(Error::Apic)?;
    RESCHEDULE_INTERRUPTS[cpu.0 as usize].fetch_add(1, Ordering::AcqRel);
    Ok(report)
}

/// Foreign-host support crates must compile for host-side tests without pretending to execute x86
/// interrupt/scheduler mechanisms.
///
/// # Safety
/// This path never accesses hardware or scheduler internals and always fails closed.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn handle_reschedule<const THREADS: usize, const WAKES: usize>(
    cpu: CpuIndex,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    maximum_wakes: usize,
) -> Result<DrainReport, Error> {
    let _ = (cpu, scheduler, maximum_wakes);
    Err(Error::UnsupportedHostArchitecture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_runtime_queries_fail_closed() {
        let invalid = CpuIndex(MAX_CPUS as u16);
        assert_eq!(apic_handle(invalid), Err(Error::CpuOutOfRange));
        assert_eq!(timer_deadline(invalid), Err(Error::CpuOutOfRange));
        assert_eq!(
            reschedule_interrupt_count(invalid),
            Err(Error::CpuOutOfRange)
        );
    }
}
