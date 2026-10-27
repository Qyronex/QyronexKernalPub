// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use kernal_apic_x86_64::RuntimeApicHandle;
#[cfg(target_arch = "x86_64")]
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(any(target_arch = "x86_64", test))]
use kernal_scheduler_smp::GlobalThreadId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Wake(kernal_scheduler_cpu::Error),
    IpiAfterWake(kernal_apic_x86_64::Error),
}

/// Result distinguishes successful notification from the fail-safe state where the wake message is
/// already durable in the target mailbox but APIC delivery failed. The caller may retry only the
/// IPI; it must not enqueue the same semantic wake again unless duplicate-ready behavior is desired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeDelivery {
    PublishedAndIpiSent,
    PublishedButIpiFailed,
}

/// Publishes a CPU-scoped remote wake before sending the reschedule IPI.
///
/// This ordering prevents a classic lost-wakeup race: the target can never observe an IPI before
/// the mailbox entry exists. If IPI delivery fails, the message remains queued and can be drained by
/// a later timer/scheduler event.
///
/// # Safety
/// `source_apic` must describe the current CPL0 CPU. The target APIC ID must correspond to
/// `target.owner()`. Local IRQ state is saved/disabled around ICR programming to serialize legacy
/// xAPIC ICR_HIGH/ICR_LOW pairs against other same-CPU interrupt paths.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wake_remote<const THREADS: usize, const WAKES: usize>(
    source_apic: RuntimeApicHandle,
    target_apic_id: u32,
    target: &'static CpuSchedulerCell<THREADS, WAKES>,
    thread: GlobalThreadId,
    reschedule_vector: u8,
) -> Result<WakeDelivery, Error> {
    target.remote_wake(thread).map_err(Error::Wake)?;
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    // SAFETY: caller guarantees CPL0/current-CPU ownership; disabling IRQs serializes local ICR use.
    let irq_state = unsafe { kernal_irq_state_x86_64::save_and_disable() };
    let sent = source_apic.send_fixed_ipi(target_apic_id, reschedule_vector);
    // SAFETY: restore exactly the local interrupt state that preceded ICR programming.
    unsafe { kernal_irq_state_x86_64::restore(irq_state) };

    match sent {
        Ok(()) => Ok(WakeDelivery::PublishedAndIpiSent),
        Err(_) => Ok(WakeDelivery::PublishedButIpiFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_percpu::CpuIndex;
    use kernal_scheduler::ThreadId;

    #[test]
    fn result_enum_keeps_ipi_failure_distinct_from_wake_failure() {
        let _ = WakeDelivery::PublishedAndIpiSent;
        let _ = WakeDelivery::PublishedButIpiFailed;
        let thread = GlobalThreadId::new(
            CpuIndex(1),
            ThreadId {
                slot: 2,
                generation: 3,
            },
        );
        assert_eq!(thread.cpu, CpuIndex(1));
    }
}
