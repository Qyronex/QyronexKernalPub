// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::hint::spin_loop;
use kernal_apic_x86_64::HardwareLocalApic;
use kernal_arch_x86_64::read_tsc_ordered;
use kernal_percpu::{CpuIndex, CpuRegistry, CpuState};
use kernal_tsc_x86_64::TscFrequency;

pub const INIT_SETTLE_NS: u64 = 10_000_000;
pub const SIPI_GAP_NS: u64 = 200_000;
pub const ONLINE_TIMEOUT_NS: u64 = 100_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnreliableTscRejected,
    TimeOverflow,
    Registry,
    Apic,
    Timeout,
    UnexpectedState,
}

pub trait StartupIpi {
    fn send_init(&mut self, destination_apic_id: u32) -> Result<(), Error>;
    fn send_sipi(&mut self, destination_apic_id: u32, vector: u8) -> Result<(), Error>;
}

impl StartupIpi for HardwareLocalApic<'_> {
    fn send_init(&mut self, destination_apic_id: u32) -> Result<(), Error> {
        self.send_init_ipi(destination_apic_id)
            .map_err(|_| Error::Apic)
    }

    fn send_sipi(&mut self, destination_apic_id: u32, vector: u8) -> Result<(), Error> {
        self.send_startup_ipi(destination_apic_id, vector)
            .map_err(|_| Error::Apic)
    }
}

pub trait DelaySource {
    fn now(&self) -> u64;
    fn cycles_for_ns(&self, ns: u64) -> Result<u64, Error>;

    fn wait_ns(&self, ns: u64) -> Result<(), Error> {
        let delta = self.cycles_for_ns(ns)?;
        let deadline = self.now().checked_add(delta).ok_or(Error::TimeOverflow)?;
        while self.now().wrapping_sub(deadline) >= (1u64 << 63) {
            spin_loop();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TscDelay {
    frequency: TscFrequency,
}

impl TscDelay {
    pub fn new(frequency: TscFrequency) -> Result<Self, Error> {
        if !frequency.reliable_for_timing() {
            return Err(Error::UnreliableTscRejected);
        }
        Ok(Self { frequency })
    }

    pub const fn frequency(self) -> TscFrequency {
        self.frequency
    }
}

impl DelaySource for TscDelay {
    fn now(&self) -> u64 {
        read_tsc_ordered()
    }

    fn cycles_for_ns(&self, ns: u64) -> Result<u64, Error> {
        self.frequency
            .ns_to_cycles_ceil(ns)
            .map_err(|_| Error::TimeOverflow)
    }
}

pub fn start_one<const N: usize, A: StartupIpi, D: DelaySource>(
    registry: &CpuRegistry<N>,
    cpu: CpuIndex,
    sipi_vector: u8,
    apic: &mut A,
    delay: &D,
) -> Result<(), Error> {
    let descriptor = registry.descriptor(cpu).ok_or(Error::Registry)?;
    registry.mark_starting(cpu).map_err(|_| Error::Registry)?;

    if let Err(error) = apic.send_init(descriptor.apic_id) {
        let _ = registry.mark_failed(cpu);
        return Err(error);
    }
    if let Err(error) = delay.wait_ns(INIT_SETTLE_NS) {
        let _ = registry.mark_failed(cpu);
        return Err(error);
    }
    if let Err(error) = apic.send_sipi(descriptor.apic_id, sipi_vector) {
        let _ = registry.mark_failed(cpu);
        return Err(error);
    }
    if let Err(error) = delay.wait_ns(SIPI_GAP_NS) {
        let _ = registry.mark_failed(cpu);
        return Err(error);
    }
    if let Err(error) = apic.send_sipi(descriptor.apic_id, sipi_vector) {
        let _ = registry.mark_failed(cpu);
        return Err(error);
    }

    let timeout_cycles = delay.cycles_for_ns(ONLINE_TIMEOUT_NS)?;
    let deadline = delay
        .now()
        .checked_add(timeout_cycles)
        .ok_or(Error::TimeOverflow)?;
    loop {
        match registry.state(cpu).map_err(|_| Error::Registry)? {
            CpuState::Online => return Ok(()),
            CpuState::Starting => {}
            CpuState::Failed => return Err(Error::UnexpectedState),
            CpuState::Offline => return Err(Error::UnexpectedState),
        }
        if delay.now().wrapping_sub(deadline) < (1u64 << 63) {
            let _ = registry.mark_failed(cpu);
            return Err(Error::Timeout);
        }
        spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use kernal_percpu::CpuRegistry;
    use kernal_tsc_x86_64::FrequencyQuality;

    struct FakeDelay {
        now: Cell<u64>,
        hz: u64,
    }
    impl DelaySource for FakeDelay {
        fn now(&self) -> u64 {
            let value = self.now.get();
            self.now.set(value + 1_000_000);
            value
        }
        fn cycles_for_ns(&self, ns: u64) -> Result<u64, Error> {
            let value = (ns as u128) * (self.hz as u128) / 1_000_000_000u128;
            u64::try_from(value).map_err(|_| Error::TimeOverflow)
        }
    }

    #[derive(Default)]
    struct FakeApic {
        init: usize,
        sipi: usize,
        last_destination: u32,
        vector: u8,
    }
    impl StartupIpi for FakeApic {
        fn send_init(&mut self, destination_apic_id: u32) -> Result<(), Error> {
            self.init += 1;
            self.last_destination = destination_apic_id;
            Ok(())
        }
        fn send_sipi(&mut self, destination_apic_id: u32, vector: u8) -> Result<(), Error> {
            self.sipi += 1;
            self.last_destination = destination_apic_id;
            self.vector = vector;
            Ok(())
        }
    }

    #[test]
    fn estimated_tsc_is_rejected_for_early_smp_timing() {
        let frequency = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Estimated,
        };
        assert_eq!(
            TscDelay::new(frequency).unwrap_err(),
            Error::UnreliableTscRejected
        );
    }

    #[test]
    fn calibrated_tsc_is_accepted_for_early_smp_timing() {
        let frequency = TscFrequency {
            hz: 3_000_000_000,
            quality: FrequencyQuality::Calibrated,
        };
        assert!(TscDelay::new(frequency).is_ok());
    }

    #[test]
    fn timeout_marks_cpu_failed_after_init_and_two_sipis() {
        let mut registry = CpuRegistry::<2>::new();
        let bsp = registry.register(1, 1, None).unwrap();
        let ap = registry.register(2, 2, None).unwrap();
        registry.set_bsp_online(bsp).unwrap();
        let delay = FakeDelay {
            now: Cell::new(0),
            hz: 1_000_000_000,
        };
        let mut apic = FakeApic::default();
        assert_eq!(
            start_one(&registry, ap, 8, &mut apic, &delay),
            Err(Error::Timeout)
        );
        assert_eq!(registry.state(ap).unwrap(), CpuState::Failed);
        assert_eq!(apic.init, 1);
        assert_eq!(apic.sipi, 2);
        assert_eq!(apic.last_destination, 2);
        assert_eq!(apic.vector, 8);
    }
}
