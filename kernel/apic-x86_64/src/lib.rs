// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::hint::spin_loop;
use core::ptr::{read_volatile, write_volatile};
use kernal_arch_x86_64::{CpuFeatures, rdmsr, wrmsr};
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_kmap_x86_64::{ActiveMapping, KmapController};

pub const IA32_APIC_BASE_MSR: u32 = 0x1b;
pub const APIC_BASE_ENABLE: u64 = 1 << 11;
pub const APIC_BASE_X2APIC: u64 = 1 << 10;
pub const DEFAULT_SPURIOUS_VECTOR: u8 = 0xff;
pub const LEGACY_ICR_POLL_LIMIT: usize = 1_000_000;
const X2APIC_EOI_MSR: u32 = 0x80b;
const X2APIC_ICR_MSR: u32 = 0x830;

pub mod register {
    pub const ID: u32 = 0x020;
    pub const EOI: u32 = 0x0b0;
    pub const SPURIOUS: u32 = 0x0f0;
    pub const ICR_LOW: u32 = 0x300;
    pub const ICR_HIGH: u32 = 0x310;
    pub const LVT_TIMER: u32 = 0x320;
    pub const LVT_THERMAL: u32 = 0x330;
    pub const LVT_PERF: u32 = 0x340;
    pub const LVT_LINT0: u32 = 0x350;
    pub const LVT_LINT1: u32 = 0x360;
    pub const LVT_ERROR: u32 = 0x370;
    pub const TIMER_INITIAL_COUNT: u32 = 0x380;
    pub const TIMER_CURRENT_COUNT: u32 = 0x390;
    pub const TIMER_DIVIDE: u32 = 0x3e0;
}

const SOFTWARE_ENABLE: u32 = 1 << 8;
const ICR_DELIVERY_STATUS: u32 = 1 << 12;
const ICR_LEVEL_ASSERT: u64 = 1 << 14;
const ICR_TRIGGER_LEVEL: u64 = 1 << 15;
const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_MODE_MASK: u32 = 0b11 << 17;
const LVT_TIMER_TSC_DEADLINE: u32 = 0b10 << 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerDivide {
    By1,
    By2,
    By4,
    By8,
    By16,
    By32,
    By64,
    By128,
}
impl TimerDivide {
    pub const fn encoding(self) -> u32 {
        match self {
            Self::By1 => 0b1011,
            Self::By2 => 0b0000,
            Self::By4 => 0b0001,
            Self::By8 => 0b0010,
            Self::By16 => 0b0011,
            Self::By32 => 0b1000,
            Self::By64 => 0b1001,
            Self::By128 => 0b1010,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    X2ApicUnsupported,
    X2ApicAlreadyActive,
    InvalidMmioBase,
    MmioMapFailed,
    InvalidRegister,
    InvalidSpuriousVector,
    InvalidInterruptVector,
    InvalidDestination,
    DeliveryTimeout,
}

pub trait LocalApicAccess {
    fn read(&self, register: u32) -> Result<u32, Error>;
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn write_icr(&mut self, value: u64) -> Result<(), Error>;
    fn id(&self) -> Result<u32, Error>;
    fn wait_icr_idle(&self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct LocalApic<A: LocalApicAccess> {
    access: A,
}
impl<A: LocalApicAccess> LocalApic<A> {
    pub const fn new(access: A) -> Self {
        Self { access }
    }
    pub fn id(&self) -> Result<u32, Error> {
        self.access.id()
    }
    pub fn into_inner(self) -> A {
        self.access
    }

    pub fn enable(&mut self, spurious_vector: u8) -> Result<(), Error> {
        if spurious_vector < 0x20 {
            return Err(Error::InvalidSpuriousVector);
        }
        let current = self.access.read(register::SPURIOUS)?;
        self.access.write(
            register::SPURIOUS,
            (current & !0xff) | spurious_vector as u32 | SOFTWARE_ENABLE,
        )
    }

    pub fn mask_bootstrap_lvts(&mut self) -> Result<(), Error> {
        for register in [
            register::LVT_TIMER,
            register::LVT_THERMAL,
            register::LVT_PERF,
            register::LVT_ERROR,
        ] {
            let value = self.access.read(register).unwrap_or(0);
            self.access.write(register, value | LVT_MASKED)?;
        }
        Ok(())
    }

    pub fn configure_tsc_deadline_timer(&mut self, vector: u8) -> Result<(), Error> {
        validate_interrupt_vector(vector)?;
        let current = self.access.read(register::LVT_TIMER).unwrap_or(0);
        let value = (current & !(0xff | LVT_MASKED | LVT_TIMER_MODE_MASK))
            | vector as u32
            | LVT_TIMER_TSC_DEADLINE;
        self.access.write(register::LVT_TIMER, value)
    }

    pub fn configure_one_shot_timer(
        &mut self,
        vector: u8,
        divide: TimerDivide,
    ) -> Result<(), Error> {
        validate_interrupt_vector(vector)?;
        let current = self.access.read(register::LVT_TIMER).unwrap_or(0);
        let value = (current & !(0xff | LVT_MASKED | LVT_TIMER_MODE_MASK)) | vector as u32;
        self.access
            .write(register::TIMER_DIVIDE, divide.encoding())?;
        self.access.write(register::LVT_TIMER, value)
    }

    pub fn set_timer_initial_count(&mut self, ticks: u32) -> Result<(), Error> {
        self.access.write(register::TIMER_INITIAL_COUNT, ticks)
    }
    pub fn timer_current_count(&self) -> Result<u32, Error> {
        self.access.read(register::TIMER_CURRENT_COUNT)
    }
    pub fn mask_timer(&mut self) -> Result<(), Error> {
        let value = self.access.read(register::LVT_TIMER).unwrap_or(0);
        self.access.write(register::LVT_TIMER, value | LVT_MASKED)
    }
    pub fn end_of_interrupt(&mut self) -> Result<(), Error> {
        self.access.write(register::EOI, 0)
    }

    pub fn send_fixed_ipi(&mut self, destination_apic_id: u32, vector: u8) -> Result<(), Error> {
        validate_interrupt_vector(vector)?;
        self.send_ipi(destination_apic_id, vector as u64)
    }

    pub fn send_init_ipi(&mut self, destination_apic_id: u32) -> Result<(), Error> {
        let low = (0b101u64 << 8) | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL;
        self.send_ipi(destination_apic_id, low)
    }

    pub fn send_startup_ipi(&mut self, destination_apic_id: u32, vector: u8) -> Result<(), Error> {
        let low = (0b110u64 << 8) | vector as u64;
        self.send_ipi(destination_apic_id, low)
    }

    fn send_ipi(&mut self, destination_apic_id: u32, low: u64) -> Result<(), Error> {
        self.access.wait_icr_idle()?;
        self.access
            .write_icr(((destination_apic_id as u64) << 32) | low)?;
        self.access.wait_icr_idle()
    }
}

fn validate_interrupt_vector(vector: u8) -> Result<(), Error> {
    if vector < 0x20 {
        Err(Error::InvalidInterruptVector)
    } else {
        Ok(())
    }
}

pub struct X2Apic;
impl X2Apic {
    /// Enables x2APIC mode through IA32_APIC_BASE after validating CPU feature support.
    ///
    /// # Safety
    /// Must execute at CPL0 on the target x86_64 CPU with privileged MSR access permitted. The
    /// caller must serialize APIC-mode transitions on that CPU and ensure no active APIC user
    /// concurrently assumes legacy xAPIC mode.
    pub unsafe fn enable(features: CpuFeatures) -> Result<Self, Error> {
        if !features.x2apic {
            return Err(Error::X2ApicUnsupported);
        }
        let base = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
        if base & APIC_BASE_X2APIC == 0 {
            unsafe { wrmsr(IA32_APIC_BASE_MSR, base | APIC_BASE_ENABLE) };
            unsafe {
                wrmsr(
                    IA32_APIC_BASE_MSR,
                    base | APIC_BASE_ENABLE | APIC_BASE_X2APIC,
                )
            };
        }
        Ok(Self)
    }

    fn msr_for(register: u32) -> Result<u32, Error> {
        if register > 0x3f0 || register & 0xf != 0 {
            return Err(Error::InvalidRegister);
        }
        Ok(0x800 + (register >> 4))
    }
}

impl LocalApicAccess for X2Apic {
    fn read(&self, register: u32) -> Result<u32, Error> {
        let msr = Self::msr_for(register)?;
        Ok(unsafe { rdmsr(msr) } as u32)
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        let msr = Self::msr_for(register)?;
        unsafe { wrmsr(msr, value as u64) };
        Ok(())
    }
    fn write_icr(&mut self, value: u64) -> Result<(), Error> {
        unsafe { wrmsr(X2APIC_ICR_MSR, value) };
        Ok(())
    }
    fn id(&self) -> Result<u32, Error> {
        Ok(unsafe { rdmsr(0x802) } as u32)
    }
}

pub struct XApicMmio<'a> {
    mapping: ActiveMapping<'a>,
}
impl<'a> XApicMmio<'a> {
    /// Enables legacy xAPIC mode and maps the Local APIC page uncached through `kmap`.
    ///
    /// # Safety
    /// Must execute at CPL0 on the target x86_64 CPU. `physical_base` must be the firmware/CPU
    /// supplied Local APIC physical page, `kmap` must be initialized for this CPU, and the returned
    /// mapping must outlive all MMIO accesses performed through this object. The caller must also
    /// ensure x2APIC mode is not concurrently enabled.
    pub unsafe fn enable_and_map(
        kmap: &'a KmapController,
        physical_base: u64,
    ) -> Result<Self, Error> {
        if physical_base == 0 || physical_base & 0xfff != 0 {
            return Err(Error::InvalidMmioBase);
        }
        let mut base = unsafe { rdmsr(IA32_APIC_BASE_MSR) };
        if base & APIC_BASE_X2APIC != 0 {
            return Err(Error::X2ApicAlreadyActive);
        }
        base |= APIC_BASE_ENABLE;
        unsafe { wrmsr(IA32_APIC_BASE_MSR, base) };
        let mapping = kmap
            .map(MappingRequest {
                physical_address: physical_base,
                writable: true,
                cache: CachePolicy::Uncached,
            })
            .map_err(|_| Error::MmioMapFailed)?;
        Ok(Self { mapping })
    }

    fn pointer(&self, register: u32) -> Result<*mut u32, Error> {
        if register > 0x3f0 || register & 0xf != 0 {
            return Err(Error::InvalidRegister);
        }
        Ok(self
            .mapping
            .virtual_address()
            .checked_add(register as u64)
            .ok_or(Error::InvalidRegister)? as *mut u32)
    }

    pub const fn virtual_base(&self) -> u64 {
        self.mapping.virtual_address()
    }
}

impl LocalApicAccess for XApicMmio<'_> {
    fn read(&self, register: u32) -> Result<u32, Error> {
        Ok(unsafe { read_volatile(self.pointer(register)?) })
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        unsafe { write_volatile(self.pointer(register)?, value) };
        Ok(())
    }
    fn write_icr(&mut self, value: u64) -> Result<(), Error> {
        let destination = (value >> 32) as u32;
        if destination > 0xff {
            return Err(Error::InvalidDestination);
        }
        self.write(register::ICR_HIGH, destination << 24)?;
        self.write(register::ICR_LOW, value as u32)
    }
    fn id(&self) -> Result<u32, Error> {
        Ok(self.read(register::ID)? >> 24)
    }
    fn wait_icr_idle(&self) -> Result<(), Error> {
        for _ in 0..LEGACY_ICR_POLL_LIMIT {
            if self.read(register::ICR_LOW)? & ICR_DELIVERY_STATUS == 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(Error::DeliveryTimeout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeApicHandle {
    X2Apic,
    XApic { virtual_base: u64 },
}

impl RuntimeApicHandle {
    pub fn end_of_interrupt(self) -> Result<(), Error> {
        match self {
            Self::X2Apic => {
                unsafe { wrmsr(X2APIC_EOI_MSR, 0) };
                Ok(())
            }
            Self::XApic { virtual_base } => {
                let address = virtual_base
                    .checked_add(register::EOI as u64)
                    .ok_or(Error::InvalidRegister)?;
                unsafe { write_volatile(address as *mut u32, 0) };
                Ok(())
            }
        }
    }

    /// Sends one fixed IPI. Caller must serialize same-CPU ICR use (normally IRQ-off) so another
    /// local context cannot interleave an xAPIC ICR_HIGH/ICR_LOW pair.
    pub fn send_fixed_ipi(self, destination: u32, vector: u8) -> Result<(), Error> {
        validate_interrupt_vector(vector)?;
        match self {
            Self::X2Apic => {
                unsafe { wrmsr(X2APIC_ICR_MSR, ((destination as u64) << 32) | vector as u64) };
                Ok(())
            }
            Self::XApic { virtual_base } => {
                if destination > 0xff {
                    return Err(Error::InvalidDestination);
                }
                let low = virtual_base
                    .checked_add(register::ICR_LOW as u64)
                    .ok_or(Error::InvalidRegister)? as *mut u32;
                let high = virtual_base
                    .checked_add(register::ICR_HIGH as u64)
                    .ok_or(Error::InvalidRegister)? as *mut u32;
                for _ in 0..LEGACY_ICR_POLL_LIMIT {
                    if unsafe { read_volatile(low) } & ICR_DELIVERY_STATUS == 0 {
                        unsafe {
                            write_volatile(high, destination << 24);
                            write_volatile(low, vector as u32);
                        }
                        for _ in 0..LEGACY_ICR_POLL_LIMIT {
                            if unsafe { read_volatile(low) } & ICR_DELIVERY_STATUS == 0 {
                                return Ok(());
                            }
                            spin_loop();
                        }
                        return Err(Error::DeliveryTimeout);
                    }
                    spin_loop();
                }
                Err(Error::DeliveryTimeout)
            }
        }
    }
}

pub enum HardwareLocalApic<'a> {
    X2(LocalApic<X2Apic>),
    XApic(LocalApic<XApicMmio<'a>>),
}

impl<'a> HardwareLocalApic<'a> {
    /// Selects and initializes the hardware Local APIC mode for the current CPU.
    ///
    /// # Safety
    /// Must execute at CPL0 on the non-migrating target x86_64 CPU with interrupts controlled by
    /// the caller. `features` must describe that CPU, `local_apic_physical` must be the validated
    /// Local APIC base when legacy xAPIC is selected, and `kmap` must remain valid for the lifetime
    /// of any returned xAPIC MMIO mapping.
    pub unsafe fn initialize(
        kmap: &'a KmapController,
        features: CpuFeatures,
        local_apic_physical: u64,
    ) -> Result<Self, Error> {
        if features.x2apic {
            Ok(Self::X2(LocalApic::new(unsafe {
                X2Apic::enable(features)
            }?)))
        } else {
            Ok(Self::XApic(LocalApic::new(unsafe {
                XApicMmio::enable_and_map(kmap, local_apic_physical)
            }?)))
        }
    }

    pub fn runtime_handle(&self) -> RuntimeApicHandle {
        match self {
            Self::X2(_) => RuntimeApicHandle::X2Apic,
            Self::XApic(apic) => RuntimeApicHandle::XApic {
                virtual_base: apic.access.virtual_base(),
            },
        }
    }

    pub fn id(&self) -> Result<u32, Error> {
        match self {
            Self::X2(a) => a.id(),
            Self::XApic(a) => a.id(),
        }
    }
    pub fn enable(&mut self, vector: u8) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.enable(vector),
            Self::XApic(a) => a.enable(vector),
        }
    }
    pub fn mask_bootstrap_lvts(&mut self) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.mask_bootstrap_lvts(),
            Self::XApic(a) => a.mask_bootstrap_lvts(),
        }
    }
    pub fn configure_tsc_deadline_timer(&mut self, vector: u8) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.configure_tsc_deadline_timer(vector),
            Self::XApic(a) => a.configure_tsc_deadline_timer(vector),
        }
    }
    pub fn configure_one_shot_timer(
        &mut self,
        vector: u8,
        divide: TimerDivide,
    ) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.configure_one_shot_timer(vector, divide),
            Self::XApic(a) => a.configure_one_shot_timer(vector, divide),
        }
    }
    pub fn set_timer_initial_count(&mut self, ticks: u32) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.set_timer_initial_count(ticks),
            Self::XApic(a) => a.set_timer_initial_count(ticks),
        }
    }
    pub fn timer_current_count(&self) -> Result<u32, Error> {
        match self {
            Self::X2(a) => a.timer_current_count(),
            Self::XApic(a) => a.timer_current_count(),
        }
    }
    pub fn mask_timer(&mut self) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.mask_timer(),
            Self::XApic(a) => a.mask_timer(),
        }
    }
    pub fn end_of_interrupt(&mut self) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.end_of_interrupt(),
            Self::XApic(a) => a.end_of_interrupt(),
        }
    }
    pub fn send_fixed_ipi(&mut self, destination: u32, vector: u8) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.send_fixed_ipi(destination, vector),
            Self::XApic(a) => a.send_fixed_ipi(destination, vector),
        }
    }
    pub fn send_init_ipi(&mut self, destination: u32) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.send_init_ipi(destination),
            Self::XApic(a) => a.send_init_ipi(destination),
        }
    }
    pub fn send_startup_ipi(&mut self, destination: u32, vector: u8) -> Result<(), Error> {
        match self {
            Self::X2(a) => a.send_startup_ipi(destination, vector),
            Self::XApic(a) => a.send_startup_ipi(destination, vector),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeApic {
        registers: [u32; 64],
        id: u32,
        icr: u64,
    }
    impl FakeApic {
        fn new(id: u32) -> Self {
            Self {
                registers: [0; 64],
                id,
                icr: 0,
            }
        }
        fn index(register: u32) -> Result<usize, Error> {
            if register > 0x3f0 || register & 0xf != 0 {
                return Err(Error::InvalidRegister);
            }
            Ok((register >> 4) as usize)
        }
    }
    impl LocalApicAccess for FakeApic {
        fn read(&self, register: u32) -> Result<u32, Error> {
            Ok(self.registers[Self::index(register)?])
        }
        fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
            self.registers[Self::index(register)?] = value;
            Ok(())
        }
        fn write_icr(&mut self, value: u64) -> Result<(), Error> {
            self.icr = value;
            Ok(())
        }
        fn id(&self) -> Result<u32, Error> {
            Ok(self.id)
        }
    }

    #[test]
    fn enable_sets_software_enable_and_vector() {
        let mut apic = LocalApic::new(FakeApic::new(7));
        apic.enable(0xf1).unwrap();
        let fake = apic.into_inner();
        assert_eq!(
            fake.registers[(register::SPURIOUS >> 4) as usize] & 0x1ff,
            0x1f1
        );
    }

    #[test]
    fn bootstrap_masking_preserves_lint_nmi_routing() {
        let mut fake = FakeApic::new(1);
        fake.registers[(register::LVT_LINT0 >> 4) as usize] = 0x1234;
        fake.registers[(register::LVT_LINT1 >> 4) as usize] = 0x4567;
        let mut apic = LocalApic::new(fake);
        apic.mask_bootstrap_lvts().unwrap();
        let fake = apic.into_inner();
        for register in [
            register::LVT_TIMER,
            register::LVT_THERMAL,
            register::LVT_PERF,
            register::LVT_ERROR,
        ] {
            assert_ne!(fake.registers[(register >> 4) as usize] & LVT_MASKED, 0);
        }
        assert_eq!(fake.registers[(register::LVT_LINT0 >> 4) as usize], 0x1234);
        assert_eq!(fake.registers[(register::LVT_LINT1 >> 4) as usize], 0x4567);
    }

    #[test]
    fn tsc_deadline_timer_programs_vector_and_mode_without_mask() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        apic.configure_tsc_deadline_timer(0xe0).unwrap();
        let fake = apic.into_inner();
        let value = fake.registers[(register::LVT_TIMER >> 4) as usize];
        assert_eq!(value & 0xff, 0xe0);
        assert_eq!(value & LVT_TIMER_MODE_MASK, LVT_TIMER_TSC_DEADLINE);
        assert_eq!(value & LVT_MASKED, 0);
    }

    #[test]
    fn one_shot_timer_uses_requested_divider() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        apic.configure_one_shot_timer(0xe1, TimerDivide::By16)
            .unwrap();
        let fake = apic.into_inner();
        assert_eq!(
            fake.registers[(register::TIMER_DIVIDE >> 4) as usize],
            TimerDivide::By16.encoding()
        );
        assert_eq!(
            fake.registers[(register::LVT_TIMER >> 4) as usize] & LVT_TIMER_MODE_MASK,
            0
        );
    }

    #[test]
    fn fixed_ipi_is_edge_triggered_fixed_delivery() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        apic.send_fixed_ipi(42, 0xe1).unwrap();
        let fake = apic.into_inner();
        assert_eq!(fake.icr >> 32, 42);
        assert_eq!(fake.icr as u32 & 0xff, 0xe1);
        assert_eq!((fake.icr >> 8) & 0x7, 0);
        assert_eq!(fake.icr & (ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL), 0);
    }

    #[test]
    fn fixed_ipi_rejects_exception_vector() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        assert_eq!(
            apic.send_fixed_ipi(2, 0x1f),
            Err(Error::InvalidInterruptVector)
        );
    }

    #[test]
    fn init_ipi_is_level_asserted_and_triggered() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        apic.send_init_ipi(42).unwrap();
        let fake = apic.into_inner();
        assert_eq!(fake.icr >> 32, 42);
        assert_eq!((fake.icr >> 8) & 0x7, 0b101);
        assert_ne!(fake.icr & ICR_LEVEL_ASSERT, 0);
        assert_ne!(fake.icr & ICR_TRIGGER_LEVEL, 0);
    }

    #[test]
    fn startup_ipi_contains_destination_and_vector() {
        let mut apic = LocalApic::new(FakeApic::new(1));
        apic.send_startup_ipi(42, 0x08).unwrap();
        let fake = apic.into_inner();
        assert_eq!(fake.icr >> 32, 42);
        assert_eq!(fake.icr as u32 & 0xff, 0x08);
        assert_eq!((fake.icr >> 8) & 0x7, 0b110);
        assert_eq!(fake.icr & ICR_TRIGGER_LEVEL, 0);
    }

    #[test]
    fn x2apic_register_mapping_is_architectural() {
        assert_eq!(X2Apic::msr_for(register::ID), Ok(0x802));
        assert_eq!(X2Apic::msr_for(register::EOI), Ok(0x80b));
        assert_eq!(X2Apic::msr_for(register::LVT_TIMER), Ok(0x832));
        assert_eq!(X2Apic::msr_for(3), Err(Error::InvalidRegister));
    }
}
