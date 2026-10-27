// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;
use kernal_arch_aarch64::CpuAffinity;

pub const REDISTRIBUTOR_STRIDE: u64 = 0x20_000;
pub const RESCHEDULE_SGI_DEFAULT: u8 = 1;
pub const DEFAULT_PRIORITY: u8 = 0xa0;
pub const SPECIAL_INTID_BASE: u32 = 1020;

const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ICENABLER: u64 = 0x0180;
const GICD_ICPENDR: u64 = 0x0280;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_RWP: u32 = 1 << 31;

const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_TYPER_LAST: u64 = 1 << 4;
const GICR_SGI_BASE: u64 = 0x1_0000;
const GICR_IGROUPR0: u64 = GICR_SGI_BASE + 0x0080;
const GICR_ISENABLER0: u64 = GICR_SGI_BASE + 0x0100;
const GICR_ICENABLER0: u64 = GICR_SGI_BASE + 0x0180;
const GICR_ICPENDR0: u64 = GICR_SGI_BASE + 0x0280;
const GICR_IPRIORITYR: u64 = GICR_SGI_BASE + 0x0400;
const GICR_ICFGR1: u64 = GICR_SGI_BASE + 0x0c04;

const ICC_SRE_SRE: u64 = 1;
const ICC_CTLR_EOIMODE: u64 = 1 << 1;
const ICC_CTLR_RSS: u64 = 1 << 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}

impl Region {
    pub fn new(base: u64, size: u64) -> Result<Self, Error> {
        if base == 0 || size == 0 || base.checked_add(size).is_none() {
            return Err(Error::InvalidRegion);
        }
        Ok(Self { base, size })
    }

    fn contains(self, address: u64, bytes: u64) -> bool {
        let Some(end) = address.checked_add(bytes) else {
            return false;
        };
        let Some(region_end) = self.base.checked_add(self.size) else {
            return false;
        };
        address >= self.base && end <= region_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidRegion,
    Mmio,
    DistributorTimeout,
    RedistributorNotFound,
    RedistributorTimeout,
    InvalidTimerInterrupt,
    InvalidSgi,
    RangeSelectorUnsupported,
    SystemRegisterInterfaceUnavailable,
}

/// MMIO access is abstracted so GIC policy can be host-tested without touching privileged
/// addresses. A runtime backend must itself enforce that these addresses are mapped Device memory,
/// never ordinary cacheable RAM.
pub trait MmioAccess {
    fn read32(&self, address: u64) -> Result<u32, Error>;
    fn write32(&mut self, address: u64, value: u32) -> Result<(), Error>;
    fn read64(&self, address: u64) -> Result<u64, Error>;
}

pub struct GicV3<M: MmioAccess> {
    mmio: M,
    distributor: Region,
    redistributors: Region,
    redistributor_stride: u64,
}

impl<M: MmioAccess> GicV3<M> {
    pub fn new(mmio: M, distributor: Region, redistributors: Region) -> Self {
        Self {
            mmio,
            distributor,
            redistributors,
            redistributor_stride: REDISTRIBUTOR_STRIDE,
        }
    }

    pub fn with_redistributor_stride(mut self, stride: u64) -> Result<Self, Error> {
        if stride < REDISTRIBUTOR_STRIDE || stride & 0xffff != 0 {
            return Err(Error::InvalidRegion);
        }
        self.redistributor_stride = stride;
        Ok(self)
    }

    pub fn into_inner(self) -> M {
        self.mmio
    }

    /// Disables every SPI before globally enabling the non-secure Group-1 interface. Individual
    /// devices remain unable to interrupt until a later capability-owned route explicitly enables
    /// their INTID.
    pub fn initialize_distributor(&mut self) -> Result<u32, Error> {
        self.write_d32(GICD_CTLR, 0)?;
        self.wait_distributor_rwp()?;

        let typer = self.read_d32(GICD_TYPER)?;
        let interrupt_count = (((typer & 0x1f) + 1) * 32).min(SPECIAL_INTID_BASE);
        let register_count = interrupt_count.div_ceil(32);
        for register in 1..register_count {
            let offset = register as u64 * 4;
            self.write_d32(GICD_ICENABLER + offset, u32::MAX)?;
            self.write_d32(GICD_ICPENDR + offset, u32::MAX)?;
            self.write_d32(GICD_IGROUPR + offset, u32::MAX)?;
        }
        self.wait_distributor_rwp()?;

        self.write_d32(GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS)?;
        self.wait_distributor_rwp()?;
        Ok(interrupt_count)
    }

    /// Explicitly enables one SPI after ownership/routing policy has approved it.
    pub fn enable_spi(&mut self, intid: u32, priority: u8) -> Result<(), Error> {
        if !(32..SPECIAL_INTID_BASE).contains(&intid) {
            return Err(Error::InvalidTimerInterrupt);
        }
        self.set_distributor_priority(intid, priority)?;
        let register = intid / 32;
        let bit = 1u32 << (intid % 32);
        self.write_d32(GICD_ISENABLER + register as u64 * 4, bit)?;
        self.wait_distributor_rwp()
    }

    /// Finds and wakes the current PE's Redistributor, then disables/clears all private interrupts
    /// before enabling only the chosen timer PPI and reschedule SGI.
    pub fn prepare_cpu_private_interrupts(
        &mut self,
        affinity: CpuAffinity,
        timer_intid: u32,
        reschedule_sgi: u8,
    ) -> Result<u64, Error> {
        if !(16..32).contains(&timer_intid) {
            return Err(Error::InvalidTimerInterrupt);
        }
        if reschedule_sgi >= 16 {
            return Err(Error::InvalidSgi);
        }

        let redistributor = self.find_redistributor(affinity)?;
        self.wake_redistributor(redistributor)?;

        self.write_r32(redistributor, GICR_ICENABLER0, u32::MAX)?;
        self.write_r32(redistributor, GICR_ICPENDR0, u32::MAX)?;
        self.write_r32(redistributor, GICR_IGROUPR0, u32::MAX)?;

        // Architected timer PPIs are level-sensitive. Clear the corresponding ICFGR1 trigger bit.
        let timer_index = timer_intid - 16;
        let trigger_bit = 1u32 << (timer_index * 2 + 1);
        let config = self.read_r32(redistributor, GICR_ICFGR1)? & !trigger_bit;
        self.write_r32(redistributor, GICR_ICFGR1, config)?;

        self.set_private_priority(redistributor, timer_intid, DEFAULT_PRIORITY)?;
        self.set_private_priority(redistributor, reschedule_sgi as u32, DEFAULT_PRIORITY)?;
        let enable = (1u32 << timer_intid) | (1u32 << reschedule_sgi);
        self.write_r32(redistributor, GICR_ISENABLER0, enable)?;
        Ok(redistributor)
    }

    fn find_redistributor(&self, affinity: CpuAffinity) -> Result<u64, Error> {
        let mut base = self.redistributors.base;
        loop {
            if !self.redistributors.contains(base, REDISTRIBUTOR_STRIDE) {
                return Err(Error::RedistributorNotFound);
            }
            let typer = self.mmio.read64(base + GICR_TYPER)?;
            if (typer >> 32) as u32 == affinity.packed() {
                return Ok(base);
            }
            if typer & GICR_TYPER_LAST != 0 {
                return Err(Error::RedistributorNotFound);
            }
            base = base
                .checked_add(self.redistributor_stride)
                .ok_or(Error::RedistributorNotFound)?;
        }
    }

    fn wake_redistributor(&mut self, base: u64) -> Result<(), Error> {
        let waker = self.read_r32(base, GICR_WAKER)?;
        self.write_r32(base, GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP)?;
        for _ in 0..1_000_000 {
            if self.read_r32(base, GICR_WAKER)? & GICR_WAKER_CHILDREN_ASLEEP == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::RedistributorTimeout)
    }

    fn set_distributor_priority(&mut self, intid: u32, priority: u8) -> Result<(), Error> {
        let register = GICD_IPRIORITYR + (intid / 4) as u64 * 4;
        let shift = (intid % 4) * 8;
        let current = self.read_d32(register)?;
        self.write_d32(
            register,
            (current & !(0xff << shift)) | ((priority as u32) << shift),
        )
    }

    fn set_private_priority(
        &mut self,
        redistributor: u64,
        intid: u32,
        priority: u8,
    ) -> Result<(), Error> {
        if intid >= 32 {
            return Err(Error::InvalidTimerInterrupt);
        }
        let register = GICR_IPRIORITYR + (intid / 4) as u64 * 4;
        let shift = (intid % 4) * 8;
        let current = self.read_r32(redistributor, register)?;
        self.write_r32(
            redistributor,
            register,
            (current & !(0xff << shift)) | ((priority as u32) << shift),
        )
    }

    fn wait_distributor_rwp(&self) -> Result<(), Error> {
        for _ in 0..1_000_000 {
            if self.read_d32(GICD_CTLR)? & GICD_CTLR_RWP == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::DistributorTimeout)
    }

    fn read_d32(&self, offset: u64) -> Result<u32, Error> {
        let address = self
            .distributor
            .base
            .checked_add(offset)
            .filter(|address| self.distributor.contains(*address, 4))
            .ok_or(Error::InvalidRegion)?;
        self.mmio.read32(address)
    }

    fn write_d32(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        let address = self
            .distributor
            .base
            .checked_add(offset)
            .filter(|address| self.distributor.contains(*address, 4))
            .ok_or(Error::InvalidRegion)?;
        self.mmio.write32(address, value)
    }

    fn read_r32(&self, base: u64, offset: u64) -> Result<u32, Error> {
        let address = base.checked_add(offset).ok_or(Error::InvalidRegion)?;
        if !self.redistributors.contains(address, 4) {
            return Err(Error::InvalidRegion);
        }
        self.mmio.read32(address)
    }

    fn write_r32(&mut self, base: u64, offset: u64, value: u32) -> Result<(), Error> {
        let address = base.checked_add(offset).ok_or(Error::InvalidRegion)?;
        if !self.redistributors.contains(address, 4) {
            return Err(Error::InvalidRegion);
        }
        self.mmio.write32(address, value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgedInterrupt {
    pub raw_iar: u64,
    pub intid: u32,
}

pub fn encode_sgi1r(intid: u8, target: CpuAffinity) -> Result<(u64, u8), Error> {
    if intid >= 16 {
        return Err(Error::InvalidSgi);
    }
    let range_selector = target.aff0 / 16;
    let target_bit = target.aff0 % 16;
    let value = ((target.aff3 as u64) << 48)
        | ((range_selector as u64) << 44)
        | ((target.aff2 as u64) << 32)
        | ((intid as u64) << 24)
        | ((target.aff1 as u64) << 16)
        | (1u64 << target_bit);
    Ok((value, range_selector))
}

/// Enables the GICv3 system-register CPU interface for non-secure Group 1 interrupts, using
/// combined priority-drop/deactivate mode so a real interrupt needs one EOIR write.
///
/// # Safety
/// Must execute at EL1 after the current PE's Redistributor/private interrupt state is ready and
/// before DAIF.I is cleared.
#[cfg(target_arch = "aarch64")]
pub unsafe fn enable_cpu_interface() -> Result<(), Error> {
    let mut sre: u64;
    unsafe {
        asm!("mrs {value}, ICC_SRE_EL1", value = out(reg) sre, options(nomem, nostack));
        sre |= ICC_SRE_SRE;
        asm!("msr ICC_SRE_EL1, {value}", value = in(reg) sre, options(nomem, nostack));
        asm!("isb", options(nostack));
        asm!("mrs {value}, ICC_SRE_EL1", value = out(reg) sre, options(nomem, nostack));
    }
    if sre & ICC_SRE_SRE == 0 {
        return Err(Error::SystemRegisterInterfaceUnavailable);
    }

    let mut control: u64;
    unsafe {
        asm!("mrs {value}, ICC_CTLR_EL1", value = out(reg) control, options(nomem, nostack));
        control &= !ICC_CTLR_EOIMODE;
        asm!("msr ICC_CTLR_EL1, {value}", value = in(reg) control, options(nomem, nostack));
        asm!("msr ICC_PMR_EL1, {value}", value = in(reg) 0xffu64, options(nomem, nostack));
        asm!("msr ICC_BPR1_EL1, {value}", value = in(reg) 0u64, options(nomem, nostack));
        asm!("msr ICC_IGRPEN1_EL1, {value}", value = in(reg) 1u64, options(nomem, nostack));
        asm!("dsb sy", "isb", options(nostack));
    }
    Ok(())
}

/// Acknowledges one Group-1 interrupt. Special/spurious INTIDs 1020..=1023 are returned as `None`
/// and must not be EOI'd.
#[cfg(target_arch = "aarch64")]
pub fn acknowledge_group1() -> Option<AcknowledgedInterrupt> {
    let raw: u64;
    // SAFETY: caller has enabled the GIC system-register interface; reading IAR1 acknowledges at
    // most one pending Group-1 interrupt for this PE.
    unsafe { asm!("mrs {value}, ICC_IAR1_EL1", value = out(reg) raw, options(nomem, nostack)) };
    let intid = (raw & 0x00ff_ffff) as u32;
    (intid < SPECIAL_INTID_BASE).then_some(AcknowledgedInterrupt {
        raw_iar: raw,
        intid,
    })
}

/// Completes a previously acknowledged real Group-1 interrupt. Do not call this for a special
/// spurious INTID.
///
/// # Safety
/// `interrupt.raw_iar` must come from the matching outstanding `ICC_IAR1_EL1` acknowledge on this
/// PE and must not already have been completed.
#[cfg(target_arch = "aarch64")]
pub unsafe fn end_of_interrupt_group1(interrupt: AcknowledgedInterrupt) {
    // SAFETY: delegated to caller; EOImode is configured to combined drop/deactivate.
    unsafe {
        asm!("msr ICC_EOIR1_EL1, {value}", value = in(reg) interrupt.raw_iar, options(nomem, nostack));
        asm!("isb", options(nostack));
    }
}

/// Sends one Group-1 SGI to a specific affinity target. A DSB ISHST orders prior remote-wake
/// publication before the interrupt becomes observable by the target PE.
///
/// # Safety
/// GICv3 system-register interface must be enabled for the current PE.
#[cfg(target_arch = "aarch64")]
pub unsafe fn send_sgi1(intid: u8, target: CpuAffinity) -> Result<(), Error> {
    let (value, range_selector) = encode_sgi1r(intid, target)?;
    if range_selector != 0 {
        let control: u64;
        unsafe {
            asm!("mrs {value}, ICC_CTLR_EL1", value = out(reg) control, options(nomem, nostack));
        }
        if control & ICC_CTLR_RSS == 0 {
            return Err(Error::RangeSelectorUnsupported);
        }
    }
    unsafe {
        asm!("dsb ishst", options(nostack));
        asm!("msr ICC_SGI1R_EL1, {value}", value = in(reg) value, options(nomem, nostack));
        asm!("isb", options(nostack));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeMmio {
        words32: BTreeMap<u64, u32>,
        words64: BTreeMap<u64, u64>,
    }

    impl MmioAccess for FakeMmio {
        fn read32(&self, address: u64) -> Result<u32, Error> {
            Ok(*self.words32.get(&address).unwrap_or(&0))
        }

        fn write32(&mut self, address: u64, value: u32) -> Result<(), Error> {
            self.words32.insert(address, value);
            Ok(())
        }

        fn read64(&self, address: u64) -> Result<u64, Error> {
            Ok(*self.words64.get(&address).unwrap_or(&0))
        }
    }

    #[test]
    fn sgi_encoding_tracks_all_affinity_levels_and_range_selector() {
        let target = CpuAffinity {
            aff0: 17,
            aff1: 2,
            aff2: 3,
            aff3: 4,
        };
        let (value, range_selector) = encode_sgi1r(5, target).unwrap();
        assert_eq!(range_selector, 1);
        assert_eq!((value >> 48) & 0xff, 4);
        assert_eq!((value >> 44) & 0xf, 1);
        assert_eq!((value >> 32) & 0xff, 3);
        assert_eq!((value >> 24) & 0xf, 5);
        assert_eq!((value >> 16) & 0xff, 2);
        assert_eq!(value & 0xffff, 1 << 1);
    }

    #[test]
    fn distributor_starts_with_every_spi_disabled() {
        let distributor = Region::new(0x0800_0000, 0x1_0000).unwrap();
        let redistributors = Region::new(0x080a_0000, 0x20_000).unwrap();
        let mut mmio = FakeMmio::default();
        // ITLinesNumber=1 => 64 INTIDs: one private bank and one SPI bank.
        mmio.words32.insert(distributor.base + GICD_TYPER, 1);
        let mut gic = GicV3::new(mmio, distributor, redistributors);
        assert_eq!(gic.initialize_distributor().unwrap(), 64);
        let mmio = gic.into_inner();
        assert_eq!(
            mmio.words32.get(&(distributor.base + GICD_ICENABLER + 4)),
            Some(&u32::MAX)
        );
        assert_eq!(
            mmio.words32.get(&(distributor.base + GICD_IGROUPR + 4)),
            Some(&u32::MAX)
        );
        assert_eq!(
            mmio.words32.get(&(distributor.base + GICD_CTLR)),
            Some(&(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS))
        );
    }

    #[test]
    fn private_interrupt_setup_enables_only_timer_and_reschedule_probe() {
        let distributor = Region::new(0x0800_0000, 0x1_0000).unwrap();
        let redistributors = Region::new(0x080a_0000, 0x20_000).unwrap();
        let mut mmio = FakeMmio::default();
        let affinity = CpuAffinity {
            aff0: 2,
            aff1: 0,
            aff2: 0,
            aff3: 0,
        };
        mmio.words64.insert(
            redistributors.base + GICR_TYPER,
            ((affinity.packed() as u64) << 32) | GICR_TYPER_LAST,
        );
        mmio.words32.insert(redistributors.base + GICR_WAKER, 0);
        let mut gic = GicV3::new(mmio, distributor, redistributors);
        let base = gic
            .prepare_cpu_private_interrupts(affinity, 27, RESCHEDULE_SGI_DEFAULT)
            .unwrap();
        assert_eq!(base, redistributors.base);
        let mmio = gic.into_inner();
        assert_eq!(
            mmio.words32.get(&(base + GICR_ISENABLER0)),
            Some(&((1u32 << 27) | (1u32 << RESCHEDULE_SGI_DEFAULT)))
        );
        assert_eq!(mmio.words32.get(&(base + GICR_ICENABLER0)), Some(&u32::MAX));
    }
}
