// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_acpi::{Madt, MadtEntry};
use kernal_acpi_srat::{Entry as SratEntry, Srat};

pub const MAX_IO_APICS: usize = 16;
pub const MAX_INTERRUPT_OVERRIDES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuCapacity,
    MemoryCapacity,
    IoApicCapacity,
    InterruptOverrideCapacity,
    DuplicateApicId,
    DuplicateProcessorUid,
    DuplicateIoApicId,
    DuplicateInterruptSource,
    OverlappingMemoryAffinity,
    InvalidLocalApicAddress,
    InvalidIoApicAddress,
    Firmware,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cpu {
    pub apic_id: u32,
    pub processor_uid: u32,
    pub enabled: bool,
    pub proximity_domain: Option<u32>,
}
impl Cpu {
    const EMPTY: Self = Self {
        apic_id: 0,
        processor_uid: 0,
        enabled: false,
        proximity_domain: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}
impl IoApic {
    const EMPTY: Self = Self {
        id: 0,
        address: 0,
        gsi_base: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptOverride {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}
impl InterruptOverride {
    const EMPTY: Self = Self {
        bus: 0,
        source: 0,
        gsi: 0,
        flags: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NumaMemory {
    pub proximity_domain: u32,
    pub start: u64,
    pub len: u64,
    pub hot_pluggable: bool,
    pub non_volatile: bool,
}
impl NumaMemory {
    const EMPTY: Self = Self {
        proximity_domain: 0,
        start: 0,
        len: 0,
        hot_pluggable: false,
        non_volatile: false,
    };
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
}

pub struct Topology<const CPUS: usize, const MEMORY: usize> {
    cpus: [Cpu; CPUS],
    cpu_len: usize,
    memory: [NumaMemory; MEMORY],
    memory_len: usize,
    io_apics: [IoApic; MAX_IO_APICS],
    io_apic_len: usize,
    interrupt_overrides: [InterruptOverride; MAX_INTERRUPT_OVERRIDES],
    interrupt_override_len: usize,
    local_apic_address: u64,
}

impl<const C: usize, const M: usize> Default for Topology<C, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const C: usize, const M: usize> Topology<C, M> {
    pub const fn new() -> Self {
        Self {
            cpus: [Cpu::EMPTY; C],
            cpu_len: 0,
            memory: [NumaMemory::EMPTY; M],
            memory_len: 0,
            io_apics: [IoApic::EMPTY; MAX_IO_APICS],
            io_apic_len: 0,
            interrupt_overrides: [InterruptOverride::EMPTY; MAX_INTERRUPT_OVERRIDES],
            interrupt_override_len: 0,
            local_apic_address: 0xfee0_0000,
        }
    }

    pub fn from_acpi(madt: &Madt<'_>, srat: Option<&Srat<'_>>) -> Result<Self, Error> {
        let mut topology = Self::new();
        topology.set_local_apic_address(madt.local_apic_address() as u64)?;
        for entry in madt.entries() {
            topology.apply_madt_entry(entry.map_err(|_| Error::Firmware)?)?;
        }
        if let Some(srat) = srat {
            topology.apply_srat(srat)?;
        }
        Ok(topology)
    }

    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.cpu_len]
    }
    pub fn memory(&self) -> &[NumaMemory] {
        &self.memory[..self.memory_len]
    }
    pub fn io_apics(&self) -> &[IoApic] {
        &self.io_apics[..self.io_apic_len]
    }
    pub fn interrupt_overrides(&self) -> &[InterruptOverride] {
        &self.interrupt_overrides[..self.interrupt_override_len]
    }
    pub const fn local_apic_address(&self) -> u64 {
        self.local_apic_address
    }
    pub fn enabled_cpu_count(&self) -> usize {
        self.cpus().iter().filter(|cpu| cpu.enabled).count()
    }

    pub fn set_local_apic_address(&mut self, address: u64) -> Result<(), Error> {
        if address == 0 || address & 0xfff != 0 {
            return Err(Error::InvalidLocalApicAddress);
        }
        self.local_apic_address = address;
        Ok(())
    }

    pub fn apply_madt_entry(&mut self, entry: MadtEntry) -> Result<(), Error> {
        match entry {
            MadtEntry::LocalApic {
                processor_uid,
                apic_id,
                flags,
            } => self.add_cpu(Cpu {
                apic_id: apic_id as u32,
                processor_uid: processor_uid as u32,
                enabled: flags & 1 != 0 || flags & 2 != 0,
                proximity_domain: None,
            }),
            MadtEntry::LocalX2Apic {
                x2apic_id,
                flags,
                processor_uid,
            } => self.add_cpu(Cpu {
                apic_id: x2apic_id,
                processor_uid,
                enabled: flags & 1 != 0 || flags & 2 != 0,
                proximity_domain: None,
            }),
            MadtEntry::IoApic {
                io_apic_id,
                address,
                gsi_base,
            } => self.add_io_apic(IoApic {
                id: io_apic_id,
                address,
                gsi_base,
            }),
            MadtEntry::InterruptSourceOverride {
                bus,
                source,
                gsi,
                flags,
            } => self.add_interrupt_override(InterruptOverride {
                bus,
                source,
                gsi,
                flags,
            }),
            MadtEntry::LocalApicAddressOverride { address } => self.set_local_apic_address(address),
            MadtEntry::Unknown { .. } => Ok(()),
        }
    }

    pub fn add_cpu(&mut self, cpu: Cpu) -> Result<(), Error> {
        if self.cpus[..self.cpu_len]
            .iter()
            .any(|existing| existing.apic_id == cpu.apic_id)
        {
            return Err(Error::DuplicateApicId);
        }
        if self.cpus[..self.cpu_len]
            .iter()
            .any(|existing| existing.processor_uid == cpu.processor_uid)
        {
            return Err(Error::DuplicateProcessorUid);
        }
        if self.cpu_len == C {
            return Err(Error::CpuCapacity);
        }
        self.cpus[self.cpu_len] = cpu;
        self.cpu_len += 1;
        Ok(())
    }

    pub fn add_io_apic(&mut self, io_apic: IoApic) -> Result<(), Error> {
        if io_apic.address == 0 || io_apic.address & 0xfff != 0 {
            return Err(Error::InvalidIoApicAddress);
        }
        if self.io_apics[..self.io_apic_len]
            .iter()
            .any(|existing| existing.id == io_apic.id)
        {
            return Err(Error::DuplicateIoApicId);
        }
        if self.io_apic_len == MAX_IO_APICS {
            return Err(Error::IoApicCapacity);
        }
        self.io_apics[self.io_apic_len] = io_apic;
        self.io_apic_len += 1;
        Ok(())
    }

    pub fn add_interrupt_override(
        &mut self,
        override_entry: InterruptOverride,
    ) -> Result<(), Error> {
        if self.interrupt_overrides[..self.interrupt_override_len]
            .iter()
            .any(|existing| {
                existing.bus == override_entry.bus && existing.source == override_entry.source
            })
        {
            return Err(Error::DuplicateInterruptSource);
        }
        if self.interrupt_override_len == MAX_INTERRUPT_OVERRIDES {
            return Err(Error::InterruptOverrideCapacity);
        }
        self.interrupt_overrides[self.interrupt_override_len] = override_entry;
        self.interrupt_override_len += 1;
        Ok(())
    }

    pub fn add_memory(&mut self, memory: NumaMemory) -> Result<(), Error> {
        if memory.len == 0 {
            return Ok(());
        }
        let end = memory.end().ok_or(Error::Overflow)?;
        for existing in &self.memory[..self.memory_len] {
            let other_end = existing.end().ok_or(Error::Overflow)?;
            if memory.start < other_end && end > existing.start {
                return Err(Error::OverlappingMemoryAffinity);
            }
        }
        if self.memory_len == M {
            return Err(Error::MemoryCapacity);
        }
        self.memory[self.memory_len] = memory;
        self.memory_len += 1;
        Ok(())
    }

    fn apply_srat(&mut self, srat: &Srat<'_>) -> Result<(), Error> {
        for entry in srat.entries() {
            match entry.map_err(|_| Error::Firmware)? {
                SratEntry::LocalApicAffinity {
                    proximity_domain,
                    apic_id,
                    enabled,
                    ..
                } => {
                    self.set_cpu_domain(apic_id as u32, proximity_domain, enabled);
                }
                SratEntry::LocalX2ApicAffinity {
                    proximity_domain,
                    x2apic_id,
                    enabled,
                    ..
                } => {
                    self.set_cpu_domain(x2apic_id, proximity_domain, enabled);
                }
                SratEntry::MemoryAffinity {
                    proximity_domain,
                    base,
                    len,
                    enabled,
                    hot_pluggable,
                    non_volatile,
                } if enabled => {
                    self.add_memory(NumaMemory {
                        proximity_domain,
                        start: base,
                        len,
                        hot_pluggable,
                        non_volatile,
                    })?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn set_cpu_domain(&mut self, apic_id: u32, domain: u32, enabled: bool) {
        if let Some(cpu) = self.cpus[..self.cpu_len]
            .iter_mut()
            .find(|cpu| cpu.apic_id == apic_id)
        {
            cpu.proximity_domain = Some(domain);
            cpu.enabled &= enabled;
        }
    }

    pub fn numa_distance_class(&self, a_cpu: usize, b_cpu: usize) -> Option<DistanceClass> {
        let a = self.cpus().get(a_cpu)?.proximity_domain;
        let b = self.cpus().get(b_cpu)?.proximity_domain;
        Some(if a.is_some() && a == b {
            DistanceClass::Local
        } else {
            DistanceClass::RemoteOrUnknown
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistanceClass {
    Local,
    RemoteOrUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_apic_ids_are_rejected() {
        let mut topology = Topology::<4, 4>::new();
        topology
            .add_cpu(Cpu {
                apic_id: 7,
                processor_uid: 1,
                enabled: true,
                proximity_domain: None,
            })
            .unwrap();
        assert_eq!(
            topology.add_cpu(Cpu {
                apic_id: 7,
                processor_uid: 2,
                enabled: true,
                proximity_domain: None
            }),
            Err(Error::DuplicateApicId)
        );
    }

    #[test]
    fn streaming_madt_entries_populate_cpu_and_interrupt_topology() {
        let mut topology = Topology::<4, 1>::new();
        topology
            .apply_madt_entry(MadtEntry::LocalApic {
                processor_uid: 3,
                apic_id: 7,
                flags: 1,
            })
            .unwrap();
        topology
            .apply_madt_entry(MadtEntry::IoApic {
                io_apic_id: 2,
                address: 0xfec0_0000,
                gsi_base: 0,
            })
            .unwrap();
        topology
            .apply_madt_entry(MadtEntry::InterruptSourceOverride {
                bus: 0,
                source: 0,
                gsi: 2,
                flags: 0,
            })
            .unwrap();
        topology
            .apply_madt_entry(MadtEntry::LocalApicAddressOverride {
                address: 0xfee0_1000,
            })
            .unwrap();
        assert_eq!(topology.enabled_cpu_count(), 1);
        assert_eq!(topology.io_apics().len(), 1);
        assert_eq!(topology.interrupt_overrides()[0].gsi, 2);
        assert_eq!(topology.local_apic_address(), 0xfee0_1000);
    }

    #[test]
    fn duplicate_io_apic_and_source_override_are_rejected() {
        let mut topology = Topology::<1, 1>::new();
        let io = IoApic {
            id: 1,
            address: 0xfec0_0000,
            gsi_base: 0,
        };
        topology.add_io_apic(io).unwrap();
        assert_eq!(topology.add_io_apic(io), Err(Error::DuplicateIoApicId));
        let iso = InterruptOverride {
            bus: 0,
            source: 1,
            gsi: 1,
            flags: 0,
        };
        topology.add_interrupt_override(iso).unwrap();
        assert_eq!(
            topology.add_interrupt_override(iso),
            Err(Error::DuplicateInterruptSource)
        );
    }

    #[test]
    fn overlapping_numa_memory_is_rejected() {
        let mut topology = Topology::<1, 4>::new();
        topology
            .add_memory(NumaMemory {
                proximity_domain: 0,
                start: 0x1000,
                len: 0x3000,
                hot_pluggable: false,
                non_volatile: false,
            })
            .unwrap();
        assert_eq!(
            topology.add_memory(NumaMemory {
                proximity_domain: 1,
                start: 0x3000,
                len: 0x2000,
                hot_pluggable: false,
                non_volatile: false
            }),
            Err(Error::OverlappingMemoryAffinity)
        );
    }

    #[test]
    fn local_distance_requires_same_known_domain() {
        let mut topology = Topology::<2, 1>::new();
        topology
            .add_cpu(Cpu {
                apic_id: 1,
                processor_uid: 1,
                enabled: true,
                proximity_domain: Some(3),
            })
            .unwrap();
        topology
            .add_cpu(Cpu {
                apic_id: 2,
                processor_uid: 2,
                enabled: true,
                proximity_domain: Some(3),
            })
            .unwrap();
        assert_eq!(
            topology.numa_distance_class(0, 1),
            Some(DistanceClass::Local)
        );
    }
}
