// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use kernal_ioapic_x86_64::{IoApic, MmioAccess};
use kernal_kmap_x86_64::KmapController;
use kernal_topology::Topology;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedHostArchitecture,
    LegacyPicMaskFailed,
    IoApicMapping,
    IoApicProbe,
    IoApicIdentityMismatch,
    IoApicMask,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuiesceReport {
    pub io_apics_masked: usize,
    pub redirection_entries_masked: usize,
}

/// Places all ordinary external IRQ sources into a fail-closed state before the kernel ever
/// enables IF. NMI/SMI are intentionally outside this mechanism.
///
/// # Safety
/// Must execute at CPL0 on the bootstrap processor with interrupts disabled. `kmap` must be the
/// prepared BSP temporary mapping window and MADT topology must already be validated.
#[cfg(target_arch = "x86_64")]
pub unsafe fn quiesce<const C: usize, const M: usize>(
    topology: &Topology<C, M>,
    kmap: &KmapController,
) -> Result<QuiesceReport, Error> {
    // SAFETY: delegated CPL0/I/O-port contract.
    let masks = unsafe { kernal_pic8259_x86_64::mask_all() };
    // SAFETY: same contract; reading back verifies the mask write reached the controllers.
    let readback = unsafe { kernal_pic8259_x86_64::read_masks() };
    if masks.master != 0xff
        || masks.slave != 0xff
        || readback.master != 0xff
        || readback.slave != 0xff
    {
        return Err(Error::LegacyPicMaskFailed);
    }

    let mut report = QuiesceReport::default();
    for firmware in topology.io_apics() {
        let access =
            MmioAccess::map(kmap, firmware.address as u64).map_err(|_| Error::IoApicMapping)?;
        let mut controller =
            IoApic::probe(access, firmware.gsi_base).map_err(|_| Error::IoApicProbe)?;
        if controller.id().map_err(|_| Error::IoApicProbe)? != (firmware.id & 0x0f) {
            return Err(Error::IoApicIdentityMismatch);
        }
        let count = controller.redirection_entries() as usize;
        controller.mask_all().map_err(|_| Error::IoApicMask)?;
        report.io_apics_masked += 1;
        report.redirection_entries_masked = report.redirection_entries_masked.saturating_add(count);
        // Dropping controller/access removes only our temporary virtual MMIO view. The IOAPIC's
        // hardware mask bits remain set until an explicit routing operation changes them.
    }
    Ok(report)
}

/// Foreign-host support builds never emulate PIC/IOAPIC hardware actions.
///
/// # Safety
/// No privileged operation is performed on this path; it always fails closed.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn quiesce<const C: usize, const M: usize>(
    topology: &Topology<C, M>,
    kmap: &KmapController,
) -> Result<QuiesceReport, Error> {
    let _ = (topology, kmap);
    Err(Error::UnsupportedHostArchitecture)
}
