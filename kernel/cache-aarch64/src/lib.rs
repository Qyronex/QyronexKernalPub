// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::asm;

const CTR_IMINLINE_SHIFT: u32 = 0;
const CTR_DMINLINE_SHIFT: u32 = 16;
const CTR_LINE_MASK: u64 = 0xf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RangeOverflow,
    UnsupportedHostArchitecture,
}

/// Cache-line geometry encoded by CTR_EL0.
///
/// `IminLine` and `DminLine` are log2(words), so the architectural byte size is `4 << field`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheGeometry {
    instruction_line_bytes: u64,
    data_line_bytes: u64,
}

impl CacheGeometry {
    pub const fn from_ctr_el0(raw: u64) -> Self {
        Self {
            instruction_line_bytes: line_bytes(raw, CTR_IMINLINE_SHIFT),
            data_line_bytes: line_bytes(raw, CTR_DMINLINE_SHIFT),
        }
    }

    pub const fn instruction_line_bytes(self) -> u64 {
        self.instruction_line_bytes
    }

    pub const fn data_line_bytes(self) -> u64 {
        self.data_line_bytes
    }
}

const fn line_bytes(raw: u64, shift: u32) -> u64 {
    let log2_words = ((raw >> shift) & CTR_LINE_MASK) as u32;
    4u64 << log2_words
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn line_start(address: u64, line_bytes: u64) -> u64 {
    address & !(line_bytes - 1)
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn checked_end(start: u64, len: u64) -> Result<u64, Error> {
    start.checked_add(len).ok_or(Error::RangeOverflow)
}

/// Makes bytes written through one virtual alias safe to execute through another virtual alias.
///
/// This implements the architectural self-modifying-code sequence over every cache line touched by
/// the range:
///
/// 1. clean D-cache lines for `write_alias_start` to the Point of Unification (`DC CVAU`),
/// 2. `DSB ISH`,
/// 3. invalidate I-cache lines for `execute_alias_start` to the Point of Unification (`IC IVAU`),
/// 4. `DSB ISH`, then `ISB`.
///
/// Keeping the aliases separate is intentional: Step 8 writes a fresh user-code frame through a
/// privileged kernel mapping but later fetches it through a lower-half EL0 VA. The instruction-cache
/// maintenance must therefore use the address from which the code will actually execute.
///
/// A zero-length range is a no-op.
///
/// # Safety
///
/// Caller must execute at EL1 and guarantee that:
/// - both VA ranges are valid in the currently active translation regime for the complete operation;
/// - both aliases name the same physical byte range and `len` bytes are backed by Normal cacheable
///   memory;
/// - all code writes through `write_alias_start` are complete from this PE before the call;
/// - no PE executes the modified range until this function has completed and the executing PE has
///   observed the final context-synchronization event.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn sync_modified_code(
    write_alias_start: u64,
    execute_alias_start: u64,
    len: u64,
) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    let write_end = checked_end(write_alias_start, len)?;
    let execute_end = checked_end(execute_alias_start, len)?;

    let ctr_el0: u64;
    // SAFETY: CTR_EL0 is architecturally readable from EL1 and does not mutate machine state.
    unsafe {
        asm!(
            "mrs {value}, CTR_EL0",
            value = out(reg) ctr_el0,
            options(nomem, nostack, preserves_flags)
        )
    };
    let geometry = CacheGeometry::from_ctr_el0(ctr_el0);

    let mut address = line_start(write_alias_start, geometry.data_line_bytes());
    while address < write_end {
        // SAFETY: caller guarantees this VA resolves to the modified Normal-memory range.
        unsafe {
            asm!(
                "dc cvau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            )
        };
        let Some(next) = address.checked_add(geometry.data_line_bytes()) else {
            break;
        };
        address = next;
    }

    // SAFETY: DSB orders completion/visibility of the preceding clean operations to the PoU.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };

    address = line_start(execute_alias_start, geometry.instruction_line_bytes());
    while address < execute_end {
        // SAFETY: caller guarantees this VA is the alias from which the modified bytes execute.
        unsafe {
            asm!(
                "ic ivau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            )
        };
        let Some(next) = address.checked_add(geometry.instruction_line_bytes()) else {
            break;
        };
        address = next;
    }

    // SAFETY: complete the instruction-cache invalidation before refetching subsequent instructions.
    unsafe {
        asm!("dsb ish", options(nostack, preserves_flags));
        asm!("isb", options(nostack, preserves_flags));
    }
    Ok(())
}

/// Host-build stub preserving the target API without pretending to perform cache maintenance.
///
/// # Safety
/// No privileged operation is executed on this host-only path.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub unsafe fn sync_modified_code(
    _write_alias_start: u64,
    _execute_alias_start: u64,
    _len: u64,
) -> Result<(), Error> {
    Err(Error::UnsupportedHostArchitecture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctr_geometry_decodes_architectural_word_exponents() {
        let raw = (5u64 << CTR_DMINLINE_SHIFT) | (4u64 << CTR_IMINLINE_SHIFT);
        let geometry = CacheGeometry::from_ctr_el0(raw);
        assert_eq!(geometry.data_line_bytes(), 128);
        assert_eq!(geometry.instruction_line_bytes(), 64);
    }

    #[test]
    fn line_start_rounds_down_to_the_cache_line() {
        assert_eq!(line_start(0x1234, 64), 0x1200);
        assert_eq!(line_start(0x12ff, 128), 0x1280);
    }

    #[test]
    fn range_end_fails_closed_on_overflow() {
        assert_eq!(checked_end(u64::MAX - 7, 8), Err(Error::RangeOverflow));
        assert_eq!(checked_end(0x1000, 0x2000), Ok(0x3000));
    }
}
