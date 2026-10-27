// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::live_vm;
use kernal_linux_abi::{Errno, MinimumRuntimeCall};
use kernal_linux_vm::Error as VmError;

const PROT_READ: u64 = 0x1;

/// Step-28's bounded `mprotect(2)` admission layer.
///
/// The unchanged static BusyBox/glibc startup path uses `mprotect(PROT_READ)` to seal its RELRO
/// pages. Step 28 deliberately admits only that monotone permission reduction; all page-range,
/// mapping-presence, W^X, transaction-bound and architecture mutation semantics remain in the shared
/// `kernal-linux-vm` owner and its canonical AArch64 adapter.
pub(super) fn handle(address: u64, length: u64, protection: u64) -> Result<Result<u64, Errno>, ()> {
    if protection != PROT_READ {
        return Ok(Err(Errno::EINVAL));
    }

    match live_vm::handle(MinimumRuntimeCall::Mprotect {
        address,
        length,
        protection,
    }) {
        Ok(Ok(result)) => Ok(Ok(result)),
        Ok(Err(VmError::Linux(errno))) => Ok(Err(errno)),
        Ok(Err(_)) | Err(()) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step28_admission_rejects_permission_promotion_before_runtime_access() {
        assert_eq!(handle(0x1_0000, 0x1000, 0x3), Ok(Err(Errno::EINVAL)));
        assert_eq!(handle(0x1_0000, 0x1000, 0x5), Ok(Err(Errno::EINVAL)));
    }
}
