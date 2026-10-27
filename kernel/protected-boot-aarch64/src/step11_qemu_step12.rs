// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

mod accepted_step11 {
    include!("step11_qemu.rs");
}

pub fn run(serial: &crate::Serial, backend: &mut crate::RuntimeTablePool) {
    accepted_step11::run(serial, backend);

    #[cfg(feature = "step12-qemu-proof")]
    crate::step12_qemu::run(serial, backend);

    #[cfg(feature = "step13-qemu-proof")]
    crate::step13_qemu::run(serial, backend);

    #[cfg(feature = "step14-qemu-proof")]
    crate::step14_qemu::run(serial, backend);
}
