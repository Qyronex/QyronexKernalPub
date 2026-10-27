// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_fd::ExternalObject;

fn stable_stdio_code(object: ExternalObject) -> u8 {
    match object {
        ExternalObject::Stdin => 0,
        ExternalObject::Stdout => 1,
        ExternalObject::Stderr => 2,
    }
}

#[test]
fn public_external_object_surface_remains_exactly_the_three_stdio_streams() {
    assert_eq!(stable_stdio_code(ExternalObject::Stdin), 0);
    assert_eq!(stable_stdio_code(ExternalObject::Stdout), 1);
    assert_eq!(stable_stdio_code(ExternalObject::Stderr), 2);
}
