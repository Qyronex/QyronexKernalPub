// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapError, CapRights};
use kernal_object::ObjectTable;
use kernal_process::{Error, Personality, Process};

#[test]
fn linux_personality_keeps_raw_handles_process_local() {
    let mut objects = ObjectTable::<4>::new();
    let left = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
    let right = Process::<8>::create(&mut objects, Personality::Linux).unwrap();

    // Capability handles are local CSpace names. A numerically identical handle from another
    // Linux process must resolve only inside the receiving process's own namespace.
    assert_eq!(left.self_handle(), right.self_handle());
    let resolved = right
        .resolve_object(&objects, left.self_handle(), CapRights::CONTROL)
        .unwrap();
    assert_eq!(resolved.object, right.id());
    assert_ne!(resolved.object, left.id());

    assert_eq!(left.address_space_handle(), right.address_space_handle());
    let resolved_address_space = right
        .resolve_object(&objects, left.address_space_handle(), CapRights::MAP)
        .unwrap();
    assert_eq!(resolved_address_space.object, right.address_space());
    assert_ne!(resolved_address_space.object, left.address_space());
}

#[test]
fn linux_personality_cannot_turn_derived_map_authority_into_grant() {
    let mut objects = ObjectTable::<4>::new();
    let mut source = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
    let mut target = Process::<8>::create(&mut objects, Personality::Linux).unwrap();

    let map_only = source
        .derive_cap(source.address_space_handle(), CapRights::MAP)
        .unwrap();
    assert_eq!(
        source.delegate_to(&objects, map_only, CapRights::MAP, &mut target),
        Err(Error::Capability(CapError::InsufficientRights))
    );

    let delegated = source
        .delegate_to(
            &objects,
            source.address_space_handle(),
            CapRights::MAP,
            &mut target,
        )
        .unwrap();
    let resolved = target
        .resolve_object(&objects, delegated, CapRights::MAP)
        .unwrap();
    assert_eq!(resolved.object, source.address_space());
    assert_eq!(resolved.rights, CapRights::MAP);
    assert_eq!(
        target.resolve_object(&objects, delegated, CapRights::CONTROL),
        Err(Error::Capability(CapError::InsufficientRights))
    );
}
