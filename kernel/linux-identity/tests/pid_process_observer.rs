// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;
use kernal_linux_identity::{Error, LinuxIdentityTable};
use kernal_object::ObjectTable;
use kernal_process::{Personality, Process, ThreadObjectBindings};

#[test]
fn pid_observer_returns_exact_live_process_objects_without_mutating_identity_state() {
    let mut objects = ObjectTable::<12>::new();
    let mut first = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
    let second = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
    let third = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
    let mut identities = LinuxIdentityTable::<4, 0>::new();

    let first_pid = identities.pid_for(&first).unwrap();
    let second_pid = identities.pid_for(&second).unwrap();

    assert_eq!(identities.process_object_for_pid(first_pid), Ok(first.id()));
    assert_eq!(
        identities.process_object_for_pid(second_pid),
        Ok(second.id())
    );

    let missing = NonZeroU32::new(999).unwrap();
    assert_eq!(
        identities.process_object_for_pid(missing),
        Err(Error::ProcessNotBound)
    );

    for _ in 0..4 {
        assert_eq!(identities.process_object_for_pid(first_pid), Ok(first.id()));
        assert_eq!(
            identities.process_object_for_pid(second_pid),
            Ok(second.id())
        );
    }
    let third_pid = identities.pid_for(&third).unwrap();
    assert_eq!(third_pid.get(), second_pid.get() + 1);

    let bindings = ThreadObjectBindings::<0>::new();
    first.exit(&mut objects, &bindings).unwrap();
    identities.retire_process(&first).unwrap();
    assert_eq!(
        identities.process_object_for_pid(first_pid),
        Err(Error::ProcessNotBound)
    );
    assert_eq!(
        identities.process_object_for_pid(second_pid),
        Ok(second.id())
    );
}
