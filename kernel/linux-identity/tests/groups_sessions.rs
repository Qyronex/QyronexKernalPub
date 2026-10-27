// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_identity::{Error, LinuxIdentityTable};
use kernal_object::ObjectTable;
use kernal_process::{Personality, Process, ThreadObjectBindings};

fn linux_process<const CAPS: usize, const OBJECTS: usize>(
    objects: &mut ObjectTable<OBJECTS>,
) -> Process<CAPS> {
    Process::create(objects, Personality::Linux).unwrap()
}

#[test]
fn standalone_process_is_group_and_session_leader_and_child_inherits_both() {
    let mut objects = ObjectTable::<8>::new();
    let parent = linux_process::<4, 8>(&mut objects);
    let child = linux_process::<4, 8>(&mut objects);
    let mut identities = LinuxIdentityTable::<4, 1>::new();

    let parent_pid = identities.pid_for(&parent).unwrap();
    assert_eq!(identities.getpgid(&parent), Ok(parent_pid));
    assert_eq!(identities.getsid(&parent), Ok(parent_pid));

    let child_pid = identities.bind_child(&parent, &child).unwrap();
    assert_ne!(child_pid, parent_pid);
    assert_eq!(identities.getpgid(&child), Ok(parent_pid));
    assert_eq!(identities.getsid(&child), Ok(parent_pid));
}

#[test]
fn parent_can_create_child_group_and_join_a_sibling_without_new_registry() {
    let mut objects = ObjectTable::<10>::new();
    let parent = linux_process::<4, 10>(&mut objects);
    let first = linux_process::<4, 10>(&mut objects);
    let second = linux_process::<4, 10>(&mut objects);
    let mut identities = LinuxIdentityTable::<6, 1>::new();

    let parent_pid = identities.pid_for(&parent).unwrap();
    let first_pid = identities.bind_child(&parent, &first).unwrap();
    identities.bind_child(&parent, &second).unwrap();

    assert_eq!(identities.setpgid(&parent, &first, 0), Ok(first_pid));
    assert_eq!(
        identities.setpgid(&parent, &second, first_pid.get() as i32),
        Ok(first_pid)
    );
    assert_eq!(identities.getpgid(&first), Ok(first_pid));
    assert_eq!(identities.getpgid(&second), Ok(first_pid));
    assert_eq!(identities.getsid(&first), Ok(parent_pid));
    assert_eq!(identities.getsid(&second), Ok(parent_pid));
}

#[test]
fn setsid_succeeds_only_for_non_group_leader_and_separates_parent_session() {
    let mut objects = ObjectTable::<8>::new();
    let parent = linux_process::<4, 8>(&mut objects);
    let child = linux_process::<4, 8>(&mut objects);
    let mut identities = LinuxIdentityTable::<4, 1>::new();

    identities.pid_for(&parent).unwrap();
    let child_pid = identities.bind_child(&parent, &child).unwrap();
    assert_eq!(identities.setsid(&child), Ok(child_pid));
    assert_eq!(identities.getpgid(&child), Ok(child_pid));
    assert_eq!(identities.getsid(&child), Ok(child_pid));
    assert_eq!(identities.setsid(&child), Err(Error::ProcessGroupLeader));
    assert_eq!(
        identities.setpgid(&parent, &child, 0),
        Err(Error::DifferentSession)
    );
}

#[test]
fn setpgid_rejects_unrelated_targets_session_leaders_and_missing_groups() {
    let mut objects = ObjectTable::<10>::new();
    let parent = linux_process::<4, 10>(&mut objects);
    let child = linux_process::<4, 10>(&mut objects);
    let unrelated = linux_process::<4, 10>(&mut objects);
    let mut identities = LinuxIdentityTable::<6, 1>::new();

    identities.pid_for(&parent).unwrap();
    identities.bind_child(&parent, &child).unwrap();
    identities.pid_for(&unrelated).unwrap();

    assert_eq!(
        identities.setpgid(&parent, &unrelated, 0),
        Err(Error::InvalidProcessGroupTarget)
    );
    assert_eq!(
        identities.setpgid(&parent, &child, -1),
        Err(Error::InvalidProcessGroup)
    );
    assert_eq!(
        identities.setpgid(&parent, &child, 777),
        Err(Error::ProcessGroupNotFound)
    );
    assert_eq!(
        identities.setpgid(&parent, &parent, 0),
        Err(Error::SessionLeader)
    );
}

#[test]
fn live_member_keeps_group_joinable_after_original_group_leader_retires() {
    let mut objects = ObjectTable::<12>::new();
    let parent = linux_process::<4, 12>(&mut objects);
    let mut leader = linux_process::<4, 12>(&mut objects);
    let member = linux_process::<4, 12>(&mut objects);
    let newcomer = linux_process::<4, 12>(&mut objects);
    let mut identities = LinuxIdentityTable::<8, 1>::new();

    identities.pid_for(&parent).unwrap();
    let group = identities.bind_child(&parent, &leader).unwrap();
    identities.bind_child(&parent, &member).unwrap();
    identities.bind_child(&parent, &newcomer).unwrap();
    identities.setpgid(&parent, &leader, 0).unwrap();
    identities
        .setpgid(&parent, &member, group.get() as i32)
        .unwrap();

    let bindings = ThreadObjectBindings::<1>::new();
    leader.exit(&mut objects, &bindings).unwrap();
    identities.retire_process(&leader).unwrap();

    assert_eq!(
        identities.setpgid(&parent, &newcomer, group.get() as i32),
        Ok(group)
    );
    assert_eq!(identities.getpgid(&newcomer), Ok(group));
}

#[test]
fn setsid_rejects_when_another_member_keeps_caller_pid_group_alive() {
    let mut objects = ObjectTable::<14>::new();
    let parent = linux_process::<4, 14>(&mut objects);
    let caller = linux_process::<4, 14>(&mut objects);
    let keeper = linux_process::<4, 14>(&mut objects);
    let other_leader = linux_process::<4, 14>(&mut objects);
    let mut identities = LinuxIdentityTable::<8, 1>::new();

    identities.pid_for(&parent).unwrap();
    let caller_pid = identities.bind_child(&parent, &caller).unwrap();
    identities.bind_child(&parent, &keeper).unwrap();
    let other_group = identities.bind_child(&parent, &other_leader).unwrap();

    identities.setpgid(&parent, &caller, 0).unwrap();
    identities
        .setpgid(&parent, &keeper, caller_pid.get() as i32)
        .unwrap();
    identities.setpgid(&parent, &other_leader, 0).unwrap();
    identities
        .setpgid(&parent, &caller, other_group.get() as i32)
        .unwrap();
    assert_eq!(identities.getpgid(&caller), Ok(other_group));
    assert_eq!(identities.getpgid(&keeper), Ok(caller_pid));
    assert_eq!(identities.setsid(&caller), Err(Error::ProcessGroupLeader));
}
