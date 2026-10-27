// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_identity::{Error, LinuxIdentityTable};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{Personality, Process, ThreadObjectBindings};
use kernal_scheduler::RunQueue;
use kernal_scheduler_smp::GlobalThreadId;

const CPU0: CpuIndex = CpuIndex(0);

fn linux_process<const CAPS: usize, const OBJECTS: usize>(
    objects: &mut ObjectTable<OBJECTS>,
) -> Process<CAPS> {
    Process::create(objects, Personality::Linux).unwrap()
}

#[test]
fn exact_parent_child_binding_is_idempotent_and_cannot_be_reparented() {
    let mut objects = ObjectTable::<6>::new();
    let parent = linux_process::<4, 6>(&mut objects);
    let other_parent = linux_process::<4, 6>(&mut objects);
    let child = linux_process::<4, 6>(&mut objects);
    let mut identities = LinuxIdentityTable::<4, 1>::new();

    let parent_pid = identities.pid_for(&parent).unwrap();
    let child_pid = identities.bind_child(&parent, &child).unwrap();

    assert_eq!(identities.bind_child(&parent, &child), Ok(child_pid));
    assert_eq!(identities.parent_pid_for(&child), Ok(parent_pid));
    assert_eq!(identities.is_child_of(&parent, &child), Ok(true));
    assert_eq!(identities.is_child_of(&other_parent, &child), Ok(false));
    assert_eq!(
        identities.bind_child(&other_parent, &child),
        Err(Error::AlreadyParented)
    );
    assert_ne!(child_pid, parent_pid);
}

#[test]
fn self_parent_and_unpublished_parent_observation_fail_closed() {
    let mut objects = ObjectTable::<4>::new();
    let process = linux_process::<4, 4>(&mut objects);
    let child = linux_process::<4, 4>(&mut objects);
    let mut identities = LinuxIdentityTable::<2, 1>::new();

    assert_eq!(
        identities.bind_child(&process, &process),
        Err(Error::InvalidParent)
    );
    identities.pid_for(&child).unwrap();
    assert_eq!(
        identities.parent_pid_for(&child),
        Err(Error::ParentNotBound)
    );
}

#[test]
fn child_leader_publication_reuses_child_pid_and_preserves_exact_parent() {
    let mut objects = ObjectTable::<12>::new();
    let parent = linux_process::<6, 12>(&mut objects);
    let mut child = Process::<6>::create_fork_child(&parent, &mut objects).unwrap();
    let mut scheduler = RunQueue::<2>::new();
    let local = scheduler.create(9).unwrap();
    let global = GlobalThreadId::new(CPU0, local);
    let mut bindings = ThreadObjectBindings::<2>::new();
    let leader = child
        .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, global)
        .unwrap();
    let mut identities = LinuxIdentityTable::<4, 4>::new();

    let parent_pid = identities.pid_for(&parent).unwrap();
    let child_pid = identities.bind_child(&parent, &child).unwrap();
    let leader_tid = identities
        .bind_leader(&child, &objects, &bindings, &scheduler, CPU0, leader)
        .unwrap();

    assert_eq!(leader_tid, child_pid);
    assert_eq!(identities.bound_pid(&child), Ok(child_pid));
    assert_eq!(identities.parent_pid_for(&child), Ok(parent_pid));
    assert_eq!(identities.is_child_of(&parent, &child), Ok(true));
    assert_eq!(
        identities.bound_tid_for_scheduler_thread(&child, global),
        Ok(child_pid)
    );
}

#[test]
fn retired_child_generation_cannot_alias_replacement_process() {
    let mut objects = ObjectTable::<4>::new();
    let parent = linux_process::<4, 4>(&mut objects);
    let mut child = linux_process::<4, 4>(&mut objects);
    let child_object = child.id();
    let bindings = ThreadObjectBindings::<1>::new();
    let mut identities = LinuxIdentityTable::<3, 1>::new();

    let parent_pid = identities.pid_for(&parent).unwrap();
    let old_child_pid = identities.bind_child(&parent, &child).unwrap();
    child.exit(&mut objects, &bindings).unwrap();
    identities.retire_process(&child).unwrap();
    assert_eq!(identities.parent_pid_for(&child), Err(Error::ProcessExited));

    // The fixed-capacity ObjectTable must reuse the retired child's object slots here, but its
    // generation-safe ObjectId and the monotonic Linux PID remain distinct from the old child.
    let replacement = linux_process::<4, 4>(&mut objects);
    let replacement_pid = identities.bind_child(&parent, &replacement).unwrap();

    assert_ne!(replacement.id(), child_object);
    assert_ne!(replacement_pid, old_child_pid);
    assert_eq!(identities.parent_pid_for(&replacement), Ok(parent_pid));
    assert_eq!(identities.is_child_of(&parent, &replacement), Ok(true));
}
