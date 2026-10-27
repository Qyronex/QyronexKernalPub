// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::{
    FsContext, MutableError, MutableTimestamp, RootId, RootedMutableError, RootedMutableNamespace,
};

const ROOT: RootId = RootId::new(131);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 17,
    nanoseconds: 0,
};

type Namespace = RootedMutableNamespace<2, 8, 1>;

#[test]
fn cwd_replacement_and_teardown_own_exactly_one_mutable_hold() {
    let mut namespace = Namespace::new(ROOT);
    let root = namespace.root_directory();

    namespace
        .create_directory(root, b"first", 0o755, 0, 0, NOW)
        .unwrap();
    namespace
        .create_directory(root, b"second", 0o755, 0, 0, NOW)
        .unwrap();

    let first_cwd = namespace.directory_handle(root, b"first").unwrap();
    let second_cwd = namespace.directory_handle(root, b"second").unwrap();

    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut namespace, first_cwd).unwrap();
    context.set_cwd(&mut namespace, second_cwd).unwrap();

    namespace.unlink(root, b"first", true).unwrap();
    namespace.unlink(root, b"second", true).unwrap();

    namespace
        .create_directory(root, b"reused", 0o755, 0, 0, NOW)
        .expect("replaced cwd must release its old mutable-directory hold");
    assert_eq!(
        namespace.create_directory(root, b"must-wait", 0o755, 0, 0, NOW),
        Err(RootedMutableError::Mutable(MutableError::NodeTableFull))
    );
    assert_eq!(context.cwd_handle(), second_cwd);

    context.release_cwd(&mut namespace).unwrap();
    namespace
        .create_directory(root, b"after-teardown", 0o755, 0, 0, NOW)
        .expect("explicit cwd teardown must release the final mutable-directory hold");
    assert!(context.cwd_handle().is_root());
}

#[test]
fn failed_new_cwd_retain_preserves_old_identity_and_hold() {
    let mut namespace = Namespace::new(ROOT);
    let root = namespace.root_directory();

    namespace
        .create_directory(root, b"held", 0o755, 0, 0, NOW)
        .unwrap();
    namespace
        .create_directory(root, b"stale", 0o755, 0, 0, NOW)
        .unwrap();

    let held_cwd = namespace.directory_handle(root, b"held").unwrap();
    let stale_cwd = namespace.directory_handle(root, b"stale").unwrap();
    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut namespace, held_cwd).unwrap();

    namespace.unlink(root, b"stale", true).unwrap();
    assert_eq!(
        context.set_cwd(&mut namespace, stale_cwd),
        Err(RootedMutableError::Mutable(MutableError::BadNode))
    );
    assert_eq!(context.cwd_handle(), held_cwd);

    namespace.unlink(root, b"held", true).unwrap();
    namespace
        .create_directory(root, b"one-free-slot", 0o755, 0, 0, NOW)
        .unwrap();
    assert_eq!(
        namespace.create_directory(root, b"held-still-blocks", 0o755, 0, 0, NOW),
        Err(RootedMutableError::Mutable(MutableError::NodeTableFull))
    );

    context.release_cwd(&mut namespace).unwrap();
    namespace
        .create_directory(root, b"released", 0o755, 0, 0, NOW)
        .unwrap();
}

#[test]
fn closing_fchdir_source_hold_does_not_release_cwd_hold() {
    let mut namespace = Namespace::new(ROOT);
    let root = namespace.root_directory();
    namespace
        .create_directory(root, b"from-fd", 0o755, 0, 0, NOW)
        .unwrap();

    let node = namespace.lookup(root, b"from-fd").unwrap();
    let cwd = namespace.directory_handle(root, b"from-fd").unwrap();

    // Model the independent lifetime owned by an opened directory FD. fchdir must acquire a second
    // cwd-owned reference rather than borrowing the descriptor's hold.
    namespace.retain_open(node).unwrap();
    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut namespace, cwd).unwrap();

    // Closing the source FD releases only its own reference. The cwd reference must keep the
    // generation alive after the directory entry itself is removed.
    namespace.release_open(node).unwrap();
    namespace.unlink(root, b"from-fd", true).unwrap();

    namespace
        .create_directory(root, b"free-slot", 0o755, 0, 0, NOW)
        .unwrap();
    assert_eq!(
        namespace.create_directory(root, b"cwd-still-owns-node", 0o755, 0, 0, NOW),
        Err(RootedMutableError::Mutable(MutableError::NodeTableFull))
    );

    context.release_cwd(&mut namespace).unwrap();
    namespace
        .create_directory(root, b"after-cwd-release", 0o755, 0, 0, NOW)
        .expect("closing the fchdir source FD must never have consumed the cwd-owned hold");
}

#[test]
fn same_cwd_noop_still_validates_namespace_instance() {
    let mut a = Namespace::new(ROOT);
    let mut b = Namespace::new(ROOT);
    let root_a = a.root_directory();

    a.create_directory(root_a, b"held", 0o755, 0, 0, NOW)
        .unwrap();
    let cwd = a.directory_handle(root_a, b"held").unwrap();

    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut a, cwd).unwrap();

    assert_eq!(
        context.set_cwd(&mut b, cwd),
        Err(RootedMutableError::NamespaceMismatch)
    );
    assert_eq!(context.cwd_handle(), cwd);

    context.release_cwd(&mut a).unwrap();
    a.unlink(root_a, b"held", true).unwrap();
    a.create_directory(root_a, b"reused", 0o755, 0, 0, NOW)
        .expect("failed foreign-namespace noop must not perturb the original cwd hold");
}
