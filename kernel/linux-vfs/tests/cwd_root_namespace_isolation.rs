// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::{FsContext, RootId, RootedMutableError, RootedMutableNamespace};

const ROOT: RootId = RootId::new(149);
type Namespace = RootedMutableNamespace<4, 4, 8>;

#[test]
fn mutable_root_directory_handle_preserves_namespace_owner() {
    let a = Namespace::new(ROOT);
    let b = Namespace::new(ROOT);
    let root_a = a.root_directory_handle();

    assert_eq!(root_a.refresh_in(&a), Ok(root_a));
    assert_eq!(
        root_a.refresh_in(&b),
        Err(RootedMutableError::NamespaceMismatch)
    );
}

#[test]
fn process_root_cwd_cannot_cross_same_root_mutable_owners() {
    let mut a = Namespace::new(ROOT);
    let mut b = Namespace::new(ROOT);
    let root_a = a.root_directory_handle();
    let mut context = FsContext::new(ROOT);

    // Bind the process cwd to the exact mutable root owner. A root has no inode slot to retain, but
    // its namespace-instance witness is still part of cwd authority.
    context.set_cwd(&mut a, root_a).unwrap();
    assert_eq!(context.cwd_handle(), root_a);

    // Equal RootId is insufficient: switching the namespace argument must not turn the current root
    // into a foreign owner's root through the same-cwd no-op path.
    assert_eq!(
        context.set_cwd(&mut b, root_a),
        Err(RootedMutableError::NamespaceMismatch)
    );
    assert_eq!(context.cwd_handle(), root_a);

    context.release_cwd(&mut a).unwrap();
}
