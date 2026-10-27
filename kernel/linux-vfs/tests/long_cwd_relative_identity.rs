// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::{
    Error, FsContext, LINUX_PATH_MAX, MutableTimestamp, RootId, RootedMutableError,
    RootedMutableNamespace,
};

const ROOT: RootId = RootId::new(139);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 29,
    nanoseconds: 0,
};
const COMPONENT: [u8; 240] = [b'x'; 240];
const DEPTH: usize = 18;

type Namespace = RootedMutableNamespace<32, 40, 1>;

#[test]
fn process_cwd_beyond_path_max_walks_dot_parent_and_child_by_identity() {
    let mut namespace = Namespace::new(ROOT);
    let mut current = namespace.root_directory();
    let mut current_handle = namespace.root_directory_handle();
    let mut process_parent = current_handle;
    let mut process_cwd = current_handle;

    for level in 0..DEPTH {
        namespace
            .create_directory(current, &COMPONENT, 0o755, 0, 0, NOW)
            .unwrap();
        let next_handle = namespace
            .directory_handle(current, &COMPONENT)
            .expect("directory identity must not require PATH_MAX-sized absolute text");
        let next = namespace
            .open_directory(current, &COMPONENT)
            .expect("identity traversal must survive long absolute text");

        if level + 1 == DEPTH {
            process_parent = current_handle;
            process_cwd = next_handle;
        }
        current = next;
        current_handle = next_handle;
    }

    namespace
        .create_directory(current, b"leaf", 0o755, 0, 0, NOW)
        .unwrap();
    let leaf = namespace.directory_handle(current, b"leaf").unwrap();

    assert!(DEPTH * COMPONENT.len() + (DEPTH - 1) > LINUX_PATH_MAX - 1);

    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut namespace, process_cwd).unwrap();

    assert_eq!(
        namespace.resolve_mutable_directory_component(context.cwd_handle(), b"."),
        Ok(process_cwd)
    );
    assert_eq!(
        namespace.resolve_mutable_directory_component(context.cwd_handle(), b".."),
        Ok(process_parent)
    );
    assert_eq!(
        namespace.resolve_mutable_directory_component(context.cwd_handle(), b"leaf"),
        Ok(leaf)
    );

    let mut output = [0u8; LINUX_PATH_MAX];
    assert_eq!(
        context.write_getcwd_live(&namespace, &mut output),
        Err(RootedMutableError::Path(Error::PathTooLong))
    );

    context.release_cwd(&mut namespace).unwrap();
    assert!(context.cwd_handle().is_root());
}
