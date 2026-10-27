// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::{
    Error, FsContext, LINUX_PATH_MAX, MutableTimestamp, RootId, RootedMutableError,
    RootedMutableNamespace,
};

const ROOT: RootId = RootId::new(137);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 23,
    nanoseconds: 0,
};
const COMPONENT: [u8; 240] = [b'x'; 240];
const DEPTH: usize = 18;

type Namespace = RootedMutableNamespace<32, 40, 1>;

#[test]
fn retained_long_cwd_fails_only_text_materialization() {
    let mut namespace = Namespace::new(ROOT);
    let mut current = namespace.root_directory();
    let mut process_cwd = namespace.root_directory_handle();

    for level in 0..DEPTH {
        namespace
            .create_directory(current, &COMPONENT, 0o755, 0, 0, NOW)
            .unwrap();

        if level + 1 == DEPTH {
            process_cwd = namespace
                .directory_handle(current, &COMPONENT)
                .expect("cwd identity must not require PATH_MAX-sized absolute text");
        }

        current = namespace
            .open_directory(current, &COMPONENT)
            .expect("identity traversal must survive long absolute text");
    }

    assert!(DEPTH * COMPONENT.len() + (DEPTH - 1) > LINUX_PATH_MAX - 1);

    let mut context = FsContext::new(ROOT);
    context.set_cwd(&mut namespace, process_cwd).unwrap();
    assert_eq!(context.cwd_handle(), process_cwd);

    let mut output = [0u8; LINUX_PATH_MAX];
    assert_eq!(
        context.write_getcwd_live(&namespace, &mut output),
        Err(RootedMutableError::Path(Error::PathTooLong))
    );

    context.release_cwd(&mut namespace).unwrap();
    assert!(context.cwd_handle().is_root());
    assert_eq!(context.root(), ROOT);
}
