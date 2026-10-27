// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::{LINUX_PATH_MAX, MutableTimestamp, RootId, RootedMutableNamespace};

const ROOT: RootId = RootId::new(109);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 19,
    nanoseconds: 0,
};
const COMPONENT: [u8; 240] = [b'x'; 240];
const DEPTH: usize = 18;

type Namespace = RootedMutableNamespace<32, 40, 1>;

#[test]
fn mutable_directory_identity_does_not_depend_on_path_max_text() {
    let mut namespace = Namespace::new(ROOT);
    let mut current = namespace.root_directory();

    for _ in 0..DEPTH {
        namespace
            .create_directory(current, &COMPONENT, 0o755, 0, 0, NOW)
            .unwrap();
        current = namespace
            .open_directory(current, &COMPONENT)
            .expect("directory identity traversal must not require a PATH_MAX absolute snapshot");
    }

    assert!(DEPTH * COMPONENT.len() + (DEPTH - 1) > LINUX_PATH_MAX - 1);

    // Namespace-relative work from the identity remains valid even though textual getcwd for this
    // location cannot fit in Linux PATH_MAX.
    let leaf = namespace
        .create_regular(current, b"leaf", 0o600, 0, 0, NOW)
        .expect("relative child creation must remain identity-based beyond PATH_MAX");
    assert_eq!(namespace.lookup(current, b"leaf"), Ok(leaf));
}
