// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableTimestamp, OverlayNamespace, OverlayNodeHandle, RootId,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(119);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 7,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 16, 24, 64, 8>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, inode: u32, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        inode,
        mode,
        0,
        0,
        1,
        0,
        u32::try_from(data.len()).unwrap(),
        0,
        0,
        0,
        0,
        u32::try_from(path.len() + 1).unwrap(),
        0,
    ] {
        hex(out, value);
    }
    assert_eq!(out.len() - start, HEADER_LEN);
    out.extend_from_slice(path);
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, 1, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, 2, b"etc", S_IFDIR | 0o755, b"");
    entry(&mut out, 3, b"etc/base", S_IFREG | 0o644, b"base");
    entry(&mut out, 4, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn retained_bound_lower_directory_survives_relative_rename_with_lower_child_authority() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let root = overlay.open_and_retain_directory_at(b"/").unwrap();
    let retained = overlay.open_and_retain_directory_at(b"/etc").unwrap();
    let stable_identity = retained.object();
    assert!(matches!(
        stable_identity,
        OverlayNodeHandle::Immutable { .. }
    ));

    // Creating through the retained lower directory materializes its exact Upper binding while the
    // logical directory identity remains the immutable lower handle.
    overlay
        .create_regular_from(retained, b"seed", 0o600, 0, 0, T)
        .unwrap();
    assert_eq!(
        overlay.open_directory_at(b"/etc").unwrap().object(),
        stable_identity
    );

    // The retained-relative rename must re-enter that binding instead of rejecting the immutable
    // logical handle as a pure lower directory.
    overlay
        .rename_from(root, b"etc", root, b"moved", false)
        .unwrap();

    assert_eq!(overlay.lookup_at(b"/etc").unwrap(), None);
    assert_eq!(overlay.lookup_at(b"/moved").unwrap(), Some(stable_identity));
    assert_eq!(
        overlay.open_directory_at(b"/moved").unwrap().object(),
        stable_identity
    );

    // The pre-rename retained identity remains authoritative for untouched lower provenance after
    // the pathname move, not only for newly published Upper children.
    let base = overlay.resolve_following_from(retained, b"base").unwrap();
    assert!(matches!(base, OverlayNodeHandle::Immutable { .. }));

    overlay
        .create_regular_from(retained, b"after-move", 0o600, 0, 0, T)
        .unwrap();
    assert!(matches!(
        overlay.lookup_at(b"/moved/after-move").unwrap(),
        Some(OverlayNodeHandle::Mutable(_))
    ));

    // Presentation follows the live Upper binding, while authority remains the stable lower object.
    let canonical = overlay.directory_canonical_path(retained).unwrap();
    assert_eq!(canonical.as_relative_bytes(), b"moved");

    overlay.release_directory(retained).unwrap();
    overlay.release_directory(root).unwrap();
}
