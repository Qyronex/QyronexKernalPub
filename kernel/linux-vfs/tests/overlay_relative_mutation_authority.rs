// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    Error, InitramfsRoot, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
    RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(211);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 81,
    nanoseconds: 7,
};

type Overlay<'a> = OverlayNamespace<'a, 64, 96, 128, 24>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        0,
        0,
        1,
        0,
        0,
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
}

fn archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755);
    entry(&mut out, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn archive_with_lower_held_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755);
    entry(&mut out, b"held", S_IFDIR | 0o755);
    entry(&mut out, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn retained_directory_mutation_follows_identity_across_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();

    overlay.rename_at(b"/held", b"/moved", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/held"), Ok(None));

    overlay
        .create_regular_from(held, b"child", 0o600, 1, 2, T)
        .unwrap();

    assert_eq!(overlay.lookup_at(b"/held/child"), Ok(None));
    let child = overlay.lookup_at(b"/moved/child").unwrap().unwrap();
    assert_eq!(overlay.resolve_following_from(held, b"child"), Ok(child));
    overlay.release_directory(held).unwrap();
}

#[test]
fn retained_relative_rename_moves_only_an_already_bound_lower_directory() {
    let bytes = archive_with_lower_held_bytes();
    let mut overlay = overlay(&bytes);
    let root = overlay.open_and_retain_directory_at(b"/").unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();

    // Pure lower directory rename remains outside Step 29. Relative authority must not materialize
    // a directory merely because a rename was requested.
    assert_eq!(
        overlay.rename_from(root, b"held", root, b"premature", false),
        Err(OverlayError::NotDirectory)
    );
    assert!(overlay.lookup_at(b"/held").unwrap().is_some());
    assert_eq!(overlay.lookup_at(b"/premature"), Ok(None));

    // Creating a child through the retained directory identity materializes the exact lower
    // directory and installs its Upper binding. The logical lower identity must remain stable.
    overlay
        .create_regular_from(held, b"before", 0o600, 1, 2, T)
        .unwrap();
    let held_identity = overlay.resolve_nofollow_from(root, b"held").unwrap();

    overlay
        .rename_from(root, b"held", root, b"moved", false)
        .unwrap();
    assert_eq!(overlay.lookup_at(b"/held"), Ok(None));
    assert_eq!(
        overlay.resolve_nofollow_from(root, b"moved"),
        Ok(held_identity)
    );

    // The retained handle is still the authority after the move; new children publish only below
    // the live Upper name and the historical lower pathname stays suppressed.
    overlay
        .create_regular_from(held, b"after", 0o600, 1, 2, T)
        .unwrap();
    let after = overlay.resolve_following_from(held, b"after").unwrap();
    assert_eq!(overlay.lookup_at(b"/moved/after"), Ok(Some(after)));
    assert_eq!(overlay.lookup_at(b"/held/after"), Ok(None));

    overlay.release_directory(held).unwrap();
    overlay.release_directory(root).unwrap();
}

#[test]
fn retained_directory_mutation_does_not_require_absolute_path_presentation() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();

    // Repeatedly wrap the retained directory in a new top-level parent. Each rename uses a short
    // pathname, but the held object's live ancestry eventually exceeds Linux PATH_MAX. Directory
    // identity remains valid even though absolute pathname presentation can no longer succeed.
    let mut current_top = b"held".to_vec();
    for index in 0..18u8 {
        let mut wrapper = vec![b'a' + (index % 26); 240];
        wrapper[0] = b'a' + (index % 26);
        let mut absolute_wrapper = Vec::with_capacity(wrapper.len() + 1);
        absolute_wrapper.push(b'/');
        absolute_wrapper.extend_from_slice(&wrapper);
        overlay.mkdir_at(&absolute_wrapper, 0o755, 1, 2, T).unwrap();

        let mut source = Vec::with_capacity(current_top.len() + 1);
        source.push(b'/');
        source.extend_from_slice(&current_top);
        let mut destination = Vec::with_capacity(wrapper.len() + current_top.len() + 2);
        destination.push(b'/');
        destination.extend_from_slice(&wrapper);
        destination.push(b'/');
        destination.extend_from_slice(&current_top);
        overlay.rename_at(&source, &destination, false).unwrap();
        current_top = wrapper;
    }

    assert!(matches!(
        overlay.directory_canonical_path(held),
        Err(OverlayError::Mutable(RootedMutableError::Path(
            Error::PathTooLong
        )))
    ));

    overlay
        .create_regular_from(held, b"child", 0o600, 1, 2, T)
        .unwrap();
    overlay.mkdir_from(held, b"subdir", 0o755, 1, 2, T).unwrap();
    overlay
        .link_regular_from(held, b"child", held, b"hard")
        .unwrap();
    overlay
        .symlink_from(held, b"child", b"sym", 1, 2, T)
        .unwrap();

    let mut target = [0u8; 16];
    let target_len = overlay.readlink_from(held, b"sym", &mut target).unwrap();
    assert_eq!(&target[..target_len], b"child");

    overlay
        .rename_from(held, b"hard", held, b"renamed", false)
        .unwrap();
    assert!(matches!(
        overlay.resolve_nofollow_from(held, b"hard"),
        Err(OverlayError::NotFound)
    ));
    let renamed = overlay.resolve_following_from(held, b"renamed").unwrap();
    let child = overlay.resolve_following_from(held, b"child").unwrap();
    assert_eq!(renamed, child);

    overlay.unlink_from(held, b"sym", false).unwrap();
    overlay.unlink_from(held, b"renamed", false).unwrap();
    overlay.unlink_from(held, b"child", false).unwrap();
    overlay.unlink_from(held, b"subdir", true).unwrap();
    assert!(matches!(
        overlay.resolve_nofollow_from(held, b"child"),
        Err(OverlayError::NotFound)
    ));

    overlay.release_directory(held).unwrap();
}
