// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    Error, InitramfsRoot, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
    RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const ROOT: RootId = RootId::new(213);
const T1: MutableTimestamp = MutableTimestamp {
    seconds: 101,
    nanoseconds: 1,
};
const T2: MutableTimestamp = MutableTimestamp {
    seconds: 102,
    nanoseconds: 2,
};
const T3: MutableTimestamp = MutableTimestamp {
    seconds: 103,
    nanoseconds: 3,
};

type Overlay<'a> = OverlayNamespace<'a, 96, 144, 512, 32>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        1,
        2,
        1,
        11,
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
    entry(&mut out, b"lower", S_IFREG | 0o600);
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
fn retained_directory_metadata_mutation_survives_parent_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T1).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();
    overlay.rename_at(b"/held", b"/moved", false).unwrap();
    overlay
        .create_regular_from(held, b"file", 0o600, 1, 2, T1)
        .unwrap();

    overlay.chmod_from(held, b"file", 0o640, T2).unwrap();
    overlay
        .chown_from(held, b"file", Some(17), Some(23), T2)
        .unwrap();
    overlay.set_times_from(held, b"file", T1, T2, T3).unwrap();

    let logical = overlay.resolve_following_from(held, b"file").unwrap();
    let metadata = overlay.metadata(logical).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o640);
    assert_eq!(metadata.uid(), 17);
    assert_eq!(metadata.gid(), 23);
    assert_eq!(metadata.atime(), T1);
    assert_eq!(metadata.mtime(), T2);
    assert_eq!(metadata.ctime(), T3);
    assert_eq!(overlay.lookup_at(b"/held/file"), Ok(None));
    assert_eq!(overlay.lookup_at(b"/moved/file"), Ok(Some(logical)));
    overlay.release_directory(held).unwrap();
}

#[test]
fn retained_root_metadata_mutation_copyups_lower_regular() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let root = overlay.open_and_retain_directory_at(b"/").unwrap();
    let logical = overlay.resolve_following_from(root, b"lower").unwrap();

    overlay.chmod_from(root, b"lower", 0o604, T2).unwrap();
    overlay
        .chown_from(root, b"lower", Some(31), Some(37), T2)
        .unwrap();
    overlay.set_times_from(root, b"lower", T1, T2, T3).unwrap();

    assert_eq!(overlay.resolve_following_from(root, b"lower"), Ok(logical));
    let metadata = overlay.metadata(logical).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o604);
    assert_eq!(metadata.uid(), 31);
    assert_eq!(metadata.gid(), 37);
    assert_eq!(metadata.atime(), T1);
    assert_eq!(metadata.mtime(), T2);
    assert_eq!(metadata.ctime(), T3);
    overlay.release_directory(root).unwrap();
}

#[test]
fn retained_directory_metadata_mutation_ignores_pathmax_presentation() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T1).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();

    let mut current_top = b"held".to_vec();
    for index in 0..18u8 {
        let mut wrapper = vec![b'a' + (index % 26); 240];
        wrapper[0] = b'a' + (index % 26);
        let mut absolute_wrapper = Vec::with_capacity(wrapper.len() + 1);
        absolute_wrapper.push(b'/');
        absolute_wrapper.extend_from_slice(&wrapper);
        overlay
            .mkdir_at(&absolute_wrapper, 0o755, 1, 2, T1)
            .unwrap();

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
        .create_regular_from(held, b"file", 0o600, 1, 2, T1)
        .unwrap();
    overlay.chmod_from(held, b"file", 0o644, T2).unwrap();
    overlay
        .chown_from(held, b"file", Some(41), Some(43), T2)
        .unwrap();

    let logical = overlay.resolve_following_from(held, b"file").unwrap();
    let metadata = overlay.metadata(logical).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o644);
    assert_eq!(metadata.uid(), 41);
    assert_eq!(metadata.gid(), 43);
    overlay.release_directory(held).unwrap();
}
