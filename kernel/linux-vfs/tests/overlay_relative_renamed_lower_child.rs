// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Step-29 authority oracles for a lower child below a retained directory that has acquired an
//! Upper binding and then moved. The retained directory identity, not the child's original CPIO
//! pathname, must remain the copy-up authority.

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayError, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const ROOT: RootId = RootId::new(214);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 111,
    nanoseconds: 1,
};
const LATER: MutableTimestamp = MutableTimestamp {
    seconds: 112,
    nanoseconds: 2,
};

type Overlay<'a> = OverlayNamespace<'a, 96, 144, 512, 32>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        1,
        2,
        1,
        11,
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
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"held", S_IFDIR | 0o755, b"");
    entry(&mut out, b"held/file", S_IFREG | 0o600, b"x");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn retain_materialize_and_rename(
    overlay: &mut Overlay<'_>,
) -> kernal_linux_vfs::OverlayDirectoryHandle {
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();
    // Force an Upper binding for the lower directory without copying up its lower child.
    overlay
        .create_regular_from(held, b"marker", 0o600, 1, 2, NOW)
        .unwrap();
    overlay.rename_at(b"/held", b"/moved", false).unwrap();

    // Logical lower EntryId remains the retained identity, but Linux-visible pathname presentation
    // must follow the live Upper ancestry after the bound directory moves.
    let presented = overlay.directory_canonical_path(held).unwrap();
    assert_eq!(presented.as_relative_bytes(), b"moved");
    held
}

#[test]
fn metadata_copyup_uses_retained_parent_after_lower_parent_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let held = retain_materialize_and_rename(&mut overlay);
    let logical = overlay.resolve_following_from(held, b"file").unwrap();

    overlay.chmod_from(held, b"file", 0o640, LATER).unwrap();
    overlay
        .chown_from(held, b"file", Some(17), Some(23), LATER)
        .unwrap();

    assert_eq!(overlay.resolve_following_from(held, b"file"), Ok(logical));
    let metadata = overlay.metadata(logical).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o640);
    assert_eq!(metadata.uid(), 17);
    assert_eq!(metadata.gid(), 23);
    overlay.release_directory(held).unwrap();
}

#[test]
fn hardlink_copyup_uses_retained_parent_after_lower_parent_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let held = retain_materialize_and_rename(&mut overlay);
    let logical = overlay.resolve_following_from(held, b"file").unwrap();

    overlay
        .link_regular_from(held, b"file", held, b"alias")
        .unwrap();

    assert_eq!(overlay.resolve_following_from(held, b"file"), Ok(logical));
    assert_eq!(overlay.resolve_following_from(held, b"alias"), Ok(logical));
    overlay.release_directory(held).unwrap();
}

#[test]
fn rename_copyup_uses_retained_parent_after_lower_parent_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let held = retain_materialize_and_rename(&mut overlay);
    let logical = overlay.resolve_following_from(held, b"file").unwrap();

    overlay
        .rename_from(held, b"file", held, b"renamed", false)
        .unwrap();

    assert_eq!(
        overlay.resolve_following_from(held, b"file"),
        Err(OverlayError::NotFound)
    );
    assert_eq!(
        overlay.resolve_following_from(held, b"renamed"),
        Ok(logical)
    );
    overlay.release_directory(held).unwrap();
}
