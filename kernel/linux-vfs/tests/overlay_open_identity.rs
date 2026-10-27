// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableError, MutableTimestamp, OverlayError, OverlayNamespace,
    OverlayNodeHandle, RootId, RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(91);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 7,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 4>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
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
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"base", S_IFREG | 0o644, b"lower");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn read_regular(overlay: &Overlay<'_>, handle: OverlayNodeHandle) -> Vec<u8> {
    let mut output = [0u8; 8];
    let count = overlay.read_regular(handle, 0, &mut output).unwrap();
    output[..count].to_vec()
}

#[test]
fn opened_immutable_object_survives_tombstone_and_name_reuse() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    let opened = overlay.lookup_at(b"/base").unwrap().unwrap();
    assert_eq!(read_regular(&overlay, opened), b"lower");
    overlay.retain_open(opened).unwrap();

    overlay.unlink_regular_at(b"/base").unwrap();
    assert_eq!(overlay.lookup_at(b"/base"), Ok(None));

    // Linux open-file semantics are object based: unlink removes the directory name, not an already
    // opened file description's reference to the inode. The old immutable handle must therefore
    // retain access to the exact lower EntryId even though fresh pathname lookup is now hidden.
    assert_eq!(read_regular(&overlay, opened), b"lower");

    overlay
        .create_regular_at(b"/base", 0o600, 0, 0, NOW)
        .unwrap();
    assert_eq!(overlay.write_at(b"/base", 0, b"upper", NOW), Ok(5));
    let replacement = overlay.lookup_at(b"/base").unwrap().unwrap();
    assert_ne!(replacement, opened);
    assert_eq!(read_regular(&overlay, replacement), b"upper");

    // Reusing the pathname for a new upper inode must not retarget the pre-existing immutable handle.
    assert_eq!(read_regular(&overlay, opened), b"lower");
    overlay.release_open(opened).unwrap();
}

#[test]
fn zero_write_validates_offset_without_copying_lower_file_up() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    assert_eq!(
        overlay.write_at(b"/base", 65, b"", NOW),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::FileTooLarge,
        )))
    );

    // A zero-byte request may validate, but must not materialize or mutate an upper object.
    assert_eq!(
        overlay.upper().lookup(upper_root, b"base"),
        Err(RootedMutableError::Mutable(MutableError::NotFound))
    );
    let lower = overlay.lookup_at(b"/base").unwrap().unwrap();
    assert_eq!(read_regular(&overlay, lower), b"lower");
}

#[test]
fn opened_mutable_object_survives_unlink_until_last_release() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    overlay
        .create_regular_at(b"/upper", 0o600, 0, 0, NOW)
        .unwrap();
    assert_eq!(overlay.write_at(b"/upper", 0, b"data", NOW), Ok(4));
    let opened = overlay.lookup_at(b"/upper").unwrap().unwrap();
    assert!(matches!(opened, OverlayNodeHandle::Mutable(_)));

    overlay.retain_open(opened).unwrap();
    overlay.unlink_regular_at(b"/upper").unwrap();
    assert_eq!(overlay.lookup_at(b"/upper"), Ok(None));
    assert_eq!(read_regular(&overlay, opened), b"data");

    overlay.release_open(opened).unwrap();
    let mut output = [0u8; 8];
    assert_eq!(
        overlay.read_regular(opened, 0, &mut output),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::BadNode,
        )))
    );
}
