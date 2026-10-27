// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableError, OverlayError, OverlayNamespace, RootId, RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const ROOT: RootId = RootId::new(101);

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
    entry(&mut out, b"lower-dir", S_IFDIR | 0o755, b"");
    entry(&mut out, b"target", S_IFREG | 0o644, b"data");
    entry(&mut out, b"lower-sym", S_IFLNK | 0o777, b"target");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn lower_only_directory_mutation_is_explicitly_fail_closed() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    assert_eq!(
        overlay.rmdir_at(b"/lower-dir"),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::DirectoryNotEmpty,
        )))
    );
    assert!(overlay.lookup_at(b"/lower-dir").unwrap().is_some());

    assert_eq!(
        overlay.rename_at(b"/lower-dir", b"/moved-dir", false),
        Err(OverlayError::NotDirectory)
    );
    assert!(overlay.lookup_at(b"/lower-dir").unwrap().is_some());
    assert!(overlay.lookup_at(b"/moved-dir").unwrap().is_none());
}

#[test]
fn lower_only_symlink_support_is_read_and_unlink_but_not_inode_copyup() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    let mut target = [0u8; 16];
    let copied = overlay.readlink_at(b"/lower-sym", &mut target).unwrap();
    assert_eq!(&target[..copied], b"target");

    assert_eq!(
        overlay.link_regular_at(b"/lower-sym", b"/hard-sym"),
        Err(OverlayError::NotRegular)
    );
    assert_eq!(
        overlay.rename_at(b"/lower-sym", b"/renamed-sym", false),
        Err(OverlayError::NotRegular)
    );
    assert!(overlay.lookup_at(b"/hard-sym").unwrap().is_none());
    assert!(overlay.lookup_at(b"/renamed-sym").unwrap().is_none());

    assert_eq!(overlay.unlink_at(b"/lower-sym", false), Ok(()));
    assert!(overlay.lookup_at(b"/lower-sym").unwrap().is_none());

    let fresh = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let mut fresh_target = [0u8; 16];
    let fresh_copied = fresh.readlink_at(b"/lower-sym", &mut fresh_target).unwrap();
    assert_eq!(&fresh_target[..fresh_copied], b"target");
}
