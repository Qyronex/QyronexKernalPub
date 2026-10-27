// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(159);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 61,
    nanoseconds: 1,
};

type Overlay<'a> = OverlayNamespace<'a, 6, 12, 64, 6>;
type TinyOverlay<'a> = OverlayNamespace<'a, 1, 4, 64, 4>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, nlink: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        0,
        0,
        nlink,
        1,
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
    entry(&mut out, b".", S_IFDIR | 0o755, 1, b"");
    entry(&mut out, b"late", S_IFREG | 0o644, 1, b"late");
    entry(&mut out, b"multi", S_IFREG | 0o644, 2, b"multi");
    entry(&mut out, b"TRAILER!!!", 0, 1, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn read_all<
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
>(
    overlay: &OverlayNamespace<'_, NODES, DENTRIES, FILE_BYTES, TOMBSTONES>,
    handle: kernal_linux_vfs::OverlayNodeHandle,
) -> Result<Vec<u8>, kernal_linux_vfs::OverlayError> {
    let mut bytes = [0u8; 16];
    let count = overlay.read_regular(handle, 0, &mut bytes)?;
    Ok(bytes[..count].to_vec())
}

#[test]
fn final_released_lower_cannot_retain_again_after_replacement() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let old = overlay.lookup_at(b"/late").unwrap().unwrap();

    overlay.retain_open(old).unwrap();
    overlay.unlink_at(b"/late", false).unwrap();
    overlay.create_regular_at(b"/late", 0o600, 1, 2, T).unwrap();
    assert_eq!(overlay.write_at(b"/late", 0, b"new", T), Ok(3));
    let replacement = overlay.lookup_at(b"/late").unwrap().unwrap();
    assert_ne!(replacement, old);

    assert_eq!(read_all(&overlay, old).unwrap(), b"late");
    overlay.release_open(old).unwrap();
    assert!(read_all(&overlay, old).is_err());
    assert!(overlay.metadata(old).is_err());

    assert!(overlay.retain_open(old).is_err());
    assert!(read_all(&overlay, old).is_err());
    assert!(overlay.metadata(old).is_err());

    assert_eq!(overlay.lookup_at(b"/late").unwrap(), Some(replacement));
    assert_eq!(read_all(&overlay, replacement).unwrap(), b"new");
}

#[test]
fn lower_multi_link_copyup_fails_before_consuming_upper_capacity() {
    let bytes = archive_bytes();
    let mut overlay = TinyOverlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let logical = overlay.lookup_at(b"/multi").unwrap().unwrap();
    let before = overlay.metadata(logical).unwrap();
    assert_eq!(before.links(), 2);
    assert_eq!(read_all(&overlay, logical).unwrap(), b"multi");

    assert!(
        overlay
            .prepare_and_retain_writable_regular_at(b"/multi")
            .is_err()
    );
    assert_eq!(overlay.lookup_at(b"/multi").unwrap(), Some(logical));
    assert_eq!(overlay.metadata(logical).unwrap(), before);
    assert_eq!(read_all(&overlay, logical).unwrap(), b"multi");

    overlay
        .create_regular_at(b"/fresh", 0o600, 1, 2, T)
        .unwrap();
    assert!(overlay.lookup_at(b"/fresh").unwrap().is_some());
}
