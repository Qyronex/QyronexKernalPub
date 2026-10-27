// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(241);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 900,
    nanoseconds: 7,
};

type Overlay<'a> = OverlayNamespace<'a, 16, 24, 128, 8>;

#[derive(Clone, Copy)]
struct NewcMetadata {
    ino: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
}

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8], metadata: NewcMetadata) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        metadata.ino,
        mode,
        metadata.uid,
        metadata.gid,
        metadata.nlink,
        metadata.mtime,
        u32::try_from(data.len()).unwrap(),
        metadata.dev_major,
        metadata.dev_minor,
        metadata.rdev_major,
        metadata.rdev_minor,
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
    entry(
        &mut out,
        b".",
        S_IFDIR | 0o755,
        b"",
        NewcMetadata {
            ino: 0x0102_0304,
            uid: 1,
            gid: 2,
            nlink: 2,
            mtime: 111,
            dev_major: 3,
            dev_minor: 4,
            rdev_major: 0,
            rdev_minor: 0,
        },
    );
    entry(
        &mut out,
        b"lower-a",
        S_IFREG | 0o644,
        b"alpha",
        NewcMetadata {
            ino: 0x1234_5678,
            uid: 17,
            gid: 23,
            nlink: 1,
            mtime: 123_456,
            dev_major: 8,
            dev_minor: 9,
            rdev_major: 10,
            rdev_minor: 11,
        },
    );
    entry(
        &mut out,
        b"lower-b",
        S_IFREG | 0o644,
        b"beta",
        NewcMetadata {
            // Same source inode number, deliberately different source device tuple.
            ino: 0x1234_5678,
            uid: 31,
            gid: 37,
            nlink: 1,
            mtime: 654_321,
            dev_major: 8,
            dev_minor: 10,
            rdev_major: 12,
            rdev_minor: 13,
        },
    );
    entry(
        &mut out,
        b"TRAILER!!!",
        0,
        b"",
        NewcMetadata {
            ino: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
        },
    );
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn immutable_source_provenance_is_exact_distinguishable_and_survives_copy_up() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let root = overlay.open_and_retain_directory_at(b"/").unwrap();

    let lower_a = overlay.resolve_following_from(root, b"lower-a").unwrap();
    let before = overlay.metadata(lower_a).unwrap();
    assert_eq!(before.source_ino(), Some(0x1234_5678));
    assert_eq!(before.source_device(), Some((8, 9)));
    assert_eq!(before.source_rdev(), Some((10, 11)));

    // OverlayMetadata is already borrow-free/Copy; CPIO provenance must remain part of that owned
    // snapshot rather than escaping a borrowed Entry from the protected archive window.
    let copied_before = before;
    assert_eq!(copied_before.source_ino(), before.source_ino());
    assert_eq!(copied_before.source_device(), before.source_device());
    assert_eq!(copied_before.source_rdev(), before.source_rdev());

    let lower_b = overlay.resolve_following_from(root, b"lower-b").unwrap();
    let source_b = overlay.metadata(lower_b).unwrap();
    assert_eq!(source_b.source_ino(), before.source_ino());
    assert_ne!(source_b.source_device(), before.source_device());
    assert_eq!(source_b.source_device(), Some((8, 10)));
    assert_eq!(source_b.source_rdev(), Some((12, 13)));

    // Copy-up changes the mutable backing, not the logical lower/source identity.
    overlay.chmod_from(root, b"lower-a", 0o600, NOW).unwrap();
    assert_eq!(
        overlay.resolve_following_from(root, b"lower-a"),
        Ok(lower_a)
    );
    let after = overlay.metadata(lower_a).unwrap();
    assert_eq!(after.source_ino(), before.source_ino());
    assert_eq!(after.source_device(), before.source_device());
    assert_eq!(after.source_rdev(), before.source_rdev());
    assert_eq!(after.mode() & 0o777, 0o600);

    // A file born in the Upper has no immutable CPIO provenance to report.
    overlay
        .create_regular_from(root, b"upper", 0o600, 41, 43, NOW)
        .unwrap();
    let upper = overlay.resolve_following_from(root, b"upper").unwrap();
    let upper_metadata = overlay.metadata(upper).unwrap();
    assert_eq!(upper_metadata.source_ino(), None);
    assert_eq!(upper_metadata.source_device(), None);
    assert_eq!(upper_metadata.source_rdev(), None);

    overlay.release_directory(root).unwrap();
}

#[test]
fn immutable_directory_metadata_exposes_source_provenance_without_open_file_semantics() {
    let bytes = archive_bytes();
    let overlay = overlay(&bytes);
    let root = overlay.open_directory_at(b"/").unwrap();
    let metadata = overlay.metadata(root.object()).unwrap();

    assert_eq!(metadata.source_ino(), Some(0x0102_0304));
    assert_eq!(metadata.source_device(), Some((3, 4)));
    assert_eq!(metadata.source_rdev(), Some((0, 0)));
    assert_eq!(metadata.uid(), 1);
    assert_eq!(metadata.gid(), 2);
    assert_eq!(metadata.links(), 2);
    assert_eq!(metadata.mtime().seconds, 111);
}

#[test]
fn detached_retained_lower_keeps_source_provenance_only_while_authority_is_live() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let logical = overlay.lookup_at(b"/lower-b").unwrap().unwrap();
    overlay.retain_open(logical).unwrap();
    overlay.unlink_at(b"/lower-b", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/lower-b"), Ok(None));

    let detached = overlay.metadata(logical).unwrap();
    assert_eq!(detached.links(), 0);
    assert_eq!(detached.source_ino(), Some(0x1234_5678));
    assert_eq!(detached.source_device(), Some((8, 10)));
    assert_eq!(detached.source_rdev(), Some((12, 13)));

    overlay.release_open(logical).unwrap();
    assert!(overlay.metadata(logical).is_err());
}
