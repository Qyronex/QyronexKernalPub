// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    Error, InitramfsRoot, MutableError, MutableTimestamp, NodeKind, OverlayError, OverlayNamespace,
    OverlayNodeHandle, RetainedRegularHandle, RootId, RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(151);
const LOWER_TIME: MutableTimestamp = MutableTimestamp {
    seconds: 31,
    nanoseconds: 0,
};
const T1: MutableTimestamp = MutableTimestamp {
    seconds: 41,
    nanoseconds: 1,
};
const T2: MutableTimestamp = MutableTimestamp {
    seconds: 42,
    nanoseconds: 2,
};
const T3: MutableTimestamp = MutableTimestamp {
    seconds: 43,
    nanoseconds: 3,
};
const T4: MutableTimestamp = MutableTimestamp {
    seconds: 44,
    nanoseconds: 4,
};
const T5: MutableTimestamp = MutableTimestamp {
    seconds: 45,
    nanoseconds: 5,
};
const T6: MutableTimestamp = MutableTimestamp {
    seconds: 46,
    nanoseconds: 6,
};

type Overlay<'a> = OverlayNamespace<'a, 12, 20, 64, 8>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, metadata: (u32, u32, u32, u32), data: &[u8]) {
    let (uid, gid, nlink, mtime) = metadata;
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        uid,
        gid,
        nlink,
        mtime,
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
    entry(&mut out, b".", S_IFDIR | 0o755, (0, 0, 1, 1), b"");
    entry(
        &mut out,
        b"base",
        S_IFREG | 0o640,
        (17, 23, 1, 31),
        b"lower",
    );
    entry(&mut out, b"late", S_IFREG | 0o644, (5, 6, 1, 7), b"late");
    entry(&mut out, b"TRAILER!!!", 0, (0, 0, 1, 0), b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn read_raw(overlay: &Overlay<'_>, handle: OverlayNodeHandle) -> Result<Vec<u8>, OverlayError> {
    let mut bytes = [0u8; 80];
    let count = overlay.read_regular(handle, 0, &mut bytes)?;
    Ok(bytes[..count].to_vec())
}

fn read_retained(
    overlay: &Overlay<'_>,
    retained: RetainedRegularHandle,
) -> Result<Vec<u8>, OverlayError> {
    let mut bytes = [0u8; 80];
    let count = overlay.read_retained_regular(retained, 0, &mut bytes)?;
    Ok(bytes[..count].to_vec())
}

#[test]
fn retained_lower_writable_object_survives_rename_unlink_and_mutates_by_identity() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let logical = overlay.lookup_at(b"/base").unwrap().unwrap();

    let lower = overlay.metadata(logical).unwrap();
    assert_eq!(lower.object(), logical);
    assert_eq!(lower.kind(), NodeKind::Regular);
    assert_eq!(lower.mode(), S_IFREG | 0o640);
    assert_eq!(lower.uid(), 17);
    assert_eq!(lower.gid(), 23);
    assert_eq!(lower.links(), 1);
    assert_eq!(lower.size(), 5);
    assert_eq!(lower.atime(), LOWER_TIME);
    assert_eq!(lower.mtime(), LOWER_TIME);
    assert_eq!(lower.ctime(), LOWER_TIME);

    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    assert_eq!(retained.object(), logical);
    assert_eq!(overlay.lookup_at(b"/base").unwrap(), Some(logical));
    assert_eq!(overlay.retained_regular_metadata(retained).unwrap(), lower);

    overlay.rename_at(b"/base", b"/moved", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/base"), Ok(None));
    assert_eq!(overlay.lookup_at(b"/moved").unwrap(), Some(logical));

    assert_eq!(
        overlay.write_retained_regular(retained, 1, b"XY", T1),
        Ok(2)
    );
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"lXYer");
    assert_eq!(
        overlay.append_retained_regular(retained, b"!", T2),
        Ok((5, 1))
    );
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"lXYer!");

    let before_empty = overlay.retained_regular_metadata(retained).unwrap();
    assert_eq!(
        overlay.append_retained_regular(retained, b"", T3),
        Ok((6, 0))
    );
    assert_eq!(
        overlay.retained_regular_metadata(retained).unwrap(),
        before_empty
    );

    let before_overflow = overlay.retained_regular_metadata(retained).unwrap();
    let too_large = [b'x'; 59];
    assert_eq!(
        overlay.append_retained_regular(retained, &too_large, T3),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::FileTooLarge,
        )))
    );
    assert_eq!(
        overlay.retained_regular_metadata(retained).unwrap(),
        before_overflow
    );
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"lXYer!");

    overlay.truncate_retained_regular(retained, 4, T3).unwrap();
    overlay.chmod_retained_regular(retained, 0o604, T3).unwrap();
    overlay
        .chown_retained_regular(retained, Some(42), Some(43), T4)
        .unwrap();
    overlay
        .set_times_retained_regular(retained, T4, T5, T6)
        .unwrap();
    let changed = overlay.retained_regular_metadata(retained).unwrap();
    assert_eq!(changed.kind(), NodeKind::Regular);
    assert_eq!(changed.mode(), S_IFREG | 0o604);
    assert_eq!(changed.uid(), 42);
    assert_eq!(changed.gid(), 43);
    assert_eq!(changed.links(), 1);
    assert_eq!(changed.size(), 4);
    assert_eq!(changed.atime(), T4);
    assert_eq!(changed.mtime(), T5);
    assert_eq!(changed.ctime(), T6);
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"lXYe");

    overlay.unlink_at(b"/moved", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/moved"), Ok(None));
    assert_eq!(overlay.write_retained_regular(retained, 0, b"Q", T4), Ok(1));
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"QXYe");
    let unlinked = overlay.retained_regular_metadata(retained).unwrap();
    assert_eq!(unlinked.links(), 0);
    assert_eq!(unlinked.size(), 4);

    overlay.release_retained_regular(retained).unwrap();
    assert!(matches!(
        overlay.retained_regular_metadata(retained),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::BadNode,
        ))) | Err(OverlayError::Path(Error::HandleMismatch))
    ));
}

#[test]
fn retained_upper_object_uses_same_api_and_final_release_reclaims_generation() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay
        .create_regular_at(b"/upper", 0o600, 1, 2, T1)
        .unwrap();
    let logical = overlay.lookup_at(b"/upper").unwrap().unwrap();
    assert!(matches!(logical, OverlayNodeHandle::Mutable(_)));

    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/upper")
        .unwrap();
    assert_eq!(retained.object(), logical);
    overlay.unlink_at(b"/upper", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/upper"), Ok(None));

    assert_eq!(
        overlay.write_retained_regular(retained, 0, b"abc", T2),
        Ok(3)
    );
    assert_eq!(
        overlay.append_retained_regular(retained, b"d", T2),
        Ok((3, 1))
    );
    overlay.truncate_retained_regular(retained, 2, T3).unwrap();
    overlay.chmod_retained_regular(retained, 0o640, T3).unwrap();
    overlay
        .chown_retained_regular(retained, Some(11), Some(12), T4)
        .unwrap();
    let metadata = overlay.retained_regular_metadata(retained).unwrap();
    assert_eq!(metadata.mode(), S_IFREG | 0o640);
    assert_eq!(metadata.uid(), 11);
    assert_eq!(metadata.gid(), 12);
    assert_eq!(metadata.links(), 0);
    assert_eq!(metadata.size(), 2);
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"ab");

    overlay.release_retained_regular(retained).unwrap();
    assert!(overlay.retained_regular_metadata(retained).is_err());
}

#[test]
fn readonly_lower_survives_unlink_only_until_final_release() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let logical = overlay.lookup_at(b"/late").unwrap().unwrap();
    overlay.retain_open(logical).unwrap();
    overlay.unlink_at(b"/late", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/late"), Ok(None));

    assert_eq!(read_raw(&overlay, logical).unwrap(), b"late");
    let detached = overlay.metadata(logical).unwrap();
    assert_eq!(detached.links(), 0);
    assert_eq!(detached.size(), 4);
    assert_eq!(
        overlay.prepare_and_retain_writable_regular_at(b"/late"),
        Err(OverlayError::NotFound)
    );

    overlay.release_open(logical).unwrap();
    assert!(matches!(
        read_raw(&overlay, logical),
        Err(OverlayError::NotFound) | Err(OverlayError::Path(Error::HandleMismatch))
    ));
    assert!(matches!(
        overlay.metadata(logical),
        Err(OverlayError::NotFound) | Err(OverlayError::Path(Error::HandleMismatch))
    ));
}

#[test]
fn stale_lower_identity_never_attaches_to_replacement_at_same_path() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let old = overlay.lookup_at(b"/late").unwrap().unwrap();
    overlay.retain_open(old).unwrap();
    overlay.unlink_at(b"/late", false).unwrap();

    overlay
        .create_regular_at(b"/late", 0o600, 90, 91, T1)
        .unwrap();
    let replacement = overlay.lookup_at(b"/late").unwrap().unwrap();
    assert_ne!(replacement, old);
    assert_eq!(read_raw(&overlay, old).unwrap(), b"late");
    assert_eq!(overlay.metadata(old).unwrap().links(), 0);

    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/late")
        .unwrap();
    assert_eq!(retained.object(), replacement);
    assert_eq!(
        overlay.write_retained_regular(retained, 0, b"new", T2),
        Ok(3)
    );
    assert_eq!(read_retained(&overlay, retained).unwrap(), b"new");

    overlay.release_open(old).unwrap();
    assert!(read_raw(&overlay, old).is_err());
    assert!(overlay.metadata(old).is_err());
    assert_eq!(overlay.lookup_at(b"/late").unwrap(), Some(replacement));
    overlay.release_retained_regular(retained).unwrap();
}

#[test]
fn sibling_overlay_owner_rejects_foreign_retained_authority() {
    let bytes = archive_bytes();
    let mut left = overlay(&bytes);
    let mut right = overlay(&bytes);

    let left_retained = left
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    let right_retained = right
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();

    assert_ne!(left_retained.object(), right_retained.object());
    assert_ne!(left_retained, right_retained);
    assert!(matches!(
        right.write_retained_regular(left_retained, 0, b"BAD", T2),
        Err(OverlayError::Mutable(RootedMutableError::NamespaceMismatch))
            | Err(OverlayError::Path(Error::HandleMismatch))
    ));
    assert!(matches!(
        right.retained_regular_metadata(left_retained),
        Err(OverlayError::Mutable(RootedMutableError::NamespaceMismatch))
            | Err(OverlayError::Path(Error::HandleMismatch))
    ));
    assert_eq!(read_retained(&right, right_retained).unwrap(), b"lower");

    left.release_retained_regular(left_retained).unwrap();
    right.release_retained_regular(right_retained).unwrap();
}
