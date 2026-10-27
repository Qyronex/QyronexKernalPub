// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableError, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
    RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(184);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 79,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 1, 4, 32, 2>;

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
        1,
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
    entry(&mut out, b"lower", S_IFDIR | 0o755);
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
fn mutable_directory_fd_and_cwd_holds_delay_reclaim_until_final_release() {
    let bytes = archive_bytes();
    let mut view = overlay(&bytes);
    view.mkdir_at(b"/held", 0o755, 1, 2, T).unwrap();

    // Directory-open intended for an OFD resolves and acquires its first hold as one VFS action.
    let opened = view.open_and_retain_directory_at(b"/held").unwrap();
    // fchdir/cwd takes an independent second hold; closing the source fd must not kill cwd.
    view.retain_directory(opened).unwrap();

    view.rmdir_at(b"/held").unwrap();
    assert_eq!(view.lookup_at(b"/held"), Ok(None));

    // NODES=1: unlinked-but-retained directory still owns the only generation-safe node slot.
    assert!(matches!(
        view.mkdir_at(b"/replacement", 0o755, 1, 2, T),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::NodeTableFull
        )))
    ));

    // Release the source-FD hold. The independent cwd hold must still keep the object unreclaimable.
    view.release_directory(opened).unwrap();
    assert!(matches!(
        view.mkdir_at(b"/replacement", 0o755, 1, 2, T),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::NodeTableFull
        )))
    ));

    // Final cwd release permits reclaim/reuse; the old generation-safe handle then becomes stale.
    view.release_directory(opened).unwrap();
    view.mkdir_at(b"/replacement", 0o755, 1, 2, T).unwrap();
    assert!(view.retain_directory(opened).is_err());
}

#[test]
fn lower_directory_retain_release_is_validated_noop_and_owner_qualified() {
    let bytes = archive_bytes();
    let mut owner = overlay(&bytes);
    let lower = owner.open_and_retain_directory_at(b"/lower").unwrap();
    owner.retain_directory(lower).unwrap();
    owner.release_directory(lower).unwrap();
    owner.release_directory(lower).unwrap();

    // A sibling Overlay with the same RootId/archive still has a distinct Upper-root owner witness.
    let mut sibling = overlay(&bytes);
    assert!(sibling.retain_directory(lower).is_err());
    assert!(sibling.release_directory(lower).is_err());
}

#[test]
fn root_directory_retain_release_is_validated_noop_and_owner_qualified() {
    let bytes = archive_bytes();
    let mut owner = overlay(&bytes);
    let root = owner.open_and_retain_directory_at(b"/").unwrap();

    // Mounted-root lifetime itself is stable, so additional holds are no-ops only after validating
    // the exact Overlay owner witness carried by the root handle.
    owner.retain_directory(root).unwrap();
    owner.release_directory(root).unwrap();
    owner.release_directory(root).unwrap();

    // RootId equality is not sufficient authority: a sibling Overlay has a different Upper-root
    // namespace witness and must reject the foreign root handle before taking the no-op path.
    let mut sibling = overlay(&bytes);
    assert!(sibling.retain_directory(root).is_err());
    assert!(sibling.release_directory(root).is_err());
}
