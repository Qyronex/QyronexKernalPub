// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{FsContext, InitramfsRoot, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(182);
const OTHER_ROOT: RootId = RootId::new(183);

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 8>;

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
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
    entry(&mut out, b"etc/base", S_IFREG | 0o644, b"child");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8], root: RootId) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), root))
}

#[test]
fn immutable_cwd_reenters_overlay_owner_for_presentation_and_relative_resolution() {
    let bytes = archive_bytes();
    let view = overlay(&bytes, ROOT);
    let cwd = view.open_directory_at(b"/etc").unwrap();

    // Path text is derived only at the owner presentation boundary; it is not stored in cwd.
    let canonical = view.directory_canonical_path(cwd).unwrap();
    assert_eq!(canonical.as_relative_bytes(), b"etc");

    // Relative namespace work stays identity-first and must resolve from the exact cwd object.
    let relative = view.resolve_following_from(cwd, b"base").unwrap();
    let absolute = view.lookup_at(b"/etc/base").unwrap().unwrap();
    assert_eq!(relative, absolute);
}

#[test]
fn immutable_cwd_cannot_be_presented_by_foreign_overlay_owner() {
    let bytes = archive_bytes();
    let owner = overlay(&bytes, ROOT);
    let cwd = owner.open_directory_at(b"/etc").unwrap();

    // Same RootId is deliberately insufficient: sibling Overlay owners have distinct Upper-root
    // witnesses and must not exchange directory authority.
    let sibling = overlay(&bytes, ROOT);
    assert!(sibling.directory_canonical_path(cwd).is_err());

    let wrong_root = overlay(&bytes, OTHER_ROOT);
    assert!(wrong_root.directory_canonical_path(cwd).is_err());
}

#[test]
fn immutable_cwd_crosses_fs_context_only_through_the_exact_overlay_owner() {
    let bytes = archive_bytes();
    let mut owner = overlay(&bytes, ROOT);
    let cwd = owner.open_directory_at(b"/etc").unwrap();
    let mut context = FsContext::new(ROOT);

    // Publishing process cwd is an Overlay-owned transaction. The context remains compact and does
    // not gain a CanonicalPath snapshot; the owner must preserve enough authority to reject a
    // same-RootId sibling when the process handle is later re-entered.
    owner.set_context_cwd(&mut context, cwd).unwrap();
    assert_eq!(context.cwd_handle().root_id(), ROOT);

    // Re-enter from the real process-context handle, then keep presentation and namespace work on
    // their existing boundaries: pathname text only for presentation, identity for relative lookup.
    let reentered = owner
        .revalidate_directory_handle(context.cwd_handle())
        .unwrap();
    assert_eq!(reentered, cwd);
    assert_eq!(
        owner
            .directory_canonical_path(reentered)
            .unwrap()
            .as_relative_bytes(),
        b"etc"
    );
    let relative = owner.resolve_following_from(reentered, b"base").unwrap();
    let absolute = owner.lookup_at(b"/etc/base").unwrap().unwrap();
    assert_eq!(relative, absolute);

    // The process cwd must not be laundered through RootId + EntryId alone. A sibling Overlay with
    // the same lower archive/root and a wrong-root Overlay both fail before presentation or lookup.
    let sibling = overlay(&bytes, ROOT);
    assert!(
        sibling
            .revalidate_directory_handle(context.cwd_handle())
            .is_err()
    );
    let wrong_root = overlay(&bytes, OTHER_ROOT);
    assert!(
        wrong_root
            .revalidate_directory_handle(context.cwd_handle())
            .is_err()
    );
}
