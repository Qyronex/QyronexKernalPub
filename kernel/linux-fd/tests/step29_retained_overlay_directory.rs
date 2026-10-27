// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable, OpenObjectKind, ReleasedObject};
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(241);
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 241,
    nanoseconds: 7,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 4>;

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
        7,
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

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn retained_overlay_directory_is_one_shared_ofd_authority_with_vfs_cursor_witnesses() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/upper", 0o755, 0, 0, NOW).unwrap();

    let directory = overlay.open_and_retain_directory_at(b"/upper").unwrap();
    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_directory_linux_with_flags(directory, false, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();

    assert_eq!(fds.object_kind(fd.fd()), Ok(OpenObjectKind::Directory));
    assert_eq!(fds.retained_directory(fd.fd()), Ok(directory));
    assert_eq!(fds.retained_directory(alias.fd()), Ok(directory));
    assert_eq!(fds.open_file_id(fd.fd()), fds.open_file_id(alias.fd()));

    let plan = fds.prepare_retained_directory(fd.fd()).unwrap();
    assert_eq!(plan.2, directory);
    assert_eq!(plan.3, 0);
    let scan = overlay
        .directory_entry_from(plan.2, plan.3)
        .unwrap()
        .unwrap();
    assert_eq!(scan.entry().name(), b".");
    assert_eq!(fds.commit_retained_directory(plan, scan), Ok(()));
    assert_eq!(fds.prepare_retained_directory(alias.fd()).unwrap().3, 1);

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final directory alias must not release VFS authority")
        }),
        Ok(Ok(()))
    );
    assert_eq!(
        fds.close_with_release(fd.fd(), |released| -> Result<(), ()> {
            let ReleasedObject::RetainedDirectory(released) = released else {
                panic!("final directory close returned the wrong authority kind");
            };
            assert_eq!(released, directory);
            overlay.release_directory(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}

#[test]
fn retained_overlay_directory_rejects_stale_alias_cursor_commit() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/upper", 0o755, 0, 0, NOW).unwrap();
    let directory = overlay.open_and_retain_directory_at(b"/upper").unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_directory_linux_with_flags(directory, false, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();

    let first = fds.prepare_retained_directory(fd.fd()).unwrap();
    let stale_alias = fds.prepare_retained_directory(alias.fd()).unwrap();
    let first_scan = overlay
        .directory_entry_from(first.2, first.3)
        .unwrap()
        .unwrap();
    let stale_scan = overlay
        .directory_entry_from(stale_alias.2, stale_alias.3)
        .unwrap()
        .unwrap();

    assert_eq!(fds.commit_retained_directory(first, first_scan), Ok(()));
    assert_eq!(
        fds.commit_retained_directory(stale_alias, stale_scan),
        Err(FdError::StaleDirectory)
    );
    assert_eq!(fds.prepare_retained_directory(alias.fd()).unwrap().3, 1);

    fds.close(alias.fd()).unwrap();
    fds.close_with_release(fd.fd(), |released| -> Result<(), ()> {
        let ReleasedObject::RetainedDirectory(released) = released else {
            panic!("final directory close returned the wrong authority kind");
        };
        overlay.release_directory(released).map_err(|_| ())
    })
    .unwrap()
    .unwrap();
}

#[test]
fn retained_overlay_directory_exact_replacement_releases_target_and_shares_source_hold() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/a", 0o755, 0, 0, NOW).unwrap();
    overlay.mkdir_at(b"/b", 0o755, 0, 0, NOW).unwrap();
    let a = overlay.open_and_retain_directory_at(b"/a").unwrap();
    let b = overlay.open_and_retain_directory_at(b"/b").unwrap();

    let mut fds = FdTable::<10>::new();
    fds.seed_standard_descriptors().unwrap();
    let source = fds
        .open_retained_directory_linux_with_flags(a, false, O_RDONLY)
        .unwrap();
    let source_alias = fds.duplicate_lowest(source.fd(), false).unwrap();
    let target = fds
        .open_retained_directory_linux_with_flags(b, false, O_RDONLY)
        .unwrap();

    let replaced = fds
        .duplicate_exact_with_release(
            source.fd(),
            target.fd(),
            false,
            |released| -> Result<(), ()> {
                let ReleasedObject::RetainedDirectory(released) = released else {
                    panic!("replaced target returned the wrong authority kind");
                };
                assert_eq!(released, b);
                overlay.release_directory(released).map_err(|_| ())
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(replaced.fd(), target.fd());
    assert_eq!(fds.retained_directory(replaced.fd()), Ok(a));
    assert_eq!(
        fds.open_file_id(source.fd()),
        fds.open_file_id(replaced.fd())
    );

    fds.close(source_alias.fd()).unwrap();
    fds.close(source.fd()).unwrap();
    fds.close_with_release(replaced.fd(), |released| -> Result<(), ()> {
        let ReleasedObject::RetainedDirectory(released) = released else {
            panic!("final source OFD release returned the wrong authority kind");
        };
        assert_eq!(released, a);
        overlay.release_directory(released).map_err(|_| ())
    })
    .unwrap()
    .unwrap();
}

#[test]
fn retained_overlay_directory_cloexec_batch_returns_one_final_authority() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/upper", 0o755, 0, 0, NOW).unwrap();
    let directory = overlay.open_and_retain_directory_at(b"/upper").unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_directory_linux_with_flags(directory, true, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), true).unwrap();
    assert_eq!(fds.open_file_id(fd.fd()), fds.open_file_id(alias.fd()));

    let plan = fds.prepare_close_on_exec().unwrap();
    let released = fds.commit_close_on_exec(plan).unwrap();
    let mut directory_releases = 0usize;
    for object in released.into_iter().flatten() {
        let ReleasedObject::RetainedDirectory(released_directory) = object else {
            panic!("CLOEXEC returned the wrong authority kind");
        };
        assert_eq!(released_directory, directory);
        directory_releases += 1;
    }
    assert_eq!(directory_releases, 1);
    assert_eq!(fds.token(fd.fd()), Err(FdError::BadFd));
    assert_eq!(fds.token(alias.fd()), Err(FdError::BadFd));
    overlay.release_directory(directory).unwrap();
}

#[test]
fn retained_overlay_directory_rejects_writable_access_without_consuming_vfs_hold() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/upper", 0o755, 0, 0, NOW).unwrap();
    let directory = overlay.open_and_retain_directory_at(b"/upper").unwrap();

    let mut fds = FdTable::<6>::new();
    fds.seed_standard_descriptors().unwrap();
    assert_eq!(
        fds.open_retained_directory_linux_with_flags(directory, false, O_WRONLY),
        Err(FdError::BadFd)
    );

    overlay.release_directory(directory).unwrap();
}
