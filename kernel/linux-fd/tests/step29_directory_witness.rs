// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable};
use kernal_linux_vfs::{AT_FDCWD, InitramfsRoot, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(0x29);

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn push_entry(out: &mut Vec<u8>, path: &str, mode: u32, data: &[u8]) {
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
    out.extend_from_slice(path.as_bytes());
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
    push_entry(&mut out, ".", S_IFDIR | 0o755, b"");
    push_entry(&mut out, "etc", S_IFDIR | 0o755, b"");
    push_entry(&mut out, "etc/hosts", S_IFREG | 0o644, b"127.0.0.1\n");
    push_entry(&mut out, "etc/ssl", S_IFDIR | 0o755, b"");
    push_entry(&mut out, "usr", S_IFDIR | 0o755, b"");
    push_entry(&mut out, "usr/bin", S_IFDIR | 0o755, b"");
    push_entry(&mut out, "TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

#[test]
fn matching_scan_commits_once_and_replay_cannot_advance_again() {
    let bytes = archive_bytes();
    let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
    let mut table = FdTable::<5>::new();
    let token = table.open_directory(directory).unwrap();
    let plan = table.prepare_directory(token.fd()).unwrap();
    let scan = root
        .directory_entry_from(directory, plan.start_cursor())
        .unwrap()
        .unwrap();
    let expected = u64::try_from(scan.next_cursor()).unwrap();

    table.commit_directory(plan, scan).unwrap();
    assert_eq!(table.offset(token.fd()), Ok(expected));

    assert_eq!(
        table.commit_directory(plan, scan),
        Err(FdError::StaleDirectory)
    );
    assert_eq!(table.offset(token.fd()), Ok(expected));
}

#[test]
fn multi_record_fault_retry_preserves_exact_cursor_witness() {
    let bytes = archive_bytes();
    let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
    let mut table = FdTable::<5>::new();
    let token = table.open_directory(directory).unwrap();

    // Record 1 is delivered successfully: commit the VFS-produced `.` witness.
    let first_plan = table.prepare_directory(token.fd()).unwrap();
    let first = root
        .directory_entry_from(directory, first_plan.start_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(first.entry().name(), b".");
    table.commit_directory(first_plan, first).unwrap();
    assert_eq!(table.offset(token.fd()), Ok(1));

    // Record 2 is prepared but userspace copy is assumed to fault. No commit is performed.
    let faulted_plan = table.prepare_directory(token.fd()).unwrap();
    assert_eq!(faulted_plan.start_cursor(), 1);
    let faulted = root
        .directory_entry_from(directory, faulted_plan.start_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(faulted.entry().name(), b"..");
    assert_eq!(table.offset(token.fd()), Ok(1));

    // A retry must prepare the exact same cursor and produce the exact same VFS witness.
    let retry_plan = table.prepare_directory(token.fd()).unwrap();
    assert_eq!(retry_plan.start_cursor(), faulted_plan.start_cursor());
    let retry = root
        .directory_entry_from(directory, retry_plan.start_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(retry, faulted);
    table.commit_directory(retry_plan, retry).unwrap();
    assert_eq!(table.offset(token.fd()), Ok(2));

    // Iteration then continues to the first ordinary child rather than skipping or replaying it.
    let child_plan = table.prepare_directory(token.fd()).unwrap();
    let child = root
        .directory_entry_from(directory, child_plan.start_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(child.entry().name(), b"hosts");
    let child_next = u64::try_from(child.next_cursor()).unwrap();
    table.commit_directory(child_plan, child).unwrap();
    assert_eq!(table.offset(token.fd()), Ok(child_next));
}

#[test]
fn full_cursor_walk_reaches_stable_eof_without_advancing() {
    let bytes = archive_bytes();
    let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
    let mut table = FdTable::<5>::new();
    let token = table.open_directory(directory).unwrap();

    for expected_name in [b".".as_slice(), b"..", b"hosts", b"ssl"] {
        let plan = table.prepare_directory(token.fd()).unwrap();
        let scan = root
            .directory_entry_from(directory, plan.start_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(scan.entry().name(), expected_name);
        let next = u64::try_from(scan.next_cursor()).unwrap();
        table.commit_directory(plan, scan).unwrap();
        assert_eq!(table.offset(token.fd()), Ok(next));
    }

    let eof_offset = table.offset(token.fd()).unwrap();
    for _ in 0..2 {
        let plan = table.prepare_directory(token.fd()).unwrap();
        assert_eq!(u64::try_from(plan.start_cursor()).unwrap(), eof_offset);
        assert!(
            root.directory_entry_from(directory, plan.start_cursor())
                .unwrap()
                .is_none()
        );
        assert_eq!(table.offset(token.fd()), Ok(eof_offset));
    }
}

#[test]
fn wrong_directory_and_wrong_start_witnesses_leave_cursor_unchanged() {
    let bytes = archive_bytes();
    let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let etc = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
    let usr = root.open_directory_at(AT_FDCWD, b"/usr").unwrap();
    let mut table = FdTable::<5>::new();
    let token = table.open_directory(etc).unwrap();
    let plan = table.prepare_directory(token.fd()).unwrap();

    let wrong_directory = root.directory_entry_from(usr, 0).unwrap().unwrap();
    assert_eq!(
        table.commit_directory(plan, wrong_directory),
        Err(FdError::InvalidDirectoryCursor)
    );
    assert_eq!(table.offset(token.fd()), Ok(0));

    let first = root.directory_entry_from(etc, 0).unwrap().unwrap();
    let wrong_start = root
        .directory_entry_from(etc, first.next_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(
        table.commit_directory(plan, wrong_start),
        Err(FdError::InvalidDirectoryCursor)
    );
    assert_eq!(table.offset(token.fd()), Ok(0));
}

#[test]
fn stale_generation_witness_cannot_mutate_reused_numeric_fd() {
    let bytes = archive_bytes();
    let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
    let mut table = FdTable::<4>::new();
    let original = table.open_directory(directory).unwrap();
    let plan = table.prepare_directory(original.fd()).unwrap();
    let scan = root
        .directory_entry_from(directory, plan.start_cursor())
        .unwrap()
        .unwrap();

    table.close(original.fd()).unwrap();
    let reused = table.open_directory(directory).unwrap();
    assert_eq!(reused.fd(), original.fd());
    assert_ne!(reused.generation(), original.generation());

    assert_eq!(
        table.commit_directory(plan, scan),
        Err(FdError::StaleDirectory)
    );
    assert_eq!(table.offset(reused.fd()), Ok(0));
}
