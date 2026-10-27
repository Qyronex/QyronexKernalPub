// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_fd::{Error, ExternalObject, FdTable, OpenObjectKind, SeekWhence};
use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

const ROOT: RootId = RootId::new(47);
const MODE: u32 = 0o100644;

fn file(entry_index: u16) -> ReadOnlyFile {
    ReadOnlyFile::new(ROOT, EntryId::from_index(entry_index), MODE, 8)
}

#[test]
fn seeded_stdio_owns_exact_low_descriptors_and_linux_open_starts_at_three() {
    let mut table = FdTable::<6>::new();
    let stdio = table.seed_standard_descriptors().unwrap();

    assert_eq!(stdio.stdin().fd(), 0);
    assert_eq!(stdio.stdout().fd(), 1);
    assert_eq!(stdio.stderr().fd(), 2);
    assert_eq!(
        table.object_kind(0),
        Ok(OpenObjectKind::External(ExternalObject::Stdin))
    );
    assert_eq!(
        table.object_kind(1),
        Ok(OpenObjectKind::External(ExternalObject::Stdout))
    );
    assert_eq!(
        table.object_kind(2),
        Ok(OpenObjectKind::External(ExternalObject::Stderr))
    );
    assert_eq!(table.status_flags(0), Ok(0));
    assert_eq!(table.status_flags(1), Ok(1));
    assert_eq!(table.status_flags(2), Ok(1));
    assert_eq!(table.close_on_exec(0), Ok(false));
    assert_eq!(table.close_on_exec(1), Ok(false));
    assert_eq!(table.close_on_exec(2), Ok(false));

    let opened = table
        .open_readonly_linux_with_flags(file(1), false, 0)
        .unwrap();
    assert_eq!(opened.fd(), 3);
    assert_eq!(table.object_kind(opened.fd()), Ok(OpenObjectKind::File));
}

#[test]
fn seeded_stdio_rejects_seek_and_positional_read_as_nonseekable() {
    let mut table = FdTable::<6>::new();
    table.seed_standard_descriptors().unwrap();

    for fd in 0..=2 {
        assert_eq!(table.seek(fd, 0, SeekWhence::Set), Err(Error::NotSeekable));
        assert_eq!(table.prepare_pread(fd, 0, 1), Err(Error::NotSeekable));
        assert_eq!(table.offset(fd), Err(Error::NotSeekable));
    }
}

#[test]
fn closing_stdin_makes_zero_the_next_linux_open_with_fresh_identity() {
    let mut table = FdTable::<6>::new();
    let stdio = table.seed_standard_descriptors().unwrap();
    let old_stdin_ofd = table.open_file_id(0).unwrap();

    table.close(0).unwrap();
    assert!(!table.token_is_live(stdio.stdin()));
    let reused = table
        .open_readonly_linux_with_flags(file(2), false, 0)
        .unwrap();

    assert_eq!(reused.fd(), 0);
    assert_eq!(reused.generation(), stdio.stdin().generation() + 1);
    assert_ne!(table.open_file_id(0).unwrap(), old_stdin_ofd);
    assert_eq!(table.object_kind(0), Ok(OpenObjectKind::File));
}

#[test]
fn stdout_dup_aliases_the_external_ofd_with_descriptor_local_cloexec() {
    let mut table = FdTable::<6>::new();
    table.seed_standard_descriptors().unwrap();
    let stdout_ofd = table.open_file_id(1).unwrap();

    let alias = table.duplicate_lowest(1, true).unwrap();
    assert_eq!(alias.fd(), 3);
    assert_eq!(table.open_file_id(alias.fd()), Ok(stdout_ofd));
    assert_eq!(
        table.object_kind(alias.fd()),
        Ok(OpenObjectKind::External(ExternalObject::Stdout))
    );
    assert_eq!(table.status_flags(alias.fd()), Ok(1));
    assert_eq!(table.close_on_exec(1), Ok(false));
    assert_eq!(table.close_on_exec(alias.fd()), Ok(true));

    table.set_close_on_exec(alias.fd(), false).unwrap();
    assert_eq!(table.close_on_exec(alias.fd()), Ok(false));
    assert_eq!(table.close_on_exec(1), Ok(false));
}

#[test]
fn external_close_and_exact_replacement_never_request_pipe_release() {
    let mut table = FdTable::<6>::new();
    table.seed_standard_descriptors().unwrap();

    let mut close_callbacks = 0usize;
    let close_result = table
        .close_with_release(0, |_| -> Result<(), ()> {
            close_callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(close_result, Ok(()));
    assert_eq!(close_callbacks, 0);

    let mut replace_callbacks = 0usize;
    let replacement = table
        .duplicate_exact_with_release(1, 2, false, |_| -> Result<(), ()> {
            replace_callbacks += 1;
            Ok(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(replacement.fd(), 2);
    assert_eq!(replace_callbacks, 0);
    assert_eq!(
        table.object_kind(2),
        Ok(OpenObjectKind::External(ExternalObject::Stdout))
    );
    assert_eq!(table.open_file_id(2), table.open_file_id(1));
}

#[test]
fn stdio_seed_is_transactional_and_one_shot() {
    let mut too_small = FdTable::<2>::new();
    assert!(too_small.seed_standard_descriptors().is_err());
    assert!(too_small.token(0).is_err());
    assert!(too_small.token(1).is_err());

    let mut table = FdTable::<5>::new();
    let first = table.seed_standard_descriptors().unwrap();
    let ids = [
        table.open_file_id(0).unwrap(),
        table.open_file_id(1).unwrap(),
        table.open_file_id(2).unwrap(),
    ];
    assert!(table.seed_standard_descriptors().is_err());
    assert_eq!(table.open_file_id(0), Ok(ids[0]));
    assert_eq!(table.open_file_id(1), Ok(ids[1]));
    assert_eq!(table.open_file_id(2), Ok(ids[2]));

    table.close(0).unwrap();
    table.close(1).unwrap();
    table.close(2).unwrap();
    assert!(!table.token_is_live(first.stdin()));
    assert!(!table.token_is_live(first.stdout()));
    assert!(!table.token_is_live(first.stderr()));
    assert!(table.seed_standard_descriptors().is_err());
    assert!(table.token(0).is_err());
    assert!(table.token(1).is_err());
    assert!(table.token(2).is_err());
}
