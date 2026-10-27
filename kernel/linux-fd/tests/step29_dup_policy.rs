use kernal_linux_fd::{Error, FdTable};
use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

const ROOT: RootId = RootId::new(29);
const MODE: u32 = 0o100644;

fn file(entry_index: u16) -> ReadOnlyFile {
    ReadOnlyFile::new(ROOT, EntryId::from_index(entry_index), MODE, 8)
}

#[test]
fn f_dupfd_invalid_source_precedes_invalid_minimum() {
    let mut table = FdTable::<7>::new();

    assert_eq!(
        table.duplicate_from(99, -1, false),
        Err(Error::BadFd),
        "Linux fcntl resolves the source fd before validating F_DUPFD minimum"
    );
}

#[test]
fn f_dupfd_out_of_range_minimum_is_not_table_exhaustion() {
    let mut table = FdTable::<7>::new();
    let source = table.open_readonly(file(1)).unwrap();

    assert_eq!(
        table.duplicate_from(source.fd(), 7, false),
        Err(Error::InvalidMinimumFd),
        "minimum at the descriptor limit is EINVAL-class, not EMFILE-class exhaustion"
    );
}
