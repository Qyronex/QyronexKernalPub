use kernal_linux_fd::{FdTable, SeekWhence};
use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

const ROOT: RootId = RootId::new(31);
const MODE: u32 = 0o100644;

fn file(entry_index: u16) -> ReadOnlyFile {
    ReadOnlyFile::new(ROOT, EntryId::from_index(entry_index), MODE, 16)
}

#[test]
fn exact_replacement_drops_only_one_reference_to_a_different_target_ofd() {
    let mut table = FdTable::<8>::new();
    let source = table.open_readonly(file(1)).unwrap();
    let target = table.open_readonly(file(2)).unwrap();
    let surviving_target_alias = table.duplicate(target.fd(), 0, false).unwrap();

    let target_ofd = table.open_file_id(target.fd()).unwrap();
    assert_eq!(
        table.open_file_id(surviving_target_alias.fd()),
        Ok(target_ofd)
    );

    let replacement = table
        .duplicate_exact(source.fd(), target.fd(), false)
        .unwrap();

    assert_eq!(replacement.fd(), target.fd());
    assert_eq!(
        table.open_file_id(replacement.fd()),
        table.open_file_id(source.fd())
    );
    assert_eq!(
        table.open_file_id(surviving_target_alias.fd()),
        Ok(target_ofd),
        "replacing one descriptor must reduce the old target OFD from two aliases to one, not destroy it"
    );

    assert_eq!(
        table.seek(surviving_target_alias.fd(), 5, SeekWhence::Set),
        Ok(5)
    );
    assert_eq!(table.offset(surviving_target_alias.fd()), Ok(5));

    table.close(surviving_target_alias.fd()).unwrap();
    table.close(source.fd()).unwrap();
    table.close(replacement.fd()).unwrap();
}
