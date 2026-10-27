use kernal_linux_fd::{Error, FdTable, ReleasedObject, SeekWhence};
use kernal_linux_pipe::PipeTable;

const O_NONBLOCK: u64 = 0x800;
const O_WRONLY: u64 = 1;

#[test]
fn pipe_pair_install_uses_two_distinct_ofds_and_preserves_endpoint_status() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<6>::new();
    let installed = fds
        .install_pipe_pair(
            pair.reader,
            pair.writer,
            true,
            O_NONBLOCK,
            O_WRONLY | O_NONBLOCK,
        )
        .unwrap();
    assert_eq!(installed.reader().fd(), 0);
    assert_eq!(installed.writer().fd(), 1);
    assert_ne!(fds.open_file_id(0).unwrap(), fds.open_file_id(1).unwrap());
    assert_eq!(fds.pipe_endpoint(0), Ok(pair.reader));
    assert_eq!(fds.pipe_endpoint(1), Ok(pair.writer));
}

#[test]
fn pair_install_failure_leaves_both_owners_unchanged() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<1>::new();
    assert_eq!(
        fds.install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY),
        Err(Error::TableFull)
    );
    assert_eq!(fds.token(0), Err(Error::BadFd));
    assert_eq!(pipes.reader_count(pair.writer), Ok(1));
    assert_eq!(pipes.writer_count(pair.reader), Ok(1));
}

#[test]
fn duplicate_aliases_one_pipe_ofd_and_final_close_releases_once() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<6>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
        .unwrap();
    let alias = fds
        .duplicate_lowest(installed.reader().fd(), false)
        .unwrap();
    assert_eq!(
        fds.open_file_id(alias.fd()),
        fds.open_file_id(installed.reader().fd())
    );
    assert_eq!(pipes.reader_count(pair.writer), Ok(1));

    assert_eq!(
        fds.close_with_release(installed.reader().fd(), |_object| -> Result<(), ()> {
            panic!("non-final alias must not release")
        })
        .unwrap(),
        Ok(())
    );
    assert_eq!(pipes.reader_count(pair.writer), Ok(1));

    assert_eq!(
        fds.close_with_release(alias.fd(), |object| {
            assert_eq!(object, ReleasedObject::Pipe(pair.reader));
            pipes.close(object.pipe_endpoint())
        })
        .unwrap(),
        Ok(())
    );
    assert_eq!(pipes.reader_count(pair.writer), Ok(0));
}

#[test]
fn exact_replacement_of_nonfinal_pipe_alias_keeps_endpoint_live() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<6>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
        .unwrap();
    let writer_alias = fds
        .duplicate_lowest(installed.writer().fd(), false)
        .unwrap();
    let writer_ofd = fds.open_file_id(writer_alias.fd()).unwrap();

    let replacement = fds
        .duplicate_exact_with_release(
            installed.reader().fd(),
            installed.writer().fd(),
            false,
            |_object| -> Result<(), ()> { panic!("non-final target OFD must not release") },
        )
        .unwrap()
        .unwrap();

    assert_eq!(replacement.fd(), installed.writer().fd());
    assert_eq!(fds.pipe_endpoint(writer_alias.fd()), Ok(pair.writer));
    assert_eq!(fds.open_file_id(writer_alias.fd()), Ok(writer_ofd));
    assert_eq!(pipes.writer_count(pair.reader), Ok(1));

    assert_eq!(
        fds.close_with_release(writer_alias.fd(), |object| {
            assert_eq!(object, ReleasedObject::Pipe(pair.writer));
            pipes.close(object.pipe_endpoint())
        })
        .unwrap(),
        Ok(())
    );
    assert_eq!(pipes.writer_count(pair.reader), Ok(0));
}

#[test]
fn failed_external_release_does_not_mutate_fd_or_ofd_state() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<4>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
        .unwrap();
    let token = installed.writer();
    let open_file = fds.open_file_id(token.fd()).unwrap();

    assert_eq!(
        fds.close_with_release(token.fd(), |_object| Err::<(), _>("blocked"))
            .unwrap(),
        Err("blocked")
    );
    assert!(fds.token_is_live(token));
    assert_eq!(fds.open_file_id(token.fd()), Ok(open_file));
    assert_eq!(pipes.writer_count(pair.reader), Ok(1));
}

#[test]
fn exact_replacement_is_rollback_safe_and_surfaces_displaced_endpoint() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<6>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
        .unwrap();
    let reader_ofd = fds.open_file_id(installed.reader().fd()).unwrap();
    let writer_ofd = fds.open_file_id(installed.writer().fd()).unwrap();

    assert_eq!(
        fds.duplicate_exact(installed.reader().fd(), installed.writer().fd(), false),
        Err(Error::StaleOpenFile)
    );
    assert_eq!(
        fds.duplicate_exact_with_release(
            installed.reader().fd(),
            installed.writer().fd(),
            false,
            |_object| Err::<(), _>("blocked"),
        )
        .unwrap(),
        Err("blocked")
    );
    assert_eq!(fds.open_file_id(installed.reader().fd()), Ok(reader_ofd));
    assert_eq!(fds.open_file_id(installed.writer().fd()), Ok(writer_ofd));
    assert_eq!(pipes.writer_count(pair.reader), Ok(1));

    let replacement = fds
        .duplicate_exact_with_release(
            installed.reader().fd(),
            installed.writer().fd(),
            false,
            |object| {
                assert_eq!(object, ReleasedObject::Pipe(pair.writer));
                pipes.close(object.pipe_endpoint())
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(replacement.fd(), installed.writer().fd());
    assert_eq!(fds.open_file_id(replacement.fd()), Ok(reader_ofd));
    assert_eq!(pipes.writer_count(pair.reader), Ok(0));
}

#[test]
fn pipe_ofd_is_not_seekable_or_regular_file_readable() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<4>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
        .unwrap();
    assert_eq!(
        fds.seek(installed.reader().fd(), 0, SeekWhence::Set),
        Err(Error::NotSeekable)
    );
    assert_eq!(fds.offset(installed.reader().fd()), Err(Error::NotSeekable));
    assert_eq!(
        fds.prepare_read(installed.reader().fd(), 1),
        Err(Error::NotFile)
    );
    let metadata = fds.metadata(installed.reader().fd()).unwrap();
    assert_eq!(metadata.size, 0);
    assert_eq!(metadata.mode & 0o170000, 0o010000);
}
