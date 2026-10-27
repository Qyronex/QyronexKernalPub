use kernal_linux_fd::{FdTableSet, ReleasedObject};
use kernal_linux_pipe::PipeTable;
use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

const ROOT: RootId = RootId::new(30);
const O_WRONLY: u64 = 1;

fn file(entry: u16, size: u64) -> ReadOnlyFile {
    ReadOnlyFile::new(ROOT, EntryId::from_index(entry), 0o100644, size)
}

#[test]
fn child_exec_cloexec_does_not_close_parent_descriptor() {
    let mut set = FdTableSet::<2, 8>::new();
    let parent = set.create_view().unwrap();
    let parent_token = set
        .with_view(parent, |fds| {
            fds.open_readonly_with_cloexec(file(1, 8), true).unwrap()
        })
        .unwrap();
    let parent_ofd = set
        .with_view(parent, |fds| fds.open_file_id(parent_token.fd()).unwrap())
        .unwrap();

    let child = set.fork_view(parent).unwrap();
    let child_token = set
        .with_view(child, |fds| fds.token(parent_token.fd()).unwrap())
        .unwrap();
    assert_ne!(child_token.generation(), parent_token.generation());

    let released = set
        .with_view(child, |fds| {
            let plan = fds.prepare_close_on_exec().unwrap();
            fds.commit_close_on_exec(plan).unwrap()
        })
        .unwrap();
    assert_eq!(released, [None; 8]);
    assert_eq!(
        set.with_view(child, |fds| fds.token(child_token.fd()))
            .unwrap(),
        Err(kernal_linux_fd::Error::BadFd)
    );
    assert!(
        set.with_view(parent, |fds| fds.token_is_live(parent_token))
            .unwrap()
    );
    assert_eq!(
        set.with_view(parent, |fds| fds.open_file_id(parent_token.fd()))
            .unwrap(),
        Ok(parent_ofd)
    );
    assert_eq!(
        set.with_view(parent, |fds| fds.close_on_exec(parent_token.fd()))
            .unwrap(),
        Ok(true)
    );
}

#[test]
fn final_cross_view_pipe_release_is_reported_exactly_once() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut set = FdTableSet::<2, 8>::new();
    let parent = set.create_view().unwrap();
    set.with_view(parent, |fds| {
        fds.install_pipe_pair(pair.reader, pair.writer, false, 0, O_WRONLY)
            .unwrap()
    })
    .unwrap();
    let child = set.fork_view(parent).unwrap();

    let child_releases = set.retire_view(child).unwrap();
    assert!(child_releases.iter().all(Option::is_none));
    assert_eq!(pipes.reader_count(pair.writer), Ok(1));
    assert_eq!(pipes.writer_count(pair.reader), Ok(1));

    let parent_releases = set.retire_view(parent).unwrap();
    let mut reader_releases = 0usize;
    let mut writer_releases = 0usize;
    for object in parent_releases.into_iter().flatten() {
        match object {
            ReleasedObject::Pipe(endpoint) if endpoint == pair.reader => reader_releases += 1,
            ReleasedObject::Pipe(endpoint) if endpoint == pair.writer => writer_releases += 1,
            _ => panic!("unexpected final release object"),
        }
        pipes.close(object.pipe_endpoint()).unwrap();
    }
    assert_eq!(reader_releases, 1);
    assert_eq!(writer_releases, 1);
    assert_eq!(
        pipes.reader_count(pair.writer),
        Err(kernal_linux_pipe::Error::StaleEndpoint)
    );
    assert_eq!(
        pipes.writer_count(pair.reader),
        Err(kernal_linux_pipe::Error::StaleEndpoint)
    );
}
