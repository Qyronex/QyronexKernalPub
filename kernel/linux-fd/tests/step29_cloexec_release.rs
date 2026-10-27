// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_fd::{FdTable, ReleasedObject};
use kernal_linux_pipe::PipeTable;

const O_WRONLY: u64 = 1;

#[test]
fn cloexec_batch_returns_only_final_pipe_release_while_non_cloexec_alias_survives() {
    let mut pipes = PipeTable::<1, 16>::new();
    let pair = pipes.create().unwrap();
    let mut fds = FdTable::<6>::new();
    let installed = fds
        .install_pipe_pair(pair.reader, pair.writer, true, 0, O_WRONLY)
        .unwrap();

    let reader_alias = fds
        .duplicate_lowest(installed.reader().fd(), false)
        .unwrap();
    assert_eq!(
        fds.open_file_id(reader_alias.fd()),
        fds.open_file_id(installed.reader().fd())
    );

    let plan = fds.prepare_close_on_exec().unwrap();
    let released = fds.commit_close_on_exec(plan).unwrap();

    assert!(!fds.token_is_live(installed.reader()));
    assert!(!fds.token_is_live(installed.writer()));
    assert!(fds.token_is_live(reader_alias));
    assert_eq!(fds.close_on_exec(reader_alias.fd()), Ok(false));

    let mut release_count = 0usize;
    for object in released.into_iter().flatten() {
        assert_eq!(object, ReleasedObject::Pipe(pair.writer));
        pipes.close(object.pipe_endpoint()).unwrap();
        release_count += 1;
    }
    assert_eq!(release_count, 1);
    assert_eq!(pipes.reader_count(pair.writer), Ok(1));
    assert_eq!(pipes.writer_count(pair.reader), Ok(0));

    assert_eq!(
        fds.close_with_release(reader_alias.fd(), |object| {
            assert_eq!(object, ReleasedObject::Pipe(pair.reader));
            pipes.close(object.pipe_endpoint())
        }),
        Ok(Ok(()))
    );
    assert_eq!(
        pipes.reader_count(pair.writer),
        Err(kernal_linux_pipe::Error::StaleEndpoint)
    );
}
