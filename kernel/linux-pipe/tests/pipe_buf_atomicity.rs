use kernal_linux_pipe::{Error, PIPE_BUF, PipeTable};

#[test]
fn blocking_and_nonblocking_small_writes_share_pipe_buf_atomic_plan_rule() {
    let mut table = PipeTable::<1, 8>::new();
    let pair = table.create().unwrap();
    let seed = table.prepare_write(pair.writer, 6).unwrap();
    table.commit_write(seed, b"abcdef").unwrap();
    assert_eq!(table.free_capacity(pair.writer), Ok(2));

    assert_eq!(
        table.prepare_write(pair.writer, 3),
        Err(Error::WouldBlock),
        "blocking <= PIPE_BUF must wait/retry rather than expose a partial plan"
    );
    assert_eq!(
        table.prepare_nonblocking_write(pair.writer, 3),
        Err(Error::WouldBlock),
        "nonblocking <= PIPE_BUF maps the same owner condition to EAGAIN in integration"
    );
    assert_eq!(table.len(pair.reader), Ok(6));
    assert_eq!(table.free_capacity(pair.writer), Ok(2));
}

#[test]
fn writes_above_pipe_buf_may_still_plan_a_positive_prefix() {
    let mut table = PipeTable::<1, 8192>::new();
    let pair = table.create().unwrap();
    let seed = table.prepare_write(pair.writer, 5000).unwrap();
    table.commit_write(seed, &[1; 5000]).unwrap();

    let requested = PIPE_BUF + 1000;
    let blocking = table.prepare_write(pair.writer, requested).unwrap();
    let nonblocking = table
        .prepare_nonblocking_write(pair.writer, requested)
        .unwrap();
    assert_eq!(blocking.len(), 3192);
    assert_eq!(nonblocking.len(), 3192);
}
