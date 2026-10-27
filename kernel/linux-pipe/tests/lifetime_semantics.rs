use kernal_linux_pipe::{Error, PipeTable};

#[test]
fn zero_length_write_does_not_report_broken_pipe() {
    let mut table = PipeTable::<1, 8>::new();
    let pair = table.create().unwrap();
    table.close(pair.reader).unwrap();

    let plan = table
        .prepare_write(pair.writer, 0)
        .expect("zero-length write must not depend on reader presence");
    assert!(plan.is_empty());
    table
        .commit_write(plan, b"")
        .expect("zero-length write commit must be side-effect free");
}

#[test]
fn copied_endpoint_value_cannot_recreate_closed_lease() {
    let mut table = PipeTable::<1, 8>::new();
    let pair = table.create().unwrap();
    let copied = pair.reader;
    table.close(pair.reader).unwrap();

    assert_eq!(
        table.close(copied),
        Err(Error::BadEndpoint),
        "a copied endpoint value names the same one-shot lease and cannot recreate it"
    );
    assert_eq!(table.reader_count(pair.writer), Ok(0));
}
