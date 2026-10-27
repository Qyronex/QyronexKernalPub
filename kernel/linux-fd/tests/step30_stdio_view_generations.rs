use kernal_linux_fd::FdTableSet;

#[test]
fn standard_descriptor_tokens_are_partitioned_by_process_view() {
    let mut set = FdTableSet::<2, 8>::new();
    let first = set.create_view().unwrap();
    let second = set.create_view().unwrap();

    let first_stdio = set
        .with_view(first, |fds| fds.seed_standard_descriptors().unwrap())
        .unwrap();
    let second_stdio = set
        .with_view(second, |fds| fds.seed_standard_descriptors().unwrap())
        .unwrap();

    assert_eq!(first_stdio.stdin().fd(), second_stdio.stdin().fd());
    assert_eq!(first_stdio.stdout().fd(), second_stdio.stdout().fd());
    assert_eq!(first_stdio.stderr().fd(), second_stdio.stderr().fd());

    assert_ne!(
        first_stdio.stdin().generation(),
        second_stdio.stdin().generation()
    );
    assert_ne!(
        first_stdio.stdout().generation(),
        second_stdio.stdout().generation()
    );
    assert_ne!(
        first_stdio.stderr().generation(),
        second_stdio.stderr().generation()
    );
}
