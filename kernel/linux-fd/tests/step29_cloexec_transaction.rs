// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::EntryId;
use kernal_linux_fd::{Error as FdError, FdTable};
use kernal_linux_vfs::{ReadOnlyFile, RootId};

const ROOT: RootId = RootId::new(229);
const MODE: u32 = 0o100644;

fn file(index: u16) -> ReadOnlyFile {
    ReadOnlyFile::new(ROOT, EntryId::from_index(index), MODE, 8)
}

#[test]
fn cloexec_transaction_rejects_generation_drift_before_any_partial_close() {
    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();

    let first = fds
        .open_readonly_linux_with_flags(file(1), true, 0)
        .unwrap();
    let second = fds
        .open_readonly_linux_with_flags(file(2), true, 0)
        .unwrap();

    // Step 29 must snapshot the complete bounded CLOEXEC descriptor-generation set before
    // committing any close. The plan is deliberately invalidated after preparation.
    let plan = fds.prepare_close_on_exec().unwrap();

    let replacement = fds.duplicate_exact(1, second.fd(), false).unwrap();
    assert_ne!(replacement.generation(), second.generation());
    assert!(!fds.token_is_live(second));
    assert!(fds.token_is_live(replacement));

    // A stale selected generation invalidates the whole transaction. In particular, `first` must
    // remain live: processing selected descriptors one-by-one would have partially closed it before
    // discovering that `second` was replaced.
    assert_eq!(fds.commit_close_on_exec(plan), Err(FdError::StaleOpenFile));
    assert!(fds.token_is_live(first));
    assert_eq!(fds.close_on_exec(first.fd()), Ok(true));
    assert!(fds.token_is_live(replacement));
}

#[test]
fn cloexec_transaction_closes_only_the_prepared_generations_as_one_commit() {
    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();

    let first = fds
        .open_readonly_linux_with_flags(file(3), true, 0)
        .unwrap();
    let shared_survivor = fds.duplicate_lowest(first.fd(), false).unwrap();
    let second = fds
        .open_readonly_linux_with_flags(file(4), true, 0)
        .unwrap();

    let plan = fds.prepare_close_on_exec().unwrap();
    let _released = fds.commit_close_on_exec(plan).unwrap();

    assert!(!fds.token_is_live(first));
    assert!(!fds.token_is_live(second));
    assert!(fds.token_is_live(shared_survivor));
    assert_eq!(fds.close_on_exec(shared_survivor.fd()), Ok(false));
}
