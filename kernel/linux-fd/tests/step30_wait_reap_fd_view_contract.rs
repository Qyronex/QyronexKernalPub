// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP30_RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");
const STEP29_RUNTIME: &str = include_str!("../../core-aarch64/src/step29_runtime.rs");

fn destructive_reap_helper() -> &'static str {
    let start = STEP30_RUNTIME
        .find("fn commit_wait_reap_with_live_owners")
        .expect("missing destructive wait/reap integration helper");
    let tail = &STEP30_RUNTIME[start..];
    let end = tail
        .find("\nfn cancel_blocking_wait")
        .expect("missing helper boundary after destructive reap");
    &tail[..end]
}

#[test]
fn destructive_wait_reap_retires_the_exact_child_fd_view_after_runtime_commit() {
    let helper = destructive_reap_helper();
    assert!(
        helper.contains("observation.child()"),
        "destructive wait/reap must retain the exact child ObjectId from the canonical WaitObservation"
    );
    assert!(
        helper.contains("step29_runtime::retire_process"),
        "successful destructive wait/reap must retire the matching process-local FdView"
    );

    let reap = helper
        .find("commit_wait_reap_reclaiming_frames")
        .expect("missing canonical runtime reap commit");
    let retire = helper
        .find("step29_runtime::retire_process")
        .expect("missing post-reap FdView retirement");
    assert!(
        reap < retire,
        "FdView retirement must happen only after the destructive Process/Wait/AddressSpace commit"
    );
}

#[test]
fn wnowait_remains_non_destructive_and_fd_owner_has_one_retirement_edge() {
    let compact: String = STEP30_RUNTIME
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(
        compact.contains("if!plan.nowait{commit_wait_observation_phase2(current,observation)?;}"),
        "waitid WNOWAIT must skip every phase-2 owner and keep the exact observation plus process-local descriptor view observable"
    );
    assert!(
        compact.contains(
            "WaitEventClass::Exited=>commit_wait_reap_with_live_owners(current,observation)"
        ),
        "ordinary terminal wait consumption must still route through the exact destructive Process/FdView reap owner"
    );
    assert!(
        STEP29_RUNTIME.contains("pub fn retire_process(process: ObjectId)"),
        "Step30 must compose the existing process-local FdView owner rather than duplicate FD/OFD teardown"
    );
}
