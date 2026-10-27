// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 regression oracle for the first exact-head Gate-5 failure after the wait/reap
// lifecycle became green. A fork child must route Step-29 descriptor syscalls through the
// canonical scheduler-generation -> Process/AddressSpace owner, never through the initial leader.

const PATH_FD: &str = include_str!("../../core-aarch64/src/step29_fd.rs");
const FD_IO: &str = include_str!("../../core-aarch64/src/step29_fd_io.rs");

fn current_process_window(source: &str) -> &str {
    let marker = "fn current_process() -> Result<ObjectId, Error>";
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing current_process marker"));
    let tail = &source[start..];
    let end = tail[marker.len()..]
        .find("\nfn ")
        .map(|offset| marker.len() + offset)
        .unwrap_or(tail.len());
    &tail[..end]
}

fn assert_generation_safe_current_process(source: &str, adapter: &str) {
    let current = current_process_window(source);

    assert!(
        current.contains("process_parts_for_scheduler_thread(current)"),
        "{adapter} must resolve the exact scheduler generation through the canonical retained Process owner"
    );
    assert!(
        !current.contains("initial_leader_parts()"),
        "{adapter} must not collapse a fork child back onto the initial leader"
    );

    let select = current
        .find("process_parts_for_scheduler_thread(current)")
        .expect("canonical process selector");
    let active = current
        .find("current_owner(")
        .expect("active AddressSpace owner proof");
    let publish = current
        .find("Ok(process.id())")
        .expect("selected Process generation publication");

    assert!(
        select < active,
        "{adapter} must select the exact retained owner before validating the active AddressSpace"
    );
    assert!(
        active < publish,
        "{adapter} must validate the active AddressSpace before returning the Process ObjectId observation"
    );
}

#[test]
fn path_fd_child_syscalls_select_the_exact_current_process_generation() {
    assert_generation_safe_current_process(PATH_FD, "step29_fd");
}

#[test]
fn fd_io_child_syscalls_select_the_exact_current_process_generation() {
    assert_generation_safe_current_process(FD_IO, "step29_fd_io");
}
