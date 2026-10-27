// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 successful-exec ExceptionFrame generation contract.
//
// A successful exec activates a distinct TTBR0 binding and advances the canonical user-switch
// generation. The trapping ExceptionFrame still carries the entry-generation snapshot consumed by
// outer return/signal processing, so that private field must be rebound through its existing owner
// after the irreversible AddressSpace swap and before returning the committed frame to EL0.

const EXCEPTIONS: &str = include_str!("../../exceptions-aarch64/src/lib.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn function_window_for_any<'a>(source: &'a str, needles: &[&str]) -> &'a str {
    let marker = needles
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
        .expect("missing function marker");
    let prefix = &source[..marker];
    let start = [
        "\npub unsafe fn ",
        "\npub fn ",
        "\n    pub unsafe fn ",
        "\n    pub fn ",
        "\nunsafe fn ",
        "\nfn ",
    ]
    .into_iter()
    .filter_map(|boundary| prefix.rfind(boundary))
    .max()
    .map(|offset| offset + 1)
    .unwrap_or(marker);
    let tail = &source[start..];
    let end = [
        "\npub unsafe fn ",
        "\npub fn ",
        "\n    pub unsafe fn ",
        "\n    pub fn ",
        "\nunsafe fn ",
        "\nfn ",
    ]
    .into_iter()
    .filter_map(|boundary| tail[1..].find(boundary).map(|offset| offset + 1))
    .min()
    .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn exception_frame_owner_exposes_only_a_narrow_nonzero_generation_rebind() {
    let rebind = function_window_for_any(
        EXCEPTIONS,
        &[
            "rebind_entry_switch_generation",
            "update_entry_switch_generation",
            "set_entry_switch_generation",
        ],
    );

    assert!(
        rebind.contains("entry_switch_generation"),
        "the existing private ExceptionFrame generation field must remain the sole mutation target"
    );
    assert!(
        rebind.contains("generation") && (rebind.contains("== 0") || rebind.contains("NonZero")),
        "the owner must reject or structurally exclude a zero switch generation"
    );
    assert!(
        rebind.contains("unsafe") || rebind.contains("# Safety"),
        "rebinding a trapped frame to a new TTBR0 generation requires an explicit exception-owner safety contract"
    );
}

#[test]
fn live_exec_rebinds_the_frame_after_root_swap_and_before_frame_commit() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist");
    let tail = &RUNTIME[exec..];
    let swap = tail
        .find("commit_exec_address_space_replacement")
        .expect("successful exec must commit the retained AddressSpace replacement");
    let rebind = [
        "rebind_entry_switch_generation",
        "update_entry_switch_generation",
        "set_entry_switch_generation",
    ]
    .into_iter()
    .filter_map(|needle| tail.find(needle))
    .min()
    .expect("successful exec must rebind the trapping ExceptionFrame generation");
    let committed = tail
        .find("Outcome::FrameCommitted")
        .expect("successful exec must return through the committed-frame boundary");

    assert!(
        swap < rebind,
        "frame generation may change only after replacement activation commits"
    );
    assert!(
        rebind < committed,
        "outer return/signal processing must never observe the stale pre-exec generation"
    );
}
