// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 host-safe negative signal-frame oracle. Untrusted EL0 frame/pointer failures must terminate
// only the exact current Linux generation through the existing signaled-exit lifecycle. Kernel
// PAN/Runtime/owner failures remain invariants and must never be relabeled as userspace SIGSEGV.

const DELIVERY: &str = include_str!("../../core-aarch64/src/step30_signal_delivery.rs");
const SIGRETURN: &str = include_str!("../../core-aarch64/src/step30_sigreturn.rs");

fn function_window<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker: {marker}"));
    let tail = &source[start..];
    let body = &tail[marker.len()..];
    let end = ["\nfn ", "\npub(super) fn ", "\npub(crate) fn ", "\npub fn "]
        .into_iter()
        .filter_map(|next| body.find(next).map(|offset| marker.len() + offset))
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn malformed_rt_sigreturn_forces_truthful_sigsegv_instead_of_kernel_fallthrough() {
    assert!(SIGRETURN.contains("enum RestoreError"));
    assert!(SIGRETURN.contains("RestoreError::BadFrame"));
    assert!(SIGRETURN.contains("RestoreError::Invariant"));
    assert!(SIGRETURN.contains("Err(RestoreError::BadFrame) => terminate_bad_sigreturn()"));

    let terminate = function_window(SIGRETURN, "fn terminate_bad_sigreturn");
    assert!(terminate.contains("rt_sigreturn bad frame -> SIGSEGV"));
    assert!(terminate.contains("handle_fatal_signal(SIGSEGV, true)"));
    assert!(!terminate.contains("return Err"));
}

#[test]
fn rt_sigreturn_usercopy_faults_and_pan_invariants_stay_distinct() {
    let classify = function_window(SIGRETURN, "fn classify_usercopy_error");
    for user_error in [
        "Error::NullGuard",
        "Error::OutsideUserRange",
        "Error::Overflow",
        "Error::TooLarge",
        "Error::Fault",
    ] {
        assert!(classify.contains(user_error));
    }
    for kernel_error in [
        "Error::PanUnavailable",
        "Error::PanStateLeak",
        "Error::FaultHandlerUnavailable",
    ] {
        assert!(classify.contains(kernel_error));
    }
    assert!(classify.contains("=> RestoreError::BadFrame"));
    assert!(classify.contains("=> RestoreError::Invariant"));
}

#[test]
fn handler_frame_user_publication_failures_are_non_destructive_until_receipt_commit() {
    let terminate = function_window(DELIVERY, "fn terminate_bad_handler_frame");
    assert!(terminate.contains("signal frame bad user state -> SIGSEGV"));
    assert!(terminate.contains("handle_fatal_signal(SIGSEGV, true)"));

    let prepare = function_window(DELIVERY, "fn prepare_handler_frame");
    assert_eq!(
        prepare.matches("return Ok(None)").count(),
        1,
        "only a genuinely non-Handler prepared delivery may return None"
    );
    assert!(prepare.contains("misaligned handler/restorer"));
    assert!(prepare.contains("handler/restorer mapping is not executable"));
    assert!(prepare.contains("signal stack underflow"));
    assert!(prepare.contains("signal frame outside userspace"));
    assert!(prepare.contains("signal frame mapping is not fully writable"));
    assert!(prepare.contains("signal frame usercopy fault"));
    assert!(
        !prepare.contains("terminate_bad_handler_frame("),
        "frame preparation must classify bad user state but may not terminate before the exact PreparedSignal receipt is revalidated/committed",
    );
    assert!(
        prepare.contains("BadUserState") || prepare.contains("BadFrame"),
        "bad user handler/frame state must be returned explicitly to the delivery caller for linearization",
    );
}

#[test]
fn handler_frame_copy_pan_failures_remain_kernel_invariants() {
    let classify = function_window(DELIVERY, "fn handler_frame_copy_fault_is_user");
    assert!(classify.contains("Error::NullGuard"));
    assert!(classify.contains("Error::OutsideUserRange"));
    assert!(classify.contains("Error::Overflow"));
    assert!(classify.contains("Error::Fault"));
    assert!(!classify.contains("Error::PanUnavailable"));
    assert!(!classify.contains("Error::PanStateLeak"));
    assert!(!classify.contains("Error::FaultHandlerUnavailable"));

    let prepare = function_window(DELIVERY, "fn prepare_handler_frame");
    let copy = prepare
        .find("copy_to_user")
        .expect("handler frame publication must use canonical usercopy");
    let user_classification = prepare[copy..]
        .find("handler_frame_copy_fault_is_user")
        .map(|offset| copy + offset)
        .expect("copy fault must be classified before any forced SIGSEGV decision");
    let invariant_return = prepare[user_classification..]
        .find("return Err(())")
        .map(|offset| user_classification + offset)
        .expect("non-usercopy infrastructure failure must remain a kernel invariant");
    assert!(copy < user_classification && user_classification < invariant_return);
}
