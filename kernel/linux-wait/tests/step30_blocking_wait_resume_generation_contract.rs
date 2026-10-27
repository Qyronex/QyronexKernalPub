// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Regression oracle for a blocking wait that switches away and later resumes the same scheduler
// generation. Destination address-space activation records a fresh switch generation, so the
// retained exception frame must be rebound before post-resume Wait/signal processing.

const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

#[test]
fn blocked_wait_rebinds_frame_before_post_resume_processing() {
    let resume = RUNTIME
        .find("Ok(resumed) if resumed == current => {")
        .expect("missing exact resumed-current wait branch");
    let tail = &RUNTIME[resume..];
    let sample = tail
        .find("current_user_switch_generation()")
        .expect("resumed wait must sample current TTBR0 switch generation");
    let rebind = tail
        .find("frame.rebind_entry_switch_generation(generation)")
        .expect("resumed wait must rebind the retained exception frame");
    let drain = tail
        .find("drain_step30_pending_exits_before_wait(current_cpu)")
        .expect("post-resume child-exit drain must remain present");
    let revalidate = tail
        .find("state.commit_wait_sleep_signal_aware(&receipt)")
        .expect("post-resume Wait revalidation must remain present");

    assert!(sample < rebind);
    assert!(rebind < drain);
    assert!(rebind < revalidate);
    assert!(tail[..drain].contains("NonZeroU64::new"));
}
