// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 regression oracle: a lower-EL IRQ frame may survive a scheduler
// switch-away/switch-back on its kernel stack. TTBR0 activation advances the
// per-PE switch generation, so the resumed exact frame must refresh only that
// generation observation before the canonical signal owner revalidates it.

const QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const EXCEPTIONS: &str = include_str!("../../exceptions-aarch64/src/lib.rs");

fn irq_signal_return_bridge() -> &'static str {
    let start = QEMU
        .find("pub(super) fn deliver_step30_signal_on_return")
        .expect("missing Step-30 signal-return bridge");
    let tail = &QEMU[start..];
    let end = tail
        .find("\n}\n\nextern \"C\" fn step15_lower_el_fallback")
        .expect("missing Step-30 signal-return bridge boundary");
    &tail[..end + 2]
}

#[test]
fn irq_roundtrip_refreshes_switch_generation_before_signal_revalidation() {
    let bridge = irq_signal_return_bridge();
    let irq_guard = bridge
        .find("frame.kind() == kernal_exceptions_aarch64::ExceptionKind::Irq")
        .expect("switch-generation refresh must remain IRQ-only");
    let generation = bridge
        .find("kernal_process_aarch64::current_user_switch_generation()")
        .expect("IRQ resume must sample the currently active TTBR0 switch generation");
    let rebind = bridge
        .find("frame.rebind_entry_switch_generation(generation)")
        .expect("resumed IRQ frame must be rebound to the exact current generation");
    let delivery = bridge
        .find("signal_delivery::deliver_on_return(frame)")
        .expect("bridge must still delegate to the canonical signal owner");

    assert!(irq_guard < generation && generation < rebind && rebind < delivery);
}

#[test]
fn synchronous_returns_do_not_unconditionally_rebind_the_entry_generation() {
    let bridge = irq_signal_return_bridge();
    assert_eq!(
        bridge
            .matches("frame.rebind_entry_switch_generation(generation)")
            .count(),
        1,
        "the IRQ roundtrip repair must not weaken the synchronous stale-frame guard",
    );
    assert!(
        bridge.contains("if frame.kind() == kernal_exceptions_aarch64::ExceptionKind::Irq"),
        "generation rebinding must stay behind the IRQ-kind guard",
    );
}

#[test]
fn exception_rebind_contract_covers_scheduler_roundtrip_ownership() {
    assert!(EXCEPTIONS.contains("scheduler switch-away/switch-back"));
    assert!(EXCEPTIONS.contains("exact current scheduler/Process"));
    assert!(EXCEPTIONS.contains("different scheduler generation"));
}
