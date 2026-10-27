// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Step 16 intentionally reuses the unchanged Step-15 Linux/musl fixture. The extra acceptance
/// condition is proof that the successful userspace program traversed the normal production owners
/// from Linux leader publication through EL0/SVC, validated write return, final TTBR0 deactivation,
/// and proof-carrying process teardown.
pub const REQUIRED_EXACT_LINES: &[&str] = &[
    "KERNAL/ARM64: Step 15 initial Linux leader published PID=1 TID=1",
    "KERNAL/ARM64: Step 15 initial Linux TTBR0 activated",
    "KERNAL/ARM64: Step 15 write result=0x0000000000000032",
    "KERNAL/ARM64: Step 15 final Linux TTBR0 deactivated",
    "KERNAL/ARM64: Step 15 exit_group finalized status=0 initial-stack=reclaimed",
    "KERNAL/ARM64: Step 15 Linux process fully finalized",
];

/// These events prove normal VM progress, but ordinary libc is allowed to issue them more than once.
/// Step 16 therefore requires presence rather than an artificial exact cardinality.
pub const REQUIRED_PREFIX_LINES: &[&str] = &[
    "KERNAL/ARM64: Step 15 brk(0) query -> ",
    "KERNAL/ARM64: Step 15 mmap -> ",
];

pub fn require_production_path(transcript: &str) -> Result<(), String> {
    for &required in REQUIRED_EXACT_LINES {
        let count = transcript.lines().filter(|line| *line == required).count();
        if count != 1 {
            return Err(format!(
                "Step-16 transcript contains `{required}` {count} times; expected exactly once"
            ));
        }
    }

    for &prefix in REQUIRED_PREFIX_LINES {
        let count = transcript
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count();
        if count == 0 {
            return Err(format!(
                "Step-16 transcript is missing required production-path prefix `{prefix}`"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted_transcript() -> String {
        [
            REQUIRED_EXACT_LINES[0],
            REQUIRED_EXACT_LINES[1],
            "KERNAL/ARM64: Step 15 brk(0) query -> 0x0000000001032f48",
            "KERNAL/ARM64: Step 15 mmap -> 0x00007fffff7fb000",
            REQUIRED_EXACT_LINES[2],
            REQUIRED_EXACT_LINES[3],
            REQUIRED_EXACT_LINES[4],
            REQUIRED_EXACT_LINES[5],
        ]
        .join("\n")
    }

    #[test]
    fn accepts_one_complete_production_path() {
        require_production_path(&accepted_transcript()).unwrap();
    }

    #[test]
    fn accepts_repeated_normal_mmap_activity() {
        let mut transcript = accepted_transcript();
        transcript.push('\n');
        transcript.push_str("KERNAL/ARM64: Step 15 mmap -> 0x00007fffff7fa000");
        require_production_path(&transcript).unwrap();
    }

    #[test]
    fn rejects_missing_vm_progress() {
        let transcript = accepted_transcript().replace(
            "KERNAL/ARM64: Step 15 mmap -> 0x00007fffff7fb000",
            "KERNAL/ARM64: missing",
        );
        assert!(require_production_path(&transcript).is_err());
    }

    #[test]
    fn rejects_missing_ttbr0_deactivation() {
        let transcript = accepted_transcript().replace(
            "KERNAL/ARM64: Step 15 final Linux TTBR0 deactivated",
            "KERNAL/ARM64: missing",
        );
        assert!(require_production_path(&transcript).is_err());
    }

    #[test]
    fn rejects_missing_exit_finalization() {
        let transcript = accepted_transcript().replace(
            "KERNAL/ARM64: Step 15 Linux process fully finalized",
            "KERNAL/ARM64: missing",
        );
        assert!(require_production_path(&transcript).is_err());
    }

    #[test]
    fn rejects_duplicate_write_return() {
        let mut transcript = accepted_transcript();
        transcript.push('\n');
        transcript.push_str(REQUIRED_EXACT_LINES[2]);
        assert!(require_production_path(&transcript).is_err());
    }
}
