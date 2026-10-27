// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE_SOURCE: &str = "tests/step15-linux-aarch64/pthread_minimum.c";
const FIXTURE_OUTPUT: &str = "target/step15-linux-aarch64/pthread_minimum";
const FIXTURE_BUILDER: &str = "tools/build-step15-musl-fixture.sh";

pub fn build_musl_fixture(root: &Path) -> Result<PathBuf, String> {
    let source = root.join(FIXTURE_SOURCE);
    if !source.is_file() {
        return Err(format!(
            "Step-15 unchanged-musl fixture source not found: {}",
            source.display()
        ));
    }

    let builder = root.join(FIXTURE_BUILDER);
    if !builder.is_file() {
        return Err(format!(
            "Step-15 musl fixture builder not found: {}",
            builder.display()
        ));
    }

    let status = Command::new("bash")
        .arg(&builder)
        .current_dir(root)
        .status()
        .map_err(|error| format!("start {}: {error}", builder.display()))?;
    if !status.success() {
        return Err(format!("Step-15 musl fixture builder failed with {status}"));
    }

    let output = root.join(FIXTURE_OUTPUT);
    let metadata = fs::metadata(&output)
        .map_err(|error| format!("stat Step-15 musl fixture {}: {error}", output.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "Step-15 musl fixture is missing or empty: {}",
            output.display()
        ));
    }

    Ok(output)
}

pub fn validate_initrd(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("stat AArch64 QEMU initrd {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "AArch64 QEMU initrd is missing or empty: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_paths_are_repo_relative_and_stable() {
        assert_eq!(
            FIXTURE_SOURCE,
            "tests/step15-linux-aarch64/pthread_minimum.c"
        );
        assert_eq!(
            FIXTURE_OUTPUT,
            "target/step15-linux-aarch64/pthread_minimum"
        );
        assert_eq!(FIXTURE_BUILDER, "tools/build-step15-musl-fixture.sh");
    }
}
