// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 live-exec program-break owner contract.
//
// Exec preserves the exact Process generation while replacing its image. The existing BreakTable
// slot must therefore be updated in-place after the irreversible AddressSpace replacement. A Core
// remove+register sequence would introduce a second fallible/capacity edge after the old image is no
// longer authoritative.

const LINUX_VM: &str = include_str!("../../linux-vm/src/lib.rs");
const RUNTIME: &str = include_str!("../../core-aarch64/src/step30_runtime.rs");

fn function_window_for_any<'a>(source: &'a str, needles: &[&str]) -> &'a str {
    let marker = needles
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
        .expect("missing function marker");
    let prefix = &source[..marker];
    let start = ["\npub fn ", "\n    pub fn ", "\nfn ", "\n    fn "]
        .into_iter()
        .filter_map(|boundary| prefix.rfind(boundary))
        .max()
        .map(|offset| offset + 1)
        .unwrap_or(marker);
    let tail = &source[start..];
    let end = ["\npub fn ", "\n    pub fn ", "\nfn ", "\n    fn "]
        .into_iter()
        .filter_map(|boundary| tail[1..].find(boundary).map(|offset| offset + 1))
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn linux_vm_exec_break_replacement_updates_the_existing_exact_process_slot() {
    let replace = function_window_for_any(
        LINUX_VM,
        &["replace_process_break_for_exec", "replace_process_break"],
    );

    assert!(
        replace.contains("USER_MIN") && replace.contains("USER_MAX_EXCLUSIVE"),
        "exec break replacement must validate the canonical user range before mutation"
    );
    assert!(
        replace.contains("resolve_mut(process)"),
        "the exact existing generation-safe Process slot must be selected directly"
    );
    assert!(
        replace.contains("base") && replace.contains("current"),
        "exec must replace both the break base and current value together"
    );
    assert!(
        !replace.contains("register(")
            && !replace.contains("remove(")
            && !replace.contains("find(|slot| !slot.occupied)"),
        "same-Process exec must not free/reallocate the BreakTable slot or re-enter capacity search"
    );
}

#[test]
fn live_exec_consumes_the_atomic_break_owner_only_after_root_replacement() {
    let exec = RUNTIME
        .find("Step30RuntimeCall::Execve")
        .expect("live Execve dispatch must exist");
    let tail = &RUNTIME[exec..];
    let swap = tail
        .find("commit_exec_address_space_replacement")
        .expect("live exec must commit the generation-safe AddressSpace replacement");
    let replace = ["replace_process_break_for_exec", "replace_process_break"]
        .into_iter()
        .filter_map(|needle| tail.find(needle))
        .min()
        .expect("live exec must consume the atomic Linux VM break replacement owner");

    assert!(
        swap < replace,
        "the new image/root must commit before its initial brk replaces same-Process VM metadata"
    );
    assert!(
        !tail[..replace].contains("remove_process_break")
            && !tail[..replace].contains("register_process_break"),
        "Core must not synthesize exec brk replacement from the legacy remove/register pair"
    );
}
