// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Step-30.7 live-exec resource contract.
//
// Returning every user PhysFrame is not sufficient for a recoverable failed exec. A fresh
// BoundProcessAddressSpace also consumes one root and may consume intermediate AArch64 page-table
// pages. The protected live table pool is finite, so an unreachable staging image must return its
// empty page-table tree through the canonical owners before failure can be reported as recoverable.

const PAGE_TABLE: &str = include_str!("../../page-table-aarch64/src/implementation.rs");
const ADDRESS_SPACE: &str = include_str!("../../address-space-aarch64/src/lib.rs");
const RUNTIME_TABLE: &str = include_str!("../../protected-boot-aarch64/src/runtime_table.rs");
const EXEC_DISCARD: &str = include_str!("../../process-aarch64/src/exec_discard.rs");
const ACTIVATION: &str = include_str!("../../process-aarch64/src/activation.rs");

fn contains_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| source.contains(needle))
}

fn earliest(source: &str, needles: &[&str]) -> Option<usize> {
    needles
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
}

fn bounded_owner_function<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source.find(marker).expect("missing owner function marker");
    let tail = &source[start..];
    let next_safe = tail.find("\n    fn ");
    let next_unsafe = tail.find("\n    unsafe fn ");
    let end = [next_safe, next_unsafe]
        .into_iter()
        .flatten()
        .filter(|offset| *offset != 0)
        .min()
        .unwrap_or(tail.len());
    &tail[..end]
}

#[test]
fn page_table_backend_has_an_explicit_terminal_table_release_edge() {
    assert!(
        contains_any(
            PAGE_TABLE,
            &[
                "unsafe fn release_table",
                "unsafe fn reclaim_table",
                "unsafe fn free_table",
                "unsafe fn recycle_table",
            ],
        ),
        "the AArch64 page-table Backend must expose an explicit terminal/unsafe table-page release edge; a safe scalar u64 release API cannot prove that a table is detached from a non-current tree"
    );
}

#[test]
fn aarch64_owner_exposes_terminal_empty_tree_reclaim() {
    assert!(
        contains_any(
            PAGE_TABLE,
            &[
                "reclaim_empty_tree",
                "reclaim_empty_page_table_tree",
                "release_empty_tree",
                "release_empty_page_table_tree",
                "reclaim_table_tree",
            ],
        ),
        "page-table ownership needs a terminal empty-tree traversal that can return children and the root after all user leaves are gone"
    );
    assert!(
        contains_any(
            ADDRESS_SPACE,
            &[
                "reclaim_empty_tree",
                "reclaim_empty_page_table_tree",
                "release_empty_tree",
                "release_empty_page_table_tree",
                "reclaim_table_tree",
            ],
        ),
        "Aarch64Root/AddressSpace must expose the terminal tree-reclaim boundary instead of making Process/Core bypass the address-space owner"
    );
}

#[test]
fn malformed_nonzero_invalid_descriptors_fail_before_destructive_reclaim() {
    for marker in ["fn verify_empty_tree", "unsafe fn reclaim_empty_children"] {
        let owner = bounded_owner_function(PAGE_TABLE, marker);
        let empty = owner
            .find("if entry == 0")
            .expect("empty-tree traversal must distinguish a genuinely zero descriptor");
        let invalid = owner
            .find("if entry & VALID == 0")
            .expect("nonzero descriptors with VALID clear must be checked explicitly");
        let rejected = owner[invalid..]
            .find("return Err(Error::InvalidDescriptor)")
            .map(|offset| invalid + offset)
            .expect("a malformed nonzero invalid descriptor must fail closed");

        assert!(
            empty < invalid && invalid < rejected,
            "{marker} must accept only entry==0 as empty, then reject nonzero VALID=0 before interpreting or mutating the tree"
        );
        assert!(
            !owner.contains("if entry & VALID == 0 {\n                continue;"),
            "{marker} must not silently treat a malformed nonzero VALID=0 descriptor as empty"
        );
    }
}

#[test]
fn live_runtime_table_pool_reuses_released_table_pages() {
    assert!(
        contains_any(
            RUNTIME_TABLE,
            &[
                "fn release_table",
                "fn reclaim_table",
                "fn free_table",
                "fn recycle_table",
            ],
        ),
        "the unique RuntimeTablePool owner must accept validated released table pages"
    );
    assert!(
        contains_any(
            RUNTIME_TABLE,
            &[
                "free_head",
                "free_list",
                "released_tables",
                "recycled_tables",
                "recycle_head",
                "reusable",
            ],
        ),
        "released tables must become reusable; a monotonic next-only cursor still leaks capacity across recoverable exec failures"
    );
}

#[test]
fn live_handoff_advances_the_reclaim_floor_past_construction_tables() {
    assert!(
        contains_any(
            RUNTIME_TABLE,
            &[
                "source.allocation_start = source.next",
                "source.recyclable_start = source.next",
                "source.release_floor = source.next",
                "owned.allocation_start = owned.next",
                "owned.recyclable_start = owned.next",
                "owned.release_floor = owned.next",
                "set_live_release_floor",
                "seal_live_release_floor",
                "advance_release_floor_to_next",
            ],
        ),
        "the recyclable/release floor must be captured at the one-way live handoff, after Step7-14 construction allocations; setting it only in RuntimeTablePool::new makes pre-live proof tables numerically releasable"
    );
}

#[test]
fn live_handoff_rejects_preexisting_recycle_state_before_cell_transition() {
    let install = bounded_owner_function(
        RUNTIME_TABLE,
        "fn install(&self, source: &mut RuntimeTablePool)",
    );
    let free_head = install
        .find("source.free_head")
        .expect("live handoff must inspect construction-window recycle state");
    let reject = install
        .find("LiveInvalidState")
        .expect("a pre-existing recycle chain must make handoff fail closed");
    let transition = install
        .find("compare_exchange")
        .expect("live handoff must retain the serialized state transition");

    assert!(
        free_head < transition && reject < transition,
        "pre-existing free/recycle state must be rejected before EMPTY -> INSTALLING mutates the live owner cell"
    );
}

#[test]
fn runtime_pool_release_implements_the_terminal_backend_authority() {
    assert!(
        contains_any(
            RUNTIME_TABLE,
            &[
                "unsafe fn release_table",
                "unsafe fn reclaim_table",
                "unsafe fn free_table",
                "unsafe fn recycle_table",
            ],
        ),
        "RuntimeTablePool must implement the terminal release authority with an unsafe/owner-proving boundary rather than expose a normal safe scalar release helper"
    );
}

#[test]
fn exec_staging_discard_drains_user_leaves_before_reclaiming_the_tree() {
    let leaf = EXEC_DISCARD
        .find("unmap_user_page_coalescing_anonymous")
        .expect("exec discard must still drain mapped anonymous user leaves through the canonical address-space owner");
    let tree = earliest(
        EXEC_DISCARD,
        &[
            "reclaim_empty_tree",
            "reclaim_empty_page_table_tree",
            "release_empty_tree",
            "release_empty_page_table_tree",
            "reclaim_table_tree",
        ],
    )
    .expect("exec discard must terminally return the now-empty staging page-table tree");

    assert!(
        leaf < tree,
        "user mappings/data frames must be removed before the staging page-table tree can be reclaimed"
    );
}

#[test]
fn successful_exec_reclaims_the_superseded_tree_after_user_frames() {
    let owner = bounded_owner_function(
        ACTIVATION,
        "pub unsafe fn reclaim_superseded_anonymous_user_frames",
    );
    let leaf = owner
        .find("unmap_user_page_coalescing_anonymous")
        .expect("superseded exec cleanup must still drain old-image user leaves");
    let tree = earliest(
        owner,
        &[
            "reclaim_empty_tree",
            "reclaim_empty_page_table_tree",
            "release_empty_tree",
            "release_empty_page_table_tree",
            "reclaim_table_tree",
        ],
    )
    .expect("successful exec must terminally reclaim the superseded old-image page-table tree");

    assert!(
        leaf < tree,
        "the superseded old image must return every user/data frame before its root/intermediate page-table pages are reclaimed"
    );
}
