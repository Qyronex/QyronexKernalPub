#!/usr/bin/env python3
"""Record append-only main-merge events and join exact repository metrics when available.

The merge-event ledger is intentionally lightweight: recording a merge must not
wait for the repository-wide LOC scan. Exact repository metrics are stored in a
separate ledger and joined by commit SHA when rendering the human report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import repository_metrics  # noqa: E402

SCHEMA_VERSION = 3
MEASUREMENT_VERSION = "kernal-merge-observation-v3"
REPOSITORY_METRICS_VERSION = "kernal-repository-metrics-v2"
DEFAULT_LEDGER = "research/main-merges.ndjson"
DEFAULT_SNAPSHOT_LEDGER = "research/repository-snapshots.ndjson"
DEFAULT_REPORT = "RESEARCH_HISTORY.md"
DEFAULT_BACKFILL = "research/backfill-main-merges.json"


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.decode("utf-8", errors="strict").strip()


def git_object_exists(rev: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", f"{rev}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_diff_base(merge_sha: str) -> str:
    """Use the exact merge commit's first parent as the pre-merge main state."""
    parents = run_git("rev-list", "--parents", "-n", "1", merge_sha).split()
    if len(parents) < 2:
        raise RuntimeError(f"cannot determine first parent for merge {merge_sha}")
    return parents[1]


def change_observation(base_sha: str, merge_sha: str) -> dict[str, Any]:
    output = run_git("diff", "--numstat", base_sha, merge_sha)
    files: list[dict[str, Any]] = []
    areas: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "files": 0,
            "additions": 0,
            "deletions": 0,
            "net": 0,
            "binary_files": 0,
        }
    )
    additions = 0
    deletions = 0
    binary_files = 0

    for line in output.splitlines():
        if not line:
            continue
        added_raw, deleted_raw, path = line.split("\t", 2)
        binary = added_raw == "-" or deleted_raw == "-"
        added = None if binary else int(added_raw)
        deleted = None if binary else int(deleted_raw)
        area = repository_metrics.area_for_path(path)
        files.append(
            {
                "path": path,
                "area": area,
                "additions": added,
                "deletions": deleted,
                "net": None if binary else added - deleted,
                "binary": binary,
            }
        )
        stats = areas[area]
        stats["files"] += 1
        if binary:
            binary_files += 1
            stats["binary_files"] += 1
        else:
            assert added is not None and deleted is not None
            additions += added
            deletions += deleted
            stats["additions"] += added
            stats["deletions"] += deleted
            stats["net"] += added - deleted

    return {
        "diff_base_sha": base_sha,
        "diff_head_sha": merge_sha,
        "files_changed": len(files),
        "binary_files_changed": binary_files,
        "additions": additions,
        "deletions": deletions,
        "net": additions - deletions,
        "areas": dict(sorted(areas.items())),
        "files": files,
    }


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid NDJSON at {path}:{number}: {exc}") from exc
    return rows


def load_snapshot_index(path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in load_ndjson(path):
        sha = str(row.get("commit", {}).get("sha") or "")
        if sha:
            index[sha] = row
    return index


def add_integrity(record: dict[str, Any]) -> None:
    canonical = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    record["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": (
            "UTF-8 JSON with sorted keys and compact separators, excluding integrity"
        ),
        "digest": hashlib.sha256(canonical).hexdigest(),
    }


def make_record(
    event: dict[str, Any],
    snapshot_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pr = event["pull_request"]
    if not pr.get("merged"):
        raise RuntimeError("pull request is not merged")
    if pr.get("base", {}).get("ref") != "main":
        raise RuntimeError("pull request base is not main")

    merge_sha = str(pr.get("merge_commit_sha") or "")
    if not merge_sha or not git_object_exists(merge_sha):
        raise RuntimeError(
            f"merge commit is unavailable locally: {merge_sha or '<empty>'}"
        )

    diff_base = canonical_diff_base(merge_sha)
    committed_at = run_git("show", "-s", "--format=%cI", merge_sha)
    change = change_observation(diff_base, merge_sha)
    mode = str(event.get("_research_observation_mode") or "github_event")
    source = str(event.get("_research_source") or "GITHUB_EVENT_PATH")
    snapshot = snapshot_index.get(merge_sha)

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "measurement_version": MEASUREMENT_VERSION,
        "record_type": "main_merge_observation",
        "event_id": f"pr-{pr['number']}-{merge_sha}",
        "observed_at_utc": utc_now(),
        "repository": (
            event.get("repository", {}).get("full_name")
            or os.environ.get("GITHUB_REPOSITORY", "")
        ),
        "main_commit": {
            "sha": merge_sha,
            "committed_at": committed_at,
        },
        "pull_request": {
            "number": pr["number"],
            "title": pr.get("title", ""),
            "url": pr.get("html_url", ""),
            "merged_at": pr.get("merged_at"),
            "base_ref": pr.get("base", {}).get("ref"),
            "base_sha_reported": pr.get("base", {}).get("sha"),
            "head_ref": pr.get("head", {}).get("ref"),
            "head_sha": pr.get("head", {}).get("sha"),
            "author": pr.get("user", {}).get("login"),
            "merged_by": pr.get("merged_by", {}).get("login"),
            "github_reported": {
                "additions": pr.get("additions"),
                "deletions": pr.get("deletions"),
                "changed_files": pr.get("changed_files"),
                "commits": pr.get("commits"),
            },
        },
        "change": change,
        "repository_snapshot_ref": {
            "commit_sha": merge_sha,
            "measurement_version": REPOSITORY_METRICS_VERSION,
            "canonical_ledger": DEFAULT_SNAPSHOT_LEDGER,
            "materialization_state_at_observation": (
                "available" if snapshot is not None else "pending"
            ),
            "integrity_digest_at_observation": (
                snapshot.get("integrity", {}).get("digest")
                if snapshot is not None
                else None
            ),
        },
        "ontology": {
            "observation_class": "MergeObservation",
            "subject_class": "SoftwareRepository",
            "event_class": "PullRequestMerge",
            "commit_class": "GitCommit",
            "snapshot_class": "RepositoryMetricSnapshot",
            "area_class": "ProjectArea",
            "file_change_class": "FileChange",
            "metric_class": "LineMetric",
            "changed_areas": sorted(change["areas"]),
        },
        "provenance": {
            "observation_mode": mode,
            "source": source,
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "actor": os.environ.get("GITHUB_ACTOR"),
            "event_name": os.environ.get("GITHUB_EVENT_NAME"),
            "git_version": run_git("--version"),
            "diff_base_rule": "first parent of exact merge commit",
            "snapshot_join_rule": (
                "research/repository-snapshots.ndjson commit.sha equals main_commit.sha"
            ),
        },
    }
    add_integrity(record)
    return record


def append_if_missing(
    records: list[dict[str, Any]],
    ledger_path: Path,
    event: dict[str, Any],
    snapshot_index: dict[str, dict[str, Any]],
) -> bool:
    pr = event.get("pull_request") or {}
    merge_sha = str(pr.get("merge_commit_sha") or "")
    if not merge_sha:
        raise RuntimeError("event has no merge_commit_sha")
    if any(row.get("main_commit", {}).get("sha") == merge_sha for row in records):
        return False
    record = make_record(event, snapshot_index)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        handle.write("\n")
    records.append(record)
    return True


def apply_backfill_manifest(
    records: list[dict[str, Any]],
    ledger_path: Path,
    manifest_path: Path,
    snapshot_index: dict[str, dict[str, Any]],
) -> int:
    if not manifest_path.exists():
        return 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not isinstance(
        manifest.get("events"), list
    ):
        raise RuntimeError(f"invalid research backfill manifest: {manifest_path}")
    added = 0
    for event in manifest["events"]:
        if append_if_missing(records, ledger_path, event, snapshot_index):
            added += 1
    return added


def render_report(
    records: list[dict[str, Any]],
    snapshot_index: dict[str, dict[str, Any]],
) -> str:
    ordered = sorted(
        records,
        key=lambda row: (
            row.get("main_commit", {}).get("committed_at") or "",
            row.get("main_commit", {}).get("sha") or "",
        ),
    )
    lines = [
        "# Kernal Research History",
        "",
        "> Derived human-readable view. Canonical merge events live in "
        "`research/main-merges.ndjson`; exact repository snapshots live in "
        "`research/repository-snapshots.ndjson` and are joined by commit SHA.",
        "",
        "## Measurement contract",
        "",
        "- Observation unit: one pull request merged into `main`.",
        "- Merge events are persisted independently of repository-wide LOC scans.",
        "- Diff base: first parent of the exact merge commit.",
        "- Change magnitude: Git `--numstat` additions/deletions from that first "
        "parent to the merge commit.",
        "- Source-code LOC and all tracked UTF-8 text LOC are separate variables.",
        "- Missing repository snapshots are reported as `pending`; no LOC value is invented.",
        "- Explicit historical backfills are marked by "
        "`provenance.observation_mode=backfill_manifest`.",
        "",
    ]

    if not ordered:
        lines.extend(
            [
                "## Recorded observations",
                "",
                "No materialized main-merge observation exists yet.",
                "",
            ]
        )
        return "\n".join(lines)

    snapshots = sorted(
        snapshot_index.values(),
        key=lambda row: (
            row.get("commit", {}).get("committed_at") or "",
            row.get("commit", {}).get("sha") or "",
        ),
    )
    lines.extend(["## Repository snapshot status", ""])
    if snapshots:
        latest_snapshot = snapshots[-1]
        lines.extend(
            [
                f"- Latest materialized metrics SHA: "
                f"`{latest_snapshot['commit']['sha']}`",
                f"- **Source-code LOC:** "
                f"{latest_snapshot['source_code']['lines']:,}",
                f"- **All tracked UTF-8 text LOC:** "
                f"{latest_snapshot['tracked_utf8_text']['lines']:,}",
                f"- Tracked blobs: "
                f"{latest_snapshot['tracked_repository']['files']:,}",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "- No exact repository-metrics-v2 snapshot has been materialized yet.",
                "- Merge-event history remains valid; LOC columns below stay `pending`.",
                "",
            ]
        )

    lines.extend(
        [
            "## Merge observations",
            "",
            "| Merged at | PR | Commit | + | - | Net | Source LOC after | "
            "All text LOC after | Snapshot | Mode | Areas |",
            "|---|---:|---|---:|---:|---:|---:|---:|---|---|---|",
        ]
    )
    for record in reversed(ordered[-500:]):
        pr = record["pull_request"]
        change = record["change"]
        sha = record["main_commit"]["sha"]
        snap = snapshot_index.get(sha)
        areas = ", ".join(sorted(change["areas"])) or "—"
        title = str(pr.get("title") or "").replace("|", "\\|")
        merged_at = (
            pr.get("merged_at")
            or record["main_commit"].get("committed_at")
            or "—"
        )
        mode = record.get("provenance", {}).get("observation_mode") or "—"
        if snap is None:
            source_loc = "pending"
            all_text_loc = "pending"
            snapshot_state = "pending"
        else:
            source_loc = str(snap["source_code"]["lines"])
            all_text_loc = str(snap["tracked_utf8_text"]["lines"])
            snapshot_state = "available"
        lines.append(
            f"| {merged_at} | [#{pr['number']}]({pr.get('url') or '#'}) {title} | "
            f"`{sha[:10]}` | {change['additions']} | {change['deletions']} | "
            f"{change['net']:+d} | {source_loc} | {all_text_loc} | "
            f"{snapshot_state} | {mode} | {areas} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation warning",
            "",
            "LOC, file counts and change magnitude are descriptive measurements. "
            "They are not direct measures of quality, productivity, complexity, "
            "correctness or scientific contribution.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"))
    parser.add_argument("--ledger", default=DEFAULT_LEDGER)
    parser.add_argument("--snapshot-ledger", default=DEFAULT_SNAPSHOT_LEDGER)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument("--backfill-manifest", default=DEFAULT_BACKFILL)
    parser.add_argument("--no-backfill", action="store_true")
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="regenerate the human report without adding merge events",
    )
    args = parser.parse_args()

    ledger_path = Path(args.ledger)
    snapshot_path = Path(args.snapshot_ledger)
    report_path = Path(args.report)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    records = load_ndjson(ledger_path)
    snapshot_index = load_snapshot_index(snapshot_path)
    changes = 0

    if not args.render_only:
        # Automatic backfill is intentionally limited to the canonical ledger.
        # PR validation uses a temporary ledger and therefore remains a one-record test.
        if not args.no_backfill and args.ledger == DEFAULT_LEDGER:
            changes += apply_backfill_manifest(
                records,
                ledger_path,
                Path(args.backfill_manifest),
                snapshot_index,
            )

        if args.event:
            event = json.loads(Path(args.event).read_text(encoding="utf-8"))
            pr = event.get("pull_request")
            if pr and pr.get("merged") and pr.get("base", {}).get("ref") == "main":
                if append_if_missing(
                    records,
                    ledger_path,
                    event,
                    snapshot_index,
                ):
                    changes += 1
            else:
                print(
                    "research-ledger: event is not a PR merge into main; event skipped"
                )
        elif changes == 0:
            raise SystemExit(
                "--event/GITHUB_EVENT_PATH is required unless a canonical backfill adds data "
                "or --render-only is used"
            )

    report_path.write_text(
        render_report(records, snapshot_index),
        encoding="utf-8",
    )
    if args.render_only:
        print(
            f"research-ledger: report refreshed; "
            f"merges={len(records)} snapshots={len(snapshot_index)}"
        )
    elif changes:
        print(
            f"research-ledger: materialized {changes} observation(s); "
            f"total={len(records)}"
        )
    else:
        print(f"research-ledger: no new observations; total={len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
