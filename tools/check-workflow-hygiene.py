#!/usr/bin/env python3
"""Fail closed when transient milestone workflows leak into the durable Actions surface."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MILESTONE_WORKFLOW = re.compile(r"^step\d+(?:[-_].*)?\.ya?ml$", re.IGNORECASE)


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    workflows = repo / ".github" / "workflows"
    if not workflows.is_dir():
        print(f"workflow hygiene: missing directory: {workflows}", file=sys.stderr)
        return 1

    forbidden = sorted(
        path.relative_to(repo).as_posix()
        for path in workflows.iterdir()
        if path.is_file() and MILESTONE_WORKFLOW.fullmatch(path.name)
    )
    if forbidden:
        print(
            "workflow hygiene: transient milestone workflows are forbidden; "
            "use runner/state-v2 and the canonical gate queue instead:",
            file=sys.stderr,
        )
        for path in forbidden:
            print(f"  {path}", file=sys.stderr)
        return 1

    print("workflow hygiene: OK milestone_workflows=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
