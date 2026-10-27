#!/usr/bin/env bash

set -u

INTERVAL="${INTERVAL:-60}"
REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO="${1:-$DEFAULT_REPO}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not available in PATH." >&2
  exit 1
fi

cd "$REPO" || {
  echo "Error: repository not found: $REPO" >&2
  exit 1
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: $REPO is not a Git repository." >&2
  exit 1
fi

log "Auto-pull started"
log "Repository: $(pwd)"
log "Tracking: ${REMOTE}/${BRANCH}"
log "Interval: ${INTERVAL}s"
log "Stop with Ctrl+C"

while true; do
  current_branch="$(git branch --show-current)"

  if [ "$current_branch" != "$BRANCH" ]; then
    log "Skipped: current branch is '$current_branch', expected '$BRANCH'."
  elif ! git diff --quiet || ! git diff --cached --quiet; then
    log "Skipped: local tracked changes are present."
  else
    log "Checking ${REMOTE}/${BRANCH} ..."

    if git fetch "$REMOTE" "$BRANCH"; then
      local_sha="$(git rev-parse HEAD)"
      remote_sha="$(git rev-parse "${REMOTE}/${BRANCH}")"

      if [ "$local_sha" = "$remote_sha" ]; then
        log "Already up to date."
      elif git merge-base --is-ancestor "$local_sha" "$remote_sha"; then
        if git pull --ff-only "$REMOTE" "$BRANCH"; then
          log "Updated ${BRANCH} successfully."
        else
          log "Pull failed; no automatic merge was attempted."
        fi
      else
        log "Skipped: local ${BRANCH} has diverged from ${REMOTE}/${BRANCH}."
      fi
    else
      log "Fetch failed."
    fi
  fi

  sleep "$INTERVAL"
done
