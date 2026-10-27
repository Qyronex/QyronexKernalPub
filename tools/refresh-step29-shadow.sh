#!/bin/bash
set -euo pipefail

REPO="${KERNAL_SHADOW_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
CONTRACT_BEGIN='<!-- KERNAL_COORDINATOR_BEGIN -->'
CONTRACT_END='<!-- KERNAL_COORDINATOR_END -->'

log() { printf '[step29-shadow] %s\n' "$*" >&2; }

board=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-board.XXXXXX")
contract=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-contract.XXXXXX")
index=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-index.XXXXXX")
owners=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-owners.XXXXXX")
manifest=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-manifest.XXXXXX")
message=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-message.XXXXXX")
cleanup() { rm -f "$board" "$contract" "$index" "$owners" "$manifest" "$message"; }
trap cleanup EXIT INT TERM
rm -f "$index"
: > "$owners"
: > "$manifest"

cd "$REPO"
git fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
git show origin/main:AGENT_TASKS.md > "$board"
awk -v begin="$CONTRACT_BEGIN" -v end="$CONTRACT_END" '
  $0 == begin { active=1; next }
  $0 == end { active=0; exit }
  active { print }
' "$board" > "$contract"

contract_value() {
  key="$1"
  sed -n "s/^${key}=//p" "$contract" | head -n 1
}

lane_record() {
  key="$1"
  sed -n 's/^lane=//p' "$contract" | awk -F'|' -v wanted="$key" '$1 == wanted { print; exit }'
}

lane_branch() {
  lane_record "$1" | awk -F'|' '{ print $2 }'
}

lane_state() {
  lane_record "$1" | awk -F'|' '{ print $3 }'
}

lane_scope() {
  key="$1"
  sed -n 's/^scope=//p' "$contract" | awk -F'|' -v wanted="$key" '$1 == wanted { print $3; exit }'
}

fetch_branch_head() {
  branch="$1"
  git fetch origin "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1
  git rev-parse "refs/remotes/origin/$branch^{commit}"
}

path_matches_scope() {
  local path="$1" patterns="$2" pattern
  local -a scope_patterns
  IFS=';' read -r -a scope_patterns <<< "$patterns"
  for pattern in "${scope_patterns[@]}"; do
    [ -n "$pattern" ] || continue
    case "$path" in
      $pattern) return 0 ;;
    esac
  done
  return 1
}

guard_source_base_compatibility() {
  local lane="$1" scope="$2" source_head="$3"
  local merge_base base_changed conflict path

  merge_base=$(git merge-base "$base_head" "$source_head") || {
    printf 'cannot determine merge base for shadow source lane %s (base=%s source=%s)\n' \
      "$lane" "$base_head" "$source_head" >&2
    return 1
  }
  [ "$merge_base" = "$base_head" ] && return 0

  base_changed=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-base-changed.XXXXXX")
  git diff --name-only --no-renames "$merge_base" "$base_head" > "$base_changed"
  conflict=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if path_matches_scope "$path" "$scope"; then
      printf 'shadow stale-base conflict: lane=%s path=%s merge_base=%s base=%s source=%s\n' \
        "$lane" "$path" "$merge_base" "$base_head" "$source_head" >&2
      conflict=1
    fi
  done < "$base_changed"
  rm -f "$base_changed"

  if [ "$conflict" -ne 0 ]; then
    printf 'shadow composition refused: source lane %s diverged from base with base-side changes inside declared scope\n' \
      "$lane" >&2
    return 1
  fi

  log "allowing divergent source lane=$lane merge_base=$merge_base: base-side changes are outside declared scope"
}

claim_path() {
  path="$1"; lane="$2"
  previous=$(awk -F'|' -v wanted="$path" '$1 == wanted { print $2; exit }' "$owners")
  if [ -n "$previous" ] && [ "$previous" != "$lane" ]; then
    printf 'shadow scope overlap: %s owned by %s and %s\n' "$path" "$previous" "$lane" >&2
    return 1
  fi
  [ -n "$previous" ] || printf '%s|%s\n' "$path" "$lane" >> "$owners"
}

apply_path_from_head() {
  path="$1"; source_head="$2"
  entry=$(git ls-tree "$source_head" -- "$path")
  if [ -z "$entry" ]; then
    GIT_INDEX_FILE="$index" git update-index --force-remove -- "$path"
    return
  fi
  mode=$(printf '%s\n' "$entry" | awk '{ print $1 }')
  blob=$(printf '%s\n' "$entry" | awk '{ print $3 }')
  [ -n "$mode" ] && [ -n "$blob" ] || {
    printf 'cannot resolve tree entry for %s at %s\n' "$path" "$source_head" >&2
    return 1
  }
  GIT_INDEX_FILE="$index" git update-index --add --cacheinfo "$mode" "$blob" "$path"
}

result_state() {
  ref="$1"; commit="$2"; job="$3"
  paths=$(git grep -l "^tested_commit=${commit}$" origin/main -- runner-results 2>/dev/null || true)
  for spec in $paths; do
    path=${spec#origin/main:}
    body=$(git show "origin/main:$path" 2>/dev/null || true)
    [ -n "$body" ] || continue
    r=$(printf '%s\n' "$body" | sed -n 's/^tested_ref=//p' | head -n1)
    [ -n "$r" ] || r=$(printf '%s\n' "$body" | sed -n 's/^ref=//p' | head -n1)
    j=$(printf '%s\n' "$body" | sed -n 's/^job=//p' | head -n1)
    x=$(printf '%s\n' "$body" | sed -n 's/^exit_code=//p' | head -n1)
    [ "$r" = "$ref" ] && [ "$j" = "$job" ] || continue
    if [ "$x" = 0 ]; then printf 'PASS\n'; return; fi
    [ -n "$x" ] && { printf 'FAIL\n'; return; }
  done
  printf 'MISSING\n'
}

request_exists() {
  ref="$1"; commit="$2"; job="$3"
  paths=$(git grep -l "^commit=${commit}$" origin/main -- RUNNER_QUEUE/v2/requests 2>/dev/null || true)
  for spec in $paths; do
    path=${spec#origin/main:}
    body=$(git show "origin/main:$path" 2>/dev/null || true)
    [ -n "$body" ] || continue
    r=$(printf '%s\n' "$body" | sed -n 's/^ref=//p' | head -n1)
    j=$(printf '%s\n' "$body" | sed -n 's/^job=//p' | head -n1)
    [ "$r" = "$ref" ] && [ "$j" = "$job" ] && return 0
  done
  return 1
}

queue_shadow_job_if_missing() {
  ref="$1"; commit="$2"; short="$3"; job="$4"
  if request_exists "$ref" "$commit" "$job"; then
    log "$short $job: already queued"
    return 0
  fi

  current=$(fetch_branch_head "$ref" 2>/dev/null || true)
  if [ "$current" != "$commit" ]; then
    log "$short $job: shadow ref moved to ${current:-missing}; stop stale enqueue"
    return 0
  fi

  id="s29shadow-${short}-${job}"
  log "queue job=$job ref=$ref commit=$commit"
  KERNAL_RUNNER_REPO="$REPO" bash "$REPO/tools/enqueue-kernel-runner.sh" "$ref" "$job" "$id" any >/dev/null
}

shadow_lane=$(contract_value shadow_integration_lane)
base_lane=$(contract_value shadow_integration_base_lane)
sources=$(contract_value shadow_integration_sources)
jobs=$(contract_value shadow_integration_jobs)

[ -n "$shadow_lane" ] && [ -n "$base_lane" ] && [ -n "$sources" ] && [ -n "$jobs" ] || {
  printf 'shadow integration contract values are incomplete\n' >&2
  exit 65
}
case ";$jobs;" in
  *';fmt-check;'*) ;;
  *)
    printf 'shadow integration jobs must include fmt-check for staged admission\n' >&2
    exit 65
    ;;
esac

base_state=$(lane_state "$base_lane")
[ -n "$base_state" ] || {
  printf 'missing state for shadow base lane %s\n' "$base_lane" >&2
  exit 65
}
if [ "$base_state" = "ACTIVE" ]; then
  log "skipping shadow refresh: base lane=$base_lane is ACTIVE"
  printf 'shadow_skipped=1\nbase_lane=%s\nbase_state=%s\n' "$base_lane" "$base_state"
  exit 0
fi

shadow_branch=$(lane_branch "$shadow_lane")
base_branch=$(lane_branch "$base_lane")
case "$shadow_branch" in agent/step29-*) ;; *) printf 'invalid Step29 shadow branch: %s\n' "$shadow_branch" >&2; exit 65 ;; esac
[ -n "$base_branch" ] || { printf 'missing base lane branch for %s\n' "$base_lane" >&2; exit 65; }

base_head=$(fetch_branch_head "$base_branch")
printf 'base=%s@%s\n' "$base_lane" "$base_head" >> "$manifest"
GIT_INDEX_FILE="$index" git read-tree "$base_head"

old_ifs=$IFS
IFS=';'
set -- $sources
IFS=$old_ifs
for lane in "$@"; do
  [ -n "$lane" ] || continue
  state=$(lane_state "$lane")
  [ -n "$state" ] || {
    printf 'missing state for shadow source lane %s\n' "$lane" >&2
    exit 65
  }
  if [ "$state" = "HOLD" ]; then
    log "skipping held shadow source lane=$lane"
    printf 'skipped_source=%s|state=%s\n' "$lane" "$state" >> "$manifest"
    continue
  fi
  branch=$(lane_branch "$lane")
  scope=$(lane_scope "$lane")
  [ -n "$branch" ] && [ -n "$scope" ] || {
    printf 'missing branch/scope for shadow source lane %s\n' "$lane" >&2
    exit 65
  }
  source_head=$(fetch_branch_head "$branch")
  guard_source_base_compatibility "$lane" "$scope" "$source_head"
  printf 'source=%s@%s\n' "$lane" "$source_head" >> "$manifest"
  changed=$(mktemp "${TMPDIR:-/tmp}/kernal-shadow-changed.XXXXXX")
  git diff --name-only --no-renames "$base_head" "$source_head" > "$changed"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    path_matches_scope "$path" "$scope" || continue
    claim_path "$path" "$lane"
    apply_path_from_head "$path" "$source_head"
  done < "$changed"
  rm -f "$changed"
done

tree=$(GIT_INDEX_FILE="$index" git write-tree)
fingerprint=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())' < "$manifest")
{
  printf 'shadow(step29): compose live source heads\n\n'
  cat "$manifest"
  printf 'tree=%s\n' "$tree"
  printf 'fingerprint=%s\n' "$fingerprint"
  printf 'non_acceptance=1\n'
} > "$message"

shadow_commit=$(
  GIT_AUTHOR_NAME='Kernal Shadow Integrator' \
  GIT_AUTHOR_EMAIL='shadow-integration@kernal.invalid' \
  GIT_COMMITTER_NAME='Kernal Shadow Integrator' \
  GIT_COMMITTER_EMAIL='shadow-integration@kernal.invalid' \
  GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' \
  GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' \
  git commit-tree "$tree" -p "$base_head" < "$message"
)

log "publishing $shadow_branch commit=$shadow_commit fingerprint=$fingerprint"
git push --force origin "$shadow_commit:refs/heads/$shadow_branch" >/dev/null

# Refresh main after composition so exact-head runner results and requests that landed while the
# synthetic tree was being built are visible before deciding which gates to release.
git fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
short=$(printf '%.12s' "$shadow_commit")
fmt_state=$(result_state "$shadow_branch" "$shadow_commit" fmt-check)
case "$fmt_state" in
  MISSING)
    log "$short fmt-check: admission result missing - queue only fmt-check"
    queue_shadow_job_if_missing "$shadow_branch" "$shadow_commit" "$short" fmt-check
    ;;
  FAIL)
    log "$short fmt-check: FAIL - hold expensive shadow gates for a new source composition"
    ;;
  PASS)
    log "$short fmt-check: PASS - release remaining declared shadow gates"
    old_ifs=$IFS
    IFS=';'
    set -- $jobs
    IFS=$old_ifs
    for job in "$@"; do
      [ -n "$job" ] || continue
      [ "$job" = fmt-check ] && continue
      state=$(result_state "$shadow_branch" "$shadow_commit" "$job")
      case "$state" in
        PASS) log "$short $job: PASS" ;;
        FAIL) log "$short $job: FAIL - keep result; do not requeue unchanged shadow head" ;;
        MISSING) queue_shadow_job_if_missing "$shadow_branch" "$shadow_commit" "$short" "$job" ;;
      esac
    done
    ;;
  *)
    printf 'unexpected fmt state for shadow commit %s: %s\n' "$shadow_commit" "$fmt_state" >&2
    exit 65
    ;;
esac

printf 'shadow_lane=%s\nshadow_branch=%s\nshadow_commit=%s\nfingerprint=%s\n' \
  "$shadow_lane" "$shadow_branch" "$shadow_commit" "$fingerprint"
cat "$manifest"
