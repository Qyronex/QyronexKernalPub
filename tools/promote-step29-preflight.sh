#!/bin/bash
set -euo pipefail

REPO="${KERNAL_FASTPATH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
CONTRACT_BEGIN='<!-- KERNAL_COORDINATOR_BEGIN -->'
CONTRACT_END='<!-- KERNAL_COORDINATOR_END -->'
CONTRACT=$(mktemp "${TMPDIR:-/tmp}/kernal-step29-promote-contract.XXXXXX")
CHANGED=$(mktemp "${TMPDIR:-/tmp}/kernal-step29-promote-paths.XXXXXX")
PATCH=$(mktemp "${TMPDIR:-/tmp}/kernal-step29-promote-patch.XXXXXX")
TMPDIR_PROMOTE=''
WT=''
cleanup() {
  if [ -n "$WT" ]; then git -C "$REPO" worktree remove --force "$WT" >/dev/null 2>&1 || true; fi
  [ -z "$TMPDIR_PROMOTE" ] || rm -rf "$TMPDIR_PROMOTE"
  rm -f "$CONTRACT" "$CHANGED" "$PATCH"
}
trap cleanup EXIT INT TERM

log() { printf '[step29-preflight-promote] %s\n' "$*" >&2; }

load_contract() {
  git -C "$REPO" show origin/main:AGENT_TASKS.md \
    | awk -v begin="$CONTRACT_BEGIN" -v end="$CONTRACT_END" '
        $0 == begin { active=1; next }
        $0 == end { active=0; exit }
        active { print }
      ' > "$CONTRACT"
  grep -q '^version=2$' "$CONTRACT" || {
    log 'canonical coordinator contract version=2 is missing'
    exit 65
  }
}

contract_value() {
  key="$1"
  sed -n "s/^${key}=//p" "$CONTRACT" | head -n1
}

lane_record() {
  lane="$1"
  sed -n 's/^lane=//p' "$CONTRACT" | awk -F'|' -v wanted="$lane" '$1 == wanted { print; exit }'
}

lane_branch() { lane_record "$1" | awk -F'|' '{ print $2 }'; }
lane_state() { lane_record "$1" | awk -F'|' '{ print $3 }'; }
lane_role() { lane_record "$1" | awk -F'|' '{ print $4 }'; }
lane_dependencies() { lane_record "$1" | awk -F'|' '{ print $5 }'; }

lane_scope() {
  lane="$1"
  sed -n 's/^scope=//p' "$CONTRACT" | awk -F'|' -v wanted="$lane" '$1 == wanted { print $3; exit }'
}

lane_gates() {
  lane="$1"
  sed -n 's/^gates=//p' "$CONTRACT" | awk -F'|' -v wanted="$lane" '$1 == wanted { print $2; exit }'
}

refresh_main() {
  git -C "$REPO" fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
  load_contract
}

refresh_branch() {
  branch="$1"
  git -C "$REPO" fetch origin "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1
}

head_for() {
  git -C "$REPO" rev-parse "refs/remotes/origin/$1^{commit}" 2>/dev/null
}

result_pass() {
  ref="$1"; commit="$2"; job="$3"
  paths=$(git -C "$REPO" grep -l "^tested_commit=${commit}$" origin/main -- runner-results 2>/dev/null || true)
  for spec in $paths; do
    path=${spec#origin/main:}
    body=$(git -C "$REPO" show "origin/main:$path" 2>/dev/null || true)
    [ -n "$body" ] || continue
    r=$(printf '%s\n' "$body" | sed -n 's/^tested_ref=//p' | head -n1)
    [ -n "$r" ] || r=$(printf '%s\n' "$body" | sed -n 's/^ref=//p' | head -n1)
    j=$(printf '%s\n' "$body" | sed -n 's/^job=//p' | head -n1)
    x=$(printf '%s\n' "$body" | sed -n 's/^exit_code=//p' | head -n1)
    [ "$r" = "$ref" ] && [ "$j" = "$job" ] && [ "$x" = 0 ] && return 0
  done
  return 1
}

require_lane_gates() {
  lane="$1"; branch="$2"; commit="$3"
  spec=$(lane_gates "$lane")
  [ -n "$spec" ] || {
    log "$lane has no declared gates"
    return 1
  }
  old_ifs=$IFS
  IFS=';'
  set -- $spec
  IFS=$old_ifs
  for job in "$@"; do
    [ -n "$job" ] || continue
    if ! result_pass "$branch" "$commit" "$job"; then
      log "$lane $branch@$commit lacks exact PASS for $job"
      return 1
    fi
  done
  return 0
}

path_matches_scope() {
  path="$1"; patterns="$2"
  old_ifs=$IFS
  IFS=';'
  set -- $patterns
  IFS=$old_ifs
  for pattern in "$@"; do
    [ -n "$pattern" ] || continue
    case "$path" in $pattern) return 0 ;; esac
  done
  return 1
}

refresh_main
active_step=$(contract_value active_step)
[ "$active_step" = 29 ] || {
  log "active_step=${active_step:-missing}; Step29 promotion is inactive"
  exit 0
}

PREFLIGHT_LANE=$(contract_value preflight_lane)
FORMAL_LANE=$(contract_value shadow_integration_base_lane)
[ -n "$PREFLIGHT_LANE" ] && [ -n "$FORMAL_LANE" ] || {
  log 'preflight_lane or shadow_integration_base_lane is missing'
  exit 65
}

PREFLIGHT_BRANCH=$(lane_branch "$PREFLIGHT_LANE")
FORMAL_BRANCH=$(lane_branch "$FORMAL_LANE")
PREFLIGHT_SCOPE=$(lane_scope "$PREFLIGHT_LANE")
FORMAL_SCOPE=$(lane_scope "$FORMAL_LANE")
SOURCE_LANES=$(lane_dependencies "$FORMAL_LANE")

case "$PREFLIGHT_BRANCH" in agent/step29-*) ;; *) log "invalid preflight branch=$PREFLIGHT_BRANCH"; exit 65 ;; esac
case "$FORMAL_BRANCH" in agent/step29-*) ;; *) log "invalid formal branch=$FORMAL_BRANCH"; exit 65 ;; esac
[ -n "$PREFLIGHT_SCOPE" ] && [ -n "$FORMAL_SCOPE" ] || {
  log 'preflight/formal integration scopes are missing'
  exit 65
}
[ -n "$SOURCE_LANES" ] && [ "$SOURCE_LANES" != none ] || {
  log "$FORMAL_LANE has no source dependencies"
  exit 65
}

formal_state=$(lane_state "$FORMAL_LANE")
if [ "$formal_state" = ACTIVE ]; then
  log "formal lane $FORMAL_LANE is already ACTIVE"
  exit 0
fi
[ "$formal_state" = WAIT ] || {
  log "formal lane $FORMAL_LANE has unexpected state=$formal_state"
  exit 65
}

preflight_state=$(lane_state "$PREFLIGHT_LANE")
[ "$preflight_state" = ACTIVE ] || {
  log "preflight lane $PREFLIGHT_LANE is not ACTIVE (state=${preflight_state:-missing}); promotion deferred"
  exit 0
}
[ "$(lane_role "$PREFLIGHT_LANE")" = integration-preflight ] || {
  log "$PREFLIGHT_LANE has unexpected role=$(lane_role "$PREFLIGHT_LANE")"
  exit 65
}

refresh_branch "$PREFLIGHT_BRANCH" || { log "missing $PREFLIGHT_BRANCH"; exit 0; }
refresh_branch "$FORMAL_BRANCH" || { log "missing $FORMAL_BRANCH"; exit 0; }

old_ifs=$IFS
IFS=','
set -- $SOURCE_LANES
IFS=$old_ifs
for lane in "$@"; do
  [ -n "$lane" ] && [ "$lane" != none ] || continue
  branch=$(lane_branch "$lane")
  [ -n "$branch" ] || { log "source lane $lane has no branch"; exit 65; }
  case "$branch" in
    main)
      log "$lane is a main reference dependency"
      continue
      ;;
    agent/step29-*) ;;
    *) log "$lane has unsupported branch=$branch"; exit 65 ;;
  esac
  refresh_branch "$branch" || { log "missing source branch $branch"; exit 0; }
  head=$(head_for "$branch" 2>/dev/null || true)
  [ -n "$head" ] || { log "missing source head $branch"; exit 0; }
  if ! git -C "$REPO" merge-base --is-ancestor "$head" origin/main 2>/dev/null; then
    log "$lane $branch@$head is not integrated into main"
    exit 0
  fi
  if ! require_lane_gates "$lane" "$branch" "$head"; then
    exit 0
  fi
  log "$lane $branch@$head is integrated with all declared exact gates"
done

preflight=$(head_for "$PREFLIGHT_BRANCH" 2>/dev/null || true)
formal=$(head_for "$FORMAL_BRANCH" 2>/dev/null || true)
[ -n "$preflight" ] && [ -n "$formal" ] || { log 'preflight/formal branch head missing'; exit 1; }
if ! require_lane_gates "$PREFLIGHT_LANE" "$PREFLIGHT_BRANCH" "$preflight"; then
  log "$PREFLIGHT_BRANCH@$preflight lacks exact declared preflight gates"
  exit 0
fi
log "$PREFLIGHT_BRANCH@$preflight has all declared exact preflight gates"

preflight_base=$(git -C "$REPO" merge-base origin/main "$preflight" 2>/dev/null || true)
[ -n "$preflight_base" ] || { log 'cannot determine preflight merge-base'; exit 1; }
if ! git -C "$REPO" merge-base --is-ancestor "$preflight_base" origin/main 2>/dev/null; then
  log "preflight base $preflight_base is not contained in main"
  exit 1
fi

git -C "$REPO" diff --name-only --no-renames "$preflight_base..$preflight" > "$CHANGED"
while IFS= read -r path; do
  [ -n "$path" ] || continue
  if ! path_matches_scope "$path" "$PREFLIGHT_SCOPE" || ! path_matches_scope "$path" "$FORMAL_SCOPE"; then
    log "preflight changed out-of-scope path: $path"
    exit 1
  fi
done < "$CHANGED"
git -C "$REPO" diff --binary "$preflight_base..$preflight" > "$PATCH"

formal_base=$(git -C "$REPO" merge-base origin/main "$formal" 2>/dev/null || true)
[ -n "$formal_base" ] || { log 'cannot determine formal merge-base'; exit 1; }
if git -C "$REPO" diff --quiet "$formal_base" "$formal" --; then
  log "formal WAIT branch $formal is a content-empty placeholder"
else
  expected_index=$(mktemp "${TMPDIR:-/tmp}/kernal-step29-promote-index.XXXXXX")
  rm -f "$expected_index"
  GIT_INDEX_FILE="$expected_index" git -C "$REPO" read-tree "$formal_base"
  if ! GIT_INDEX_FILE="$expected_index" git -C "$REPO" apply --cached --3way "$PATCH" >/dev/null 2>&1; then
    rm -f "$expected_index"
    log 'formal WAIT branch cannot be reconstructed from accepted preflight delta'
    exit 1
  fi
  expected_tree=$(GIT_INDEX_FILE="$expected_index" git -C "$REPO" write-tree)
  rm -f "$expected_index"
  actual_tree=$(git -C "$REPO" rev-parse "$formal^{tree}")
  if [ "$expected_tree" != "$actual_tree" ]; then
    log 'formal WAIT branch has content beyond the accepted preflight candidate'
    exit 1
  fi
  log "formal WAIT branch $formal is an exact prepared preflight candidate"
fi

TMPDIR_PROMOTE=$(mktemp -d "${TMPDIR:-/tmp}/kernal-step29-promote.XXXXXX")
WT="$TMPDIR_PROMOTE/worktree"
git -C "$REPO" worktree add --detach "$WT" origin/main >/dev/null
cd "$WT"
git config user.name "kernal-fastpath-bot"
git config user.email "fastpath@kernal.invalid"

if [ -s "$PATCH" ]; then
  if ! git apply --index --3way "$PATCH" >/dev/null 2>&1; then
    log 'preflight delta conflicts with integrated main; explicit integration resolution required'
    exit 1
  fi
  git diff --cached --check
  git commit -m "integrate(step29): promote board-declared ARM64 preflight" >/dev/null
fi

if ! git -C "$REPO" merge-base --is-ancestor "$formal" HEAD 2>/dev/null; then
  git merge --no-ff -s ours -m "coord(step29): preserve formal integration WAIT ancestry" "$formal" >/dev/null
fi
candidate=$(git rev-parse HEAD)
if ! git -C "$REPO" merge-base --is-ancestor "$formal" "$candidate" 2>/dev/null; then
  log 'candidate is not a fast-forward of formal integration'
  exit 1
fi

cd "$REPO"
refresh_main
refresh_branch "$PREFLIGHT_BRANCH" || exit 0
refresh_branch "$FORMAL_BRANCH" || exit 1
latest_preflight=$(head_for "$PREFLIGHT_BRANCH" 2>/dev/null || true)
latest_formal=$(head_for "$FORMAL_BRANCH" 2>/dev/null || true)
latest_main=$(git -C "$REPO" rev-parse origin/main)
if [ "$latest_preflight" != "$preflight" ]; then
  log "preflight advanced during candidate build: expected=$preflight current=${latest_preflight:-missing}"
  exit 0
fi
if ! require_lane_gates "$PREFLIGHT_LANE" "$PREFLIGHT_BRANCH" "$preflight"; then
  log 'preflight evidence changed while candidate was built'
  exit 0
fi
if [ "$latest_formal" != "$formal" ]; then
  log "formal branch advanced during candidate build: expected=$formal current=${latest_formal:-missing}"
  exit 0
fi
if ! git -C "$REPO" merge-base --is-ancestor "$latest_main" "$candidate" 2>/dev/null; then
  log 'main advanced during candidate build; retry on next trigger'
  exit 0
fi

git -C "$REPO" push origin "$candidate:refs/heads/$FORMAL_BRANCH" >/dev/null
log "formal integration branch advanced: lane=$FORMAL_LANE candidate=$candidate"

git -C "$REPO" reset --hard origin/main >/dev/null
python3 - AGENT_TASKS.md "$PREFLIGHT_LANE" "$FORMAL_LANE" "$PREFLIGHT_BRANCH" "$FORMAL_BRANCH" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
preflight, formal, preflight_branch, formal_branch = sys.argv[2:]
text = path.read_text(encoding='utf-8')
lines = text.splitlines()

lane_seen = {preflight: False, formal: False}
lease_seen = False
formal_lease_seen = False
priority_seen = False
out = []
for line in lines:
    if line.startswith('critical_path_priority='):
        items = [x for x in line.split('=', 1)[1].split(';') if x]
        items = [x for x in items if x not in {formal, preflight}]
        line = 'critical_path_priority=' + ';'.join([formal, *items])
        priority_seen = True
    elif line.startswith('lane='):
        parts = line.split('=', 1)[1].split('|')
        if len(parts) == 5 and parts[0] in lane_seen:
            name = parts[0]
            lane_seen[name] = True
            expected = 'ACTIVE' if name == preflight else 'WAIT'
            replacement = 'HOLD' if name == preflight else 'ACTIVE'
            if parts[2] != expected:
                raise SystemExit(f'{name}: expected state {expected}, got {parts[2]}')
            parts[2] = replacement
            line = 'lane=' + '|'.join(parts)
    elif line.startswith(f'lease={formal}|'):
        formal_lease_seen = True
    elif line.startswith(f'lease={preflight}|'):
        parts = line.split('=', 1)[1].split('|')
        if len(parts) != 5 or parts[2] != preflight or parts[3] != 'WRITE':
            raise SystemExit('invalid preflight WRITE lease record')
        parts[0] = formal
        parts[2] = formal
        parts[4] = formal_branch.removeprefix('agent/')
        line = 'lease=' + '|'.join(parts)
        lease_seen = True
    out.append(line)

if not all(lane_seen.values()):
    raise SystemExit(f'missing lane records: {lane_seen}')
if formal_lease_seen:
    raise SystemExit('formal integration already has a WRITE lease before transfer')
if not lease_seen:
    raise SystemExit('preflight WRITE lease missing')
if not priority_seen:
    raise SystemExit('critical_path_priority missing')

text = '\n'.join(out) + '\n'
text = text.replace(
    f'#### Integration preflight — `{preflight}` (ACTIVE, non-acceptance)',
    f'#### Integration preflight — `{preflight}` (HANDED OFF / HOLD)',
)
text = text.replace(
    f'#### Formal integration — `{formal}` (WAIT)',
    f'#### Formal integration — `{formal}` (ACTIVE)',
)
path.write_text(text, encoding='utf-8')
PY

python3 tools/agent_policy.py validate
git add AGENT_TASKS.md
git diff --cached --check
git commit -m "coord(step29): hand board preflight to formal integration" >/dev/null

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if git push origin HEAD:main >/dev/null 2>&1; then
    log "formal integration activated candidate=$candidate attempt=$attempt"
    exit 0
  fi
  log "main moved during lease handoff; rebasing attempt=$attempt"
  git fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
  if ! git rebase origin/main >/dev/null 2>&1; then
    git rebase --abort >/dev/null 2>&1 || true
    log 'real AGENT_TASKS overlap during lease handoff; refusing automatic resolution'
    exit 1
  fi
  python3 tools/agent_policy.py validate
  sleep 1
done

log 'main kept moving after bounded retries; formal branch is prepared but board handoff remains WAIT for next trigger'
exit 1
