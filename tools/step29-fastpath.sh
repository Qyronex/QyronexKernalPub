#!/bin/bash
set -euo pipefail

REPO="${KERNAL_FASTPATH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
ENQUEUE="$REPO/tools/enqueue-kernel-runner.sh"
CONTRACT_BEGIN='<!-- KERNAL_COORDINATOR_BEGIN -->'
CONTRACT_END='<!-- KERNAL_COORDINATOR_END -->'
CONTRACT=$(mktemp "${TMPDIR:-/tmp}/kernal-step29-fastpath-contract.XXXXXX")
trap 'rm -f "$CONTRACT"' EXIT INT TERM

log() { printf '[step29-fastpath] %s\n' "$*" >&2; }

refresh_ref() {
  branch="$1"
  git -C "$REPO" fetch origin "+refs/heads/$branch:refs/remotes/origin/$branch" >/dev/null 2>&1
}

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

lane_records() {
  sed -n 's/^lane=//p' "$CONTRACT"
}

lane_record() {
  lane="$1"
  lane_records | awk -F'|' -v wanted="$lane" '$1 == wanted { print; exit }'
}

lane_branch() {
  lane_record "$1" | awk -F'|' '{ print $2 }'
}

lane_state() {
  lane_record "$1" | awk -F'|' '{ print $3 }'
}

lane_role() {
  lane_record "$1" | awk -F'|' '{ print $4 }'
}

lane_dependencies() {
  lane_record "$1" | awk -F'|' '{ print $5 }'
}

lane_gates() {
  lane="$1"
  sed -n 's/^gates=//p' "$CONTRACT" | awk -F'|' -v wanted="$lane" '$1 == wanted { print $2; exit }'
}

contract_value() {
  key="$1"
  sed -n "s/^${key}=//p" "$CONTRACT" | head -n1
}

refresh() {
  git -C "$REPO" fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
  load_contract
  while IFS='|' read -r _lane branch _state _role _deps; do
    case "$branch" in
      agent/*) refresh_ref "$branch" || true ;;
    esac
  done < <(lane_records)
}

head_for() {
  git -C "$REPO" rev-parse "refs/remotes/origin/$1^{commit}" 2>/dev/null
}

job_is_blocked() {
  job="$1"
  blocked=$(contract_value blocked_runner_jobs)
  [ -n "$blocked" ] || return 1
  printf '%s\n' "$blocked" | awk -v RS=';' -v wanted="$job" '$0 == wanted { found=1 } END { exit !found }'
}

result_state() {
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
    [ "$r" = "$ref" ] && [ "$j" = "$job" ] || continue
    if [ "$x" = 0 ]; then printf 'PASS\n'; return; fi
    [ -n "$x" ] && { printf 'FAIL\n'; return; }
  done
  printf 'MISSING\n'
}

request_exists() {
  ref="$1"; commit="$2"; job="$3"
  paths=$(git -C "$REPO" grep -l "^commit=${commit}$" origin/main -- RUNNER_QUEUE/v2/requests 2>/dev/null || true)
  for spec in $paths; do
    path=${spec#origin/main:}
    body=$(git -C "$REPO" show "origin/main:$path" 2>/dev/null || true)
    [ -n "$body" ] || continue
    r=$(printf '%s\n' "$body" | sed -n 's/^ref=//p' | head -n1)
    j=$(printf '%s\n' "$body" | sed -n 's/^job=//p' | head -n1)
    [ "$r" = "$ref" ] && [ "$j" = "$job" ] && return 0
  done
  return 1
}

queue_request_if_missing() {
  lane="$1"; ref="$2"; commit="$3"; short="$4"; prefix="$5"; job="$6"
  if request_exists "$ref" "$commit" "$job"; then
    log "$lane $short $job: already queued"
    return 0
  fi

  if ! refresh_ref "$ref"; then
    log "$lane $short $job: cannot refresh ref; defer"
    return 0
  fi
  current=$(head_for "$ref" 2>/dev/null || true)
  if [ "$current" != "$commit" ]; then
    log "$lane $short $job: ref moved to ${current:-missing}; stop stale fan-out"
    return 0
  fi

  id="${prefix}-${short}-${job}"
  log "$lane $short $job: queue $id"
  KERNAL_RUNNER_REPO="$REPO" bash "$ENQUEUE" "$ref" "$job" "$id" any >/dev/null
}

queue_declared_gates() {
  lane="$1"; ref="$2"; prefix="$3"
  commit=$(head_for "$ref" 2>/dev/null || true)
  [ -n "$commit" ] || { log "$lane: branch missing, skip"; return 0; }
  short=$(printf '%.10s' "$commit")
  spec=$(lane_gates "$lane")
  [ -n "$spec" ] || { log "$lane $short: no declared gates, skip"; return 0; }

  if git -C "$REPO" merge-base --is-ancestor "$commit" origin/main 2>/dev/null; then
    log "$lane $short: head already integrated into main - skip historical gates"
    return 0
  fi

  case ";$spec;" in
    *';fmt-check;'*)
      fmt_state=$(result_state "$ref" "$commit" fmt-check)
      case "$fmt_state" in
        PASS) log "$lane $short fmt-check: PASS - release remaining declared gates" ;;
        FAIL) log "$lane $short fmt-check: FAIL - hold remaining gates for source repair"; return 0 ;;
        MISSING) queue_request_if_missing "$lane" "$ref" "$commit" "$short" "$prefix" fmt-check; return 0 ;;
      esac
      ;;
  esac

  old_ifs=$IFS
  IFS=';'
  set -- $spec
  IFS=$old_ifs
  for job in "$@"; do
    [ -n "$job" ] || continue
    [ "$job" = fmt-check ] && continue
    if job_is_blocked "$job"; then
      log "$lane $short: declared gate $job is blocked by canonical policy"
      exit 65
    fi
    state=$(result_state "$ref" "$commit" "$job")
    case "$state" in
      PASS) log "$lane $short $job: PASS" ;;
      FAIL) log "$lane $short $job: FAIL - source owner must repair before retry" ;;
      MISSING) queue_request_if_missing "$lane" "$ref" "$commit" "$short" "$prefix" "$job" ;;
    esac
  done
}

lane_contains_live_dependencies() {
  lane="$1"; ref="$2"
  candidate=$(head_for "$ref" 2>/dev/null || true)
  [ -n "$candidate" ] || return 1
  deps=$(lane_dependencies "$lane")
  [ -n "$deps" ] || return 0

  old_ifs=$IFS
  IFS=','
  set -- $deps
  IFS=$old_ifs
  for dep in "$@"; do
    [ -n "$dep" ] && [ "$dep" != none ] || continue
    dep_branch=$(lane_branch "$dep")
    [ -n "$dep_branch" ] || {
      log "$lane: dependency $dep has no canonical branch"
      return 1
    }
    case "$dep_branch" in
      main) continue ;;
      agent/*)
        dep_head=$(head_for "$dep_branch" 2>/dev/null || true)
        [ -n "$dep_head" ] || {
          log "$lane: dependency branch $dep_branch is missing"
          return 1
        }
        if ! git -C "$REPO" merge-base --is-ancestor "$dep_head" "$candidate" 2>/dev/null; then
          log "$lane: candidate does not contain live dependency $dep@$dep_head"
          return 1
        fi
        ;;
      *)
        log "$lane: unsupported dependency branch policy $dep_branch"
        return 1
        ;;
    esac
  done
  return 0
}

refresh

active_count=0
while IFS='|' read -r lane ref state role _deps; do
  [ "$state" = ACTIVE ] || continue
  case "$role" in
    source-worker|integration-preflight) ;;
    *) continue ;;
  esac
  case "$ref" in
    agent/step29-*) ;;
    *) log "$lane: active Step29 fastpath lane has unexpected ref $ref"; exit 65 ;;
  esac

  active_count=$((active_count + 1))
  if ! lane_contains_live_dependencies "$lane" "$ref"; then
    log "$lane: hold gates until current dependency heads are contained"
    continue
  fi
  safe_lane=${lane//[^A-Za-z0-9._-]/-}
  queue_declared_gates "$lane" "$ref" "fast-${safe_lane}"
done < <(lane_records)

if [ "$active_count" -eq 0 ]; then
  log 'no ACTIVE Step29 source/preflight lanes in canonical board'
fi

log 'fastpath reconciliation complete; shadow composition is handled by its board-driven workflow'
