#!/bin/bash
set -euo pipefail

REPO="${KERNAL_FASTPATH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
CONTRACT_BEGIN='<!-- KERNAL_COORDINATOR_BEGIN -->'
CONTRACT_END='<!-- KERNAL_COORDINATOR_END -->'

log() { printf '[step29-preflight-enable] %s\n' "$*" >&2; }

cd "$REPO"
git fetch origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1
board=$(git show origin/main:AGENT_TASKS.md)
contract=$(printf '%s\n' "$board" | awk -v begin="$CONTRACT_BEGIN" -v end="$CONTRACT_END" '
  $0 == begin { active=1; next }
  $0 == end { active=0; exit }
  active { print }
')

active_step=$(printf '%s\n' "$contract" | sed -n 's/^active_step=//p' | head -n1)
preflight_lane=$(printf '%s\n' "$contract" | sed -n 's/^preflight_lane=//p' | head -n1)

if [ "$active_step" != 29 ]; then
  log "active_step=${active_step:-missing}; Step29 preflight enabler is inactive"
  exit 0
fi

if [ -z "$preflight_lane" ]; then
  log 'canonical Step29 board has no preflight_lane; refusing legacy board mutation'
  exit 65
fi

record=$(printf '%s\n' "$contract" | sed -n 's/^lane=//p' | awk -F'|' -v wanted="$preflight_lane" '$1 == wanted { print; exit }')
if [ -z "$record" ]; then
  log "preflight_lane=$preflight_lane has no lane record; refusing mutation"
  exit 65
fi

branch=$(printf '%s\n' "$record" | awk -F'|' '{ print $2 }')
state=$(printf '%s\n' "$record" | awk -F'|' '{ print $3 }')
role=$(printf '%s\n' "$record" | awk -F'|' '{ print $4 }')
case "$branch" in agent/step29-*) ;; *) log "invalid preflight branch=$branch"; exit 65 ;; esac
case "$state" in ACTIVE|HOLD) ;; *) log "invalid preflight state=$state"; exit 65 ;; esac
[ "$role" = integration-preflight ] || {
  log "invalid preflight role=$role"
  exit 65
}

python3 tools/agent_policy.py validate
log "canonical board already owns preflight activation: lane=$preflight_lane branch=$branch state=$state; no legacy rewrite performed"
