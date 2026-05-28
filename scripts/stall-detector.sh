#!/usr/bin/env bash
# stall-detector.sh — Detect agents that may be stuck (uncommitted changes for >N minutes).
#
# Usage: ./scripts/stall-detector.sh [--threshold-minutes N]
#        Defaults to 15 minutes.
#
# Run this from the project root. Checks all registered git worktrees for
# uncommitted changes that haven't moved in more than the threshold.
#
# Exit 0: no stalls detected. Exit 1: stalls found.

set -euo pipefail

THRESHOLD_MINUTES=15
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold-minutes) THRESHOLD_MINUTES="$2"; shift 2 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

ROOT="$(git rev-parse --show-toplevel)"
STALLS=0
NOW=$(date +%s)

echo "=== STALL DETECTOR (threshold: ${THRESHOLD_MINUTES}m) ==="

while IFS= read -r line; do
    WORKTREE_PATH=$(echo "$line" | awk '{print $1}')
    BRANCH=$(echo "$line" | grep -o '\[.*\]' | tr -d '[]' || echo "unknown")

    # Skip the main worktree (lead's directory)
    if [[ "$WORKTREE_PATH" == "$ROOT" ]]; then
        continue
    fi

    # Check for uncommitted changes
    DIRTY=$(git -C "$WORKTREE_PATH" status --porcelain 2>/dev/null | wc -l | tr -d '[:space:]')
    if [[ "$DIRTY" -eq 0 ]]; then
        echo "  [OK] $BRANCH — clean"
        continue
    fi

    # Find the oldest modified file's mtime
    OLDEST_MTIME=0
    while IFS= read -r filepath; do
        if [[ -f "$WORKTREE_PATH/$filepath" ]]; then
            MTIME=$(stat -f %m "$WORKTREE_PATH/$filepath" 2>/dev/null || stat -c %Y "$WORKTREE_PATH/$filepath" 2>/dev/null || echo 0)
            if [[ $MTIME -gt $OLDEST_MTIME ]]; then
                OLDEST_MTIME=$MTIME
            fi
        fi
    done < <(git -C "$WORKTREE_PATH" status --porcelain 2>/dev/null | awk '{print $2}')

    if [[ $OLDEST_MTIME -eq 0 ]]; then
        echo "  [OK] $BRANCH — $DIRTY modified file(s), recently changed"
        continue
    fi

    AGE_SECONDS=$((NOW - OLDEST_MTIME))
    AGE_MINUTES=$((AGE_SECONDS / 60))

    if [[ $AGE_MINUTES -ge $THRESHOLD_MINUTES ]]; then
        echo "  [STALL] $BRANCH — $DIRTY uncommitted file(s), oldest modified ${AGE_MINUTES}m ago"
        STALLS=$((STALLS + 1))
    else
        echo "  [OK] $BRANCH — $DIRTY modified file(s), ${AGE_MINUTES}m ago (under threshold)"
    fi
done < <(git worktree list 2>/dev/null)

echo ""
if [[ $STALLS -gt 0 ]]; then
    echo "=== STALLS DETECTED: ${STALLS} worktree(s) may be stuck ==="
    echo "    Check active agents and ping them or restart if necessary."
    exit 1
fi

echo "=== NO STALLS DETECTED ==="
exit 0
