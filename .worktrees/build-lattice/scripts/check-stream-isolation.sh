#!/usr/bin/env bash
# check-stream-isolation.sh — Enforce the stream isolation invariant.
#
# internal/stream/ must not import internal/audit or internal/policy.
# These packages are injected via pkg/aegis.StreamTap and pkg/aegis.SnapshotReader.
#
# This script replaces a broken golangci-lint v2 depguard files-scoped deny rule:
# golangci-lint v2.12.2's files-scoped deny rules are silently ignored.
# Verified: even with correct YAML syntax, secondary rules with files: patterns
# produce 0 findings regardless of actual violations. The Main deny rule works
# but cannot be file-scoped. This script provides the actual enforcement.
#
# Run: ./scripts/check-stream-isolation.sh
# Exit 0: invariant holds. Exit 1: violation found.

set -euo pipefail

STREAM_DIR="internal/stream"
FORBIDDEN=(
    "github.com/mayjain/aegis/internal/audit"
    "github.com/mayjain/aegis/internal/policy"
)

if [[ ! -d "$STREAM_DIR" ]]; then
    echo "check-stream-isolation: internal/stream/ does not exist yet — OK"
    exit 0
fi

VIOLATIONS=0
for pkg in "${FORBIDDEN[@]}"; do
    matches=$(grep -rn "\"${pkg}\"" "$STREAM_DIR" --include="*.go" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        echo "VIOLATION: internal/stream imports ${pkg}"
        echo "  Inject via pkg/aegis interfaces instead (StreamTap, SnapshotReader)"
        echo "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done

if [[ $VIOLATIONS -gt 0 ]]; then
    echo ""
    echo "Stream isolation violated: ${VIOLATIONS} forbidden import(s) found."
    exit 1
fi

echo "check-stream-isolation: OK"
