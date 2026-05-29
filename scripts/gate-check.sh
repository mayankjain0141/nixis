#!/usr/bin/env bash
# gate-check.sh — Mandatory pre-merge gate for all agent workstreams.
#
# Usage: ./scripts/gate-check.sh <package-path> [worktree-path]
#
# Examples:
#   ./scripts/gate-check.sh ./internal/cel/
#   ./scripts/gate-check.sh ./internal/cel/ .worktrees/wave2-ws04
#   ./scripts/gate-check.sh ./dashboard/         # runs npm checks instead
#
# The lead MUST run this and get PASS before merging any agent branch.
# A merge made without a passing gate check is a process violation.

set -euo pipefail

PKG="${1:-}"
WORKTREE="${2:-}"

if [[ -z "$PKG" ]]; then
    echo "Usage: $0 <package-path> [worktree-path]"
    exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"
WORKDIR="${WORKTREE:+${ROOT}/${WORKTREE}}"
WORKDIR="${WORKDIR:-${ROOT}}"

echo "=== GATE CHECK: ${PKG} (workdir: ${WORKDIR}) ==="
FAILURES=0

run_check() {
    local name="$1"; shift
    if "$@" 2>&1; then
        echo "  [PASS] ${name}"
    else
        echo "  [FAIL] ${name}"
        FAILURES=$((FAILURES + 1))
    fi
}

# ─── Go package checks ────────────────────────────────────────────────────────
if [[ "$PKG" != *"dashboard"* ]]; then

    cd "$WORKDIR"

    # 1. No nolint directives anywhere in the package
    echo ""
    echo "--- Shortcut checks ---"
    if NOLINT_HITS=$(grep -rn "//nolint:" "${PKG}" 2>/dev/null) && [[ -n "$NOLINT_HITS" ]]; then
        NOLINT_COUNT=$(echo "$NOLINT_HITS" | wc -l | tr -d '[:space:]')
        echo "  [FAIL] Found ${NOLINT_COUNT} //nolint: directive(s):"
        echo "$NOLINT_HITS" | head -10
        FAILURES=$((FAILURES + 1))
    else
        echo "  [PASS] No //nolint: directives"
    fi

    # 2. No TODO/FIXME/HACK that signal incomplete work (warning only)
    STUB_HITS=$(grep -rn "TODO\|FIXME\|HACK\|placeholder\|not implemented" "${PKG}" \
        --include="*.go" 2>/dev/null | grep -v "_test.go" || true)
    if [[ -n "$STUB_HITS" ]]; then
        STUB_COUNT=$(echo "$STUB_HITS" | wc -l | tr -d '[:space:]')
        echo "  [WARN] ${STUB_COUNT} TODO/FIXME/HACK in production code (review manually):"
        echo "$STUB_HITS" | head -5
    else
        echo "  [PASS] No stubs or incomplete markers in production code"
    fi

    # 3. Integration wiring check (catch components built but not wired to callers)
    WIRING_GAPS=0
    echo ""
    echo "--- Integration wiring check ---"

    # Extract the package name from the path
    PKG_NAME=$(basename "${PKG%/}")

    # Known wiring expectations (add new ones as architecture evolves)
    case "$PKG_NAME" in
        stream)
            # internal/stream must be imported by internal/daemon
            if ! grep -r "\"github.com/mayjain/aegis/internal/stream\"" cmd/ internal/daemon/ 2>/dev/null | grep -q "stream"; then
                echo "  [WARN] internal/stream not imported by daemon or cmd/ — may be dead code"
            else
                echo "  [PASS] internal/stream wired into daemon"
            fi
            ;;
        bundle)
            # internal/bundle must be imported by cmd/aegis-daemon
            if ! grep -r "\"github.com/mayjain/aegis/internal/bundle\"" cmd/ 2>/dev/null | grep -q "bundle"; then
                echo "  [WARN] internal/bundle not imported by cmd/ — startup policy loading may be missing"
            else
                echo "  [PASS] internal/bundle wired into daemon startup"
            fi
            ;;
        secret)
            # internal/secret must be imported by cmd/aegis-daemon (WithSecretScanner)
            if ! grep -r "\"github.com/mayjain/aegis/internal/secret\"" cmd/ 2>/dev/null | grep -q "secret"; then
                echo "  [WARN] internal/secret not imported by cmd/ — secret scanning is disabled"
            else
                echo "  [PASS] internal/secret wired into daemon"
            fi
            ;;
        reload)
            # internal/reload must be imported by cmd/aegis-daemon
            if ! grep -r "\"github.com/mayjain/aegis/internal/reload\"" cmd/ 2>/dev/null | grep -q "reload"; then
                echo "  [WARN] internal/reload not imported by cmd/ — hot-reload is disabled"
            else
                echo "  [PASS] internal/reload wired into daemon"
            fi
            ;;
        delegation)
            # internal/delegation must be imported by cmd/aegis-daemon (WithDelegationValidator)
            if ! grep -r "\"github.com/mayjain/aegis/internal/delegation\"" cmd/ 2>/dev/null | grep -q "delegation"; then
                echo "  [WARN] internal/delegation not imported by cmd/ — delegation validation is disabled"
            else
                echo "  [PASS] internal/delegation wired into daemon"
            fi
            ;;
        *)
            echo "  [SKIP] No wiring check defined for ${PKG_NAME}"
            ;;
    esac

    echo ""
    echo "--- Go build and vet ---"
    run_check "go build" go build "${PKG}"
    run_check "go vet" go vet "${PKG}"

    echo ""
    echo "--- Tests (race detector) ---"
    run_check "go test -race" go test -race "${PKG}" -timeout 120s

    echo ""
    echo "--- Lint ---"
    run_check "golangci-lint" golangci-lint run "${PKG}"

    # 3. Benchmark check (if bench_test.go exists)
    BENCH_FILE=$(find "${PKG}" -name "bench_test.go" 2>/dev/null | head -1)
    if [[ -n "$BENCH_FILE" ]]; then
        echo ""
        echo "--- Benchmarks ---"
        echo "  Running benchmarks (3 runs)..."
        go test -bench=. -benchmem -count=3 "${PKG}" 2>&1 | grep -E "Benchmark" | tee /tmp/bench_out.txt
        echo "  [INFO] Benchmark results above — verify targets manually against spec"
    fi

# ─── Dashboard checks ─────────────────────────────────────────────────────────
else

    # Dashboard check: if PKG is ./dashboard/, WORKDIR is the worktree root
    # If called with a worktree path, use that; otherwise use project root
    if [[ -n "$WORKTREE" ]]; then
        DASH_DIR="${ROOT}/${WORKTREE}/dashboard"
    else
        DASH_DIR="${ROOT}/dashboard"
    fi
    cd "$DASH_DIR"

    echo ""
    echo "--- TypeScript shortcuts ---"
    if TS_HITS=$(grep -rn "@ts-ignore\|as any\b\|eslint-disable" src/ 2>/dev/null) && [[ -n "$TS_HITS" ]]; then
        TS_COUNT=$(echo "$TS_HITS" | wc -l | tr -d '[:space:]')
        echo "  [FAIL] Found ${TS_COUNT} TypeScript suppression(s):"
        echo "$TS_HITS" | head -5
        FAILURES=$((FAILURES + 1))
    else
        echo "  [PASS] No @ts-ignore / as any / eslint-disable"
    fi

    # Dashboard wiring checks
    echo ""
    echo "--- Dashboard integration wiring ---"
    WIRING_ISSUES=0

    # ws-manager must be imported by App.tsx
    if ! grep -q "createWebSocketManager\|ws-manager" "$DASH_DIR/src/App.tsx" 2>/dev/null; then
        echo "  [FAIL] ws-manager not used in App.tsx — WebSocket is inline"
        WIRING_ISSUES=$((WIRING_ISSUES + 1))
    else
        echo "  [PASS] ws-manager wired in App.tsx"
    fi

    # ingestion-pipeline must be imported by App.tsx
    if ! grep -q "createEventIngestionPipeline\|ingestion-pipeline" "$DASH_DIR/src/App.tsx" 2>/dev/null; then
        echo "  [FAIL] ingestion-pipeline not used in App.tsx — events parsed inline"
        WIRING_ISSUES=$((WIRING_ISSUES + 1))
    else
        echo "  [PASS] ingestion-pipeline wired in App.tsx"
    fi

    # lattice-store must be called somewhere for label.escalated events
    if ! grep -q "useLatticeStore\|latticeStore" "$DASH_DIR/src/App.tsx" 2>/dev/null; then
        echo "  [WARN] lattice-store not routed in App.tsx — label.escalated events unhandled"
    else
        echo "  [PASS] lattice-store routed in App.tsx"
    fi

    # threat-store must be called somewhere for secret.detected events
    if ! grep -q "useThreatStore\|threatStore" "$DASH_DIR/src/App.tsx" 2>/dev/null; then
        echo "  [WARN] threat-store not routed in App.tsx — secret.detected events unhandled"
    else
        echo "  [PASS] threat-store routed in App.tsx"
    fi

    if [[ $WIRING_ISSUES -gt 0 ]]; then
        FAILURES=$((FAILURES + WIRING_ISSUES))
    fi

    echo ""
    echo "--- TypeScript type check ---"
    run_check "npm run type-check" npm run type-check

    echo ""
    echo "--- Build ---"
    run_check "npm run build" npm run build

    echo ""
    echo "--- Tests ---"
    run_check "npm test" npm test

fi

# ─── Result ───────────────────────────────────────────────────────────────────
echo ""
if [[ "$FAILURES" -eq 0 ]]; then
    echo "=== GATE: PASS — safe to merge ${PKG} ==="
    exit 0
else
    echo "=== GATE: FAIL — ${FAILURES} check(s) failed, do NOT merge ${PKG} ==="
    echo "    Fix all failures, re-run this script, then merge."
    exit 1
fi
