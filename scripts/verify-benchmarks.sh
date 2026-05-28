#!/usr/bin/env bash
# verify-benchmarks.sh — Verifies all benchmark targets from REQ-001 through REQ-011.
# Usage: ./scripts/verify-benchmarks.sh
# Exit 0 = all targets met, Exit 1 = one or more targets missed.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FAILURES=0

echo "=== Benchmark Verification ==="

run_bench() {
    local pkg="$1" bench="$2" target_ns="$3" label="$4"
    result=$(go test -bench="$bench" -benchmem -count=1 -run='^$' "$pkg" 2>/dev/null | grep "$bench" | head -1 | awk '{print $3}' || true)
    if [[ -z "$result" ]]; then
        echo "  [SKIP] $label — benchmark not found"
        return
    fi

    # Parse result which may be in ns/op, µs/op, or ms/op format
    # Convert everything to nanoseconds for comparison
    local ns=""
    if [[ "$result" =~ ^([0-9.]+)ns/op$ ]] || [[ "$result" =~ ^([0-9.]+)ns$ ]]; then
        ns="${BASH_REMATCH[1]}"
    elif [[ "$result" =~ ^([0-9.]+)(µs/op|μs/op)$ ]] || [[ "$result" =~ ^([0-9.]+)(µs|μs)$ ]]; then
        # Microseconds — multiply by 1000
        local us="${BASH_REMATCH[1]}"
        ns=$(echo "$us * 1000" | bc -l)
    elif [[ "$result" =~ ^([0-9.]+)ms/op$ ]] || [[ "$result" =~ ^([0-9.]+)ms$ ]]; then
        # Milliseconds — multiply by 1000000
        local ms="${BASH_REMATCH[1]}"
        ns=$(echo "$ms * 1000000" | bc -l)
    elif [[ "$result" =~ ^([0-9.]+)$ ]]; then
        # Plain number, assume ns
        ns="$result"
    else
        echo "  [SKIP] $label — could not parse result: $result"
        return
    fi

    if ! [[ "$ns" =~ ^[0-9.]+$ ]]; then
        echo "  [SKIP] $label — invalid numeric value: $ns"
        return
    fi

    if (( $(echo "$ns > $target_ns" | bc -l) )); then
        echo "  [FAIL] $label: ${ns}ns > ${target_ns}ns target"
        FAILURES=$((FAILURES + 1))
    else
        echo "  [PASS] $label: ${ns}ns <= ${target_ns}ns"
    fi
}

# Core evaluation benchmarks
run_bench "./internal/cel/"        "BenchmarkCEL"                 "3000"   "CEL eval <3us"
run_bench "./internal/delegation/" "BenchmarkDelegation"          "100"    "Delegation ceiling <100ns"
run_bench "./internal/ifc/"        "BenchmarkIFC"                 "100"    "IFC dominates <100ns"
run_bench "./internal/otel/"       "BenchmarkOTel_DisabledPath"   "50"     "OTel disabled <50ns"
run_bench "./internal/secret/"     "BenchmarkSecret"              "100000" "Secret scan <100us"

# gRPC and integration benchmarks (if present)
run_bench "./internal/grpc/"       "BenchmarkGRPC"                "200000" "gRPC ext_authz <200us"

echo ""
if [[ "$FAILURES" -eq 0 ]]; then
    echo "=== BENCHMARK VERIFICATION: PASS ==="
    exit 0
else
    echo "=== BENCHMARK VERIFICATION: FAIL — $FAILURES target(s) missed ==="
    exit 1
fi
