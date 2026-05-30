#!/usr/bin/env bash
set -euo pipefail

# Aegis Adversarial Eval Runner
# Sends test cases to daemon and compares actual vs expected decisions

DAEMON_SOCKET="/tmp/aegis.sock"
CASES_DIR="./eval/adversarial"
OUTPUT_DIR="./eval/results"
FILTER=""
TIMEOUT_MS=5000

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run adversarial evaluation against Aegis daemon.

Options:
    --daemon-socket PATH   Unix socket path (default: /tmp/aegis.sock)
    --cases-dir DIR        Directory containing JSONL test files (default: ./eval/adversarial)
    --output-dir DIR       Directory for results output (default: ./eval/results)
    --filter CATEGORY      Only run cases matching this category
    --timeout-ms N         Request timeout in milliseconds (default: 5000)
    -h, --help             Show this help

Exit codes:
    0    All tests passed
    1    One or more tests failed
    2    Configuration or runtime error
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --daemon-socket) DAEMON_SOCKET="$2"; shift 2 ;;
        --cases-dir) CASES_DIR="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --filter) FILTER="$2"; shift 2 ;;
        --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    RESET=''
fi

if [[ ! -S "$DAEMON_SOCKET" ]]; then
    echo -e "${RED}Error: Daemon socket not found at $DAEMON_SOCKET${RESET}" >&2
    echo "Is the Aegis daemon running?" >&2
    exit 2
fi

if [[ ! -d "$CASES_DIR" ]]; then
    echo -e "${RED}Error: Cases directory not found at $CASES_DIR${RESET}" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

EVAL_SCRIPT=$(cat <<'PYTHON_EOF'
import json
import socket
import struct
import sys
import time
import uuid

def send_request(sock_path, request_json, timeout_ms):
    """Send CheckRequest to daemon, return (response_dict, latency_ms) or (None, error_str)."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_ms / 1000.0)
        sock.connect(sock_path)

        body = json.dumps(request_json).encode('utf-8')
        length = struct.pack('>I', len(body))

        start = time.time()
        sock.sendall(length + body)

        resp_len_bytes = sock.recv(4)
        if len(resp_len_bytes) < 4:
            return None, "incomplete length header"

        resp_len = struct.unpack('>I', resp_len_bytes)[0]
        if resp_len > 2 * 1024 * 1024:
            return None, f"response too large: {resp_len} bytes"

        resp_body = b''
        while len(resp_body) < resp_len:
            chunk = sock.recv(min(resp_len - len(resp_body), 8192))
            if not chunk:
                return None, "connection closed mid-response"
            resp_body += chunk

        latency_ms = (time.time() - start) * 1000
        sock.close()

        response = json.loads(resp_body.decode('utf-8'))
        return response, latency_ms

    except socket.timeout:
        return None, "timeout"
    except ConnectionRefusedError:
        return None, "connection refused"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON response: {e}"
    except Exception as e:
        return None, str(e)

def run_case(sock_path, case, timeout_ms):
    """Run a single test case, return result dict."""
    case_id = case.get('id', 'UNKNOWN')
    description = case.get('description', '')
    request = dict(case.get('request', {}))
    expected = case.get('expected_decision', 'deny')
    expected_layer = case.get('expected_layer')

    # Unique session per case prevents taint bleed when cases share session IDs in JSONL.
    request['session_id'] = f"eval-{case_id}-{uuid.uuid4().hex[:8]}"

    response, latency_or_error = send_request(sock_path, request, timeout_ms)

    if response is None:
        return {
            'id': case_id,
            'description': description,
            'status': 'ERROR',
            'error': latency_or_error,
            'latency_ms': None,
            'actual_decision': None,
            'expected_decision': expected,
            'actual_layer': None,
            'expected_layer': expected_layer,
        }

    # Daemon returns PascalCase keys (Go JSON default)
    decision_obj = response.get('Decision', response.get('decision', {}))
    actual = decision_obj.get('Action', decision_obj.get('action', 'unknown')).lower()
    actual_layer = (response.get('EnforcingLayer') or response.get('enforcing_layer') or '').lower() or None
    latency_ms = latency_or_error

    passed = (actual == expected)
    layer_match = (expected_layer is None) or (actual_layer == expected_layer)

    return {
        'id': case_id,
        'description': description,
        'status': 'PASS' if passed else 'FAIL',
        'latency_ms': latency_ms,
        'actual_decision': actual,
        'expected_decision': expected,
        'actual_layer': actual_layer,
        'expected_layer': expected_layer,
        'layer_match': layer_match,
        'response': response,
    }

def main():
    if len(sys.argv) < 4:
        print("Usage: python eval.py <socket_path> <jsonl_file> <timeout_ms>", file=sys.stderr)
        sys.exit(2)

    sock_path = sys.argv[1]
    jsonl_file = sys.argv[2]
    timeout_ms = int(sys.argv[3])

    results = []
    with open(jsonl_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                case = json.loads(line)
                result = run_case(sock_path, case, timeout_ms)
                results.append(result)
            except json.JSONDecodeError as e:
                results.append({
                    'id': f'LINE-{line_num}',
                    'description': 'Parse error',
                    'status': 'ERROR',
                    'error': f'Invalid JSON on line {line_num}: {e}',
                    'latency_ms': None,
                })

    print(json.dumps(results))

if __name__ == '__main__':
    main()
PYTHON_EOF
)

declare -a ALL_LATENCIES=()
declare -i TOTAL_PASS=0 TOTAL_FAIL=0 TOTAL_ERROR=0 TOTAL_SKIP=0
declare -i TOTAL_TP=0 TOTAL_FP=0 TOTAL_TN=0 TOTAL_FN=0
declare -i LAYER_MATCH=0 LAYER_TOTAL=0

print_result() {
    local status="$1"
    local id="$2"
    local desc="$3"
    local latency="$4"
    local layer="$5"
    local extra="${6:-}"

    case $status in
        PASS)  prefix="${GREEN}[PASS]${RESET}" ;;
        FAIL)  prefix="${RED}[FAIL]${RESET}" ;;
        ERROR) prefix="${YELLOW}[ERROR]${RESET}" ;;
        SKIP)  prefix="${BLUE}[SKIP]${RESET}" ;;
    esac

    if [[ -n "$latency" && "$latency" != "null" ]]; then
        latency_str=$(printf "%.1fms" "$latency")
    else
        latency_str="-"
    fi

    layer_str="${layer:-"-"}"

    echo -e "${prefix} ${id}: ${desc} (${latency_str}, layer: ${layer_str})"

    if [[ -n "$extra" ]]; then
        echo -e "  ${extra}"
    fi
}

process_results() {
    local category="$1"
    local results_json="$2"

    local cat_pass=0 cat_fail=0 cat_error=0
    local cat_tp=0 cat_fp=0 cat_tn=0 cat_fn=0

    local count
    count=$(echo "$results_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

    for ((i=0; i<count; i++)); do
        local case_json
        case_json=$(echo "$results_json" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)[$i]))")

        local status id desc latency actual expected layer expected_layer error
        status=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
        id=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
        desc=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('description',''))")
        latency=$(echo "$case_json" | python3 -c "import sys,json; l=json.load(sys.stdin).get('latency_ms'); print(l if l else '')")
        actual=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('actual_decision',''))")
        expected=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expected_decision',''))")
        layer=$(echo "$case_json" | python3 -c "import sys,json; l=json.load(sys.stdin).get('actual_layer'); print(l if l else '')")
        expected_layer=$(echo "$case_json" | python3 -c "import sys,json; l=json.load(sys.stdin).get('expected_layer'); print(l if l else '')")
        error=$(echo "$case_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))")
        layer_match=$(echo "$case_json" | python3 -c "import sys,json; m=json.load(sys.stdin).get('layer_match'); print('true' if m else 'false')")

        case $status in
            PASS)
                ((cat_pass++))
                ((TOTAL_PASS++))
                if [[ "$expected" == "deny" ]]; then
                    ((cat_tp++))
                    ((TOTAL_TP++))
                else
                    ((cat_tn++))
                    ((TOTAL_TN++))
                fi
                print_result "PASS" "$id" "$desc" "$latency" "$layer"
                ;;
            FAIL)
                ((cat_fail++))
                ((TOTAL_FAIL++))
                if [[ "$expected" == "deny" ]]; then
                    ((cat_fn++))
                    ((TOTAL_FN++))
                else
                    ((cat_fp++))
                    ((TOTAL_FP++))
                fi
                print_result "FAIL" "$id" "$desc" "$latency" "$layer" "Expected: ${expected}, Got: ${actual}"
                ;;
            ERROR)
                ((cat_error++))
                ((TOTAL_ERROR++))
                print_result "ERROR" "$id" "$desc" "" "" "$error"
                ;;
        esac

        if [[ -n "$latency" ]]; then
            ALL_LATENCIES+=("$latency")
        fi

        if [[ -n "$expected_layer" ]]; then
            ((LAYER_TOTAL++))
            if [[ "$layer_match" == "true" ]]; then
                ((LAYER_MATCH++))
            fi
        fi
    done

    local cat_total=$((cat_pass + cat_fail + cat_error))
    local cat_precision="-" cat_recall="-"

    if [[ $((cat_tp + cat_fp)) -gt 0 ]]; then
        cat_precision=$(python3 -c "print(f'{100 * $cat_tp / ($cat_tp + $cat_fp):.1f}%')")
    fi
    if [[ $((cat_tp + cat_fn)) -gt 0 ]]; then
        cat_recall=$(python3 -c "print(f'{100 * $cat_tp / ($cat_tp + $cat_fn):.1f}%')")
    fi

    echo ""
    echo -e "${BOLD}Category: ${category}${RESET}"
    echo "  Total: ${cat_total}, Passed: ${cat_pass}, Failed: ${cat_fail}, Errors: ${cat_error}"
    echo "  Precision: ${cat_precision}, Recall: ${cat_recall}"
}

echo -e "${BOLD}=== Aegis Adversarial Evaluation ===${RESET}"
echo "Socket: $DAEMON_SOCKET"
echo "Cases dir: $CASES_DIR"
echo "Timeout: ${TIMEOUT_MS}ms"
if [[ -n "$FILTER" ]]; then
    echo "Filter: $FILTER"
fi
echo ""

JSONL_FILES=$(find "$CASES_DIR" -maxdepth 1 -name "*.jsonl" -type f | sort)

if [[ -z "$JSONL_FILES" ]]; then
    echo -e "${YELLOW}Warning: No JSONL files found in $CASES_DIR${RESET}"
    exit 0
fi

for jsonl_file in $JSONL_FILES; do
    category=$(basename "$jsonl_file" .jsonl | sed 's/^[0-9]*_//')

    if [[ -n "$FILTER" && "$category" != *"$FILTER"* ]]; then
        echo -e "${BLUE}Skipping $category (filter: $FILTER)${RESET}"
        continue
    fi

    echo -e "${BOLD}--- Running: $(basename "$jsonl_file") ---${RESET}"

    results_json=$(echo "$EVAL_SCRIPT" | python3 - "$DAEMON_SOCKET" "$jsonl_file" "$TIMEOUT_MS" 2>&1) || {
        echo -e "${RED}Error running eval for $jsonl_file${RESET}" >&2
        echo "$results_json" >&2
        continue
    }

    process_results "$category" "$results_json"
    echo ""
done

echo -e "${BOLD}=== Overall Results ===${RESET}"

TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_ERROR))
echo "Total: ${TOTAL}, Passed: ${TOTAL_PASS}, Failed: ${TOTAL_FAIL}, Errors: ${TOTAL_ERROR}"

if [[ $((TOTAL_TP + TOTAL_FP)) -gt 0 ]]; then
    PRECISION=$(python3 -c "print(f'{100 * $TOTAL_TP / ($TOTAL_TP + $TOTAL_FP):.1f}')")
else
    PRECISION="-"
fi

if [[ $((TOTAL_TP + TOTAL_FN)) -gt 0 ]]; then
    RECALL=$(python3 -c "print(f'{100 * $TOTAL_TP / ($TOTAL_TP + $TOTAL_FN):.1f}')")
else
    RECALL="-"
fi

echo "Precision: ${PRECISION}%, Recall: ${RECALL}%"

if [[ $LAYER_TOTAL -gt 0 ]]; then
    LAYER_ACC=$(python3 -c "print(f'{100 * $LAYER_MATCH / $LAYER_TOTAL:.1f}')")
    echo "Layer attribution accuracy: ${LAYER_ACC}% (${LAYER_MATCH}/${LAYER_TOTAL})"
fi

if [[ ${#ALL_LATENCIES[@]} -gt 0 ]]; then
    LATENCY_STATS=$(python3 <<PYEOF
import statistics
latencies = [${ALL_LATENCIES[*]/%/,}]
latencies = [l for l in latencies if l > 0]
if latencies:
    latencies.sort()
    mean = statistics.mean(latencies)
    p50 = latencies[len(latencies)//2]
    p95 = latencies[int(len(latencies)*0.95)]
    p99 = latencies[int(len(latencies)*0.99)]
    print(f"Latency: mean={mean:.1f}ms, p50={p50:.1f}ms, p95={p95:.1f}ms, p99={p99:.1f}ms")
else:
    print("Latency: no data")
PYEOF
)
    echo "$LATENCY_STATS"
fi

RESULTS_FILE="${OUTPUT_DIR}/eval-$(date +%Y%m%d-%H%M%S).json"
cat > "$RESULTS_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "socket": "$DAEMON_SOCKET",
  "cases_dir": "$CASES_DIR",
  "filter": "$FILTER",
  "timeout_ms": $TIMEOUT_MS,
  "totals": {
    "total": $TOTAL,
    "passed": $TOTAL_PASS,
    "failed": $TOTAL_FAIL,
    "errors": $TOTAL_ERROR
  },
  "confusion_matrix": {
    "true_positives": $TOTAL_TP,
    "false_positives": $TOTAL_FP,
    "true_negatives": $TOTAL_TN,
    "false_negatives": $TOTAL_FN
  },
  "metrics": {
    "precision": $([[ "$PRECISION" != "-" ]] && echo "$PRECISION" || echo "null"),
    "recall": $([[ "$RECALL" != "-" ]] && echo "$RECALL" || echo "null")
  }
}
EOF
echo ""
echo "Results saved to: $RESULTS_FILE"

if [[ $TOTAL_FAIL -gt 0 || $TOTAL_ERROR -gt 0 ]]; then
    echo -e "${RED}Exit code: 1 (failures or errors detected)${RESET}"
    exit 1
else
    echo -e "${GREEN}Exit code: 0 (all tests passed)${RESET}"
    exit 0
fi
