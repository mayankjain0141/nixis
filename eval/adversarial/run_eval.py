#!/usr/bin/env python3
"""Aegis adversarial eval runner — parallel, single-process, no subprocess overhead."""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── colour ───────────────────────────────────────────────────────────────────
_tty = sys.stdout.isatty()
def _c(code): return code if _tty else ""
RED    = _c("\033[0;31m")
GREEN  = _c("\033[0;32m")
YELLOW = _c("\033[0;33m")
BLUE   = _c("\033[0;34m")
BOLD   = _c("\033[1m")
RESET  = _c("\033[0m")

# ── wire protocol ─────────────────────────────────────────────────────────────
def _send_recv(sock_path: str, request: dict, timeout_s: float):
    """One CheckRequest → CheckResponse over a fresh Unix socket connection."""
    body = json.dumps(request).encode()
    wire = struct.pack(">I", len(body)) + body

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect(sock_path)
        t0 = time.perf_counter()
        sock.sendall(wire)

        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("socket closed before length header")
            hdr += chunk

        resp_len = struct.unpack(">I", hdr)[0]
        if resp_len > 4 * 1024 * 1024:
            raise ValueError(f"response too large: {resp_len} bytes")

        resp_body = b""
        while len(resp_body) < resp_len:
            chunk = sock.recv(min(resp_len - len(resp_body), 65536))
            if not chunk:
                raise ConnectionError("socket closed mid-response")
            resp_body += chunk

        latency_ms = (time.perf_counter() - t0) * 1000
        return json.loads(resp_body), latency_ms
    finally:
        sock.close()

# ── case evaluation ───────────────────────────────────────────────────────────
def _eval_case(sock_path: str, case: dict, timeout_s: float) -> dict:
    """Evaluate one test case. Thread-safe — no shared mutable state."""
    case_id  = case.get("id", "UNKNOWN")
    desc     = case.get("description", "")
    request  = dict(case.get("request", {}))
    expected = case.get("expected_decision", "deny")
    exp_layer = case.get("expected_layer")
    category = case.get("category", "")

    # Unique session per case prevents taint bleed when cases share session IDs in JSONL.
    request["session_id"] = f"eval-{case_id}-{uuid.uuid4().hex[:8]}"

    try:
        response, latency_ms = _send_recv(sock_path, request, timeout_s)
    except socket.timeout:
        return _err(case_id, desc, category, expected, exp_layer, "timeout")
    except Exception as e:
        return _err(case_id, desc, category, expected, exp_layer, str(e))

    dec_obj   = response.get("Decision", response.get("decision", {}))
    actual    = dec_obj.get("Action", dec_obj.get("action", "unknown")).lower()
    act_layer = (response.get("EnforcingLayer") or response.get("enforcing_layer") or "").lower() or None

    passed      = (actual == expected)
    layer_match = (exp_layer is None) or (act_layer == exp_layer)

    return {
        "id":                case_id,
        "description":       desc,
        "status":            "PASS" if (passed and layer_match) else "FAIL",
        "category":          category,
        "latency_ms":        latency_ms,
        "actual_decision":   actual,
        "expected_decision": expected,
        "actual_layer":      act_layer,
        "expected_layer":    exp_layer,
        "layer_match":       layer_match,
    }

def _err(id_, desc, category, expected, exp_layer, msg):
    return {"id": id_, "description": desc, "status": "ERROR", "error": msg,
            "category": category, "expected_decision": expected,
            "expected_layer": exp_layer, "latency_ms": None,
            "actual_decision": None, "actual_layer": None}

# ── metrics ───────────────────────────────────────────────────────────────────
def _metrics(results: list) -> dict:
    tp = tn = fp = fn = 0
    for r in results:
        if r["status"] == "ERROR":
            continue
        exp = r["expected_decision"]
        act = r.get("actual_decision")
        if   exp == "deny"  and act == "deny":  tp += 1
        elif exp == "allow" and act == "allow": tn += 1
        elif exp == "deny"  and act == "allow": fn += 1
        elif exp == "allow" and act == "deny":  fp += 1
    precision = tp / (tp + fp) if (tp + fp) else None
    recall    = tp / (tp + fn) if (tp + fn) else None
    f1        = 2*precision*recall / (precision+recall) if precision and recall else None
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn,
            "precision": precision, "recall": recall, "f1": f1}

def _latency(results: list) -> dict | None:
    lats = sorted(r["latency_ms"] for r in results if r.get("latency_ms") is not None)
    if not lats:
        return None
    n = len(lats)
    return {
        "n":    n,
        "mean": sum(lats) / n,
        "p50":  lats[n // 2],
        "p95":  lats[int(n * 0.95)],
        "p99":  lats[int(n * 0.99)],
        "min":  lats[0],
        "max":  lats[-1],
    }

# ── output ────────────────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def _print_result(r: dict):
    status = r["status"]
    lat    = r.get("latency_ms")
    layer  = r.get("actual_layer") or "-"
    lat_s  = f"{lat:.1f}ms" if lat is not None else "-"

    prefix = {
        "PASS":  f"{GREEN}[PASS]{RESET}",
        "FAIL":  f"{RED}[FAIL]{RESET}",
        "ERROR": f"{YELLOW}[ERROR]{RESET}",
    }.get(status, status)

    line = f"{prefix} {r['id']}: {r['description']} ({lat_s}, layer: {layer})"

    extra = ""
    if status == "FAIL" and r.get("actual_decision") is not None:
        extra = f"\n  Expected: {r['expected_decision']}, Got: {r['actual_decision']}"
    elif status == "ERROR":
        extra = f"\n  {r.get('error', '')}"

    with _print_lock:
        print(line + extra)

def _pct(v): return f"{v*100:.1f}%" if v is not None else "n/a"

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Aegis adversarial eval runner")
    ap.add_argument("--daemon-socket", default="/tmp/aegis.sock")
    ap.add_argument("--cases-dir",     default="./eval/adversarial")
    ap.add_argument("--output-dir",    default="./eval/results")
    ap.add_argument("--filter",        default="", help="only run files matching this substring")
    ap.add_argument("--timeout-ms",    type=int, default=5000)
    ap.add_argument("--workers",       type=int, default=32,
                    help="parallel worker threads (default: 32)")
    ap.add_argument("--quiet",         action="store_true",
                    help="suppress per-case lines, show only summaries")
    args = ap.parse_args()

    if not os.path.exists(args.daemon_socket):
        print(f"{RED}Error: daemon socket not found at {args.daemon_socket}{RESET}", file=sys.stderr)
        print("Is the Aegis daemon running?", file=sys.stderr)
        sys.exit(2)

    cases_dir  = Path(args.cases_dir)
    output_dir = Path(args.output_dir)

    if not cases_dir.is_dir():
        print(f"{RED}Error: cases dir not found: {cases_dir}{RESET}", file=sys.stderr)
        sys.exit(2)

    output_dir.mkdir(parents=True, exist_ok=True)

    # ── load all cases ────────────────────────────────────────────────────────
    jsonl_files = sorted(cases_dir.glob("*.jsonl"))
    if args.filter:
        jsonl_files = [f for f in jsonl_files if args.filter in f.stem]

    if not jsonl_files:
        print(f"{YELLOW}No JSONL files found in {cases_dir}{RESET}")
        sys.exit(0)

    file_cases: dict[Path, list] = {}
    for jf in jsonl_files:
        cases = []
        with open(jf) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    cases.append(json.loads(line))
                except json.JSONDecodeError as e:
                    cases.append({"id": f"{jf.stem}-LINE{lineno}", "description": "json parse error",
                                  "request": {}, "expected_decision": "deny",
                                  "category": "", "_parse_error": str(e)})
        file_cases[jf] = cases

    total = sum(len(v) for v in file_cases.values())

    print(f"{BOLD}=== Aegis Adversarial Evaluation ==={RESET}")
    print(f"Socket:    {args.daemon_socket}")
    print(f"Cases dir: {cases_dir}  ({total} cases across {len(jsonl_files)} files)")
    print(f"Workers:   {args.workers}   Timeout: {args.timeout_ms}ms")
    if args.filter:
        print(f"Filter:    {args.filter}")
    print()

    # ── parallel evaluation ───────────────────────────────────────────────────
    sock_path = args.daemon_socket
    timeout_s = args.timeout_ms / 1000.0
    results_by_id: dict[str, dict] = {}

    t_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for case in (c for cases in file_cases.values() for c in cases):
            if "_parse_error" in case:
                r = _err(case["id"], case["description"], case.get("category", ""),
                         case["expected_decision"], case.get("expected_layer"),
                         case["_parse_error"])
                results_by_id[case["id"]] = r
                if not args.quiet:
                    _print_result(r)
                continue
            futures[pool.submit(_eval_case, sock_path, case, timeout_s)] = case["id"]

        done = len(results_by_id)
        for fut in as_completed(futures):
            r = fut.result()
            results_by_id[r["id"]] = r
            done += 1
            if not args.quiet:
                _print_result(r)
            else:
                pct = done / total * 100
                print(f"\r  {done}/{total} ({pct:.0f}%)...", end="", flush=True)

    elapsed = time.perf_counter() - t_start
    if args.quiet:
        print()

    # ── per-file summaries ────────────────────────────────────────────────────
    all_results = []
    print()
    for jf in jsonl_files:
        ids     = [c["id"] for c in file_cases[jf]]
        results = [results_by_id[id_] for id_ in ids if id_ in results_by_id]
        all_results.extend(results)

        m      = _metrics(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        errors = sum(1 for r in results if r["status"] == "ERROR")

        print(f"{BOLD}{jf.name}{RESET}  "
              f"total={len(results)}  pass={passed}  fail={failed}  err={errors}  "
              f"TP={m['TP']} TN={m['TN']} FP={m['FP']} FN={m['FN']}  "
              f"precision={_pct(m['precision'])}  recall={_pct(m['recall'])}")

    # ── overall ───────────────────────────────────────────────────────────────
    m   = _metrics(all_results)
    lat = _latency(all_results)

    passed = sum(1 for r in all_results if r["status"] == "PASS")
    failed = sum(1 for r in all_results if r["status"] == "FAIL")
    errors = sum(1 for r in all_results if r["status"] == "ERROR")

    print(f"\n{BOLD}=== Overall ==={RESET}")
    print(f"Total: {total}  Pass: {passed}  Fail: {failed}  Error: {errors}")
    print(f"TP={m['TP']}  TN={m['TN']}  FP={m['FP']}  FN={m['FN']}")
    print(f"Precision: {_pct(m['precision'])}  Recall: {_pct(m['recall'])}  F1: {_pct(m['f1'])}")
    if lat:
        print(f"Latency:   mean={lat['mean']:.1f}ms  p50={lat['p50']:.1f}ms  "
              f"p95={lat['p95']:.1f}ms  p99={lat['p99']:.1f}ms")
    print(f"Wall time: {elapsed:.2f}s  ({total/elapsed:.0f} cases/sec)")

    # ── save results ──────────────────────────────────────────────────────────
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"eval-{ts}.json"
    path.write_text(json.dumps({
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "socket":           sock_path,
        "cases_dir":        str(cases_dir),
        "filter":           args.filter,
        "timeout_ms":       args.timeout_ms,
        "workers":          args.workers,
        "wall_time_s":      round(elapsed, 3),
        "totals":           {"total": total, "passed": passed, "failed": failed, "errors": errors},
        "confusion_matrix": {"TP": m["TP"], "TN": m["TN"], "FP": m["FP"], "FN": m["FN"]},
        "metrics": {
            "precision": round(m["precision"] * 100, 1) if m["precision"] is not None else None,
            "recall":    round(m["recall"]    * 100, 1) if m["recall"]    is not None else None,
            "f1":        round(m["f1"]        * 100, 1) if m["f1"]        is not None else None,
        },
        "latency": lat,
        "results": all_results,
    }, indent=2))
    print(f"Results:   {path}")

    sys.exit(0 if failed == 0 and errors == 0 else 1)

if __name__ == "__main__":
    main()
