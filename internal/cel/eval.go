// SPDX-License-Identifier: MIT
package cel

import (
	"context"
	"sync"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mayjain/nixis/internal/classify"
	"github.com/mayjain/nixis/internal/label"
	nixis "github.com/mayjain/nixis/pkg/nixis"
)

// activationPool pools plain map[string]any values to avoid heap allocation on the hot path.
// CEL requires the underlying dynamic type to be exactly map[string]any (not a named alias).
// The pool stores *map[string]any so the pointer itself is reused without an extra alloc.
var activationPool = sync.Pool{
	New: func() any {
		m := make(map[string]any, 8)
		return &m
	},
}

// ActivationBuilder provides zero-alloc CEL activation construction via sync.Pool.
// Safe for concurrent use: the pool is internally concurrent-safe.
type ActivationBuilder struct {
	pool sync.Pool
}

// NewActivationBuilder creates an ActivationBuilder with its own pool.
func NewActivationBuilder() *ActivationBuilder {
	return &ActivationBuilder{
		pool: sync.Pool{
			New: func() any {
				m := make(map[string]any, 8)
				return &m
			},
		},
	}
}

// emptyArgs is a shared immutable empty map used when decodedArgs is nil.
// Never written to; sharing across goroutines is safe.
var emptyArgs = map[string]any{}

// emptyParams is a shared immutable empty map used when params is nil.
// Never written to; sharing across goroutines is safe.
var emptyParams = map[string]any{}

// Evaluate evaluates a compiled CEL program against a CheckRequest and VerdictEntry.
//
// Hot path contract (zero-alloc):
//   - ctx carries the per-request 50ms deadline from daemon.handleConnection.
//     ContextEval honours cancellation mid-expression.
//   - decodedArgs must be a pre-decoded map[string]any. Callers decode json.RawMessage
//     exactly ONCE before the evaluation loop, never inside it.
//   - The activation map is acquired from the pool, populated, evaluated, cleared, and
//     returned to the pool — no allocation on the steady-state path from our code.
//   - Passing nil decodedArgs is safe (treated as empty args map).
//   - sessionProjectRoot is the immutable project root for the session (from SessionLabels).
//     Empty string is valid (policy uses session.projectRoot == "" to skip boundary check).
//
// CEL evaluation is PURE: same inputs → same output.
// time.Now(), goroutine scheduling, I/O — FORBIDDEN inside CEL programs.
func (a *ActivationBuilder) Evaluate(
	ctx context.Context,
	prog *celgo.Program,
	req nixis.CheckRequest,
	verdictEntry classify.VerdictEntry,
	decodedArgs map[string]any,
	labeled label.LabeledRequest,
	params map[string]any,
	sessionProjectRoot string,
) (ref.Val, error) {
	mp := a.pool.Get().(*map[string]any)
	m := *mp

	if decodedArgs == nil {
		decodedArgs = emptyArgs
	}
	if params == nil {
		params = emptyParams
	}

	m["tool"] = req.Tool
	m["args"] = decodedArgs
	m["session_id"] = req.SessionID
	m["session"] = map[string]any{
		"projectRoot": sessionProjectRoot,
	}
	m["confidentiality"] = int64(req.SecurityLabel.Confidentiality)
	m["integrity"] = int64(req.SecurityLabel.Integrity)
	m["categories"] = int64(req.SecurityLabel.Category)
	m["risk_level"] = string(verdictEntry.RiskLevel)
	m["effects"] = verdictEntry.Effects
	m["resource_matched"] = types.Bool(labeled.Matched)
	m["resource_conf"] = types.Int(labeled.ResourceLabel.Confidentiality)
	m["resource_cat"] = types.Int(labeled.ResourceLabel.Category)
	m["resource_type"] = types.String(labeled.ResourceType)
	m["resource_path"] = types.String(labeled.ResourcePath)
	m["resource_network_cmd"] = types.Bool(labeled.ContainsNetworkCmd)
	m["resource_unknown_tool"] = types.Bool(labeled.UnknownTool)
	m["resource_interpreter_exec"] = types.Bool(labeled.ContainsInterpreterExec)
	m["params"] = params

	val, _, err := (*prog).ContextEval(ctx, m)

	// Clear before returning to pool to avoid retaining references across evaluations.
	for k := range m {
		delete(m, k)
	}
	*mp = m
	a.pool.Put(mp)

	return val, err
}

// Eval is the package-level hot-path entry point.
//
// snap is the current EngineSnapshot — carried here so the policy engine can thread
// policy metadata through the evaluation stack without a separate global.
//
// decodedArgs must be pre-decoded (see Evaluate for the full contract).
// sessionProjectRoot is the immutable project root for the session; empty is valid.
func Eval(
	ctx context.Context,
	prog *celgo.Program,
	req nixis.CheckRequest,
	verdictEntry classify.VerdictEntry,
	snap *nixis.EngineSnapshot,
	decodedArgs map[string]any,
	labeled label.LabeledRequest,
	params map[string]any,
	sessionProjectRoot string,
) (ref.Val, error) {
	mp := activationPool.Get().(*map[string]any)
	m := *mp

	if decodedArgs == nil {
		decodedArgs = emptyArgs
	}
	if params == nil {
		params = emptyParams
	}

	m["tool"] = req.Tool
	m["args"] = decodedArgs
	m["session_id"] = req.SessionID
	m["session"] = map[string]any{
		"projectRoot": sessionProjectRoot,
	}
	m["confidentiality"] = int64(req.SecurityLabel.Confidentiality)
	m["integrity"] = int64(req.SecurityLabel.Integrity)
	m["categories"] = int64(req.SecurityLabel.Category)
	m["risk_level"] = string(verdictEntry.RiskLevel)
	m["effects"] = verdictEntry.Effects
	m["resource_matched"] = types.Bool(labeled.Matched)
	m["resource_conf"] = types.Int(labeled.ResourceLabel.Confidentiality)
	m["resource_cat"] = types.Int(labeled.ResourceLabel.Category)
	m["resource_type"] = types.String(labeled.ResourceType)
	m["resource_path"] = types.String(labeled.ResourcePath)
	m["resource_network_cmd"] = types.Bool(labeled.ContainsNetworkCmd)
	m["resource_unknown_tool"] = types.Bool(labeled.UnknownTool)
	m["resource_interpreter_exec"] = types.Bool(labeled.ContainsInterpreterExec)
	m["params"] = params

	_ = snap // no-op at this layer

	val, _, err := (*prog).ContextEval(ctx, m)

	for k := range m {
		delete(m, k)
	}
	*mp = m
	activationPool.Put(mp)

	return val, err
}
