// SPDX-License-Identifier: MIT
package cel

import (
	"context"
	"sync"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mayjain/aegis/internal/classify"
	aegis "github.com/mayjain/aegis/pkg/aegis"
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

// Evaluate evaluates a compiled CEL program against a CheckRequest and VerdictEntry.
//
// Hot path contract (INV-007 zero-alloc, ENGINEERING_STANDARDS §5.5):
//   - ctx carries the per-request 50ms deadline from daemon.handleConnection.
//     Context is the first parameter per §5.5: "Context flows from socket accept
//     through entire evaluation." ContextEval honours cancellation mid-expression.
//   - decodedArgs must be a pre-decoded map[string]any. Callers decode json.RawMessage
//     exactly ONCE before the evaluation loop, never inside it. Decoding inside here
//     allocates on every call and violates the zero-alloc invariant.
//   - The activation map is acquired from the pool, populated, evaluated, cleared, and
//     returned to the pool — no allocation on the steady-state path from our code.
//   - Passing nil decodedArgs is safe (treated as empty args map).
//
// CEL evaluation is PURE (INV-10): same inputs → same output.
// time.Now(), goroutine scheduling, I/O — FORBIDDEN inside CEL programs.
func (a *ActivationBuilder) Evaluate(
	ctx context.Context,
	prog *celgo.Program,
	req aegis.CheckRequest,
	verdictEntry classify.VerdictEntry,
	decodedArgs map[string]any,
) (ref.Val, error) {
	mp := a.pool.Get().(*map[string]any)
	m := *mp

	if decodedArgs == nil {
		decodedArgs = emptyArgs
	}

	m["tool"] = req.Tool
	m["args"] = decodedArgs
	m["session_id"] = req.SessionID
	m["confidentiality"] = int64(req.SecurityLabel.Confidentiality)
	m["integrity"] = int64(req.SecurityLabel.Integrity)
	m["categories"] = int64(req.SecurityLabel.Category)
	m["risk_level"] = string(verdictEntry.RiskLevel)
	m["effects"] = verdictEntry.Effects

	val, _, err := (*prog).ContextEval(ctx, m)

	// Clear before returning to pool to avoid retaining references across evaluations.
	for k := range m {
		delete(m, k)
	}
	*mp = m
	a.pool.Put(mp)

	return val, err
}

// Eval is the package-level hot-path entry point per the WS-04 spec interface.
//
// Signature follows ENGINEERING_STANDARDS §5.5: context is the first parameter.
// snap is the current EngineSnapshot — carried here so WS-05 can thread policy
// metadata through the evaluation stack without a separate global. Unused at
// the WS-04 layer; WS-05 will use it to resolve binding scopes.
//
// decodedArgs must be pre-decoded (see Evaluate for the full contract).
func Eval(
	ctx context.Context,
	prog *celgo.Program,
	req aegis.CheckRequest,
	verdictEntry classify.VerdictEntry,
	snap *aegis.EngineSnapshot,
	decodedArgs map[string]any,
) (ref.Val, error) {
	mp := activationPool.Get().(*map[string]any)
	m := *mp

	if decodedArgs == nil {
		decodedArgs = emptyArgs
	}

	m["tool"] = req.Tool
	m["args"] = decodedArgs
	m["session_id"] = req.SessionID
	m["confidentiality"] = int64(req.SecurityLabel.Confidentiality)
	m["integrity"] = int64(req.SecurityLabel.Integrity)
	m["categories"] = int64(req.SecurityLabel.Category)
	m["risk_level"] = string(verdictEntry.RiskLevel)
	m["effects"] = verdictEntry.Effects

	_ = snap // available for WS-05 to use; no-op at this layer

	val, _, err := (*prog).ContextEval(ctx, m)

	for k := range m {
		delete(m, k)
	}
	*mp = m
	activationPool.Put(mp)

	return val, err
}
