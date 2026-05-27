package cel

import (
	"sync"

	"github.com/google/cel-go/cel"
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
// Hot path contract (INV-007 zero-alloc):
//   - decodedArgs must be a pre-decoded map[string]any. Callers decode json.RawMessage
//     exactly ONCE before the evaluation loop, never inside it. Decoding inside here
//     allocates on every call and violates the zero-alloc invariant.
//   - The activation map is acquired from the pool, populated, evaluated, cleared, and
//     returned to the pool — no allocation on the steady-state path.
//   - Passing nil decodedArgs is safe (treated as empty args map).
//
// CEL evaluation is PURE (INV-10): same inputs → same output.
// time.Now(), goroutine scheduling, I/O — FORBIDDEN inside CEL programs.
func (a *ActivationBuilder) Evaluate(
	prog cel.Program,
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

	val, _, err := prog.Eval(m)

	// Clear before returning to pool to avoid retaining references across evaluations.
	for k := range m {
		delete(m, k)
	}
	*mp = m
	a.pool.Put(mp)

	return val, err
}

// EvalWithPool evaluates using the package-level activation pool.
// decodedArgs must be a pre-decoded map[string]any; nil is treated as empty args.
func EvalWithPool(
	prog cel.Program,
	req aegis.CheckRequest,
	verdictEntry classify.VerdictEntry,
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

	val, _, err := prog.Eval(m)

	for k := range m {
		delete(m, k)
	}
	*mp = m
	activationPool.Put(mp)

	return val, err
}
