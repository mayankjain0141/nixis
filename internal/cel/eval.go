package cel

import (
	"encoding/json"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mayjain/aegis/internal/classify"
	aegis "github.com/mayjain/aegis/pkg/aegis"
)

// activationPool pools plain map[string]any values to avoid heap allocation on the hot path.
// CEL requires the underlying type to be exactly map[string]any (not a named alias).
var activationPool = sync.Pool{
	New: func() any {
		m := make(map[string]any, 8)
		return &m
	},
}

// ActivationBuilder provides zero-alloc CEL activation construction via sync.Pool.
// Not safe for concurrent use per instance, but pool-level concurrency is safe.
type ActivationBuilder struct {
	pool sync.Pool
}

// NewActivationBuilder creates an ActivationBuilder with pre-warmed pool entries.
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

// Evaluate evaluates a compiled CEL program against a CheckRequest and VerdictEntry.
//
// Hot path contract:
//   - Activation map acquired from pool — never allocated fresh.
//   - Args decoded inline (json.Unmarshal is unavoidable for map[string]any from json.RawMessage;
//     the pool prevents the map allocation itself).
//   - Returns the raw CEL value — caller checks if it's a bool.
//
// CEL evaluation is PURE (INV-10): same inputs → same output.
// time.Now(), goroutine scheduling, I/O — FORBIDDEN.
func (a *ActivationBuilder) Evaluate(
	prog cel.Program,
	req aegis.CheckRequest,
	verdictEntry classify.VerdictEntry,
) (ref.Val, error) {
	mp := a.pool.Get().(*map[string]any)
	m := *mp

	// Decode args from json.RawMessage to map[string]any.
	// json.Unmarshal allocates the inner map; the outer activation map is pooled.
	var args map[string]any
	if len(req.Args) > 0 {
		_ = json.Unmarshal(req.Args, &args) // best-effort; nil args → empty map below
	}
	if args == nil {
		args = make(map[string]any)
	}

	// Populate the activation with all declared CEL variables.
	m["tool"] = req.Tool
	m["args"] = args
	m["session_id"] = req.SessionID
	m["confidentiality"] = int64(req.SecurityLabel.Confidentiality)
	m["integrity"] = int64(req.SecurityLabel.Integrity)
	m["categories"] = int64(req.SecurityLabel.Category)
	m["risk_level"] = string(verdictEntry.RiskLevel)
	m["effects"] = verdictEntry.Effects

	val, _, err := prog.Eval(m)

	// Reset map before returning to pool (avoids retaining references).
	for k := range m {
		delete(m, k)
	}
	*mp = m
	a.pool.Put(mp)

	return val, err
}

// EvalWithPool is a package-level convenience using the shared activationPool.
// Use ActivationBuilder.Evaluate for instance-level pool control.
func EvalWithPool(prog cel.Program, req aegis.CheckRequest, verdictEntry classify.VerdictEntry) (ref.Val, error) {
	mp := activationPool.Get().(*map[string]any)
	m := *mp

	var args map[string]any
	if len(req.Args) > 0 {
		_ = json.Unmarshal(req.Args, &args)
	}
	if args == nil {
		args = make(map[string]any)
	}

	m["tool"] = req.Tool
	m["args"] = args
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
