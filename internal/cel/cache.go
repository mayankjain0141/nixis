package cel

import (
	"errors"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// programMeta carries compiled program state plus source location for CheckResponse.
type programMeta struct {
	prog       cel.Program
	sourceFile string
	sourceLine int
}

// ProgramCache holds compiled CEL programs keyed by policy ID.
//
// VALUE TYPE — NOT an atomic.Pointer. ProgramCache is embedded in EngineSnapshot and
// swapped atomically as part of the whole snapshot (INV-008). Copying a ProgramCache
// copies the map header only; the underlying programs are immutable after CompileAll.
type ProgramCache struct {
	programs map[string]programMeta
	version  uint64
}

// Get returns the compiled program for the given policy ID.
// Returns false if the policy ID is unknown.
func (c *ProgramCache) Get(policyID string) (cel.Program, bool) {
	m, ok := c.programs[policyID]
	if !ok {
		return nil, false
	}
	return m.prog, true
}

// SourceLocation returns the "file:line" source location for a compiled policy.
// Returns an empty string if the policy ID is unknown or has no source location.
func (c *ProgramCache) SourceLocation(policyID string) string {
	m, ok := c.programs[policyID]
	if !ok || m.sourceFile == "" {
		return ""
	}
	if m.sourceLine <= 0 {
		return m.sourceFile
	}
	return m.sourceFile + ":" + itoa(m.sourceLine)
}

// Version returns the snapshot version this cache was compiled for.
func (c *ProgramCache) Version() uint64 { return c.version }

// itoa converts a non-negative int to its decimal string representation.
// SourceLine values from policy YAML are expected to be >= 1; this function
// is only called when sourceLine > 0. Negative values are clamped to "0"
// rather than producing a garbled or empty string.
func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := 20
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// CompileAll compiles all policy templates into a ProgramCache.
// Called only during snapshot reload — NEVER on the hot path.
//
// On the first compile failure the function returns an error immediately (fail-closed).
// The error message includes the policy ID and source location.
func CompileAll(env *CELEnvironment, templates []policy_types.PolicyTemplate) (*ProgramCache, error) {
	cache := &ProgramCache{
		programs: make(map[string]programMeta, len(templates)),
	}

	for i := range templates {
		t := &templates[i]
		if len(t.Expression) > maxExpressionLength {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("expression exceeds maxExpressionLength (4096)"),
			}
		}

		ast, issues := env.env.Compile(t.Expression)
		if issues != nil && issues.Err() != nil {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      issues.Err(),
			}
		}

		// Enforce AST depth limit.
		if depth := astDepth(ast); depth > maxASTDepth {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("AST depth exceeds maxASTDepth (32)"),
			}
		}

		// Enforce cost budget via static analysis at compile time.
		// Using cel.CostLimit() as a ProgramOption adds OptTrackCost, which allocates a
		// cost-tracker struct on every Eval() call — incompatible with INV-007 (zero allocs).
		// Static estimation is the correct place to enforce this limit: policies are immutable
		// after compilation, so any expression within the static cost bound is safe at runtime.
		cost, costErr := env.env.EstimateCost(ast, conservativeSizeEstimator{})
		if costErr != nil {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      costErr,
			}
		}
		if cost.Max > maxCostBudget {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("static cost estimate exceeds maxCostBudget (10000)"),
			}
		}

		prog, err := env.env.Program(ast)
		if err != nil {
			return nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      err,
			}
		}

		cache.programs[t.ID] = programMeta{
			prog:       prog,
			sourceFile: t.SourceFile,
			sourceLine: t.SourceLine,
		}
	}

	return cache, nil
}

// CompileError is returned by CompileAll on the first compile failure.
type CompileError struct {
	PolicyID   string
	SourceFile string
	SourceLine int
	Cause      error
}

func (e *CompileError) Error() string {
	loc := e.SourceFile
	if e.SourceLine > 0 && loc != "" {
		loc = loc + ":" + itoa(e.SourceLine)
	}
	if loc != "" {
		return "policy " + e.PolicyID + " (" + loc + "): " + e.Cause.Error()
	}
	return "policy " + e.PolicyID + ": " + e.Cause.Error()
}

func (e *CompileError) Unwrap() error { return e.Cause }

// astDepth returns the depth of a compiled AST via a lightweight walk.
func astDepth(ast *cel.Ast) int {
	if ast == nil {
		return 0
	}
	// Use CEL's native AST visitor depth.
	return exprDepth(ast)
}

// exprDepth computes the nesting depth of a CEL AST by walking the native representation.
// Called only at compile time — not on the hot path.
func exprDepth(a *cel.Ast) int {
	native := a.NativeRep()
	if native == nil {
		return 0
	}
	return countExprDepth(native.Expr(), 0)
}

// conservativeSizeEstimator implements checker.CostEstimator for static cost analysis.
//
// It returns conservative (large) size estimates for string and list variables so that
// the static cost bound is an upper bound on actual runtime cost. If the worst-case
// static estimate fits within maxCostBudget, the expression is safe to evaluate at runtime.
type conservativeSizeEstimator struct{}

func (conservativeSizeEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	// For string and list variables, assume a worst-case size of 1024 elements/chars.
	// This is conservative: real policy expressions operate on tool names (short strings)
	// and effects lists (typically 1-5 items). The 1024 bound gives headroom while
	// keeping the static cost estimate meaningful.
	return &checker.SizeEstimate{Min: 0, Max: 1024}
}

func (conservativeSizeEstimator) EstimateCallCost(_, _ string, _ *checker.AstNode, _ []checker.AstNode) *checker.CallEstimate {
	// Return nil to use CEL's built-in cost estimates for all function calls.
	// Our custom bash.* and path.* functions are O(1) string operations; their
	// default cost of 1 per call is accurate.
	return nil
}

// _ asserts conservativeSizeEstimator implements checker.CostEstimator at compile time.
var _ checker.CostEstimator = conservativeSizeEstimator{}
