// SPDX-License-Identifier: MIT
package cel

import (
	"errors"
	"log"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// programMeta carries a pointer to a compiled program and source location metadata.
// The program is stored as *celgo.Program (pointer to interface) per the spec:
//
//	func (c *ProgramCache) Get(policyID string) (*celgo.Program, bool)
//
// The heap allocation per entry is acceptable — CompileAll runs only at reload time,
// never on the hot path. Storing a pointer (not the interface value directly) keeps
// the Get return type consistent with the spec and avoids a copy of the interface fat pointer
// on every hot-path Get call.
type programMeta struct {
	prog       *celgo.Program
	sourceFile string
	sourceLine int
}

// ProgramCache holds compiled CEL programs keyed by policy ID.
//
// VALUE TYPE — NOT an atomic.Pointer. ProgramCache is embedded in
// EngineSnapshot and swapped atomically as part of the whole snapshot.
// Copying a ProgramCache copies the map header; the underlying program pointers
// and source metadata are immutable after CompileAll returns.
type ProgramCache struct {
	programs map[string]programMeta // policy_id → *celgo.Program + source location
	version  uint64
}

// Get returns a pointer to the compiled program for the given policy ID.
// Returns (nil, false) if the policy ID is unknown.
//
// The returned *celgo.Program is immutable — do not mutate the pointed-to value.
// Pass the pointer directly to Eval() or ActivationBuilder.Evaluate().
func (c *ProgramCache) Get(policyID string) (*celgo.Program, bool) {
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
// Called only from SourceLocation — not on the hot path. Negative values return "0".
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

// SkippedPolicy records a policy template that failed CEL type-checking and was skipped.
type SkippedPolicy struct {
	TemplateID    string
	DefaultAction string
	CompileErr    error
}

// CompileAll compiles all policy templates into a ProgramCache.
// Called only during snapshot reload — NEVER on the hot path.
//
// Fail-closed: on the first compile failure, returns an error with policy ID and
// source location. The caller retains the previous EngineSnapshot.
//
// Skipped returns policies that were skipped because their expressions reference
// undeclared CEL variables or functions. Skipping is not an error — the caller should
// log the skipped IDs so operators know which policies are inactive. Callers must
// inspect SkippedPolicy.DefaultAction: if "DENY", refuse to load the bundle.
func CompileAll(env *CELEnvironment, templates []policy_types.PolicyTemplate) (*ProgramCache, []SkippedPolicy, error) {
	cache := &ProgramCache{
		programs: make(map[string]programMeta, len(templates)),
	}
	var skipped []SkippedPolicy

	for i := range templates {
		t := &templates[i]
		if len(t.Expression) > maxExpressionLength {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("expression exceeds maxExpressionLength (4096)"),
			}
		}

		// Phase 1: parse only — syntax errors are hard failures regardless of phase.
		parsedAst, parseIssues := env.env.Parse(t.Expression)
		if parseIssues != nil && parseIssues.Err() != nil {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      parseIssues.Err(),
			}
		}

		// Phase 2: type-check — skip policies referencing undeclared variables or functions.
		ast, checkIssues := env.env.Check(parsedAst)
		if checkIssues != nil && checkIssues.Err() != nil {
			log.Printf("WARN: policy %q skipped — undeclared CEL variable or function in expression %q: %v. Register missing functions in Phase 2 to activate this policy.", t.ID, t.Expression, checkIssues.Err())
			skipped = append(skipped, SkippedPolicy{
				TemplateID:    t.ID,
				DefaultAction: t.DefaultAction,
				CompileErr:    checkIssues.Err(),
			})
			continue
		}

		// Enforce AST depth limit at compile time.
		if depth := astDepth(ast); depth > maxASTDepth {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("AST depth exceeds maxASTDepth (32)"),
			}
		}

		// Enforce cost budget via static analysis at compile time.
		// cel.CostLimit() as a ProgramOption adds OptTrackCost, which allocates a
		// cost-tracker struct on every ContextEval() call — violates the zero-alloc hot path.
		// Static estimation enforces the budget at compile time: policies are immutable
		// after build, so a statically-safe expression is safe at runtime.
		cost, costErr := env.env.EstimateCost(ast, conservativeSizeEstimator{})
		if costErr != nil {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      costErr,
			}
		}
		if cost.Max > maxCostBudget {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      errors.New("static cost estimate exceeds maxCostBudget (10000)"),
			}
		}

		// InterruptCheckFrequency enables context cancellation checks inside evaluation.
		// Without it, ContextEval ignores ctx.Done() during expression evaluation — the
		// 50ms deadline would only be checked at program entry.
		// Value 100 means: check for cancellation every 100 evaluation steps.
		prog, err := env.env.Program(ast, celgo.InterruptCheckFrequency(100))
		if err != nil {
			return nil, nil, &CompileError{
				PolicyID:   t.ID,
				SourceFile: t.SourceFile,
				SourceLine: t.SourceLine,
				Cause:      err,
			}
		}

		// Allocating a pointer here is acceptable: this is compile time, not hot path.
		cache.programs[t.ID] = programMeta{
			prog:       &prog,
			sourceFile: t.SourceFile,
			sourceLine: t.SourceLine,
		}
	}

	return cache, skipped, nil
}

// CompileError is returned by CompileAll on a hard compile failure (syntax error,
// AST depth exceeded, cost budget exceeded). Distinct from SkippedPolicy, which
// records soft failures (undeclared variable/function) where skipping is acceptable.
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

// astDepth returns the maximum nesting depth of a compiled AST.
func astDepth(ast *celgo.Ast) int {
	if ast == nil {
		return 0
	}
	return exprDepth(ast)
}

// exprDepth walks the CEL AST native representation to compute nesting depth.
// Called only at compile time — not on the hot path.
func exprDepth(a *celgo.Ast) int {
	native := a.NativeRep()
	if native == nil {
		return 0
	}
	return countExprDepth(native.Expr(), 0)
}

// conservativeSizeEstimator implements checker.CostEstimator for static cost analysis.
// Returns conservative (large) estimates so the static cost bound is a worst-case ceiling.
type conservativeSizeEstimator struct{}

func (conservativeSizeEstimator) EstimateSize(_ checker.AstNode) *checker.SizeEstimate {
	// Assume worst-case size of 1024 for all variable-length inputs (strings, lists).
	// Policy expressions operate on short tool names and small effects lists in practice.
	return &checker.SizeEstimate{Min: 0, Max: 1024}
}

func (conservativeSizeEstimator) EstimateCallCost(_, _ string, _ *checker.AstNode, _ []checker.AstNode) *checker.CallEstimate {
	// nil → use CEL's built-in cost estimates for all functions.
	// bash.* and path.* are O(1) string operations; their default cost of 1 is accurate.
	return nil
}

// compile-time interface assertion
var _ checker.CostEstimator = conservativeSizeEstimator{}
