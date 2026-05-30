// SPDX-License-Identifier: MIT
package nixis

import "context"

// EvaluatorConfig configures an in-process policy evaluator.
type EvaluatorConfig struct {
	PolicyDir string // path to policy YAML directory
}

// evaluateEngine is the minimal interface for policy evaluation.
// Users construct an engine externally (e.g., using internal/policy.PolicyEngine)
// and pass it to NewInProcessEvaluator via dependency injection.
// This avoids circular imports between pkg/nixis and internal packages.
type evaluateEngine interface {
	Evaluate(ctx context.Context, req CheckRequest) CheckResponse
}

// InProcessEvaluator evaluates tool calls against a local policy set
// without requiring a running daemon. Useful for testing, CI pipelines,
// and Go-based agent frameworks that want governance checks in-process.
type InProcessEvaluator struct {
	engine evaluateEngine
}

// NewInProcessEvaluator creates an evaluator wrapping the given engine.
// The caller is responsible for constructing and configuring the engine
// (parsing policies, creating CEL environment, calling Reload).
//
// Example usage with a real PolicyEngine:
//
//	celEnv, _ := cel.NewCELEnvironment()
//	engine := policy.NewPolicyEngine(sessions, celEnv)
//	templates, bindings, _ := bundle.ParsePolicyDir("./policies")
//	engine.Reload(ctx, &nixis.CompiledBundle{Templates: templates, Bindings: bindings})
//	evaluator := nixis.NewInProcessEvaluator(engine)
//	resp := evaluator.Check(ctx, req)
func NewInProcessEvaluator(engine evaluateEngine) *InProcessEvaluator {
	return &InProcessEvaluator{engine: engine}
}

// Check evaluates a tool call against the loaded policies.
// Returns a CheckResponse with the decision, latency, and enforcing layer.
// Safe for concurrent use from multiple goroutines.
func (e *InProcessEvaluator) Check(ctx context.Context, req CheckRequest) CheckResponse {
	return e.engine.Evaluate(ctx, req)
}
