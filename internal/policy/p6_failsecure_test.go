// SPDX-License-Identifier: MIT
package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/mayankjain0141/nixis/internal/classify"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/pkg/adapters"
	"github.com/mayankjain0141/nixis/pkg/nixis"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
)

// makeEngineWithDefaultAction builds a minimal engine with a single CEL policy
// that has the given expression, and sets DefaultAction on both the template and binding.
// It does not set classifer so the snap uses a catalogued Bash classifier.
func makeEngineWithDefaultAction(t *testing.T, templateID, expression, defaultAction string) *PolicyEngine {
	t.Helper()
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{Tool: "Bash", Operation: "exec", Family: "shell", RiskLevel: "medium", ResourceType: "process"},
	}
	classifier := classify.NewClassifier(catalog)

	templates := []policy_types.PolicyTemplate{
		{
			ID:            templateID,
			Name:          templateID,
			Expression:    expression,
			SourceFile:    "test.yaml",
			SourceLine:    1,
			DefaultAction: defaultAction,
		},
	}
	programs, _, err := cel.CompileAll(celEnv, templates)
	if err != nil {
		t.Fatalf("CompileAll: %v", err)
	}

	binding := policy_types.PolicyBinding{
		TemplateID:    templateID,
		DefaultAction: defaultAction,
	}
	bindings := []compiledBinding{{binding: binding}}
	allBindings := make([]*compiledBinding, len(bindings))
	for i := range bindings {
		allBindings[i] = &bindings[i]
	}

	snap := &engineSnapshot{
		public:     nixis.EngineSnapshot{Version: 1},
		classifier: classifier,
		programs:   programs,
		bindings:   bindings,
		bindingIdx: bindingIndex{all: allBindings},
	}
	engine.applySnapshot(snap)
	return engine
}

// runtimeErrorExpr is a CEL expression that passes type-checking but fails at runtime
// with a division-by-zero error. Used to simulate runtime evaluation errors in tests.
// confidentiality is always 0 for requests with no explicit SecurityLabel, making
// confidentiality / 0 deterministically fail without depending on external state.
const runtimeErrorExpr = `confidentiality / 0 > 0`

// TestEngine_P6_EvalError_AllowDefault_PolicySkipped verifies that when a policy has
// defaultAction="" (not DENY) and the CEL program returns a runtime error, the request
// continues (the policy is skipped, not fail-closed).
func TestEngine_P6_EvalError_AllowDefault_PolicySkipped(t *testing.T) {
	engine := makeEngineWithDefaultAction(t, "allow-default-policy", runtimeErrorExpr, "ALLOW")

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", SessionID: "s1"})

	// The erroring policy should be skipped. No other policy denies, so we expect Allow.
	// If the decision IS deny, it must not have come from our policy (PolicyID check).
	if resp.Decision.Action == nixis.ActionDeny && resp.Decision.PolicyID == "allow-default-policy" {
		t.Errorf("defaultAction=ALLOW: policy should be skipped on eval error, not denied; got %+v", resp.Decision)
	}
}

// TestEngine_P6_EvalError_DenyDefault_FailsSecure verifies that when a policy has
// defaultAction="DENY" and the CEL program returns a runtime error, the response is
// ActionDeny — fail-secure behaviour.
func TestEngine_P6_EvalError_DenyDefault_FailsSecure(t *testing.T) {
	engine := makeEngineWithDefaultAction(t, "deny-default-policy", runtimeErrorExpr, "DENY")

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", SessionID: "s1"})

	if resp.Decision.Action != nixis.ActionDeny {
		t.Errorf("defaultAction=DENY: expected ActionDeny on eval error, got %v", resp.Decision.Action)
	}
	if resp.EnforcingLayer != nixis.EnforcingLayerCEL {
		t.Errorf("expected EnforcingLayerCEL, got %v", resp.EnforcingLayer)
	}
}

// TestBundle_P6_CompileError_DenyDefault_RefusesLoad verifies that buildSnapshot refuses
// to activate a bundle when a policy with defaultAction="DENY" fails CEL compilation.
// This prevents a syntax-error injection attack from silently disabling a DENY policy.
func TestBundle_P6_CompileError_DenyDefault_RefusesLoad(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	// A policy with defaultAction=DENY that references an undeclared variable will be
	// skipped by CompileAll (type-check phase), and buildSnapshot must reject it.
	bundle := &nixis.CompiledBundle{
		Templates: []policy_types.PolicyTemplate{
			{
				ID:            "deny-with-bad-cel",
				Name:          "deny-with-bad-cel",
				Expression:    `__undeclared_variable__ == "foo"`,
				DefaultAction: "DENY",
			},
		},
		Bindings: []policy_types.PolicyBinding{
			{
				TemplateID:    "deny-with-bad-cel",
				DefaultAction: "DENY",
			},
		},
	}

	err = engine.Reload(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected Reload to return error for DENY policy with bad CEL, got nil")
	}
	if !strings.Contains(err.Error(), "cannot load") {
		t.Errorf("error should contain 'cannot load', got: %v", err)
	}
}
