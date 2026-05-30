// SPDX-License-Identifier: MIT
package policy

import (
	"context"
	"testing"

	"github.com/mayjain/nixis/internal/cel"
	"github.com/mayjain/nixis/internal/classify"
	"github.com/mayjain/nixis/internal/ifc"
	"github.com/mayjain/nixis/pkg/adapters"
	"github.com/mayjain/nixis/pkg/nixis"
	policy_types "github.com/mayjain/nixis/pkg/policy/types"
)

func makeEngineWithCELBinding(t *testing.T, templateID, expression string, binding policy_types.PolicyBinding) *PolicyEngine {
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
		{ID: templateID, Name: templateID, Expression: expression, SourceFile: "test.yaml", SourceLine: 1},
	}
	programs, _, err := cel.CompileAll(celEnv, templates)
	if err != nil {
		t.Fatalf("CompileAll: %v", err)
	}

	binding.TemplateID = templateID
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

func TestEngine_RequireApprovalPolicy_ReturnsActionRequireApproval(t *testing.T) {
	engine := makeEngineWithCELBinding(t, "ra-policy", `tool != "Bash"`, policy_types.PolicyBinding{
		RequireApproval: true,
		Message:         "requires approval",
	})

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", Args: []byte(`{"command":"ls"}`), SessionID: "s1"})

	if resp.Decision.Action != nixis.ActionRequireApproval {
		t.Errorf("Action = %v, want ActionRequireApproval", resp.Decision.Action)
	}
	if resp.EnforcingLayer != nixis.EnforcingLayerCEL {
		t.Errorf("EnforcingLayer = %v, want EnforcingLayerCEL", resp.EnforcingLayer)
	}
}

func TestEngine_DenyPolicy_StillReturnsDeny(t *testing.T) {
	engine := makeEngineWithCELBinding(t, "deny-policy", `tool != "Bash"`, policy_types.PolicyBinding{
		RequireApproval: false,
	})

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", Args: []byte(`{"command":"ls"}`), SessionID: "s1"})

	if resp.Decision.Action != nixis.ActionDeny {
		t.Errorf("Action = %v, want ActionDeny", resp.Decision.Action)
	}
}

func TestEngine_PolicyMessage_UsedAsReason(t *testing.T) {
	engine := makeEngineWithCELBinding(t, "msg-policy", `tool != "Bash"`, policy_types.PolicyBinding{
		RequireApproval: false,
		Message:         "human readable message",
	})

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", Args: []byte(`{"command":"ls"}`), SessionID: "s1"})

	if resp.Decision.Reason != "human readable message" {
		t.Errorf("Reason = %q, want %q", resp.Decision.Reason, "human readable message")
	}
}

func TestEngine_PolicyNoMessage_FallbackReason(t *testing.T) {
	engine := makeEngineWithCELBinding(t, "no-msg-policy", `tool != "Bash"`, policy_types.PolicyBinding{
		RequireApproval: false,
		Message:         "",
	})

	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{Tool: "Bash", Args: []byte(`{"command":"ls"}`), SessionID: "s1"})

	if resp.Decision.Reason != "CEL policy evaluation returned false" {
		t.Errorf("Reason = %q, want fallback string", resp.Decision.Reason)
	}
}
