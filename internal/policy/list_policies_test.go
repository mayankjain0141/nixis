package policy

import (
	"testing"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

func TestListPoliciesNilSnapshot(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)
	// snapshot is nil — ListPolicies must return nil, not panic.
	result := engine.ListPolicies()
	if result != nil {
		t.Errorf("expected nil from nil snapshot, got %v", result)
	}
}

func TestListPoliciesWithTemplates(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	// Inject a snapshot with two templates and one binding.
	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{Version: 1},
		templates: []policy_types.PolicyTemplate{
			{ID: "t1", Name: "Template One", Expression: "true", Description: "first"},
			{ID: "t2", Name: "Template Two", Expression: "false", Description: "second"},
		},
		bindings: []compiledBinding{
			{binding: policy_types.PolicyBinding{TemplateID: "t1", Layer: "ifc"}},
		},
		programs:   &cel.ProgramCache{},
		bindingIdx: buildBindingIndex(nil),
	}
	engine.snapshot.Store(snap)

	result := engine.ListPolicies()
	if len(result) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(result))
	}

	// t1 should pick up layer from binding.
	p1 := result[0]
	if p1.ID != "t1" {
		t.Errorf("expected ID t1, got %q", p1.ID)
	}
	if p1.Name != "Template One" {
		t.Errorf("expected Name 'Template One', got %q", p1.Name)
	}
	if p1.Layer != "ifc" {
		t.Errorf("expected Layer ifc (from binding), got %q", p1.Layer)
	}
	if p1.CelExpression != "true" {
		t.Errorf("expected CelExpression 'true', got %q", p1.CelExpression)
	}
	if p1.Description != "first" {
		t.Errorf("expected Description 'first', got %q", p1.Description)
	}
	if !p1.Enabled {
		t.Error("expected Enabled true")
	}

	// t2 has no binding — layer defaults to "cel".
	p2 := result[1]
	if p2.ID != "t2" {
		t.Errorf("expected ID t2, got %q", p2.ID)
	}
	if p2.Layer != "cel" {
		t.Errorf("expected Layer cel (default), got %q", p2.Layer)
	}
}

func TestListPoliciesEmptyTemplates(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	snap := &engineSnapshot{
		public:     aegis.EngineSnapshot{Version: 1},
		templates:  []policy_types.PolicyTemplate{},
		bindings:   []compiledBinding{},
		programs:   &cel.ProgramCache{},
		bindingIdx: buildBindingIndex(nil),
	}
	engine.snapshot.Store(snap)

	result := engine.ListPolicies()
	if result == nil {
		t.Error("expected empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected 0 policies, got %d", len(result))
	}
}
