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

// BenchmarkEvaluate_CachedProgram measures evaluation latency with cached CEL programs.
// Gate: <10μs P99 per ENGINEERING_STANDARDS §3.2.
func BenchmarkEvaluate_CachedProgram(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "ReadTool",
			Operation:    "read",
			Family:       "test",
			RiskLevel:    "low",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	templates := []policy_types.PolicyTemplate{
		{
			ID:         "allow-read",
			Name:       "Allow Read",
			Expression: `tool == "ReadTool"`,
		},
	}

	programs, _, err := cel.CompileAll(celEnv, templates)
	if err != nil {
		b.Fatalf("failed to compile policies: %v", err)
	}

	bindings := []compiledBinding{
		{
			binding: policy_types.PolicyBinding{
				TemplateID: "allow-read",
				Priority:   1,
			},
		},
	}

	allBindings := make([]*compiledBinding, len(bindings))
	for i := range bindings {
		allBindings[i] = &bindings[i]
	}

	snap := &engineSnapshot{
		public: nixis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   programs,
		bindings:   bindings,
		bindingIdx: bindingIndex{
			all: allBindings,
		},
	}
	engine.applySnapshot(snap)

	req := nixis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: "bench-session",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ctx, req)
	}
}

// BenchmarkEvaluate_DefaultDeny measures evaluation latency when no policies match.
// Gate: <5μs per ENGINEERING_STANDARDS §3.2.
func BenchmarkEvaluate_DefaultDeny(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "UnknownTool",
			Operation:    "exec",
			Family:       "test",
			RiskLevel:    "critical",
			ResourceType: "process",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: nixis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := nixis.CheckRequest{
		Tool:      "UnknownTool",
		SessionID: "bench-session",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ctx, req)
	}
}

// BenchmarkEvaluate_IFCCheck measures IFC dominance check latency.
func BenchmarkEvaluate_IFCCheck(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "ReadTool",
			Operation:    "read",
			Family:       "test",
			RiskLevel:    "low",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: nixis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	sessionID := "bench-session"
	sessions.Elevate(sessionID, nixis.SecurityLabel{
		Confidentiality: 50000,
		Integrity:       50000,
	})

	req := nixis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: sessionID,
		SecurityLabel: nixis.SecurityLabel{
			Confidentiality: 1000,
			Integrity:       1000,
		},
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ctx, req)
	}
}

// BenchmarkEvaluate_NilSnapshot measures fail-secure path latency.
func BenchmarkEvaluate_NilSnapshot(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	req := nixis.CheckRequest{
		Tool:      "TestTool",
		SessionID: "bench-session",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ctx, req)
	}
}

// BenchmarkReload measures reload latency (not on hot path, but should be <500ms).
func BenchmarkReload(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	bundle := &nixis.CompiledBundle{
		Version: 1,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Reload(ctx, bundle)
	}
}
