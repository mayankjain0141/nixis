package cel_test

import (
	"encoding/json"
	"testing"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	aegis "github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// BenchmarkCEL_Evaluate_CachedProgram benchmarks the hot-path evaluation.
// Target: <10μs, minimal allocs.
func BenchmarkCEL_Evaluate_CachedProgram(b *testing.B) {
	env, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("NewCELEnvironment: %v", err)
	}

	templates := []policy_types.PolicyTemplate{
		{ID: "bench-allow", Expression: `tool == "Read" && risk_level == "low"`},
	}
	cache, err := cel.CompileAll(env, templates)
	if err != nil {
		b.Fatalf("CompileAll: %v", err)
	}
	prog, ok := cache.Get("bench-allow")
	if !ok {
		b.Fatal("program not found")
	}

	args, _ := json.Marshal(map[string]any{"file_path": "/tmp/bench.txt"})
	req := aegis.CheckRequest{
		Tool:      "Read",
		Args:      aegis.CheckRequest{}.Args,
		SessionID: "bench-session",
	}
	req.Args = args
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskLow, Effects: []string{"read_files"}}

	builder := cel.NewActivationBuilder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = builder.Evaluate(prog, req, verdict)
	}
}
