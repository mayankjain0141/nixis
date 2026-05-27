package cel_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	aegis "github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// BenchmarkCEL_EvalSimple benchmarks a simple single-comparison expression.
// Spec target: <3μs, 0 allocs (INV-007, ENGINEERING_STANDARDS §3.4).
//
// decodedArgs is pre-decoded outside the loop to simulate the WS-05 pattern:
// json.RawMessage is decoded once per CheckRequest, before the per-program
// evaluation loop. Decoding inside the loop would allocate and violate INV-007.
func BenchmarkCEL_EvalSimple(b *testing.B) {
	env, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("NewCELEnvironment: %v", err)
	}

	templates := []policy_types.PolicyTemplate{
		{ID: "simple", Expression: `tool == "Read"`},
	}
	cache, err := cel.CompileAll(env, templates)
	if err != nil {
		b.Fatalf("CompileAll: %v", err)
	}
	prog, ok := cache.Get("simple")
	if !ok {
		b.Fatal("program not found")
	}

	req := aegis.CheckRequest{
		Tool:      "Read",
		SessionID: "bench-session",
	}
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskLow}
	// decodedArgs pre-decoded once, outside the benchmark loop.
	decodedArgs := map[string]any{"file_path": "/tmp/bench.txt"}

	builder := cel.NewActivationBuilder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = builder.Evaluate(prog, req, verdict, decodedArgs)
	}
}

// BenchmarkCEL_EvalComplex benchmarks a more complex expression with multiple
// conjunctions, CEL built-in string methods, and list membership.
// Spec target: <8μs, 0 allocs.
func BenchmarkCEL_EvalComplex(b *testing.B) {
	env, err := cel.NewCELEnvironment()
	if err != nil {
		b.Fatalf("NewCELEnvironment: %v", err)
	}

	templates := []policy_types.PolicyTemplate{
		{
			ID: "complex",
			Expression: `tool == "Bash" && risk_level != "critical" &&
				!("credential_use" in effects) &&
				confidentiality < 5 &&
				bash.targetPort(args.command) == 0`,
		},
	}
	cache, err := cel.CompileAll(env, templates)
	if err != nil {
		b.Fatalf("CompileAll: %v", err)
	}
	prog, ok := cache.Get("complex")
	if !ok {
		b.Fatal("program not found")
	}

	req := aegis.CheckRequest{
		Tool:          "Bash",
		SessionID:     "bench-session",
		SecurityLabel: aegis.SecurityLabel{Confidentiality: 2, Integrity: 3},
	}
	verdict := classify.VerdictEntry{
		RiskLevel: classify.RiskMedium,
		Effects:   []string{"exec_process"},
	}
	decodedArgs := map[string]any{"command": "go build ./..."}

	builder := cel.NewActivationBuilder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = builder.Evaluate(prog, req, verdict, decodedArgs)
	}
}
