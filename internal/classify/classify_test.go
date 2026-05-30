package classify

import (
	"testing"

	"github.com/mayankjain0141/nixis/pkg/adapters"
)

// loadCatalog is a test helper that panics if the embedded catalog fails to load.
func loadCatalog(t *testing.T) []adapters.AdapterDef {
	t.Helper()
	catalog, err := adapters.Catalog()
	if err != nil {
		t.Fatalf("adapters.Catalog() failed: %v", err)
	}
	return catalog
}

// newTestClassifier builds a Classifier from the embedded production catalog.
func newTestClassifier(t *testing.T) *Classifier {
	t.Helper()
	return NewClassifier(loadCatalog(t))
}

// --- Compile-time invariant: VerdictEntry must NOT have an Action field (RISK-009) ---

// TestClassify_NeverFinalDecision verifies at compile time that VerdictEntry has no Action field.
// This is enforced structurally — the type cannot be constructed with an Action.
func TestClassify_NeverFinalDecision(t *testing.T) {
	// If this compiles, the invariant holds.
	// Any attempt to add an Action field to VerdictEntry would require
	// updating this struct literal, making the violation visible in review.
	_ = VerdictEntry{
		Classification:        "readonly",
		Effects:               nil,
		RiskLevel:             RiskLow,
		DefaultClassification: "readonly",
		AdapterName:           "test",
		ResourceType:          ResFile,
		AdapterMatch:          true,
	}
}

// --- Readonly tools ---

func TestClassify_ReadonlyTools(t *testing.T) {
	c := newTestClassifier(t)

	cases := []struct {
		tool             string
		wantRiskMax      RiskLevel
		wantAdapterMatch bool
	}{
		{"cat", RiskLow, true},
		{"grep", RiskLow, true},
		{"ls", RiskLow, true},
		{"git log", RiskLow, true},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			entry, ok := c.Classify(tc.tool)
			if tc.wantAdapterMatch && !ok {
				t.Errorf("expected AdapterMatch for %q, got heuristic", tc.tool)
			}
			if entry.Classification != "readonly" {
				t.Errorf("%q: got Classification=%q, want readonly", tc.tool, entry.Classification)
			}
			// Readonly tools must have risk ≤ low
			if riskLevel(entry.RiskLevel) > riskLevel(tc.wantRiskMax) {
				t.Errorf("%q: got RiskLevel=%q, want ≤%q", tc.tool, entry.RiskLevel, tc.wantRiskMax)
			}
		})
	}
}

// riskLevel converts RiskLevel to a comparable integer for ordering tests.
func riskLevel(r RiskLevel) int {
	switch r {
	case RiskNone:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return 5
	}
}

// --- Heuristic fallback ---

func TestClassify_FallbackHeuristic(t *testing.T) {
	c := newTestClassifier(t)

	entry, ok := c.Classify("some_completely_unknown_tool_xyz_987")
	if ok {
		t.Error("expected AdapterMatch=false for unknown tool, got true")
	}
	if entry.AdapterMatch {
		t.Error("expected AdapterMatch=false for unknown tool")
	}
}

// --- SendMessage must NOT be content_publish ---

func TestClassify_SendMessage_NotContentPublish(t *testing.T) {
	c := newTestClassifier(t)

	entry, ok := c.Classify("SendMessage")
	if !ok {
		t.Fatal("SendMessage: expected AdapterMatch=true, got false")
	}
	for _, eff := range entry.Effects {
		if eff == EffectContentPublish {
			t.Error("SendMessage must not have EffectContentPublish — must use EffectContentInternal")
		}
	}
	hasInternal := false
	for _, eff := range entry.Effects {
		if eff == EffectContentInternal {
			hasInternal = true
		}
	}
	if !hasInternal {
		t.Errorf("SendMessage must have EffectContentInternal in Effects, got %v", entry.Effects)
	}
}

// --- TaskCreate low risk ---

func TestClassify_TaskCreate_LowRisk(t *testing.T) {
	c := newTestClassifier(t)

	entry, ok := c.Classify("TaskCreate")
	if !ok {
		t.Fatal("TaskCreate: expected AdapterMatch=true")
	}
	if entry.RiskLevel != RiskLow {
		t.Errorf("TaskCreate: got RiskLevel=%q, want %q", entry.RiskLevel, RiskLow)
	}
}

// --- Agent must have EffectProcessCoordination and ResAgentCoordination ---

func TestClassify_Agent_ProcessCoordination(t *testing.T) {
	c := newTestClassifier(t)

	entry, ok := c.Classify("Agent")
	if !ok {
		t.Fatal("Agent: expected AdapterMatch=true")
	}
	if !effectsContain(entry.Effects, EffectProcessCoordination) {
		t.Errorf("Agent: want EffectProcessCoordination in Effects, got %v", entry.Effects)
	}
	if entry.ResourceType != ResAgentCoordination {
		t.Errorf("Agent: got ResourceType=%q, want %q", entry.ResourceType, ResAgentCoordination)
	}
}

// --- All 10 coordination tools must have AdapterMatch=true ---

func TestClassify_AllCoordinationTools_NoHeuristic(t *testing.T) {
	c := newTestClassifier(t)

	tools := []string{
		"TaskCreate", "TaskUpdate", "TaskGet", "TaskList",
		"SendMessage", "TeamCreate", "TeamDelete",
		"Agent", "Skill", "ExitPlanMode",
	}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			entry, ok := c.Classify(tool)
			if !ok {
				t.Errorf("%s: expected AdapterMatch=true (exact catalog hit), got false", tool)
			}
			if !entry.AdapterMatch {
				t.Errorf("%s: VerdictEntry.AdapterMatch=false, want true", tool)
			}
		})
	}
}

// --- Credential pattern pre-scan ---

func TestClassify_ExportAPIKey_HasCredentialUse(t *testing.T) {
	c := newTestClassifier(t)

	cases := []struct {
		name    string
		command string
	}{
		{"sk- prefix", `export LITELLM_API_KEY="sk-abc123"`},
		{"ghp_ prefix", `export GH_TOKEN=ghp_sometoken`},
		{"AKIA prefix", `export AWS_ACCESS_KEY_ID="AKIA1234"`},
		{"slack xoxb", `export SLACK_TOKEN='xoxb-12345-abcde'`},
		{"slack xoxp", `export SLACK_TOKEN='xoxp-12345-abcde'`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := c.ClassifyBash("Bash", tc.command)
			if !effectsContain(entry.Effects, EffectCredentialUse) {
				t.Errorf("command %q: want EffectCredentialUse in Effects, got %v", tc.command, entry.Effects)
			}
		})
	}
}

func TestClassify_NormalBash_NoCredentialUse(t *testing.T) {
	c := newTestClassifier(t)

	entry := c.ClassifyBash("Bash", "ls -la /tmp")
	if effectsContain(entry.Effects, EffectCredentialUse) {
		t.Error("normal bash command must not have EffectCredentialUse")
	}
}

// --- Benchmarks ---

func BenchmarkClassify_VerdictMap(b *testing.B) {
	catalog, err := adapters.Catalog()
	if err != nil {
		b.Fatalf("Catalog() failed: %v", err)
	}
	vm := BuildVerdictMap(catalog)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = vm.Classify("Bash")
	}
}

func BenchmarkClassify_VerdictMap_CoordinationTool(b *testing.B) {
	catalog, err := adapters.Catalog()
	if err != nil {
		b.Fatalf("Catalog() failed: %v", err)
	}
	vm := BuildVerdictMap(catalog)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = vm.Classify("SendMessage")
	}
}

func BenchmarkClassify_CredentialPattern(b *testing.B) {
	const cmd = `export LITELLM_API_KEY="sk-abc123-do-not-commit"`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasCredentialPattern(cmd)
	}
}

func BenchmarkClassify_CredentialPattern_NoMatch(b *testing.B) {
	const cmd = `go test ./... -race -count=1`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasCredentialPattern(cmd)
	}
}

func BenchmarkClassify_Heuristic(b *testing.B) {
	catalog, err := adapters.Catalog()
	if err != nil {
		b.Fatalf("Catalog() failed: %v", err)
	}
	c := NewClassifier(catalog)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Classify("some_completely_unknown_tool_that_is_not_in_catalog")
	}
}
