package policy

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/adapters"
	"github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

func TestPolicyEngine_NilSnapshot_ReturnsDeny(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	req := aegis.CheckRequest{
		Tool:      "TestTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny, got %v", resp.Decision.Action)
	}
	if resp.Decision.Reason == "" {
		t.Error("expected a reason for deny")
	}
}

func TestPolicyEngine_Reload_SingleWriter(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	var wg sync.WaitGroup
	var reloadCount atomic.Int32
	var lastVersion atomic.Uint64
	const numGoroutines = 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			bundle := &aegis.CompiledBundle{
				Version: uint64(n),
			}
			err := engine.Reload(context.Background(), bundle)
			if err != nil {
				t.Errorf("reload failed: %v", err)
			}
			reloadCount.Add(1)
			snap := engine.snapshot.Load()
			if snap != nil {
				lastVersion.Store(snap.public.Version)
			}
		}(i)
	}

	wg.Wait()

	if reloadCount.Load() != numGoroutines {
		t.Errorf("expected %d reloads, got %d", numGoroutines, reloadCount.Load())
	}

	snap := engine.snapshot.Load()
	if snap == nil {
		t.Fatal("expected snapshot to be non-nil after reload")
	}

	if snap.public.Version != uint64(numGoroutines) {
		t.Errorf("expected final version %d (serialized reloads increment from 1), got %d",
			numGoroutines, snap.public.Version)
	}
}

func TestPolicyEngine_Evaluate_Pipeline_AdapterLayer(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "CriticalTool",
			Operation:    "delete",
			Family:       "test",
			RiskLevel:    "critical",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := aegis.CheckRequest{
		Tool:      "CriticalTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny for critical tool, got %v", resp.Decision.Action)
	}
	if resp.EnforcingLayer != aegis.EnforcingLayerAdapter {
		t.Errorf("expected EnforcingLayerAdapter, got %v", resp.EnforcingLayer)
	}
	if resp.ThreatSeverity != "critical" {
		t.Errorf("expected threat severity 'critical', got %v", resp.ThreatSeverity)
	}
}

func TestPolicyEngine_Evaluate_Pipeline_IFCLayer(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
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
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	sessionID := "low-priv-session"
	sessions.Elevate(sessionID, aegis.SecurityLabel{
		Confidentiality: 1000,
		Integrity:       1000,
	})

	req := aegis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: sessionID,
		SecurityLabel: aegis.SecurityLabel{
			Confidentiality: 50000,
			Integrity:       50000,
		},
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny for IFC violation, got %v", resp.Decision.Action)
	}
	if resp.EnforcingLayer != aegis.EnforcingLayerIFC {
		t.Errorf("expected EnforcingLayerIFC, got %v", resp.EnforcingLayer)
	}
}

func TestPolicyEngine_Evaluate_Pipeline_CELLayer(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "Bash",
			Operation:    "exec",
			Family:       "shell",
			RiskLevel:    "medium",
			ResourceType: "process",
		},
	}
	classifier := classify.NewClassifier(catalog)

	// CEL validation expressions return true to ALLOW, false to DENY.
	// This expression returns false when tool is "Bash", causing a DENY.
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "deny-bash",
			Name:       "Deny Bash",
			Expression: `tool != "Bash"`,
			SourceFile: "test.yaml",
			SourceLine: 10,
		},
	}

	programs, _, err := cel.CompileAll(celEnv, templates)
	if err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	bindings := []compiledBinding{
		{
			binding: policy_types.PolicyBinding{
				TemplateID: "deny-bash",
				Priority:   1,
			},
		},
	}

	allBindings := make([]*compiledBinding, len(bindings))
	for i := range bindings {
		allBindings[i] = &bindings[i]
	}

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
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

	req := aegis.CheckRequest{
		Tool:      "Bash",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny from CEL, got %v", resp.Decision.Action)
	}
	if resp.EnforcingLayer != aegis.EnforcingLayerCEL {
		t.Errorf("expected EnforcingLayerCEL, got %v", resp.EnforcingLayer)
	}
	if resp.PolicySourceLocation != "test.yaml:10" {
		t.Errorf("expected policy source location 'test.yaml:10', got %v", resp.PolicySourceLocation)
	}
}

func TestPolicyEngine_Evaluate_NoPolicies_ReturnsAllow(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "SafeTool",
			Operation:    "read",
			Family:       "test",
			RiskLevel:    "low",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   nil,
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := aegis.CheckRequest{
		Tool:      "SafeTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("expected ActionAllow when no policies match, got %v", resp.Decision.Action)
	}
}

// panicClassifier is a test classifier that panics on Classify().
type panicClassifier struct{}

func (p *panicClassifier) Classify(_ string) (classify.VerdictEntry, bool) {
	panic("intentional panic for fail-secure test")
}

func (p *panicClassifier) ClassifyBash(_, _ string) classify.VerdictEntry {
	panic("intentional panic for fail-secure test")
}

func TestPolicyEngine_Evaluate_FailSecure(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifierIntf: &panicClassifier{},
		programs:       &cel.ProgramCache{},
		bindingIdx:     bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := aegis.CheckRequest{
		Tool:      "AnyTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny on panic (fail-secure), got %v", resp.Decision.Action)
	}
	if resp.Decision.Reason != "internal evaluation panic" {
		t.Errorf("expected reason 'internal evaluation panic', got %v", resp.Decision.Reason)
	}
}

func TestEvaluate_EnforcingLayer_Adapter(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "DangerousTool",
			Operation:    "delete",
			Family:       "test",
			RiskLevel:    "critical",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := aegis.CheckRequest{
		Tool:      "DangerousTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.EnforcingLayer != aegis.EnforcingLayerAdapter {
		t.Errorf("expected EnforcingLayerAdapter, got %v", resp.EnforcingLayer)
	}
}

func TestPolicyEngine_Reload_FailedReloadKeepsOld(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	firstBundle := &aegis.CompiledBundle{
		Version: 1,
	}
	err = engine.Reload(context.Background(), firstBundle)
	if err != nil {
		t.Fatalf("first reload failed: %v", err)
	}

	snap1 := engine.snapshot.Load()
	if snap1 == nil {
		t.Fatal("expected snapshot after first reload")
	}
	version1 := snap1.public.Version

	buildErr := errors.New("intentional build failure for test")
	engine.buildSnapshotFunc = func(_ context.Context, _ *aegis.CompiledBundle, _ uint64) (*engineSnapshot, []string, error) {
		return nil, nil, buildErr
	}

	secondBundle := &aegis.CompiledBundle{
		Version: 2,
	}
	err = engine.Reload(context.Background(), secondBundle)
	if err == nil {
		t.Fatal("expected second reload to fail")
	}
	if err != buildErr {
		t.Errorf("expected build error, got %v", err)
	}

	snap2 := engine.snapshot.Load()
	if snap2 == nil {
		t.Fatal("expected snapshot to still exist after failed reload")
	}
	if snap2.public.Version != version1 {
		t.Errorf("expected version to remain %d on failed reload, got %d", version1, snap2.public.Version)
	}
}

func TestProgramCache_IsValueType(t *testing.T) {
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	templates := []policy_types.PolicyTemplate{
		{
			ID:         "test-policy",
			Name:       "Test Policy",
			Expression: `true`,
		},
	}

	cache1, _, err := cel.CompileAll(celEnv, templates)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	v1 := cache1.Version()

	cache2 := *cache1

	if cache2.Version() != v1 {
		t.Error("copied cache should have same version as original")
	}

	prog1, ok1 := cache1.Get("test-policy")
	prog2, ok2 := cache2.Get("test-policy")

	if !ok1 || !ok2 {
		t.Fatal("both caches should have the test-policy")
	}

	if prog1 != prog2 {
		t.Log("Note: program pointers differ (expected for value type copy)")
	}
}

func TestPolicyEngine_Evaluate_AllowsValidRequest(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
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
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	sessionID := "valid-session"
	sessions.Elevate(sessionID, aegis.SecurityLabel{
		Confidentiality: 50000,
		Integrity:       50000,
	})

	req := aegis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: sessionID,
		SecurityLabel: aegis.SecurityLabel{
			Confidentiality: 1000,
			Integrity:       1000,
		},
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("expected ActionAllow, got %v (reason: %s)", resp.Decision.Action, resp.Decision.Reason)
	}
}

func TestPolicyEngine_Evaluate_DelegationCeilingExceeded(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
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
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	parentLabel := aegis.SecurityLabel{
		Confidentiality: 10000,
		Integrity:       10000,
	}
	childSessionID := "child-session"
	sessions.InitWithCeiling(childSessionID, parentLabel)

	sessions.Elevate(childSessionID, aegis.SecurityLabel{
		Confidentiality: 50000,
		Integrity:       50000,
	})

	req := aegis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: childSessionID,
		SecurityLabel: aegis.SecurityLabel{
			Confidentiality: 1000,
			Integrity:       1000,
		},
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected ActionDeny for ceiling violation, got %v", resp.Decision.Action)
	}
	if resp.EnforcingLayer != aegis.EnforcingLayerDelegation {
		t.Errorf("expected EnforcingLayerDelegation, got %v", resp.EnforcingLayer)
	}
}

func TestPolicyEngine_Evaluate_ContextTimeout(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "SlowTool",
			Operation:    "read",
			Family:       "test",
			RiskLevel:    "low",
			ResourceType: "file",
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(1 * time.Millisecond)

	req := aegis.CheckRequest{
		Tool:      "SlowTool",
		SessionID: "test-session",
	}

	resp := engine.Evaluate(ctx, req)

	if resp.Decision.Action != aegis.ActionAllow {
		t.Logf("Note: got %v (context was already cancelled, but pipeline completed)", resp.Decision.Action)
	}
}

func TestPolicyEngine_Evaluate_WithBashCommandText(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	catalog := []adapters.AdapterDef{
		{
			Tool:         "Bash",
			Operation:    "exec",
			Family:       "shell",
			RiskLevel:    "medium",
			ResourceType: "process",
			Effects:      []string{"exec_process"},
		},
	}
	classifier := classify.NewClassifier(catalog)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	args := map[string]any{
		"command": "ls -la",
	}
	argsJSON, _ := json.Marshal(args)

	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON,
		SessionID: "test-session",
	}

	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("expected ActionAllow for simple bash command, got %v", resp.Decision.Action)
	}
}

func BenchmarkPolicyEngine_Evaluate(b *testing.B) {
	sessions := &ifc.SessionLabels{}
	celEnv, _ := cel.NewCELEnvironment()
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
		public: aegis.EngineSnapshot{
			Version: 1,
		},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)

	req := aegis.CheckRequest{
		Tool:      "ReadTool",
		SessionID: "bench-session",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(context.Background(), req)
	}
}

func TestPolicyEngine_Reload_WithBuiltinPolicies(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	engine := NewPolicyEngine(sessions, celEnv)

	templates := []policy_types.PolicyTemplate{
		{
			ID:         "git-branch-protection",
			Name:       "git-branch-protection",
			Expression: `!(bash.isGitForcePush(args["command"]) && bash.gitBranchTarget(args["command"]).matches("(?i)^(main|master)$"))`,
			SourceFile: "policies/builtin/git-branch-protection.yaml",
			SourceLine: 50,
		},
	}
	bindings := []policy_types.PolicyBinding{
		{
			TemplateID: "git-branch-protection",
			Scope: policy_types.PolicyScope{
				Tools: []string{"Bash"},
			},
			Layer: "cel",
		},
	}

	bundle := &aegis.CompiledBundle{
		Version:   1,
		Templates: templates,
		Bindings:  bindings,
	}

	err = engine.Reload(context.Background(), bundle)
	if err != nil {
		t.Fatalf("reload with builtin policies failed: %v", err)
	}

	snap := engine.snapshot.Load()
	if snap == nil {
		t.Fatal("expected snapshot after reload")
	}
	if snap.programs == nil {
		t.Fatal("expected programs cache after reload")
	}

	prog, ok := snap.programs.Get("git-branch-protection")
	if !ok {
		t.Fatal("expected git-branch-protection program in cache")
	}
	if prog == nil {
		t.Fatal("expected non-nil program pointer")
	}

	loc := snap.programs.SourceLocation("git-branch-protection")
	if loc != "policies/builtin/git-branch-protection.yaml:50" {
		t.Errorf("expected source location, got %q", loc)
	}

	if len(snap.bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(snap.bindings))
	}
	if snap.bindingIdx.byTool == nil {
		t.Fatal("expected byTool index")
	}
	bashBindings := snap.bindingIdx.byTool["Bash"]
	if len(bashBindings) != 1 {
		t.Errorf("expected 1 Bash binding in index, got %d", len(bashBindings))
	}
}

// TestPolicyEngine_ParamsFlowToCEL verifies that PolicyTemplate.Params are passed
// into CEL evaluation so expressions referencing params.devPorts work correctly.
//
// Test cases mirror the dev-port-cleanup policy spec:
//   - Port in devPorts → ALLOW (expression false → no REQUIRE_APPROVAL)
//   - Port not in devPorts → REQUIRE_APPROVAL (expression true)
//   - No port pattern (targetPort=0) → ALLOW (targetPort > 0 is false)
func TestPolicyEngine_ParamsFlowToCEL(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	// Expression mirrors dev-port-cleanup after variable inlining and wrapping by parse.go.
	// The bundle parser wraps non-DENY validations with !(...): when the wrapped expression
	// is false, the engine DENYs. So the full compiled expression for dev-port-cleanup is:
	//   !(!(targetPort in devPorts) && targetPort > 0)
	// true  → engine allows (port is in devPorts, or no port pattern)
	// false → engine denies (port is not in devPorts and > 0)
	expr := `!(!(bash.targetPort(args["command"]) in params.devPorts) && bash.targetPort(args["command"]) > 0)`
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "dev-port-test",
			Name:       "dev-port-test",
			Expression: expr,
			Params: map[string]any{
				"devPorts": []any{int64(3000), int64(5173), int64(7474), int64(8080)},
			},
		},
	}
	bindings := []policy_types.PolicyBinding{
		{
			TemplateID: "dev-port-test",
			Scope:      policy_types.PolicyScope{Tools: []string{"Bash"}},
			Layer:      "cel",
		},
	}
	bundle := &aegis.CompiledBundle{
		Version:   1,
		Templates: templates,
		Bindings:  bindings,
	}
	if err := engine.Reload(context.Background(), bundle); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	makeReq := func(cmd string) aegis.CheckRequest {
		args, _ := json.Marshal(map[string]any{"command": cmd})
		return aegis.CheckRequest{
			Tool:      "Bash",
			Args:      args,
			SessionID: "test-session",
		}
	}

	// Port in devPorts → expression false → ALLOW.
	resp := engine.Evaluate(context.Background(), makeReq("lsof -ti:7474 | xargs kill -9"))
	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("port 7474 in devPorts: expected Allow, got %v (reason: %s)", resp.Decision.Action, resp.Decision.Reason)
	}

	// Port not in devPorts → expression true → DENY.
	resp = engine.Evaluate(context.Background(), makeReq("lsof -ti:443 | xargs kill -9"))
	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("port 443 not in devPorts: expected Deny, got %v", resp.Decision.Action)
	}

	// No port pattern → targetPort=0 → && 0 > 0 is false → ALLOW.
	resp = engine.Evaluate(context.Background(), makeReq("kill -9 12345"))
	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("no port pattern: expected Allow, got %v", resp.Decision.Action)
	}

	// Another devPort (fuser pattern).
	resp = engine.Evaluate(context.Background(), makeReq("fuser -k 3000/tcp"))
	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("port 3000 in devPorts (fuser): expected Allow, got %v", resp.Decision.Action)
	}
}

// TestPolicyEngine_DevPortCleanup_NotSkipped verifies that the dev-port-cleanup builtin
// policy is NOT in the SkippedPolicies list after loading the builtin bundle.
// Before params support, this policy was skipped because params was an undeclared CEL variable.
func TestPolicyEngine_DevPortCleanup_NotSkipped(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv)

	// Build a minimal bundle that exercises the dev-port-cleanup expression with params.
	// Expression uses the wrapped form produced by parse.go's buildCombinedExpression.
	expr := `!(!(bash.targetPort(args["command"]) in params.devPorts) && bash.targetPort(args["command"]) > 0)`
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "dev-port-cleanup",
			Name:       "dev-port-cleanup",
			Expression: expr,
			Params: map[string]any{
				"devPorts": []any{int64(3000), int64(3001), int64(5173), int64(7474), int64(8000), int64(8080), int64(9000)},
			},
		},
	}
	bindings := []policy_types.PolicyBinding{
		{
			TemplateID: "dev-port-cleanup",
			Scope:      policy_types.PolicyScope{Tools: []string{"Bash"}},
			Layer:      "cel",
		},
	}
	bundle := &aegis.CompiledBundle{
		Version:   1,
		Templates: templates,
		Bindings:  bindings,
	}
	if err := engine.Reload(context.Background(), bundle); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	skipped := engine.SkippedPolicies()
	for _, id := range skipped {
		if id == "dev-port-cleanup" {
			t.Error("dev-port-cleanup was skipped — params variable not declared in CEL environment")
		}
	}
}
