package cel_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/label"
	aegis "github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// helpers

func mustNewEnv(t *testing.T) *cel.CELEnvironment {
	t.Helper()
	env, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	return env
}

func mustCompile(t *testing.T, env *cel.CELEnvironment, templates []policy_types.PolicyTemplate) *cel.ProgramCache {
	t.Helper()
	cache, _, err := cel.CompileAll(env, templates)
	if err != nil {
		t.Fatalf("CompileAll: %v", err)
	}
	return cache
}

func argsJSON(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal args: %v", err)
	}
	return b
}

// decodeArgs decodes json.RawMessage into map[string]any.
// In production code (WS-05 policy engine) this decode happens once per CheckRequest,
// before the CEL evaluation loop, so it is not on the alloc-critical per-program path.
// In tests we replicate that pattern: decode first, then pass the decoded map.
func decodeArgs(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decodeArgs: %v", err)
	}
	return m
}

// --- TestCEL_Compile_AllTemplates ---

func TestCEL_Compile_AllTemplates(t *testing.T) {
	env := mustNewEnv(t)

	templates := []policy_types.PolicyTemplate{
		{
			ID:         "allow-read",
			Expression: `tool == "Read"`,
			SourceFile: "policies/read.yaml",
			SourceLine: 10,
		},
		{
			ID:         "deny-critical",
			Expression: `risk_level == "critical"`,
			SourceFile: "policies/deny.yaml",
			SourceLine: 5,
		},
		{
			ID:         "effects-check",
			Expression: `"credential_use" in effects`,
			SourceFile: "policies/effects.yaml",
			SourceLine: 1,
		},
	}

	cache := mustCompile(t, env, templates)

	for _, tmpl := range templates {
		if _, ok := cache.Get(tmpl.ID); !ok {
			t.Errorf("policy %q missing from cache", tmpl.ID)
		}
	}
}

// --- TestCEL_Evaluate_AllowRule ---

func TestCEL_Evaluate_AllowRule(t *testing.T) {
	env := mustNewEnv(t)

	templates := []policy_types.PolicyTemplate{
		{ID: "allow-read", Expression: `tool == "Read"`},
	}
	cache := mustCompile(t, env, templates)

	prog, ok := cache.Get("allow-read")
	if !ok {
		t.Fatal("program not found")
	}

	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Read",
		Args:      argsJSON(t, map[string]any{"file_path": "/tmp/foo.txt"}),
		SessionID: "sess-001",
	}
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskLow}

	val, err := builder.Evaluate(context.Background(), prog, req, verdict, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected True for Read tool, got %v", val)
	}
}

func TestCEL_Evaluate_AllowRule_FalseForOtherTool(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "allow-read", Expression: `tool == "Read"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("allow-read")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON(t, map[string]any{"command": "ls"}), SessionID: "s"}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{RiskLevel: classify.RiskLow}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.False {
		t.Errorf("expected False for Bash tool, got %v", val)
	}
}

// --- TestCEL_Evaluate_DenyRule ---

func TestCEL_Evaluate_DenyRule(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "deny-critical", Expression: `risk_level == "critical"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("deny-critical")

	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON(t, map[string]any{"command": "rm -rf /"}), SessionID: "s"}
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskCritical}

	val, err := builder.Evaluate(context.Background(), prog, req, verdict, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected True for critical risk_level, got %v", val)
	}
}

// --- TestCEL_Evaluate_CustomFunctions ---

func TestCEL_Evaluate_CustomFunctions(t *testing.T) {
	env := mustNewEnv(t)

	t.Run("label.dominates true", func(t *testing.T) {
		templates := []policy_types.PolicyTemplate{
			{ID: "dom-true", Expression: `label.dominates(5, 3, 0, 3, 2, 0)`},
		}
		cache := mustCompile(t, env, templates)
		prog, _ := cache.Get("dom-true")
		builder := cel.NewActivationBuilder()
		req := aegis.CheckRequest{Tool: "Read", SessionID: "s"}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if val != types.True {
			t.Errorf("expected True for dominates(5,3,0,3,2,0), got %v", val)
		}
	})

	t.Run("label.dominates false", func(t *testing.T) {
		templates := []policy_types.PolicyTemplate{
			{ID: "dom-false", Expression: `label.dominates(3, 2, 0, 5, 3, 0)`},
		}
		cache := mustCompile(t, env, templates)
		prog, _ := cache.Get("dom-false")
		builder := cel.NewActivationBuilder()
		req := aegis.CheckRequest{Tool: "Read", SessionID: "s"}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if val != types.False {
			t.Errorf("expected False for dominates(3,2,0,5,3,0), got %v", val)
		}
	})

	t.Run("label.join result type", func(t *testing.T) {
		templates := []policy_types.PolicyTemplate{
			{ID: "join-list", Expression: `size(label.join(5, 3, 0, 3, 7, 0)) == 3`},
		}
		cache := mustCompile(t, env, templates)
		prog, _ := cache.Get("join-list")
		builder := cel.NewActivationBuilder()
		req := aegis.CheckRequest{Tool: "Read", SessionID: "s"}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if val != types.True {
			t.Errorf("expected True for size(label.join(...))==3, got %v", val)
		}
	})
}

// --- TestCEL_SourceLocation_E2E ---

func TestCEL_SourceLocation_E2E(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "loc-test",
			Expression: `tool == "Bash"`,
			SourceFile: "policies/deny.yaml",
			SourceLine: 42,
		},
	}
	cache := mustCompile(t, env, templates)

	loc := cache.SourceLocation("loc-test")
	want := "policies/deny.yaml:42"
	if loc != want {
		t.Errorf("SourceLocation = %q, want %q", loc, want)
	}

	// Unknown policy returns "".
	if got := cache.SourceLocation("unknown"); got != "" {
		t.Errorf("SourceLocation for unknown = %q, want empty", got)
	}
}

// --- TestProgramCache_IsValueType ---

func TestProgramCache_IsValueType(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "p1", Expression: `tool == "Read"`},
		{ID: "p2", Expression: `tool == "Bash"`},
	}
	original := mustCompile(t, env, templates)

	// Copy the cache by value — this is what EngineSnapshot does when it embeds ProgramCache.
	copyCache := *original

	// Both the original and the copy must see the same compiled programs.
	if _, ok := copyCache.Get("p1"); !ok {
		t.Error("copy missing p1")
	}
	if _, ok := copyCache.Get("p2"); !ok {
		t.Error("copy missing p2")
	}
	if _, ok := original.Get("p1"); !ok {
		t.Error("original lost p1 after copy")
	}
	if _, ok := original.Get("p2"); !ok {
		t.Error("original lost p2 after copy")
	}

	// Verify versions agree.
	if original.Version() != copyCache.Version() {
		t.Errorf("Version mismatch after copy: original=%d copy=%d", original.Version(), copyCache.Version())
	}

	// Compile a second cache with different templates and verify the first is unaffected.
	// This exercises the key INV-008 contract: ProgramCache is embedded by value in
	// EngineSnapshot. When a new snapshot is built (CompileAll returns a new *ProgramCache),
	// old snapshots that copied the struct value must not be corrupted.
	templates2 := []policy_types.PolicyTemplate{
		{ID: "p3", Expression: `risk_level == "high"`},
	}
	second := mustCompile(t, env, templates2)

	if _, ok := original.Get("p1"); !ok {
		t.Error("original.p1 disappeared after second CompileAll")
	}
	if _, ok := second.Get("p1"); ok {
		t.Error("second cache should not contain p1 from the first compile")
	}
	if _, ok := second.Get("p3"); !ok {
		t.Error("second cache missing p3")
	}
}

// --- Compile error cases ---

func TestCEL_CompileRejectsOverLengthExpression(t *testing.T) {
	env := mustNewEnv(t)
	// Build an expression longer than maxExpressionLength (32768) characters.
	long := ""
	for len(long) < 32769 {
		long += "a"
	}
	templates := []policy_types.PolicyTemplate{
		{ID: "too-long", Expression: long},
	}
	_, _, err := cel.CompileAll(env, templates)
	if err == nil {
		t.Fatal("expected error for over-length expression, got nil")
	}
}

func TestCEL_CompileRejectsInvalidSyntax(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "bad-syntax", Expression: `tool ==`},
	}
	_, _, err := cel.CompileAll(env, templates)
	if err == nil {
		t.Fatal("expected compile error for invalid syntax, got nil")
	}
}

// --- bash.* function tests ---

func TestCEL_BashTargetPort_LsofPipe(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "port-test", Expression: `bash.targetPort(args.command) == 7474`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("port-test")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "lsof -ti:7474 | xargs kill -9"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected True for lsof -ti:7474 port extraction, got %v", val)
	}
}

func TestCEL_BashTargetPort_Subshell(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "port-sub", Expression: `bash.targetPort(args.command) == 5173`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("port-sub")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "kill -9 $(lsof -ti:5173)"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected True for lsof -ti:5173 subshell port, got %v", val)
	}
}

func TestCEL_BashTargetPort_NoPatch(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "port-none", Expression: `bash.targetPort(args.command) == 0`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("port-none")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "kill -9 12345"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected 0 port for bare kill -9, got %v", val)
	}
}

func TestCEL_BashTargetUrl_CurlExtraction(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "url-test", Expression: `bash.targetUrl(args.command).startsWith("http://localhost")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("url-test")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": `curl -H "Authorization: Bearer sk-abc" http://localhost:8000/health`}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected True for localhost URL extraction, got %v", val)
	}
}

func TestCEL_GitBranchTarget_BranchD(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "branch-d", Expression: `bash.gitBranchTarget(args.command) == "feature-x"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("branch-d")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git branch -D feature-x"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected feature-x from git branch -D, got %v", val)
	}
}

func TestCEL_GitBranchTarget_PushForce(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "push-force", Expression: `bash.gitBranchTarget(args.command) == "main"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("push-force")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push --force origin main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected main from git push --force origin main, got %v", val)
	}
}

func TestCEL_GitBranchTarget_PlusRefspec(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "plus-ref", Expression: `bash.gitBranchTarget(args.command) == "main"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("plus-ref")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push origin +main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected main from git push origin +main, got %v", val)
	}
}

func TestCEL_GitBranchTarget_ColonDelete(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "colon-del", Expression: `bash.gitBranchTarget(args.command) == "main"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("colon-del")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push origin :main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected main from git push origin :main, got %v", val)
	}
}

func TestCEL_GitBranchTarget_HeadRefspec(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "head-ref", Expression: `bash.gitBranchTarget(args.command) == "main"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("head-ref")
	builder := cel.NewActivationBuilder()

	testCases := []string{
		"git push origin HEAD:main",
		"git push origin HEAD:refs/heads/main",
	}

	for _, cmd := range testCases {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected main from %q, got %v", cmd, val)
		}
	}
}

func TestCEL_IsGitForcePush_AllForms(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "force-push", Expression: `bash.isGitForcePush(args.command)`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("force-push")
	builder := cel.NewActivationBuilder()

	forceForms := []string{
		"git push --force origin main",
		"git push -f origin main",
		"git push origin +main",
		"git push origin +refs/heads/main",
	}

	for _, cmd := range forceForms {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected isGitForcePush=true for %q, got %v", cmd, val)
		}
	}
}

func TestCEL_IsGitBranchDelete_AllForms(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "branch-del", Expression: `bash.isGitBranchDelete(args.command)`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("branch-del")
	builder := cel.NewActivationBuilder()

	deleteForms := []string{
		"git branch -D main",
		"git branch -d main",
		"git push origin :main",
	}

	for _, cmd := range deleteForms {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected isGitBranchDelete=true for %q, got %v", cmd, val)
		}
	}
}

func TestCEL_BranchProtection_CaseInsensitive(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "case-insens", Expression: `bash.gitBranchTarget(args.command) == "main"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("case-insens")
	builder := cel.NewActivationBuilder()

	cmds := []string{
		"git branch -D Main",
		"git branch -D MAIN",
		"git push --force origin Main",
	}

	for _, cmd := range cmds {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected gitBranchTarget=%q for %q (case-insensitive), got %v", "main", cmd, val)
		}
	}
}

func TestCEL_FindSearchRoot_AbsolutePath(t *testing.T) {
	// bash.findSearchRoot resolves symlinks via filepath.EvalSymlinks before returning.
	// On macOS /tmp → /private/tmp; on Linux /tmp → /tmp.
	// We must compute the expected value the same way the implementation does, not
	// assume a platform-specific resolved path in the test.
	searchPath := "/usr"
	expected, err := filepath.EvalSymlinks(filepath.Clean(searchPath))
	if err != nil {
		t.Skipf("cannot resolve %q on this platform: %v", searchPath, err)
	}

	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		// Expression uses the actual resolved path so the test is platform-independent.
		{ID: "find-root", Expression: `bash.findSearchRoot(args.command) == "` + expected + `"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("find-root")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": `find ` + searchPath + ` -name "*.env"`}),
		SessionID: "s",
	}
	val, evalErr := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if evalErr != nil {
		t.Fatalf("Evaluate: %v", evalErr)
	}
	if val != types.True {
		t.Errorf("expected findSearchRoot(%q) == %q, got %v", searchPath, expected, val)
	}
}

func TestCEL_PathIsWithinProject_True(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "within-project", Expression: `path.isWithinProject("/tmp", "/")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("within-project")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s"}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected /tmp to be within /, got %v", val)
	}
}

func TestCEL_PathIsWithinProject_False(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "not-within", Expression: `path.isWithinProject("/tmp", "/home/user")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("not-within")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s"}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.False {
		t.Errorf("expected /tmp NOT to be within /home/user, got %v", val)
	}
}

func TestCEL_PathIsWithinProject_Symlink_FailSecure(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		// A non-existent symlink — should return false (fail-secure).
		{ID: "symlink-fail", Expression: `!path.isWithinProject("/nonexistent/symlink/path", "/nonexistent/root")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("symlink-fail")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s"}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected fail-secure false for unresolvable symlink, got %v", val)
	}
}

// --- bash.isSafeReadOnly ---

func TestCEL_BashIsSafeReadOnly(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "readonly-check", Expression: `bash.isSafeReadOnly(args.command)`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("readonly-check")
	builder := cel.NewActivationBuilder()

	readOnly := []string{"ls -la", "cat file.txt", "grep foo bar"}
	for _, cmd := range readOnly {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected isSafeReadOnly=true for %q, got %v", cmd, val)
		}
	}
}

// --- bash.extractTool ---

func TestCEL_BashExtractTool(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "extract-tool", Expression: `bash.extractTool(args.command) == "git"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("extract-tool")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push --force origin main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected extractTool=git, got %v", val)
	}
}

// --- bash.hasFlag ---

func TestCEL_BashHasFlag(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "has-flag", Expression: `bash.hasFlag(args.command, "--force")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("has-flag")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push --force origin main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected hasFlag(--force)=true, got %v", val)
	}
}

// --- bash.argCount ---

func TestCEL_BashArgCount(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "arg-count", Expression: `bash.argCount(args.command) == 3`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("arg-count")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": "git push origin main"}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected argCount=3 for 'git push origin main', got %v", val)
	}
}

// --- Determinism ---

func TestCEL_EvalDeterministic(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "det-test", Expression: `tool == "Read" && risk_level == "low"`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("det-test")
	builder := cel.NewActivationBuilder()

	req := aegis.CheckRequest{
		Tool:      "Read",
		Args:      argsJSON(t, map[string]any{"file_path": "/tmp/x"}),
		SessionID: "s",
	}
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskLow}

	decodedArgs := decodeArgs(t, req.Args)
	var prev string
	for i := 0; i < 1000; i++ {
		val, err := builder.Evaluate(context.Background(), prog, req, verdict, decodedArgs, label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		cur := val.Type().TypeName()
		if i > 0 && cur != prev {
			t.Errorf("non-deterministic result at iteration %d: %s != %s", i, cur, prev)
		}
		prev = cur
	}
}

// TestCEL_SourceLocationThreaded is the spec-mandated test name from WS-04 acceptance criteria.
// It verifies that PolicyTemplate.SourceFile and SourceLine are threaded through to
// ProgramCache.SourceLocation(), which WS-05 will use to populate CheckResponse.PolicySourceLocation.
func TestCEL_SourceLocationThreaded(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "loc-threaded",
			Expression: `tool == "Bash"`,
			SourceFile: "policies/deny.yaml",
			SourceLine: 42,
		},
	}
	cache := mustCompile(t, env, templates)

	got := cache.SourceLocation("loc-threaded")
	want := "policies/deny.yaml:42"
	if got != want {
		t.Errorf("SourceLocation = %q, want %q (CheckResponse.PolicySourceLocation not populated correctly)", got, want)
	}
}

// --- TestCompileAll_SkippedPoliciesReported ---

// TestCompileAll_SkippedPoliciesReported verifies that CompileAll returns the
// policy ID in the skipped list when the expression references an undeclared
// variable, and that this is not treated as an error.
func TestCompileAll_SkippedPoliciesReported(t *testing.T) {
	env := mustNewEnv(t)

	templates := []policy_types.PolicyTemplate{
		{ID: "valid-policy", Expression: `tool == "Bash"`},
		// __phantom__ is not declared in the CEL environment.
		{ID: "undeclared-var", Expression: `__phantom__ == "foo"`},
	}

	cache, skipped, err := cel.CompileAll(env, templates)
	if err != nil {
		t.Fatalf("CompileAll returned unexpected error: %v", err)
	}

	if len(skipped) != 1 || skipped[0] != "undeclared-var" {
		t.Errorf("expected skipped=[\"undeclared-var\"], got %v", skipped)
	}

	if _, ok := cache.Get("valid-policy"); !ok {
		t.Error("valid-policy should be in cache")
	}
	if _, ok := cache.Get("undeclared-var"); ok {
		t.Error("undeclared-var should NOT be in cache — it was skipped")
	}
}

// --- Regression tests for bugs found during code review ---

// TestCEL_FindSearchRoot_NonExistentPath_FailSecure verifies that bashFindSearchRoot
// returns "" (not a raw cleaned path) when the search root does not exist on disk.
// The old code returned filepath.Clean(t) on EvalSymlinks error, which could allow
// a policy boundary check to be bypassed via a crafted non-existent path string.
func TestCEL_FindSearchRoot_NonExistentPath_FailSecure(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "find-nonexist", Expression: `bash.findSearchRoot(args.command) == ""`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("find-nonexist")
	builder := cel.NewActivationBuilder()

	// This path does not exist on disk — EvalSymlinks will fail.
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": `find /this/path/does/not/exist -name "*.env"`}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected findSearchRoot(\"/this/path/does/not/exist\") == \"\", got %v (fail-secure violated)", val)
	}
}

// TestCEL_SourceLocation_NegativeSourceLine verifies that negative SourceLine values
// produce a sane SourceLocation string rather than a garbled one.
// The old itoa loop ran `for n > 0` which never executes for n < 0, producing "".
func TestCEL_SourceLocation_NegativeSourceLine(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{
			ID:         "neg-line",
			Expression: `tool == "Bash"`,
			SourceFile: "policies/test.yaml",
			SourceLine: -5,
		},
	}
	cache := mustCompile(t, env, templates)
	// SourceLine <= 0 → SourceLocation returns only the file, not file:line.
	loc := cache.SourceLocation("neg-line")
	if loc != "policies/test.yaml" {
		t.Errorf("SourceLocation with SourceLine=-5: got %q, want %q", loc, "policies/test.yaml")
	}
}

// TestCEL_LabelJoin_ReturnsCorrectValues verifies that label.join produces the
// mathematically correct LUB result, not just a list of the right size.
// The old code used []ref.Val which could produce an untyped list; we now use []int64.
func TestCEL_LabelJoin_ReturnsCorrectValues(t *testing.T) {
	env := mustNewEnv(t)

	// Join({C:5, I:3, Cat:0}, {C:3, I:7, Cat:0})
	// Expected: C=max(5,3)=5, I=min(3,7)=3 (Bell-LaPadula Join: integrity goes DOWN), Cat=0|0=0
	templates := []policy_types.PolicyTemplate{
		// label.join returns [conf, integrity, category].
		// Index 0 = confidentiality = 5
		{ID: "join-conf", Expression: `label.join(5, 3, 0, 3, 7, 0)[0] == 5`},
		// Index 1 = integrity = min(3, 7) = 3 (Join: integrity goes DOWN)
		{ID: "join-int", Expression: `label.join(5, 3, 0, 3, 7, 0)[1] == 3`},
		// Index 2 = category = 0 | 0 = 0
		{ID: "join-cat", Expression: `label.join(5, 3, 0, 3, 7, 0)[2] == 0`},
	}
	cache := mustCompile(t, env, templates)
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Read", SessionID: "s"}

	for _, tmpl := range templates {
		prog, ok := cache.Get(tmpl.ID)
		if !ok {
			t.Fatalf("program %q not found", tmpl.ID)
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("%s: Evaluate: %v", tmpl.ID, err)
		}
		if val != types.True {
			t.Errorf("%s: expression %q evaluated to %v, expected true", tmpl.ID, tmpl.Expression, val)
		}
	}
}

// TestCEL_SetSessionLabels_ConcurrentSafe verifies that SetSessionLabels and concurrent
// ifc.highWaterMark evaluations do not race. The old implementation used a plain pointer
// assignment which is a data race under the Go memory model.
func TestCEL_SetSessionLabels_ConcurrentSafe(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	cel.SetSessionLabels(sessions)

	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "hwm", Expression: `ifc.highWaterMark(session_id) >= 0`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("hwm")
	builder := cel.NewActivationBuilder()

	done := make(chan struct{})

	// Writer goroutine: repeatedly calls SetSessionLabels.
	go func() {
		for i := 0; i < 100; i++ {
			cel.SetSessionLabels(sessions)
		}
		close(done)
	}()

	// Reader goroutines: concurrently evaluate expressions that call ifc.highWaterMark.
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "concurrent-session"}
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				_, _ = builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
			}
		}()
	}

	<-done
	// If the race detector fires, the test fails. No assertion needed beyond non-crash.
}

// TestCEL_GitBranchTarget_PushNoRefspec verifies that git push with only a remote
// (no explicit refspec) returns "" — we cannot determine the branch from command text.
func TestCEL_GitBranchTarget_PushNoRefspec(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "no-refspec", Expression: `bash.gitBranchTarget(args.command) == ""`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("no-refspec")
	builder := cel.NewActivationBuilder()

	cmds := []string{
		"git push origin",         // only remote, no refspec
		"git push --force origin", // force flag but still no refspec
		"git push -f origin",
	}
	for _, cmd := range cmds {
		req := aegis.CheckRequest{
			Tool:      "Bash",
			Args:      argsJSON(t, map[string]any{"command": cmd}),
			SessionID: "s",
		}
		val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("gitBranchTarget(%q): expected empty string for ambiguous push, got %v", cmd, val)
		}
	}
}

// --- session.projectRoot CEL variable ---

// TestCEL_Session_ProjectRoot_IsAccessible verifies that session.projectRoot is
// readable from CEL expressions and reflects the sessionProjectRoot argument.
func TestCEL_Session_ProjectRoot_IsAccessible(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "session-root-check", Expression: `session.projectRoot == "/code/myproject"`},
	}
	cache := mustCompile(t, env, templates)
	prog, ok := cache.Get("session-root-check")
	if !ok {
		t.Fatal("program not found in cache")
	}
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s"}

	// With matching root → true
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, nil, label.LabeledRequest{}, "/code/myproject")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected true when projectRoot matches, got %v", val)
	}

	// With non-matching root → false
	val, err = builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, nil, label.LabeledRequest{}, "/code/other")
	if err != nil {
		t.Fatalf("Evaluate (non-match): %v", err)
	}
	if val != types.False {
		t.Errorf("expected false when projectRoot does not match, got %v", val)
	}
}

// TestCEL_Session_ProjectRoot_EmptyDefault verifies that session.projectRoot is
// empty string when no root is passed (zero value is safe for policies to check).
func TestCEL_Session_ProjectRoot_EmptyDefault(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "session-root-empty", Expression: `session.projectRoot == ""`},
	}
	cache := mustCompile(t, env, templates)
	prog, ok := cache.Get("session-root-empty")
	if !ok {
		t.Fatal("program not found in cache")
	}
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s"}

	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, nil, label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected true for empty projectRoot, got %v", val)
	}
}

// --- path.isWithinProject via CEL ---

// evalIsWithinProject is a helper that evaluates path.isWithinProject(path, root)
// via a real CEL program, testing the actual registered function.
func evalIsWithinProject(t *testing.T, path, root string) bool {
	t.Helper()
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "within-check", Expression: `path.isWithinProject(args["path"], args["root"])`},
	}
	cache := mustCompile(t, env, templates)
	prog, ok := cache.Get("within-check")
	if !ok {
		t.Fatal("within-check program not found")
	}
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{Tool: "Bash", SessionID: "s", Args: argsJSON(t, map[string]any{"path": path, "root": root})}
	val, err := builder.Evaluate(context.Background(), prog, req, classify.VerdictEntry{}, decodeArgs(t, req.Args), label.LabeledRequest{}, "")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	b, ok := val.Value().(bool)
	if !ok {
		t.Fatalf("expected bool result, got %T", val.Value())
	}
	return b
}

func TestPathIsWithinProject_Inside(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "src", "main.go")
	if err := os.MkdirAll(filepath.Dir(sub), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !evalIsWithinProject(t, sub, root) {
		t.Errorf("expected %q to be within %q", sub, root)
	}
}

func TestPathIsWithinProject_Outside(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	outside := filepath.Join(other, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if evalIsWithinProject(t, outside, root) {
		t.Errorf("expected %q to NOT be within %q", outside, root)
	}
}

func TestPathIsWithinProject_EmptyRoot_ReturnsFalse(t *testing.T) {
	root := t.TempDir()
	if evalIsWithinProject(t, root, "") {
		t.Error("empty root must return false (fail-secure)")
	}
}

func TestPathIsWithinProject_ExactMatch(t *testing.T) {
	root := t.TempDir()
	if !evalIsWithinProject(t, root, root) {
		t.Errorf("exact match: expected %q within itself", root)
	}
}

func TestPathIsWithinProject_SymlinkEscape_ReturnsFalse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "escape")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	escapedPath := filepath.Join(symlink, "secret.txt")
	if evalIsWithinProject(t, escapedPath, root) {
		t.Error("symlink escape must return false (INV-014)")
	}
}
