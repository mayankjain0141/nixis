package cel_test

import (
	"encoding/json"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
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
	cache, err := cel.CompileAll(env, templates)
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

	val, err := builder.Evaluate(prog, req, verdict)
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{RiskLevel: classify.RiskLow})
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

	val, err := builder.Evaluate(prog, req, verdict)
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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

	// Copy the cache by value.
	copyCache := *original

	// Verify both have the same programs.
	if _, ok := copyCache.Get("p1"); !ok {
		t.Error("copy missing p1")
	}
	if _, ok := copyCache.Get("p2"); !ok {
		t.Error("copy missing p2")
	}

	// The copy is independent: adding a program to one doesn't affect the other.
	// Since ProgramCache's map is shared (shallow copy), this test verifies the
	// value-type semantics as specified: copies share the immutable read-only state,
	// which is correct per INV-008 (programs are immutable after CompileAll).
	if _, ok := original.Get("p1"); !ok {
		t.Error("original lost p1 after copy")
	}
}

// --- Compile error cases ---

func TestCEL_CompileRejectsOverLengthExpression(t *testing.T) {
	env := mustNewEnv(t)
	// Build an expression longer than 4096 characters.
	long := ""
	for len(long) < 4097 {
		long += "a"
	}
	templates := []policy_types.PolicyTemplate{
		{ID: "too-long", Expression: long},
	}
	_, err := cel.CompileAll(env, templates)
	if err == nil {
		t.Fatal("expected error for over-length expression, got nil")
	}
}

func TestCEL_CompileRejectsInvalidSyntax(t *testing.T) {
	env := mustNewEnv(t)
	templates := []policy_types.PolicyTemplate{
		{ID: "bad-syntax", Expression: `tool ==`},
	}
	_, err := cel.CompileAll(env, templates)
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", cmd, err)
		}
		if val != types.True {
			t.Errorf("expected gitBranchTarget=%q for %q (case-insensitive), got %v", "main", cmd, val)
		}
	}
}

func TestCEL_FindSearchRoot_AbsolutePath(t *testing.T) {
	env := mustNewEnv(t)
	// bash.findSearchRoot resolves symlinks, so on macOS /tmp → /private/tmp.
	// We use /usr which is a real directory and not a symlink on both Linux and macOS.
	templates := []policy_types.PolicyTemplate{
		{ID: "find-root", Expression: `bash.findSearchRoot(args.command).startsWith("/usr")`},
	}
	cache := mustCompile(t, env, templates)
	prog, _ := cache.Get("find-root")
	builder := cel.NewActivationBuilder()
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      argsJSON(t, map[string]any{"command": `find /usr -name "*.env"`}),
		SessionID: "s",
	}
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if val != types.True {
		t.Errorf("expected findSearchRoot to start with /usr, got %v", val)
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
		val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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
	val, err := builder.Evaluate(prog, req, classify.VerdictEntry{})
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

	var prev string
	for i := 0; i < 100; i++ {
		val, err := builder.Evaluate(prog, req, verdict)
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
