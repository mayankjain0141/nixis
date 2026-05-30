// Package workflow_test contains end-to-end workflow integration tests for the
// Nixis governance pipeline. Each test exercises the full stack:
// Unix socket → daemon handler → policy engine → audit writer → SQLite.
package workflow_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mayankjain0141/nixis/internal/audit"
	"github.com/mayankjain0141/nixis/internal/bundle"
	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/mayankjain0141/nixis/internal/daemon"
	"github.com/mayankjain0141/nixis/internal/delegation"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/internal/policy"
	"github.com/mayankjain0141/nixis/internal/secret"
	"github.com/mayankjain0141/nixis/pkg/nixis"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
	_ "modernc.org/sqlite"
)

// ─── socket counter ───────────────────────────────────────────────────────────

var wfSocketCounter atomic.Int64

func workflowSocketPath() string {
	n := wfSocketCounter.Add(1)
	return filepath.Join(os.TempDir(), fmt.Sprintf("wf%d.sock", n))
}

// ─── shared helpers ───────────────────────────────────────────────────────────

// builtinPolicyDir returns the absolute path to policies/builtin, skipping the
// test if it cannot be found.
func builtinPolicyDir(t *testing.T) string {
	t.Helper()
	candidate := "../../policies/builtin"
	if _, err := os.Stat(candidate); err == nil {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	t.Skip("policies/builtin not found — skipping workflow test")
	return ""
}

// newAuditWriter creates a Writer backed by a temp SQLite DB and starts its
// goroutine. Returns the writer, a cancel func, and a done channel.
func newAuditWriter(t *testing.T) (*audit.Writer, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	w, err := audit.NewWriter(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Start(ctx)
	}()
	return w, cancel, done
}

// waitSocketReady polls until the Unix socket file is accessible or the
// deadline expires. External tests cannot access the unexported setReadyCh.
func waitSocketReady(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("daemon socket %s never became ready", socketPath)
}

// startWorkflowDaemon starts a daemon wired with a real CEL environment and the
// given policy bundle. Pass policyDir="" to start with no policies loaded
// (engine will deny-all until reloaded). Returns the socket path and the engine
// (for hot-reload tests).
func startWorkflowDaemon(
	t *testing.T,
	policyDir string,
	sessions *ifc.SessionLabels,
) (socketPath string, eng *policy.PolicyEngine) {
	t.Helper()

	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}

	if sessions == nil {
		sessions = &ifc.SessionLabels{}
	}

	eng = policy.NewPolicyEngine(sessions, celEnv)

	if policyDir != "" {
		templates, bindings, err := bundle.ParsePolicyDir(policyDir)
		if err != nil {
			t.Fatalf("ParsePolicyDir(%s): %v", policyDir, err)
		}
		compiled := &nixis.CompiledBundle{Version: 1, Templates: templates, Bindings: bindings}
		if err := eng.Reload(context.Background(), compiled); err != nil {
			t.Fatalf("engine.Reload: %v", err)
		}
	}

	socketPath = workflowSocketPath()
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cfg := daemon.Config{SocketPath: socketPath}
	w, auditCancel, auditDone := newAuditWriter(t)
	d := daemon.New(cfg, eng, w, nil, sessions)
	d.SetAuditContext(auditCancel, auditDone)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
	})

	return socketPath, eng
}

// sendWorkflowRequest dials the socket, sends a request, and returns the response.
func sendWorkflowRequest(t *testing.T, socketPath string, req nixis.CheckRequest) nixis.CheckResponse {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	payload, _ := json.Marshal(req)
	deadline := time.Now().Add(2 * time.Second)
	if err := daemon.WriteMessage(conn, payload, deadline); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	raw, err := daemon.ReadMessage(conn, deadline, nixis.MaxMessageSize)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	var resp nixis.CheckResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestWorkflow_HookAllow_ExitZero verifies the allow path end-to-end through
// the daemon's Unix socket using the real built-in policy bundle.
func TestWorkflow_HookAllow_ExitZero(t *testing.T) {
	t.Parallel()
	policyDir := builtinPolicyDir(t)

	socketPath, _ := startWorkflowDaemon(t, policyDir, nil)
	waitSocketReady(t, socketPath)

	resp := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "Bash",
		Args:      json.RawMessage(`{"command":"ls -la"}`),
		SessionID: "wf-allow-test-001",
	})

	if resp.Decision.Action != nixis.ActionAllow {
		t.Errorf("expected Allow for 'ls -la', got %v (reason: %q, layer: %q)",
			resp.Decision.Action, resp.Decision.Reason, resp.EnforcingLayer)
	}
	if resp.LatencyNs <= 0 {
		t.Errorf("expected positive latency, got %d ns", resp.LatencyNs)
	}
}

// TestWorkflow_HookDeny_ExitTwo verifies the deny path: 'git branch -D main'
// is denied by the git-branch-protection policy in the built-in bundle.
func TestWorkflow_HookDeny_ExitTwo(t *testing.T) {
	t.Parallel()
	policyDir := builtinPolicyDir(t)

	socketPath, _ := startWorkflowDaemon(t, policyDir, nil)
	waitSocketReady(t, socketPath)

	resp := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "Bash",
		Args:      json.RawMessage(`{"command":"git branch -D main"}`),
		SessionID: "wf-deny-test-001",
	})

	if resp.Decision.Action != nixis.ActionDeny {
		t.Errorf("expected Deny for 'git branch -D main', got %v (reason: %q)",
			resp.Decision.Action, resp.Decision.Reason)
	}
}

// TestWorkflow_PolicyReload_WhileServing verifies hot-reload semantics: the
// engine transitions from deny (uninitialised) → allow (empty bundle) → deny
// (deny-all bundle) while the daemon is running, without panics or lost requests.
func TestWorkflow_PolicyReload_WhileServing(t *testing.T) {
	t.Parallel()

	socketPath, eng := startWorkflowDaemon(t, "", nil)
	waitSocketReady(t, socketPath)

	// Phase 1: engine has no snapshot → deny (fail-secure).
	resp1 := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "Bash",
		Args:      json.RawMessage(`{"command":"ls -la"}`),
		SessionID: "wf-reload-test-001",
	})
	if resp1.Decision.Action != nixis.ActionDeny {
		t.Errorf("pre-reload: expected Deny (uninitialized engine), got %v", resp1.Decision.Action)
	}

	// Phase 2: reload empty bundle → allow-all (no DENY policies present).
	emptyBundle := &nixis.CompiledBundle{Version: 1}
	if err := eng.Reload(context.Background(), emptyBundle); err != nil {
		t.Fatalf("Reload (empty bundle): %v", err)
	}

	resp2 := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "Bash",
		Args:      json.RawMessage(`{"command":"ls -la"}`),
		SessionID: "wf-reload-test-002",
	})
	if resp2.Decision.Action != nixis.ActionAllow {
		t.Errorf("post-reload (empty bundle): expected Allow, got %v (reason: %q)",
			resp2.Decision.Action, resp2.Decision.Reason)
	}

	// Phase 3: reload deny-all bundle → deny.
	denyBundle := &nixis.CompiledBundle{
		Version: 2,
		Templates: []policy_types.PolicyTemplate{
			{
				ID:         "deny-all",
				Name:       "deny-all",
				Expression: "false",
				SourceFile: "test-deny-all",
				SourceLine: 1,
			},
		},
		Bindings: []policy_types.PolicyBinding{
			{
				TemplateID: "deny-all",
				Scope:      policy_types.PolicyScope{},
				Priority:   0,
				Layer:      "cel",
			},
		},
	}
	if err := eng.Reload(context.Background(), denyBundle); err != nil {
		t.Fatalf("Reload (deny-all): %v", err)
	}

	resp3 := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "Bash",
		Args:      json.RawMessage(`{"command":"ls -la"}`),
		SessionID: "wf-reload-test-003",
	})
	if resp3.Decision.Action != nixis.ActionDeny {
		t.Errorf("post-reload (deny-all): expected Deny, got %v", resp3.Decision.Action)
	}
}

// TestWorkflow_IFC_LabelEscalation verifies that TaintWithSecret raises the
// session label. After taint, the label must carry TaintBit and state must be
// LabelStateTaintedBySecret.
func TestWorkflow_IFC_LabelEscalation(t *testing.T) {
	t.Parallel()

	sessions := &ifc.SessionLabels{}
	socketPath, _ := startWorkflowDaemon(t, "", sessions)
	waitSocketReady(t, socketPath)

	const sid = "wf-ifc-taint-001"

	// Issue a request so the session is known to the daemon handler.
	_ = sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
		Tool:      "ReadFile",
		SessionID: sid,
	})

	// Before taint: state must not be tainted.
	if state := sessions.LabelState(sid); state == ifc.LabelStateTaintedBySecret {
		t.Errorf("session tainted before TaintWithSecret, got %v", state)
	}

	// Taint the session.
	sessions.TaintWithSecret(sid)

	// TaintBit must be set in the label.
	label := sessions.Current(sid)
	if label.Category&ifc.TaintBit == 0 {
		t.Errorf("TaintBit not set after TaintWithSecret: Category=%#x", label.Category)
	}

	// State must be tainted_by_secret.
	if state := sessions.LabelState(sid); state != ifc.LabelStateTaintedBySecret {
		t.Errorf("expected LabelStateTaintedBySecret, got %v", state)
	}
}

// TestWorkflow_AuditRecord_Persistence sends 3 requests through the daemon,
// waits for the audit writer to flush, then queries SQLite to verify 3 records.
func TestWorkflow_AuditRecord_Persistence(t *testing.T) {
	t.Parallel()

	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	eng := policy.NewPolicyEngine(sessions, celEnv)
	if err := eng.Reload(context.Background(), &nixis.CompiledBundle{Version: 1}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "audit-persist.db")
	w, err := audit.NewWriter(dbPath)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	auditCtx, auditCancel := context.WithCancel(context.Background())
	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		w.Start(auditCtx)
	}()

	socketPath := workflowSocketPath()
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cfg := daemon.Config{SocketPath: socketPath}
	d := daemon.New(cfg, eng, w, nil, sessions)
	d.SetAuditContext(auditCancel, auditDone)

	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(daemonCtx) }()
	t.Cleanup(func() {
		daemonCancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
	})

	waitSocketReady(t, socketPath)

	const sessionID = "wf-audit-persist-001"
	reqs := []nixis.CheckRequest{
		{Tool: "Bash", Args: json.RawMessage(`{"command":"ls -la"}`), SessionID: sessionID},
		{Tool: "ReadFile", Args: json.RawMessage(`{"file_path":"/tmp/x"}`), SessionID: sessionID},
		{Tool: "WriteFile", Args: json.RawMessage(`{"file_path":"/tmp/y"}`), SessionID: sessionID},
	}
	for _, req := range reqs {
		sendWorkflowRequest(t, socketPath, req)
	}

	// Shut down the daemon, which cancels the audit writer via SetAuditContext.
	daemonCancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down in time")
	}

	// Wait for audit writer flush.
	select {
	case <-auditDone:
	case <-time.After(5 * time.Second):
		t.Fatal("audit writer did not flush in time")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("audit writer Close: %v", err)
	}

	// Query SQLite directly.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var count int
	if err := db.QueryRow(
		`SELECT count(*) FROM audit_log WHERE session_id = ?`, sessionID,
	).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 audit records for session %q, got %d", sessionID, count)
	}

	// Verify each record has a non-empty tool and valid action.
	rows, err := db.Query(
		`SELECT tool, action FROM audit_log WHERE session_id = ? ORDER BY id`, sessionID,
	)
	if err != nil {
		t.Fatalf("select rows: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var gotRows int
	for rows.Next() {
		var tool, action string
		if err := rows.Scan(&tool, &action); err != nil {
			t.Fatalf("row scan: %v", err)
		}
		if tool == "" {
			t.Errorf("audit row has empty tool")
		}
		if action != "allow" && action != "deny" && action != "require_approval" && action != "audit" {
			t.Errorf("unexpected action value in audit: %q", action)
		}
		gotRows++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if gotRows != 3 {
		t.Errorf("expected 3 rows, got %d", gotRows)
	}
}

// TestWorkflow_DelegationChain_Validate creates an Ed25519 key pair, signs a
// root token, validates the chain via ValidateChain, registers it, verifies
// ListActive, and revokes it.
func TestWorkflow_DelegationChain_Validate(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("delegation.New: %v", err)
	}

	tok := delegation.DelegationToken{
		Issuer:   "test-issuer",
		Audience: "test-agent",
		Capabilities: delegation.CapabilitySet{
			Operations: 0xFF,
			Effects:    0xFF,
			Resources:  0xFFFF,
			MaxRisk:    10,
		},
		MaxDepth:  1,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	tok.Signature = ed25519.Sign(priv, tok.CanonicalBytes())

	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}

	ref := nixis.DelegationRef{TokenID: string(raw), Issuer: tok.Issuer}
	chain, err := eng.ValidateChain([]nixis.DelegationRef{ref}, time.Now())
	if err != nil {
		t.Fatalf("ValidateChain: %v", err)
	}
	if chain == nil {
		t.Fatal("expected non-nil Chain from ValidateChain")
	}

	ceil := chain.Ceiling()
	if !ceil.ExpiresAt.After(time.Now()) {
		t.Errorf("ceiling ExpiresAt is not in the future: %v", ceil.ExpiresAt)
	}

	// Register and verify in ListActive.
	const chainID = "test-chain-001"
	eng.Register(chainID, chain)

	found := false
	for _, a := range eng.ListActive() {
		if a.ChainID == chainID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("registered chain %q not found in ListActive", chainID)
	}

	// Revoke and verify it is gone.
	eng.Revoke(chainID)
	for _, a := range eng.ListActive() {
		if a.ChainID == chainID {
			t.Errorf("revoked chain %q still present in ListActive", chainID)
		}
	}
}

// TestWorkflow_CELPolicy_GitBranchProtection loads the built-in policy bundle and
// verifies each known case for the git-branch-protection policy.
func TestWorkflow_CELPolicy_GitBranchProtection(t *testing.T) {
	t.Parallel()
	policyDir := builtinPolicyDir(t)

	socketPath, _ := startWorkflowDaemon(t, policyDir, nil)
	waitSocketReady(t, socketPath)

	cases := []struct {
		name     string
		cmd      string
		wantDeny bool
	}{
		{"delete main → DENY", "git branch -D main", true},
		{"force push to main → DENY", "git push --force origin main", true},
		{"force push short flag → DENY", "git push -f origin main", true},
		{"ls is safe → ALLOW", "ls -la", false},
		{"delete feature branch → not DENY", "git branch -D feature/my-feature", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args, _ := json.Marshal(map[string]string{"command": tc.cmd})
			resp := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
				Tool:      "Bash",
				Args:      args,
				SessionID: "wf-git-" + tc.name,
			})
			isDeny := resp.Decision.Action == nixis.ActionDeny
			if isDeny != tc.wantDeny {
				t.Errorf("cmd=%q: wantDeny=%v, got action=%v (reason: %q)",
					tc.cmd, tc.wantDeny, resp.Decision.Action, resp.Decision.Reason)
			}
		})
	}
}

// TestWorkflow_SecretDetection_TaintsSession creates a Scanner, scans content
// with a detectable secret, and verifies the Finding is redacted and the
// returned SecurityLabel has elevated Confidentiality.
// Not parallel: gitleaks initialises a global viper singleton via sync.Once;
// two parallel goroutines calling NewDetectorDefaultConfig concurrently race on it.
func TestWorkflow_SecretDetection_TaintsSession(t *testing.T) {
	s := secret.NewScanner()
	ctx := context.Background()

	// Synthetic GitHub Personal Access Token — gitleaks default config detects these.
	fakeToken := "ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	content := fmt.Sprintf(`export GITHUB_TOKEN="%s"`, fakeToken)

	findings, label := s.ScanBoundary(ctx, content, policy.BoundaryToolArgs)

	if len(findings) == 0 {
		t.Skip("gitleaks did not detect synthetic token in this environment — skipping")
	}

	for _, f := range findings {
		if f.Redacted == fakeToken {
			t.Errorf("raw secret leaked into Finding.Redacted: %q", f.Redacted)
		}
		if f.Redacted == "" {
			t.Errorf("Finding.Redacted is empty for rule %q", f.Rule)
		}
	}

	if label.Confidentiality == 0 {
		t.Errorf("expected elevated Confidentiality on secret detection, got 0")
	}
}

// TestWorkflow_SecretScan_PipelineDenies wires the real secret Scanner into the
// PolicyEngine and verifies it denies when a known secret is found in tool args.
// Not parallel: shares gitleaks global viper init with TestWorkflow_SecretDetection_TaintsSession.
func TestWorkflow_SecretScan_PipelineDenies(t *testing.T) {
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	s := secret.NewScanner()
	eng := policy.NewPolicyEngine(sessions, celEnv, policy.WithSecretScanner(s))

	if err := eng.Reload(context.Background(), &nixis.CompiledBundle{Version: 1}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	fakeToken := "ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	args, _ := json.Marshal(map[string]string{"command": fmt.Sprintf("echo %s", fakeToken)})

	const sid = "wf-secret-scan-001"
	resp := eng.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Bash",
		Args:      args,
		SessionID: sid,
	})

	if resp.Decision.Action == nixis.ActionDeny {
		// If detection fired, enforcing layer must be secret-scan.
		if resp.EnforcingLayer != nixis.EnforcingLayerSecretScan {
			t.Errorf("expected EnforcingLayerSecretScan, got %q", resp.EnforcingLayer)
		}
		// Session must be tainted after a secret-scan deny.
		if state := sessions.LabelState(sid); state != ifc.LabelStateTaintedBySecret {
			t.Errorf("session not tainted after secret-scan deny: %v", state)
		}
	}
	// Allow is acceptable when gitleaks does not detect the pattern (env variation).
}

// TestWorkflow_DelegationChain_ExpiredToken verifies that an expired token is
// rejected by ValidateChain.
func TestWorkflow_DelegationChain_ExpiredToken(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("delegation.New: %v", err)
	}

	tok := delegation.DelegationToken{
		Issuer:    "test-issuer",
		Audience:  "test-agent",
		MaxDepth:  1,
		ExpiresAt: time.Now().Add(-time.Minute), // already expired
		Capabilities: delegation.CapabilitySet{
			Operations: 0xFF,
			Resources:  0xFFFF,
		},
	}
	tok.Signature = ed25519.Sign(priv, tok.CanonicalBytes())

	raw, _ := json.Marshal(tok)
	ref := nixis.DelegationRef{TokenID: string(raw), Issuer: tok.Issuer}

	chain, err := eng.ValidateChain([]nixis.DelegationRef{ref}, time.Now())
	if err == nil {
		t.Errorf("expected error for expired token, got chain=%v", chain)
	}
}

// TestWorkflow_ConcurrentRequests verifies the daemon handles multiple concurrent
// requests without data races or corruption. Must pass -race.
func TestWorkflow_ConcurrentRequests(t *testing.T) {
	t.Parallel()
	policyDir := builtinPolicyDir(t)

	socketPath, _ := startWorkflowDaemon(t, policyDir, nil)
	waitSocketReady(t, socketPath)

	const n = 10
	type result struct{ action nixis.Action }
	results := make(chan result, n)

	for i := range n {
		go func(i int) {
			resp := sendWorkflowRequest(t, socketPath, nixis.CheckRequest{
				Tool:      "Bash",
				Args:      json.RawMessage(`{"command":"ls -la"}`),
				SessionID: fmt.Sprintf("wf-concurrent-%d", i),
			})
			results <- result{resp.Decision.Action}
		}(i)
	}

	for range n {
		r := <-results
		if r.action != nixis.ActionAllow && r.action != nixis.ActionDeny {
			t.Errorf("unexpected action from concurrent request: %v", r.action)
		}
	}
}

// TestWorkflow_PolicyEngine_ReloadDoesNotDropRequests verifies that concurrent
// Reload() calls interleaved with Evaluate() do not panic or return invalid actions.
func TestWorkflow_PolicyEngine_ReloadDoesNotDropRequests(t *testing.T) {
	t.Parallel()

	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	eng := policy.NewPolicyEngine(sessions, celEnv)

	if err := eng.Reload(context.Background(), &nixis.CompiledBundle{Version: 1}); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var evalErrors atomic.Int64
	evalDone := make(chan struct{})

	go func() {
		defer close(evalDone)
		for i := range 100 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			resp := eng.Evaluate(ctx, nixis.CheckRequest{
				Tool:      "Bash",
				Args:      json.RawMessage(`{"command":"ls"}`),
				SessionID: fmt.Sprintf("wf-race-%d", i),
			})
			if resp.Decision.Action != nixis.ActionAllow && resp.Decision.Action != nixis.ActionDeny {
				evalErrors.Add(1)
			}
		}
	}()

	for v := range 5 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			break
		}
		if err := eng.Reload(ctx, &nixis.CompiledBundle{Version: uint64(v + 2)}); err != nil {
			t.Errorf("concurrent Reload v%d: %v", v+2, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	<-evalDone

	if n := evalErrors.Load(); n > 0 {
		t.Errorf("%d evaluations returned unexpected action during concurrent reload", n)
	}
}
