package e2e_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
	"go.uber.org/goleak"
	_ "modernc.org/sqlite"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestE2E_CheckRequest_PolicyEvaluation_AuditWrite tests the full path:
// CheckRequest -> Policy evaluation -> Audit write -> Response
func TestE2E_CheckRequest_PolicyEvaluation_AuditWrite(t *testing.T) {
	// 1. Set up audit writer with temp DB
	tmpDB := t.TempDir() + "/audit.db"
	writer, err := audit.NewWriter(tmpDB)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	auditDone := make(chan struct{})
	go func() { defer close(auditDone); writer.Start(ctx) }()

	// 2. Set up CEL environment + policy engine
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	engine := policy.NewPolicyEngine(sessions, celEnv, policy.WithAuditWriter(writer))

	// 3. Load policies from builtin dir
	policyDir := "../../policies/builtin"
	if _, err := os.Stat(policyDir); os.IsNotExist(err) {
		t.Skip("policies/builtin not found — skipping E2E test")
	}
	templates, bindings, err := bundle.ParsePolicyDir(policyDir)
	if err != nil {
		t.Fatalf("ParsePolicyDir: %v", err)
	}
	compiled := &aegis.CompiledBundle{Version: 1, Templates: templates, Bindings: bindings}
	if err := engine.Reload(ctx, compiled); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	// 4. Evaluate a CheckRequest
	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      []byte(`{"command": "ls -la"}`),
		SessionID: "e2e-test-session-001",
	}
	resp := engine.Evaluate(ctx, req)

	// 5. Verify response is valid (allow or deny — both are valid outcomes)
	if resp.Decision.Action != aegis.ActionAllow && resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("unexpected action: %v", resp.Decision.Action)
	}

	// 6. Cancel context, wait for audit flush, then close the DB.
	cancel()
	select {
	case <-auditDone:
	case <-time.After(5 * time.Second):
		t.Error("audit writer did not shut down in time")
		return
	}
	if err := writer.Close(); err != nil {
		t.Errorf("audit writer Close: %v", err)
	}

	// Verify the audit record was actually written to SQLite.
	db, err := sql.Open("sqlite", tmpDB)
	if err != nil {
		t.Fatalf("open audit DB for verification: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close verification DB: %v", err)
		}
	}()

	var count int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_log WHERE session_id = ?",
		req.SessionID,
	).Scan(&count); err != nil {
		t.Fatalf("query audit records: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one audit record for session, got 0")
	}
}

// TestE2E_DenyOnUninitializedEngine verifies fail-secure behaviour (INV-001):
// evaluating before any Reload must return Deny.
func TestE2E_DenyOnUninitializedEngine(t *testing.T) {
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	engine := policy.NewPolicyEngine(sessions, celEnv)

	req := aegis.CheckRequest{
		Tool:      "Bash",
		Args:      []byte(`{"command": "rm -rf /"}`),
		SessionID: "e2e-uninit-session",
	}
	resp := engine.Evaluate(context.Background(), req)

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected Deny for uninitialized engine, got: %v", resp.Decision.Action)
	}
}

// TestE2E_ReloadAndEvaluate verifies that Reload followed by Evaluate produces
// a consistent response when the policy dir exists and compiles cleanly.
func TestE2E_ReloadAndEvaluate(t *testing.T) {
	policyDir := "../../policies/builtin"
	if _, err := os.Stat(policyDir); os.IsNotExist(err) {
		t.Skip("policies/builtin not found — skipping E2E test")
	}

	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}
	sessions := &ifc.SessionLabels{}
	engine := policy.NewPolicyEngine(sessions, celEnv)

	ctx := context.Background()

	templates, bindings, err := bundle.ParsePolicyDir(policyDir)
	if err != nil {
		t.Fatalf("ParsePolicyDir: %v", err)
	}
	compiled := &aegis.CompiledBundle{Version: 1, Templates: templates, Bindings: bindings}
	if err := engine.Reload(ctx, compiled); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	cases := []struct {
		name string
		req  aegis.CheckRequest
	}{
		{
			name: "safe_read_only",
			req: aegis.CheckRequest{
				Tool:      "Bash",
				Args:      []byte(`{"command": "ls -la"}`),
				SessionID: "e2e-session-safe",
			},
		},
		{
			name: "write_tool",
			req: aegis.CheckRequest{
				Tool:      "Write",
				Args:      []byte(`{"file_path": "/tmp/test.txt", "content": "hello"}`),
				SessionID: "e2e-session-write",
			},
		},
		{
			name: "read_tool",
			req: aegis.CheckRequest{
				Tool:      "Read",
				Args:      []byte(`{"file_path": "/tmp/test.txt"}`),
				SessionID: "e2e-session-read",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := engine.Evaluate(ctx, tc.req)
			if resp.Decision.Action != aegis.ActionAllow && resp.Decision.Action != aegis.ActionDeny {
				t.Errorf("unexpected action for %s: %v", tc.name, resp.Decision.Action)
			}
			if resp.LatencyNs <= 0 {
				t.Errorf("expected positive latency, got %d ns", resp.LatencyNs)
			}
		})
	}
}
