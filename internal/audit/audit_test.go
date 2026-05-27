package audit_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/pkg/aegis"
	_ "modernc.org/sqlite"
)

func newTestWriter(t *testing.T) (*audit.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	w, err := audit.NewWriter(dbPath)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w, dbPath
}

// TestAudit_WriteRecord_Roundtrip writes a record and reads it back to verify fields.
func TestAudit_WriteRecord_Roundtrip(t *testing.T) {
	w, dbPath := newTestWriter(t)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Start(ctx)
	}()

	now := time.Now().UnixNano()
	rec := audit.AuditRecord{
		Timestamp: now,
		SessionID: "sess-abc",
		Tool:      "bash",
		Args:      json.RawMessage(`{"cmd":"ls"}`),
		Decision: aegis.Decision{
			Action:   aegis.ActionAllow,
			Reason:   "policy matched",
			PolicyID: "pol-001",
		},
		LatencyNs:      12345,
		PolicyID:       "pol-001",
		EnforcingLayer: aegis.EnforcingLayerCEL,
		LabelBefore:    aegis.SecurityLabel{Confidentiality: 1, Integrity: 2, Category: 3},
		LabelAfter:     aegis.SecurityLabel{Confidentiality: 2, Integrity: 2, Category: 3},
	}

	w.WriteRecord(rec)

	// Give the batch timer time to flush (>100ms).
	time.Sleep(200 * time.Millisecond)

	cancel()
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}

	// Read back from DB directly.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var (
		sessionID string
		tool      string
		action    string
		reason    string
		policyID  string
		latencyNs int64
		labelBefC int
		labelBefI int
		labelAftC int
	)
	row := db.QueryRow(`SELECT session_id, tool, action, reason, policy_id, latency_ns,
		label_before_c, label_before_i, label_after_c
		FROM audit_log LIMIT 1`)
	if err := row.Scan(&sessionID, &tool, &action, &reason, &policyID, &latencyNs,
		&labelBefC, &labelBefI, &labelAftC); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if sessionID != "sess-abc" {
		t.Errorf("session_id: got %q, want %q", sessionID, "sess-abc")
	}
	if tool != "bash" {
		t.Errorf("tool: got %q, want %q", tool, "bash")
	}
	if action != "allow" {
		t.Errorf("action: got %q, want %q", action, "allow")
	}
	if reason != "policy matched" {
		t.Errorf("reason: got %q, want %q", reason, "policy matched")
	}
	if policyID != "pol-001" {
		t.Errorf("policy_id: got %q, want %q", policyID, "pol-001")
	}
	if latencyNs != 12345 {
		t.Errorf("latency_ns: got %d, want 12345", latencyNs)
	}
	if labelBefC != 1 {
		t.Errorf("label_before_c: got %d, want 1", labelBefC)
	}
	if labelAftC != 2 {
		t.Errorf("label_after_c: got %d, want 2", labelAftC)
	}
}

// TestAudit_AppendOnly_NoUpdate verifies the schema DDL and audit.go contain no UPDATE/DELETE.
func TestAudit_AppendOnly_NoUpdate(t *testing.T) {
	src, err := os.ReadFile("audit.go")
	if err != nil {
		t.Fatalf("read audit.go: %v", err)
	}

	upper := strings.ToUpper(string(src))

	// Strip comments (lines starting with //).
	lines := strings.Split(upper, "\n")
	var nonComment []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		nonComment = append(nonComment, line)
	}
	code := strings.Join(nonComment, "\n")

	for _, forbidden := range []string{"UPDATE ", "DELETE "} {
		// Allow "DELETE" only when it appears inside a SQL string comment-context check
		// (it shouldn't; if it does, the test catches it).
		if strings.Contains(code, forbidden) {
			t.Errorf("audit.go contains forbidden SQL keyword %q — audit log must be append-only", forbidden)
		}
	}
}

// TestAudit_SanitizeArgs_RedactsSecrets verifies that secret-named fields are redacted.
func TestAudit_SanitizeArgs_RedactsSecrets(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
	}{
		{
			name:    "api_key field",
			input:   `{"api_key":"sk-supersecret","model":"gpt-4"}`,
			wantKey: "api_key",
			wantVal: "[REDACTED]",
		},
		{
			name:    "token field",
			input:   `{"access_token":"tok123","user":"alice"}`,
			wantKey: "access_token",
			wantVal: "[REDACTED]",
		},
		{
			name:    "password field",
			input:   `{"password":"hunter2","user":"bob"}`,
			wantKey: "password",
			wantVal: "[REDACTED]",
		},
		{
			name:    "secret field",
			input:   `{"client_secret":"s3cr3t"}`,
			wantKey: "client_secret",
			wantVal: "[REDACTED]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := audit.SanitizeArgs(json.RawMessage(tc.input))

			var m map[string]interface{}
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("unmarshal output: %v", err)
			}
			val, ok := m[tc.wantKey]
			if !ok {
				t.Fatalf("key %q missing from output", tc.wantKey)
			}
			if val != tc.wantVal {
				t.Errorf("field %q: got %q, want %q", tc.wantKey, val, tc.wantVal)
			}
		})
	}
}

// TestAudit_SanitizeArgs_PreservesNonSecret verifies that non-secret fields are unchanged.
func TestAudit_SanitizeArgs_PreservesNonSecret(t *testing.T) {
	input := `{"cmd":"ls","path":"/tmp"}`
	out := audit.SanitizeArgs(json.RawMessage(input))

	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["cmd"] != "ls" {
		t.Errorf("cmd: got %v, want ls", m["cmd"])
	}
}

// TestAudit_WriteRecord_NonBlocking verifies WriteRecord returns immediately even when busy.
func TestAudit_WriteRecord_NonBlocking(t *testing.T) {
	w, _ := newTestWriter(t)
	// Do NOT start the writer goroutine — channel will fill up.

	rec := audit.AuditRecord{
		Timestamp: time.Now().UnixNano(),
		SessionID: "sess-nb",
		Tool:      "bash",
	}

	// Fill the channel (cap=1024) and a bit more; all calls must return fast.
	start := time.Now()
	for i := 0; i < 1100; i++ {
		w.WriteRecord(rec)
	}
	elapsed := time.Since(start)

	// All 1100 calls should complete in well under 1 second with no blocking.
	if elapsed > time.Second {
		t.Errorf("WriteRecord blocked: elapsed=%v, want <1s", elapsed)
	}

	// Some events must have been dropped.
	dropped := w.Dropped()
	if dropped == 0 {
		t.Error("expected some dropped events when channel is full, got 0")
	}

	if err := w.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}
}

// TestAudit_SessionLabel_Write verifies session label records are persisted correctly.
func TestAudit_SessionLabel_Write(t *testing.T) {
	w, dbPath := newTestWriter(t)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Start(ctx)
	}()

	now := time.Now().UnixNano()
	lrec := audit.SessionLabelRecord{
		SessionID:  "sess-label-01",
		LabelState: "escalated",
		Label:      aegis.SecurityLabel{Confidentiality: 3, Integrity: 1, Category: 7},
		ChangedAt:  now,
	}
	w.WriteSessionLabel(lrec)

	time.Sleep(200 * time.Millisecond)

	cancel()
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var (
		sessionID  string
		labelState string
		labelC     int
		labelI     int
		labelK     uint32
		changedAt  int64
	)
	row := db.QueryRow(`SELECT session_id, label_state, label_c, label_i, label_k, changed_at
		FROM session_labels LIMIT 1`)
	if err := row.Scan(&sessionID, &labelState, &labelC, &labelI, &labelK, &changedAt); err != nil {
		t.Fatalf("scan session_labels: %v", err)
	}

	if sessionID != "sess-label-01" {
		t.Errorf("session_id: got %q, want %q", sessionID, "sess-label-01")
	}
	if labelState != "escalated" {
		t.Errorf("label_state: got %q, want %q", labelState, "escalated")
	}
	if labelC != 3 {
		t.Errorf("label_c: got %d, want 3", labelC)
	}
	if labelI != 1 {
		t.Errorf("label_i: got %d, want 1", labelI)
	}
	if labelK != 7 {
		t.Errorf("label_k: got %d, want 7", labelK)
	}
	if changedAt != now {
		t.Errorf("changed_at: got %d, want %d", changedAt, now)
	}
}
