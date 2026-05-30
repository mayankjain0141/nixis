// SPDX-License-Identifier: MIT
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mayjain/nixis/internal/audit"
	"github.com/mayjain/nixis/internal/ifc"
)

// --- approval endpoint unit tests (no running daemon, direct handler call) ---

func newApprovalDaemon(t *testing.T, sessions *ifc.SessionLabels) *Daemon {
	t.Helper()
	dir := t.TempDir()
	w, err := audit.NewWriter(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = w.Close()
	})

	return &Daemon{
		auditWriter: w,
		sessions:    sessions,
	}
}

func postApproval(t *testing.T, d *Daemon, sessionID string, body approvalRequest) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := "/api/v1/sessions/" + sessionID + "/approve"
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	d.handleApprove(rr, req)
	return rr
}

func TestApprovalAPI_ValidRequest(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := newApprovalDaemon(t, sessions)

	rr := postApproval(t, d, "sess-1", approvalRequest{
		Effect:          "network_egress",
		ResourcePattern: "*.github.com",
		TTLSeconds:      1800,
		GrantedBy:       "user-ide",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp approvalResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StandingRuleID == "" {
		t.Error("standing_rule_id must not be empty")
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at must not be empty")
	}
	// Verify expiry is approximately now + 30 min
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	expected := time.Now().Add(1800 * time.Second)
	if diff := expiresAt.Sub(expected).Abs(); diff > 5*time.Second {
		t.Errorf("expires_at off by %v", diff)
	}

	// Verify AddStandingRule was called
	snap := sessions.Snapshot("sess-1")
	if len(snap.StandingRules) != 1 {
		t.Fatalf("expected 1 standing rule, got %d", len(snap.StandingRules))
	}
	rule := snap.StandingRules[0]
	if rule.Effect != "network_egress" {
		t.Errorf("effect = %q, want %q", rule.Effect, "network_egress")
	}
	if rule.ResourcePattern != "*.github.com" {
		t.Errorf("resource_pattern = %q, want %q", rule.ResourcePattern, "*.github.com")
	}
	if rule.GrantedBy != "user-ide" {
		t.Errorf("granted_by = %q, want %q", rule.GrantedBy, "user-ide")
	}
	if snap.ApprovalState != ifc.ApprovalStandingRule {
		t.Errorf("approval_state = %v, want ApprovalStandingRule", snap.ApprovalState)
	}
}

func TestApprovalAPI_InvalidEffect(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := newApprovalDaemon(t, sessions)

	rr := postApproval(t, d, "sess-bad-effect", approvalRequest{
		Effect:          "not_a_real_effect",
		ResourcePattern: "*.example.com",
		TTLSeconds:      300,
		GrantedBy:       "user",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var errResp map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp["error"] != "invalid effect" {
		t.Errorf("error message = %q, want %q", errResp["error"], "invalid effect")
	}
}

func TestApprovalAPI_MissingSessionID(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := newApprovalDaemon(t, sessions)

	// Path without sessionID
	b, _ := json.Marshal(approvalRequest{
		Effect:          "network_egress",
		ResourcePattern: "*.github.com",
		TTLSeconds:      300,
		GrantedBy:       "user",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions//approve", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	d.handleApprove(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing sessionID, got %d", rr.Code)
	}
}

func TestApprovalAPI_NilSessions_Returns404(t *testing.T) {
	d := newApprovalDaemon(t, nil)

	rr := postApproval(t, d, "sess-no-sessions", approvalRequest{
		Effect:          "network_egress",
		ResourcePattern: "*.github.com",
		TTLSeconds:      300,
		GrantedBy:       "user",
	})

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when sessions is nil, got %d", rr.Code)
	}
}

func TestApprovalAPI_TTLOverMax_Returns400(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := newApprovalDaemon(t, sessions)

	rr := postApproval(t, d, "sess-ttl", approvalRequest{
		Effect:          "content_publish",
		ResourcePattern: "*.example.com",
		TTLSeconds:      maxApprovalTTLSeconds + 1,
		GrantedBy:       "user",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for TTL over max, got %d: %s", rr.Code, rr.Body.String())
	}
	var errResp map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestApprovalAPI_AllValidEffects(t *testing.T) {
	effects := []string{
		"network_egress",
		"content_publish",
		"process_coordination",
		"content_internal",
		"message_content",
	}
	for _, eff := range effects {
		t.Run(eff, func(t *testing.T) {
			sessions := &ifc.SessionLabels{}
			d := newApprovalDaemon(t, sessions)
			rr := postApproval(t, d, "sess-"+eff, approvalRequest{
				Effect:          eff,
				ResourcePattern: "*.example.com",
				TTLSeconds:      600,
				GrantedBy:       "user",
			})
			if rr.Code != http.StatusOK {
				t.Errorf("effect %q: expected 200, got %d: %s", eff, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestApprovalAPI_MissingResourcePattern_Returns400(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := newApprovalDaemon(t, sessions)

	rr := postApproval(t, d, "sess-no-pattern", approvalRequest{
		Effect:     "network_egress",
		TTLSeconds: 300,
		GrantedBy:  "user",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing resource_pattern, got %d", rr.Code)
	}
}

func TestExtractSessionID(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/sessions/abc123/approve", "abc123"},
		{"/api/v1/sessions/my-session-id/approve", "my-session-id"},
		{"/api/v1/sessions//approve", ""},
		{"/api/v1/sessions/approve", ""},
		{"/api/v1/sessions/abc/bad/approve", ""},
		{"/other/path", ""},
	}
	for _, tc := range cases {
		got := extractSessionID(tc.path)
		if got != tc.want {
			t.Errorf("extractSessionID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
