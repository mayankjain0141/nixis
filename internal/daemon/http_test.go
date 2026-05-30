// SPDX-License-Identifier: MIT
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// --- mock evaluators for HTTP tests ---

type mockAllowEvaluator struct{}

func (mockAllowEvaluator) Evaluate(_ context.Context, _ nixis.CheckRequest) nixis.CheckResponse {
	return nixis.CheckResponse{
		Decision:       nixis.Decision{Action: nixis.ActionAllow},
		LatencyNs:      1234,
		EnforcingLayer: nixis.EnforcingLayerAdapter,
	}
}

type mockDenyEvaluator struct{}

func (mockDenyEvaluator) Evaluate(_ context.Context, req nixis.CheckRequest) nixis.CheckResponse {
	return nixis.CheckResponse{
		Decision: nixis.Decision{
			Action:   nixis.ActionDeny,
			Reason:   "blocked by policy",
			PolicyID: "block-dangerous-ops",
		},
		LatencyNs:      5678,
		EnforcingLayer: nixis.EnforcingLayerCEL,
	}
}

func TestCheckHandler_Allow(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockAllowEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"tool":"Read","args":{"file_path":"/tmp/safe.txt"},"session_id":"sess-1"}`
	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var out checkResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Decision.Action != "allow" {
		t.Errorf("decision.action = %q, want allow", out.Decision.Action)
	}
	if out.LatencyNs != 1234 {
		t.Errorf("latency_ns = %d, want 1234", out.LatencyNs)
	}
}

func TestCheckHandler_Deny(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockDenyEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"tool":"Shell","args":{"command":"rm -rf /"},"session_id":"sess-2"}`
	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var out checkResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Decision.Action != "deny" {
		t.Errorf("decision.action = %q, want deny", out.Decision.Action)
	}
	if out.Decision.Reason != "blocked by policy" {
		t.Errorf("decision.reason = %q, want 'blocked by policy'", out.Decision.Reason)
	}
	if out.Decision.PolicyID != "block-dangerous-ops" {
		t.Errorf("decision.policy_id = %q, want 'block-dangerous-ops'", out.Decision.PolicyID)
	}
}

func TestCheckHandler_MalformedJSON(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockAllowEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{not valid json`
	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCheckHandler_EmptyBody(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockAllowEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(""))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCheckHandler_MissingToolField(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockAllowEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"args":{"command":"ls"},"session_id":"sess-3"}`
	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCheckHandler_ContentTypeJSON(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	RegisterCheckHandler(mux, mockAllowEvaluator{})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"tool":"Read","args":{},"session_id":"s1"}`
	resp, err := http.Post(srv.URL+"/v1/check", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/check: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
