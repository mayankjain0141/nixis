package stream

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mayjain/nixis/pkg/nixis"
)

// mockPolicyLister is a test implementation of nixis.PolicyLister.
type mockPolicyLister struct {
	policies []nixis.PolicySummary
}

func (m *mockPolicyLister) ListPolicies() []nixis.PolicySummary {
	return m.policies
}

func TestHandlePoliciesNilLister(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	// policyLister is nil — should return 501.

	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	rec := httptest.NewRecorder()
	s.handlePolicies(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 Not Implemented, got %d", rec.Code)
	}
}

func TestHandlePoliciesGET(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithPolicyLister(&mockPolicyLister{
		policies: []nixis.PolicySummary{
			{ID: "p1", Name: "Policy One", Layer: "cel", Enabled: true, CelExpression: "true", Description: "desc1"},
			{ID: "p2", Name: "Policy Two", Layer: "ifc", Enabled: true},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	rec := httptest.NewRecorder()
	s.handlePolicies(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var got []PolicyInfo
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(got))
	}
	if got[0].ID != "p1" || got[0].Name != "Policy One" || got[0].Layer != "cel" {
		t.Errorf("first policy mismatch: %+v", got[0])
	}
	if got[0].CelExpression != "true" {
		t.Errorf("expected cel_expression 'true', got %q", got[0].CelExpression)
	}
	if got[1].ID != "p2" || got[1].Layer != "ifc" {
		t.Errorf("second policy mismatch: %+v", got[1])
	}
}

func TestHandlePoliciesPOST(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithPolicyLister(&mockPolicyLister{}))

	req := httptest.NewRequest(http.MethodPost, "/policies", nil)
	rec := httptest.NewRecorder()
	s.handlePolicies(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rec.Code)
	}
}

func TestHandlePoliciesOPTIONS(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithPolicyLister(&mockPolicyLister{}))

	req := httptest.NewRequest(http.MethodOptions, "/policies", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	s.handlePolicies(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Errorf("CORS Allow-Origin header missing or wrong: %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Methods") != "GET, OPTIONS" {
		t.Errorf("CORS Allow-Methods header missing or wrong: %q", rec.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestHandlePoliciesCORSNonLocalhost(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithPolicyLister(&mockPolicyLister{
		policies: []nixis.PolicySummary{{ID: "p1", Name: "P1", Layer: "cel", Enabled: true}},
	}))

	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	s.handlePolicies(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("CORS header must not be set for non-localhost origin")
	}
}
