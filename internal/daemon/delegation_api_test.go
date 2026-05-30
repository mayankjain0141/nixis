package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mayankjain0141/nixis/internal/delegation"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// newDelegEngine creates a delegation.Engine with a fresh ephemeral key pair.
func newDelegEngine(t *testing.T) (*delegation.Engine, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("delegation.New: %v", err)
	}
	return eng, priv
}

// registerTestChain builds a signed single-token chain via ValidateChain and
// registers it under chainID. Returns the engine for further assertions.
func registerTestChain(t *testing.T, eng *delegation.Engine, priv ed25519.PrivateKey, chainID string) {
	t.Helper()
	tok := delegation.DelegationToken{
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(time.Hour),
		MaxDepth:  1,
		Capabilities: delegation.CapabilitySet{
			Operations: 0x0001,
		},
	}
	tok.Signature = ed25519.Sign(priv, tok.CanonicalBytes())

	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	refs := []nixis.DelegationRef{{TokenID: string(raw), Issuer: tok.Issuer}}
	chain, err := eng.ValidateChain(refs, time.Now())
	if err != nil {
		t.Fatalf("ValidateChain: %v", err)
	}
	eng.Register(chainID, chain)
}

// chainIsInList returns true if chainID appears in the list endpoint response.
func chainIsInList(t *testing.T, mux *http.ServeMux, chainID string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/list", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list returned %d", rr.Code)
	}
	var resp struct {
		Chains []delegation.ActiveChainInfo `json:"chains"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, c := range resp.Chains {
		if c.ChainID == chainID {
			return true
		}
	}
	return false
}

func TestDaemonAPI_RevokeEndpoint(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body := `{"chain_id":"test-chain-revoke"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/delegation/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if revoked, ok := resp["revoked"].(bool); !ok || !revoked {
		t.Errorf("expected revoked=true, got %v", resp)
	}
	if resp["chain_id"] != "test-chain-revoke" {
		t.Errorf("expected chain_id=test-chain-revoke, got %v", resp["chain_id"])
	}
}

func TestDaemonAPI_RevokeEndpoint_MissingChainID(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/delegation/revoke", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing chain_id, got %d", rr.Code)
	}
}

func TestDaemonAPI_RevokeEndpoint_WrongMethod(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/revoke", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on revoke, got %d", rr.Code)
	}
}

func TestDaemonAPI_ListEndpoint(t *testing.T) {
	eng, priv := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	registerTestChain(t, eng, priv, "list-chain-1")

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/list", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Chains []delegation.ActiveChainInfo `json:"chains"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(resp.Chains))
	}
	if resp.Chains[0].ChainID != "list-chain-1" {
		t.Errorf("expected chain_id=list-chain-1, got %q", resp.Chains[0].ChainID)
	}
}

func TestDaemonAPI_ListEndpoint_Empty(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/list", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty list, got %d", rr.Code)
	}
	var resp struct {
		Chains []delegation.ActiveChainInfo `json:"chains"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Chains) != 0 {
		t.Errorf("expected empty chains, got %d", len(resp.Chains))
	}
}

func TestDaemonAPI_ListEndpoint_WrongMethod(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/delegation/list", bytes.NewReader(nil))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST on list, got %d", rr.Code)
	}
}

func TestDelegationAPI_RevokeRemovesFromList(t *testing.T) {
	eng, priv := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	registerTestChain(t, eng, priv, "revoke-then-list")

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// Verify chain is present via list endpoint.
	if !chainIsInList(t, mux, "revoke-then-list") {
		t.Fatal("chain should be active before revoke")
	}

	// Revoke it via the API.
	body := `{"chain_id":"revoke-then-list"}`
	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/delegation/revoke", strings.NewReader(body))
	revokeReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, revokeReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke returned %d: %s", rr.Code, rr.Body.String())
	}

	// List must no longer include the revoked chain.
	if chainIsInList(t, mux, "revoke-then-list") {
		t.Error("revoked chain still appears in list response")
	}
}

func TestDaemonAPI_ContentTypeJSON(t *testing.T) {
	eng, _ := newDelegEngine(t)
	api := NewDelegationAPI(eng)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/list", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// TestDaemonHealthzStillServedWithDelegAPI verifies that /healthz and delegation
// routes coexist on the same mux without interfering.
func TestDaemonHealthzStillServedWithDelegAPI(t *testing.T) {
	eng, _ := newDelegEngine(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	api := NewDelegationAPI(eng)
	api.RegisterRoutes(mux)

	// /healthz still works.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from /healthz, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != "ok" {
		t.Errorf("expected body 'ok', got %q", string(body))
	}

	// Delegation list also works on the same mux.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/delegation/list", nil)
	lrr := httptest.NewRecorder()
	mux.ServeHTTP(lrr, listReq)
	if lrr.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/v1/delegation/list, got %d", lrr.Code)
	}
}
