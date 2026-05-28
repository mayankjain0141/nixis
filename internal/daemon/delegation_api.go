package daemon

import (
	"encoding/json"
	"net/http"

	"github.com/mayjain/aegis/internal/delegation"
)

// DelegationAPI exposes delegation chain operations over HTTP.
type DelegationAPI struct {
	engine *delegation.Engine
}

// NewDelegationAPI constructs a DelegationAPI backed by the given Engine.
func NewDelegationAPI(engine *delegation.Engine) *DelegationAPI {
	return &DelegationAPI{engine: engine}
}

// RegisterRoutes registers delegation endpoints on mux.
func (a *DelegationAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/delegation/revoke", a.handleRevoke)
	mux.HandleFunc("/api/v1/delegation/list", a.handleList)
}

// handleRevoke handles POST /api/v1/delegation/revoke.
// Body: {"chain_id": "<id>"}
// Response: {"revoked": true, "chain_id": "<id>"}
func (a *DelegationAPI) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ChainID string `json:"chain_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChainID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"chain_id required"}`))
		return
	}
	a.engine.Revoke(req.ChainID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"revoked": true, "chain_id": req.ChainID}); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

// handleList handles GET /api/v1/delegation/list.
// Response: {"chains": [...]}
func (a *DelegationAPI) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	chains := a.engine.ListActive()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"chains": chains}); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}
