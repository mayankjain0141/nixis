// SPDX-License-Identifier: MIT
package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mayjain/aegis/internal/ifc"
	"github.com/google/uuid"
)

const maxApprovalTTLSeconds = 7200

// validEffects is the set of permitted effect strings for standing rules.
var validEffects = map[string]bool{
	"network_egress":       true,
	"content_publish":      true,
	"process_coordination": true,
	"content_internal":     true,
	"message_content":      true,
}

// approvalRequest is the JSON body for POST /api/v1/sessions/{sessionID}/approve.
type approvalRequest struct {
	Effect          string `json:"effect"`
	ResourcePattern string `json:"resource_pattern"`
	TTLSeconds      int    `json:"ttl_seconds"`
	GrantedBy       string `json:"granted_by"`
}

// approvalResponse is the JSON body returned on success.
type approvalResponse struct {
	StandingRuleID string `json:"standing_rule_id"`
	ExpiresAt      string `json:"expires_at"`
}

// handleApprove handles POST /api/v1/sessions/{sessionID}/approve.
func (d *Daemon) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Extract sessionID from path: /api/v1/sessions/{sessionID}/approve
	sessionID := extractSessionID(r.URL.Path)
	if sessionID == "" {
		writeJSONError(w, "session id required", http.StatusBadRequest)
		return
	}

	if d.sessions == nil {
		writeJSONError(w, "session not found", http.StatusNotFound)
		return
	}

	var req approvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !validEffects[req.Effect] {
		writeJSONError(w, "invalid effect", http.StatusBadRequest)
		return
	}

	if req.ResourcePattern == "" {
		writeJSONError(w, "resource_pattern required", http.StatusBadRequest)
		return
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 1800
	}
	if ttl > maxApprovalTTLSeconds {
		writeJSONError(w, "ttl_seconds exceeds maximum of 7200", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)

	rule := ifc.StandingRule{
		Effect:          req.Effect,
		ResourcePattern: req.ResourcePattern,
		ExpiresAt:       expiresAt,
		GrantedAt:       now,
		GrantedBy:       req.GrantedBy,
	}

	d.sessions.AddStandingRule(sessionID, rule)

	ruleID := uuid.NewString()

	resp := approvalResponse{
		StandingRuleID: ruleID,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// extractSessionID parses the sessionID from a path of the form
// /api/v1/sessions/{sessionID}/approve.
func extractSessionID(path string) string {
	// Strip trailing slash
	path = strings.TrimRight(path, "/")

	// Expect: /api/v1/sessions/<id>/approve
	const prefix = "/api/v1/sessions/"
	const suffix = "/approve"

	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}

	// Guard against paths like /api/v1/sessions/approve (no room for sessionID)
	if len(path) <= len(prefix)+len(suffix) {
		return ""
	}

	mid := path[len(prefix) : len(path)-len(suffix)]
	if mid == "" || strings.Contains(mid, "/") {
		return ""
	}
	return mid
}

// writeJSONError writes a JSON error body with the given status code.
func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// registerApprovalRoutes wires the approval endpoint into the mux.
func (d *Daemon) registerApprovalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/sessions/", d.handleApprove)
}
