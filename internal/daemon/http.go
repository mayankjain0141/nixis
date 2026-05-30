// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// Evaluator is the interface the HTTP handler needs for policy evaluation.
type Evaluator interface {
	Evaluate(ctx context.Context, req nixis.CheckRequest) nixis.CheckResponse
}

// checkRequestJSON is the REST wire format for incoming /v1/check requests.
// Uses snake_case JSON tags for SDK consumer ergonomics.
type checkRequestJSON struct {
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args"`
	SessionID string          `json:"session_id"`
}

// checkResponseJSON is the wire format for the /v1/check response.
type checkResponseJSON struct {
	Decision    decisionJSON   `json:"decision"`
	LatencyNs   int64          `json:"latency_ns"`
	Layer       string         `json:"enforcing_layer,omitempty"`
	Annotations []annotationJSON `json:"annotations,omitempty"`
}

type decisionJSON struct {
	Action   string `json:"action"`
	Reason   string `json:"reason,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

type annotationJSON struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RegisterCheckHandler adds the POST /v1/check endpoint to the given mux.
// The handler accepts a CheckRequest JSON body and returns a CheckResponse.
// It enforces a 50ms evaluation deadline consistent with the daemon's socket handler.
func RegisterCheckHandler(mux *http.ServeMux, engine Evaluator) {
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, nixis.MaxMessageSize)

		var wire checkRequestJSON
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid request body: " + err.Error(),
			})
			return
		}

		if wire.Tool == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "missing required field: tool",
			})
			return
		}

		req := nixis.CheckRequest{
			Tool:      wire.Tool,
			Args:      wire.Args,
			SessionID: wire.SessionID,
		}

		evalCtx, cancel := context.WithTimeout(r.Context(), evaluationDeadline)
		defer cancel()

		resp := engine.Evaluate(evalCtx, req)

		if evalCtx.Err() == context.DeadlineExceeded {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "evaluation deadline exceeded",
			})
			return
		}

		out := checkResponseJSON{
			Decision: decisionJSON{
				Action:   actionString(resp.Decision.Action),
				Reason:   resp.Decision.Reason,
				PolicyID: resp.Decision.PolicyID,
			},
			LatencyNs: resp.LatencyNs,
			Layer:     string(resp.EnforcingLayer),
		}
		for _, a := range resp.Annotations {
			out.Annotations = append(out.Annotations, annotationJSON{Key: a.Key, Value: a.Value})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	})
}
