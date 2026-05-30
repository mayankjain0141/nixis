package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// fakeEvaluator is a test double for the Evaluator interface.
type fakeEvaluator struct {
	resp nixis.CheckResponse
}

func (f *fakeEvaluator) Evaluate(_ context.Context, _ nixis.CheckRequest) nixis.CheckResponse {
	return f.resp
}

func TestSimulate_ReturnsDecisionAndEmitsEvent(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithEvaluator(&fakeEvaluator{
		resp: nixis.CheckResponse{
			Decision: nixis.Decision{
				Action: nixis.ActionDeny,
				Reason: "blocked by policy",
			},
			EnforcingLayer: nixis.EnforcingLayerCEL,
			LatencyNs:      100,
		},
	}))

	// Subscribe to emitted events before calling /simulate.
	eventCh := make(chan nixis.StreamEvent, 1)
	go func() {
		ev := <-s.events
		eventCh <- ev
	}()

	req := nixis.CheckRequest{
		Tool:      "Bash",
		SessionID: "test-session-1",
		Timestamp: time.Now().UnixNano(),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/simulate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleSimulate(w, r)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var resp nixis.CheckResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Decision.Action != nixis.ActionDeny {
		t.Errorf("expected action=deny, got %v", resp.Decision.Action)
	}
	if resp.Decision.Reason != "blocked by policy" {
		t.Errorf("expected reason 'blocked by policy', got %q", resp.Decision.Reason)
	}

	// Verify event was emitted to the stream.
	select {
	case ev := <-eventCh:
		if ev.Type != "policy.denied" {
			t.Errorf("expected event type 'policy.denied', got %q", ev.Type)
		}
		if ev.SessionID != "test-session-1" {
			t.Errorf("expected session_id 'test-session-1', got %q", ev.SessionID)
		}
		if ev.Action != nixis.ActionDeny {
			t.Errorf("expected action deny in event, got %v", ev.Action)
		}
		if ev.Tool != "Bash" {
			t.Errorf("expected tool 'Bash' in event, got %q", ev.Tool)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for emitted event")
	}
}

func TestSimulate_MethodNotAllowed(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithEvaluator(&fakeEvaluator{}))
	r := httptest.NewRequest(http.MethodGet, "/simulate", nil)
	w := httptest.NewRecorder()
	s.handleSimulate(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestSimulate_NoEvaluator(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	r := httptest.NewRequest(http.MethodPost, "/simulate", bytes.NewReader([]byte(`{}`)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSimulate(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

func TestSimulate_FillsDefaultSessionIDAndTimestamp(t *testing.T) {
	var capturedReq nixis.CheckRequest
	capture := &capturingEvaluator{captureReq: &capturedReq}
	s := NewStreamServer(nil, nullReader{}, WithEvaluator(capture))
	// drain one event so Emit doesn't block
	go func() { <-s.events }()

	body := []byte(`{"tool":"Write"}`)
	r := httptest.NewRequest(http.MethodPost, "/simulate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	before := time.Now().UnixNano()
	s.handleSimulate(w, r)
	after := time.Now().UnixNano()

	if capturedReq.SessionID == "" {
		t.Error("expected SessionID to be filled in")
	}
	if capturedReq.Timestamp < before || capturedReq.Timestamp > after {
		t.Errorf("expected Timestamp within [%d, %d], got %d", before, after, capturedReq.Timestamp)
	}
}

func TestSimulate_CORSPreflight(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithEvaluator(&fakeEvaluator{}))
	r := httptest.NewRequest(http.MethodOptions, "/simulate", nil)
	r.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	s.handleSimulate(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("expected CORS origin header 'http://localhost:3000', got %q", got)
	}
}

func TestSimulate_AllowAction_EmitsPolicyEvaluated(t *testing.T) {
	s := NewStreamServer(nil, nullReader{}, WithEvaluator(&fakeEvaluator{
		resp: nixis.CheckResponse{
			Decision: nixis.Decision{
				Action: nixis.ActionAllow,
				Reason: "no policy matched",
			},
			EnforcingLayer: nixis.EnforcingLayerCEL,
			LatencyNs:      50,
		},
	}))

	eventCh := make(chan nixis.StreamEvent, 1)
	go func() {
		ev := <-s.events
		eventCh <- ev
	}()

	body := []byte(`{"tool":"Read","session_id":"sess-allow"}`)
	r := httptest.NewRequest(http.MethodPost, "/simulate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSimulate(w, r)

	select {
	case ev := <-eventCh:
		if ev.Type != "policy.evaluated" {
			t.Errorf("expected event type %q, got %q", "policy.evaluated", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for emitted event")
	}
}

// capturingEvaluator records the CheckRequest it receives.
type capturingEvaluator struct {
	captureReq *nixis.CheckRequest
}

func (c *capturingEvaluator) Evaluate(_ context.Context, req nixis.CheckRequest) nixis.CheckResponse {
	*c.captureReq = req
	return nixis.CheckResponse{
		Decision: nixis.Decision{Action: nixis.ActionAllow},
	}
}
