package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mayjain/aegis/internal/mcp"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockUpstream struct {
	callCount  int
	callResult json.RawMessage
	callErr    error
	tools      []mcp.ToolDefinition
}

func (m *mockUpstream) Call(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	m.callCount++
	return m.callResult, m.callErr
}

func (m *mockUpstream) ListTools(_ context.Context) ([]mcp.ToolDefinition, error) {
	return m.tools, nil
}

func (m *mockUpstream) Close() error { return nil }

type mockPipeline struct {
	resp aegis.CheckResponse
}

func (m *mockPipeline) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return m.resp
}

type mockScanner struct {
	findings []policy.Finding
	detected bool
}

func (s *mockScanner) ScanBoundary(_ context.Context, _ string, _ policy.BoundaryType) ([]policy.Finding, aegis.SecurityLabel) {
	if s.detected {
		s.findings = []policy.Finding{{Rule: "test-secret-rule"}}
	}
	return s.findings, aegis.SecurityLabel{}
}

func (s *mockScanner) ShouldScan(_ []string, _ policy.BoundaryType) bool {
	return true
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func toolCallRequest(toolName string) mcp.JSONRPCRequest {
	params, _ := json.Marshal(map[string]any{
		"name":      toolName,
		"arguments": map[string]any{"key": "value"},
	})
	id, _ := json.Marshal(1)
	return mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	}
}

func allowPipeline() *mockPipeline {
	return &mockPipeline{resp: aegis.CheckResponse{
		Decision: aegis.Decision{Action: aegis.ActionAllow},
	}}
}

func denyPipeline(reason string) *mockPipeline {
	return &mockPipeline{resp: aegis.CheckResponse{
		Decision: aegis.Decision{Action: aegis.ActionDeny, Reason: reason},
	}}
}

func requireApprovalPipeline() *mockPipeline {
	return &mockPipeline{resp: aegis.CheckResponse{
		Decision: aegis.Decision{Action: aegis.ActionRequireApproval, Reason: "needs approval"},
	}}
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestMCP_ToolDrift_RequireApproval(t *testing.T) {
	tracker := mcp.NewIntegrityTracker()

	tool1 := mcp.ToolDefinition{Name: "bash", Description: "v1", InputSchema: json.RawMessage(`{}`)}
	tool2 := mcp.ToolDefinition{Name: "bash", Description: "v2 — changed", InputSchema: json.RawMessage(`{}`)}

	hasDrift1, _ := tracker.CheckDrift(tool1)
	if hasDrift1 {
		t.Fatal("first call must not report drift")
	}

	hasDrift2, _ := tracker.CheckDrift(tool2)
	if !hasDrift2 {
		t.Fatal("second call with different description must report drift")
	}
}

func TestMCP_RequestDeny_NoForward(t *testing.T) {
	upstream := &mockUpstream{callResult: json.RawMessage(`"ok"`)}
	proxy := mcp.New(upstream, denyPipeline("not allowed"), nil, "sess-1")

	resp := proxy.HandleRequest(context.Background(), toolCallRequest("bash"))
	proxy.Wait()

	if resp.Error == nil {
		t.Fatal("expected error response on DENY")
	}
	if upstream.callCount != 0 {
		t.Fatalf("upstream must not be called on DENY, got callCount=%d", upstream.callCount)
	}
}

func TestMCP_ResponseScan_TaintsLabel(t *testing.T) {
	upstream := &mockUpstream{callResult: json.RawMessage(`"AKIAIOSFODNN7EXAMPLE"`)}
	scanner := &mockScanner{detected: true}
	proxy := mcp.New(upstream, allowPipeline(), scanner, "sess-secret")

	resp := proxy.HandleRequest(context.Background(), toolCallRequest("read_file"))
	proxy.Wait()

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if len(scanner.findings) == 0 {
		t.Fatal("scanner must have returned findings for secret content")
	}
}

func TestMCP_IntegrityTracker_FirstCallSetsBaseline(t *testing.T) {
	tracker := mcp.NewIntegrityTracker()
	tool := mcp.ToolDefinition{Name: "read", Description: "reads a file", InputSchema: json.RawMessage(`{}`)}

	hasDrift, baselineHash := tracker.CheckDrift(tool)
	if hasDrift {
		t.Fatal("first call must return hasDrift=false")
	}
	expected := tracker.Fingerprint(tool)
	if baselineHash != expected {
		t.Fatalf("baseline hash mismatch: got %x want %x", baselineHash, expected)
	}
}

func TestMCP_IntegrityTracker_DriftDetected(t *testing.T) {
	tracker := mcp.NewIntegrityTracker()
	tool1 := mcp.ToolDefinition{Name: "write", Description: "original", InputSchema: json.RawMessage(`{}`)}
	tool2 := mcp.ToolDefinition{Name: "write", Description: "tampered description", InputSchema: json.RawMessage(`{}`)}

	tracker.CheckDrift(tool1)
	hasDrift, _ := tracker.CheckDrift(tool2)
	if !hasDrift {
		t.Fatal("expected drift when description changes")
	}
}

func TestMCP_Fingerprint_Deterministic(t *testing.T) {
	tracker := mcp.NewIntegrityTracker()
	tool := mcp.ToolDefinition{
		Name:        "grep",
		Description: "search files",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"pattern":{"type":"string"}}}`),
	}

	h1 := tracker.Fingerprint(tool)
	h2 := tracker.Fingerprint(tool)
	h3 := tracker.Fingerprint(tool)

	if h1 != h2 || h2 != h3 {
		t.Fatalf("fingerprint not deterministic: %x %x %x", h1, h2, h3)
	}
}

func TestMCP_PassThrough_NonToolCall(t *testing.T) {
	expected := json.RawMessage(`{"name":"aegis-mcp","version":"0.1"}`)
	upstream := &mockUpstream{callResult: expected}
	proxy := mcp.New(upstream, denyPipeline("should not reach pipeline"), nil, "sess-2")

	id, _ := json.Marshal(42)
	req := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "initialize",
		Params:  json.RawMessage(`{}`),
	}

	resp := proxy.HandleRequest(context.Background(), req)
	proxy.Wait()

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if string(resp.Result) != string(expected) {
		t.Fatalf("pass-through result mismatch: got %s want %s", resp.Result, expected)
	}
	if upstream.callCount != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", upstream.callCount)
	}
}

func TestMCP_GovernancePipeline_Allow_Forwards(t *testing.T) {
	expected := json.RawMessage(`{"exit":0}`)
	upstream := &mockUpstream{callResult: expected}
	proxy := mcp.New(upstream, allowPipeline(), nil, "sess-3")

	resp := proxy.HandleRequest(context.Background(), toolCallRequest("bash"))
	proxy.Wait()

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if upstream.callCount != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", upstream.callCount)
	}
}

func TestMCP_RequireApproval_ReturnsError(t *testing.T) {
	upstream := &mockUpstream{callResult: json.RawMessage(`"ok"`)}
	proxy := mcp.New(upstream, requireApprovalPipeline(), nil, "sess-4")

	resp := proxy.HandleRequest(context.Background(), toolCallRequest("deploy"))
	proxy.Wait()

	if resp.Error == nil {
		t.Fatal("expected error response on REQUIRE_APPROVAL")
	}
	if upstream.callCount != 0 {
		t.Fatalf("upstream must not be called on REQUIRE_APPROVAL, got callCount=%d", upstream.callCount)
	}
}
