package mcp_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/mcp"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
	_ "modernc.org/sqlite"
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

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test db: %v", err)
		}
	})
	return db
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestMCP_ToolDrift_RequireApproval verifies that a tools/call to a tool whose
// definition has drifted since the last tools/list is blocked with a
// RequireApproval error and the upstream is never contacted.
func TestMCP_ToolDrift_RequireApproval(t *testing.T) {
	tool1 := mcp.ToolDefinition{Name: "bash", Description: "v1", InputSchema: json.RawMessage(`{}`)}
	tool2 := mcp.ToolDefinition{Name: "bash", Description: "v2 — changed", InputSchema: json.RawMessage(`{}`)}

	upstream := &mockUpstream{
		callResult: json.RawMessage(`{"exit":0}`),
		tools:      []mcp.ToolDefinition{tool1},
	}
	proxy := mcp.NewInMemory(upstream, allowPipeline(), nil, "sess-drift")

	// First tools/list — sets baseline for "bash".
	id1, _ := json.Marshal(1)
	listReq1 := mcp.JSONRPCRequest{JSONRPC: "2.0", ID: id1, Method: "tools/list"}
	resp1 := proxy.HandleRequest(context.Background(), listReq1)
	if resp1.Error != nil {
		t.Fatalf("first tools/list failed: %v", resp1.Error)
	}

	// Second tools/list — with changed description, drift detected.
	upstream.tools = []mcp.ToolDefinition{tool2}
	id2, _ := json.Marshal(2)
	listReq2 := mcp.JSONRPCRequest{JSONRPC: "2.0", ID: id2, Method: "tools/list"}
	resp2 := proxy.HandleRequest(context.Background(), listReq2)
	if resp2.Error != nil {
		t.Fatalf("second tools/list failed: %v", resp2.Error)
	}

	// tools/call to the drifted tool must return an error without forwarding.
	callResp := proxy.HandleRequest(context.Background(), toolCallRequest("bash"))
	proxy.Wait()

	if callResp.Error == nil {
		t.Fatal("expected RequireApproval error for drifted tool call")
	}
	// upstream.callCount must still be 0 (only ListTools was called, not Call)
	if upstream.callCount != 0 {
		t.Fatalf("upstream.Call must not be invoked for drifted tool, got callCount=%d", upstream.callCount)
	}
}

func TestMCP_RequestDeny_NoForward(t *testing.T) {
	upstream := &mockUpstream{callResult: json.RawMessage(`"ok"`)}
	proxy := mcp.NewInMemory(upstream, denyPipeline("not allowed"), nil, "sess-1")

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
	proxy := mcp.NewInMemory(upstream, allowPipeline(), scanner, "sess-secret")

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
	proxy := mcp.NewInMemory(upstream, denyPipeline("should not reach pipeline"), nil, "sess-2")

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
	proxy := mcp.NewInMemory(upstream, allowPipeline(), nil, "sess-3")

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
	proxy := mcp.NewInMemory(upstream, requireApprovalPipeline(), nil, "sess-4")

	resp := proxy.HandleRequest(context.Background(), toolCallRequest("deploy"))
	proxy.Wait()

	if resp.Error == nil {
		t.Fatal("expected error response on REQUIRE_APPROVAL")
	}
	if upstream.callCount != 0 {
		t.Fatalf("upstream must not be called on REQUIRE_APPROVAL, got callCount=%d", upstream.callCount)
	}
}

// TestMCP_BaselinePersistence verifies that NewIntegrityTrackerWithDB loads
// baselines from SQLite on construction, so drift detection survives restarts.
func TestMCP_BaselinePersistence(t *testing.T) {
	db := openTestDB(t)
	tool := mcp.ToolDefinition{Name: "persist-tool", Description: "original", InputSchema: json.RawMessage(`{}`)}

	// First tracker instance records the baseline.
	tracker1, err := mcp.NewIntegrityTrackerWithDB(db)
	if err != nil {
		t.Fatalf("NewIntegrityTrackerWithDB: %v", err)
	}
	hasDrift, _ := tracker1.CheckDrift(tool)
	if hasDrift {
		t.Fatal("first call must not report drift")
	}

	// Second tracker instance on the same DB must load the baseline.
	tracker2, err := mcp.NewIntegrityTrackerWithDB(db)
	if err != nil {
		t.Fatalf("NewIntegrityTrackerWithDB (reload): %v", err)
	}
	// Same definition — no drift even though this is the first CheckDrift call on tracker2.
	hasDrift2, _ := tracker2.CheckDrift(tool)
	if hasDrift2 {
		t.Fatal("reloaded tracker must not report drift for unchanged tool")
	}

	// Changed definition must be detected as drift by the reloaded tracker.
	changed := mcp.ToolDefinition{Name: "persist-tool", Description: "tampered", InputSchema: json.RawMessage(`{}`)}
	hasDrift3, _ := tracker2.CheckDrift(changed)
	if !hasDrift3 {
		t.Fatal("reloaded tracker must detect drift for changed tool")
	}
}

// TestMCP_CircuitBreaker_OpensAfterThreshold verifies that after 5 consecutive
// upstream failures the circuit opens and subsequent calls return an error
// without contacting the upstream.
func TestMCP_CircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := mcp.NewCircuitBreaker(5, 30*time.Second)

	// Record 5 failures — should open the circuit.
	for i := 0; i < 5; i++ {
		if !cb.Allow() {
			t.Fatalf("circuit should be closed before threshold, iteration %d", i)
		}
		cb.RecordFailure()
	}

	// Circuit must now be open.
	if cb.Allow() {
		t.Fatal("circuit must be open after threshold failures")
	}
}

// TestMCP_CircuitBreaker_RecoveryAfterSuccess verifies RecordSuccess resets the
// failure count so the circuit stays closed.
func TestMCP_CircuitBreaker_RecoveryAfterSuccess(t *testing.T) {
	cb := mcp.NewCircuitBreaker(5, 30*time.Second)

	// 4 failures followed by a success — circuit must stay closed.
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	cb.RecordSuccess()

	// One more failure — counter was reset, so circuit is still closed.
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("circuit must still be closed after success reset")
	}
}
