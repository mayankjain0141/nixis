package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/aegis"
)

// --- stub engine implementations ---

type allowEngine struct{}

func (allowEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return aegis.CheckResponse{
		Decision:       aegis.Decision{Action: aegis.ActionAllow},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
}
func (allowEngine) Reload(_ context.Context, _ *aegis.CompiledBundle) error { return nil }

type denyEngine struct{ reason string }

func (e denyEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return aegis.CheckResponse{
		Decision:       aegis.Decision{Action: aegis.ActionDeny, Reason: e.reason},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
}
func (e denyEngine) Reload(_ context.Context, _ *aegis.CompiledBundle) error { return nil }

// nilSnapshotEngine simulates a PolicyEngine whose snapshot has not been loaded yet.
type nilSnapshotEngine struct{}

func (nilSnapshotEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return aegis.CheckResponse{
		Decision:       aegis.Decision{Action: aegis.ActionDeny, Reason: "policy engine not initialized"},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
}
func (nilSnapshotEngine) Reload(_ context.Context, _ *aegis.CompiledBundle) error { return nil }

// slowEngine sleeps for the given duration before returning, simulating a slow evaluation.
type slowEngine struct{ delay time.Duration }

func (e slowEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	time.Sleep(e.delay)
	return aegis.CheckResponse{
		Decision:       aegis.Decision{Action: aegis.ActionAllow},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
}
func (e slowEngine) Reload(_ context.Context, _ *aegis.CompiledBundle) error { return nil }

// --- helpers ---

// testSocketCounter generates short unique socket paths to stay within the
// 104-character AF_UNIX path limit on macOS.
var testSocketCounter atomic.Int64

// testPortCounter generates unique ports starting from 19091.
var testPortCounter atomic.Int64

func testSocketPath() string {
	n := testSocketCounter.Add(1)
	return filepath.Join(os.TempDir(), fmt.Sprintf("ae%d.sock", n))
}

func testHealthzAddr() string {
	port := 19091 + testPortCounter.Add(1)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func newTestAuditWriter(t *testing.T) (*audit.Writer, context.CancelFunc, <-chan struct{}) {
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
	return w, cancel, done
}

// startDaemon creates, wires, and runs a Daemon in a background goroutine.
// Returns the daemon and a channel closed once the listener is bound and ready.
// The daemon is stopped and fully drained in t.Cleanup before TempDir cleanup.
func startDaemon(t *testing.T, engine aegis.Engine) (*Daemon, <-chan struct{}) {
	t.Helper()
	socketPath := testSocketPath()
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cfg := Config{SocketPath: socketPath}
	w, auditCancel, auditDone := newTestAuditWriter(t)
	d := New(cfg, engine, w, nil, nil)
	d.SetAuditContext(auditCancel, auditDone)

	ready := make(chan struct{})
	d.setReadyCh(ready)

	runDone := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	go func() { runDone <- d.Run(ctx) }()

	// Cleanup: cancel context, drain runDone, then clean the socket.
	// This runs before TempDir cleanup (LIFO) since it's registered last.
	t.Cleanup(func() {
		cancel()
		// Drain runDone — may already have a value if Run() returned early.
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
	})

	return d, ready
}

// sendRequest dials the daemon socket and performs one framed request/response exchange.
func sendRequest(t *testing.T, socketPath string, req aegis.CheckRequest) aegis.CheckResponse {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	if err := WriteMessage(conn, payload, deadline); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	raw, err := ReadMessage(conn, deadline, aegis.MaxMessageSize)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	var resp aegis.CheckResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

// waitReady waits for the ready channel or fails the test after 10 seconds.
func waitReady(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("daemon never became ready")
	}
}

// --- tests ---

func TestDaemon_StartStop(t *testing.T) {
	d, ready := startDaemon(t, allowEngine{})
	waitReady(t, ready)

	info, err := os.Stat(d.cfg.SocketPath)
	if err != nil {
		t.Fatalf("socket file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != socketPermissions {
		t.Errorf("socket permissions: got %04o, want %04o", perm, socketPermissions)
	}
}

func TestDaemon_HandleRequest_Allow(t *testing.T) {
	d, ready := startDaemon(t, allowEngine{})
	waitReady(t, ready)

	resp := sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "ReadFile",
		SessionID: "sess-allow-test",
	})

	if resp.Decision.Action != aegis.ActionAllow {
		t.Errorf("expected Allow, got %v (reason: %q)", resp.Decision.Action, resp.Decision.Reason)
	}
}

func TestDaemon_HandleRequest_Deny(t *testing.T) {
	d, ready := startDaemon(t, denyEngine{reason: "blocked tool"})
	waitReady(t, ready)

	resp := sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "Shell",
		SessionID: "sess-deny-test",
	})

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected Deny, got %v", resp.Decision.Action)
	}
	if resp.Decision.Reason != "blocked tool" {
		t.Errorf("unexpected reason: %q", resp.Decision.Reason)
	}
}

func TestDaemon_MaxMessageSize(t *testing.T) {
	d, ready := startDaemon(t, allowEngine{})
	waitReady(t, ready)

	conn, err := net.Dial("unix", d.cfg.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send a payload that exceeds MaxMessageSize — the daemon must either respond
	// with a Deny or close the connection (both are acceptable fail-secure responses).
	oversized := make([]byte, aegis.MaxMessageSize+1)
	deadline := time.Now().Add(500 * time.Millisecond)
	_ = WriteMessage(conn, oversized, deadline)

	raw, err := ReadMessage(conn, deadline, aegis.MaxMessageSize*2)
	if err != nil {
		// Connection closed by daemon — acceptable fail-secure response.
		return
	}

	var resp aegis.CheckResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected Deny for oversized message, got %v", resp.Decision.Action)
	}
}

func TestDaemon_FailOpenReconcile(t *testing.T) {
	// nilSnapshotEngine returns Deny — verifies fail-secure when no snapshot is loaded.
	d, ready := startDaemon(t, nilSnapshotEngine{})
	waitReady(t, ready)

	resp := sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "AnyTool",
		SessionID: "sess-nil-snap",
	})

	if resp.Decision.Action != aegis.ActionDeny {
		t.Errorf("expected Deny when snapshot is nil, got %v", resp.Decision.Action)
	}
}

func TestDaemon_GracefulShutdown(t *testing.T) {
	// Sends a request, triggers shutdown while it is in-flight, and verifies
	// that Run() waits for the in-flight request to complete before returning.

	const slowDelay = 30 * time.Millisecond

	socketPath := testSocketPath()
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cfg := Config{SocketPath: socketPath}
	w, auditCancel, auditDone := newTestAuditWriter(t)
	d := New(cfg, slowEngine{delay: slowDelay}, w, nil, nil)
	d.SetAuditContext(auditCancel, auditDone)

	ready := make(chan struct{})
	d.setReadyCh(ready)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()

	waitReady(t, ready)

	// Send a slow request concurrently.
	var requestCompleted sync.WaitGroup
	requestCompleted.Add(1)
	go func() {
		defer requestCompleted.Done()
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		payload, _ := json.Marshal(aegis.CheckRequest{Tool: "SlowTool", SessionID: "sess-shutdown"})
		deadline := time.Now().Add(2 * time.Second)
		_ = WriteMessage(conn, payload, deadline)
		_, _ = ReadMessage(conn, deadline, aegis.MaxMessageSize)
	}()

	// Wait briefly so the request goroutine is inside handleConnection.
	time.Sleep(5 * time.Millisecond)

	// Trigger graceful shutdown.
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not complete graceful shutdown within 3 seconds")
	}

	requestCompleted.Wait()
}

// mockStreamTap records the events it receives via Emit.
type mockStreamTap struct {
	mu     sync.Mutex
	events []aegis.StreamEvent
}

func (m *mockStreamTap) Emit(_ context.Context, evt aegis.StreamEvent) {
	m.mu.Lock()
	m.events = append(m.events, evt)
	m.mu.Unlock()
}

func (m *mockStreamTap) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// startDaemonWithTap creates a Daemon wired with the given StreamTap (can be nil).
// Returns the daemon, ready channel, and the healthz address (e.g., "127.0.0.1:19092").
func startDaemonWithTap(t *testing.T, engine aegis.Engine, tap aegis.StreamTap, sessions *ifc.SessionLabels) (*Daemon, <-chan struct{}, string) {
	t.Helper()
	socketPath := testSocketPath()
	healthzAddr := testHealthzAddr()
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cfg := Config{SocketPath: socketPath, HealthzAddr: healthzAddr}
	w, auditCancel, auditDone := newTestAuditWriter(t)

	d := &Daemon{
		cfg:         cfg,
		engine:      engine,
		auditWriter: w,
		streamSrv:   tap,
		sessions:    sessions,
		sem:         make(chan struct{}, maxConcurrentConnections),
	}
	cfg.applyDefaults()
	d.cfg = cfg
	d.SetAuditContext(auditCancel, auditDone)

	ready := make(chan struct{})
	d.setReadyCh(ready)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
	})

	return d, ready, healthzAddr
}

func TestDaemon_StreamEmit(t *testing.T) {
	tap := &mockStreamTap{}
	d, ready, _ := startDaemonWithTap(t, allowEngine{}, tap, nil)
	waitReady(t, ready)

	_ = sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "ReadFile",
		SessionID: "sess-stream-test",
	})

	// Allow time for the async emit path.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if tap.count() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if tap.count() == 0 {
		t.Error("expected at least one StreamEvent after Evaluate, got 0")
	}
}

func TestDaemon_HealthzEndpoint(t *testing.T) {
	d, ready, healthzAddr := startDaemonWithTap(t, allowEngine{}, nil, nil)
	waitReady(t, ready)

	// Poll until /healthz responds or timeout.
	// DisableKeepAlives prevents the HTTP transport from keeping the connection
	// alive in a pool after the test completes — which would cause goleak to fail.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = client.Get("http://" + healthzAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("healthz endpoint never became available")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from /healthz, got %d", resp.StatusCode)
	}

	_ = d // referenced to avoid unused var
}

func TestDaemon_Healthz_StructuredJSON(t *testing.T) {
	d, ready, healthzAddr := startDaemonWithTap(t, allowEngine{}, nil, nil)
	waitReady(t, ready)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = client.Get("http://" + healthzAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("healthz endpoint never became available")
	}
	defer func() { _ = resp.Body.Close() }()

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode healthz response: %v", err)
	}

	if health.Status != "healthy" {
		t.Errorf("status = %q, want %q", health.Status, "healthy")
	}
	if health.Mode != "normal" {
		t.Errorf("mode = %q, want %q", health.Mode, "normal")
	}
	if health.UptimeMs < 0 {
		t.Errorf("uptime_ms = %d, want >= 0", health.UptimeMs)
	}
	if health.Evaluations < 0 {
		t.Errorf("evaluations = %d, want >= 0", health.Evaluations)
	}
	if health.Version != "v4" {
		t.Errorf("version = %q, want %q", health.Version, "v4")
	}
	if len(health.Checks) == 0 {
		t.Error("checks array is empty, want at least one check")
	}

	_ = d
}

func TestDaemon_Healthz_DegradedMode(t *testing.T) {
	d, ready, healthzAddr := startDaemonWithTap(t, allowEngine{}, nil, nil)
	waitReady(t, ready)

	d.SetMode(ModeDegraded, "audit chain broken")

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = client.Get("http://" + healthzAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("healthz endpoint never became available")
	}
	defer func() { _ = resp.Body.Close() }()

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode healthz response: %v", err)
	}

	if health.Status != "degraded" {
		t.Errorf("status = %q, want %q", health.Status, "degraded")
	}
	if health.Mode != "degraded" {
		t.Errorf("mode = %q, want %q", health.Mode, "degraded")
	}
	if health.ModeReason != "audit chain broken" {
		t.Errorf("mode_reason = %q, want %q", health.ModeReason, "audit chain broken")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for degraded mode, got %d", resp.StatusCode)
	}
}

func TestDaemon_Healthz_DenyAllMode(t *testing.T) {
	d, ready, healthzAddr := startDaemonWithTap(t, allowEngine{}, nil, nil)
	waitReady(t, ready)

	d.SetMode(ModeDenyAll, "no valid policy bundle")

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = client.Get("http://" + healthzAddr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("healthz endpoint never became available")
	}
	defer func() { _ = resp.Body.Close() }()

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode healthz response: %v", err)
	}

	if health.Status != "unhealthy" {
		t.Errorf("status = %q, want %q", health.Status, "unhealthy")
	}
	if health.Mode != "deny_all" {
		t.Errorf("mode = %q, want %q", health.Mode, "deny_all")
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for deny_all mode, got %d", resp.StatusCode)
	}

	_ = d
}

func TestDaemon_EvalCounter_Increments(t *testing.T) {
	d, ready := startDaemon(t, allowEngine{})
	waitReady(t, ready)

	initialCount := d.Evaluations()

	_ = sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "ReadFile",
		SessionID: "sess-counter-1",
	})
	_ = sendRequest(t, d.cfg.SocketPath, aegis.CheckRequest{
		Tool:      "WriteFile",
		SessionID: "sess-counter-2",
	})

	finalCount := d.Evaluations()
	if finalCount != initialCount+2 {
		t.Errorf("evaluations = %d, want %d", finalCount, initialCount+2)
	}
}
