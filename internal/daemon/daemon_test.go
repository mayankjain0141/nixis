package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/audit"
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

func testSocketPath() string {
	n := testSocketCounter.Add(1)
	return filepath.Join(os.TempDir(), fmt.Sprintf("ae%d.sock", n))
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
	d := New(cfg, engine, w)
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
	d := New(cfg, slowEngine{delay: slowDelay}, w)
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
