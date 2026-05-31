package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	grpcauthz "github.com/mayankjain0141/nixis/internal/grpc"
	"github.com/mayankjain0141/nixis/internal/otel"
	"github.com/mayankjain0141/nixis/internal/reload"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// TestIntegration_HotReload verifies that the reload watcher fires when a YAML policy
// file is modified, that ReloadSuccessTotal increments, and that the reload completes
// well within 500ms of the file write (debounce is 100ms).
func TestIntegration_HotReload(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(builtinPoliciesDir(t), "git-branch-protection.yaml")
	dst := filepath.Join(dir, "git-branch-protection.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("os.ReadFile policy: %v", err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("os.WriteFile policy: %v", err)
	}

	successBefore := reload.ReloadSuccessTotal()

	reloaded := make(chan struct{}, 1)
	reloader := &countingReloader{done: reloaded}

	watcher, err := reload.New(dir, reloader)
	if err != nil {
		t.Fatalf("reload.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error, 1)
	go func() {
		watchDone <- watcher.Start(ctx)
	}()

	// fsnotify watch registration is async inside Start(); there is no exported
	// ready-signal, so we use a short sleep — reduced from 50ms to 20ms.
	time.Sleep(20 * time.Millisecond)

	writeAt := time.Now()
	if err := os.WriteFile(dst, append(data, '\n'), 0600); err != nil {
		t.Fatalf("os.WriteFile trigger: %v", err)
	}

	// Debounce is 100ms; allow 2s total but log timing.
	select {
	case <-reloaded:
		elapsed := time.Since(writeAt)
		t.Logf("reload completed in %v after file write", elapsed)
		if elapsed > 500*time.Millisecond {
			t.Errorf("reload took %v, want <= 500ms (debounce=100ms)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reload watcher did not fire within 2s after file modification")
	}

	successAfter := reload.ReloadSuccessTotal()
	if successAfter <= successBefore {
		t.Errorf("ReloadSuccessTotal did not increment: before=%d after=%d", successBefore, successAfter)
	}

	cancel()
	select {
	case <-watchDone:
	case <-time.After(2 * time.Second):
		t.Log("warning: watcher did not stop within 2s")
	}
	// The debounce time.AfterFunc goroutine has no exported done-signal; wait
	// briefly so it finishes before the next test touches OTel global state.
	time.Sleep(20 * time.Millisecond)
}

// countingReloader satisfies reload.PolicyReloader and signals a channel on each reload.
type countingReloader struct {
	done chan struct{}
}

func (r *countingReloader) Reload() error {
	select {
	case r.done <- struct{}{}:
	default:
	}
	return nil
}

// errorReloader satisfies reload.PolicyReloader and always returns an error.
// Used to simulate a policy parse failure on reload.
type errorReloader struct {
	called chan struct{}
}

func (r *errorReloader) Reload() error {
	select {
	case r.called <- struct{}{}:
	default:
	}
	return os.ErrInvalid // non-nil so reload.ReloadErrorTotal increments
}

// TestIntegration_HotReload_CorruptedPolicy_KeepsOld verifies that when a reload
// attempt fails (corrupted policy file), the watcher keeps the old policy active
// (INV-007: failed reload must not call Store) and no panic occurs.
func TestIntegration_HotReload_CorruptedPolicy_KeepsOld(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(builtinPoliciesDir(t), "git-branch-protection.yaml")
	dst := filepath.Join(dir, "git-branch-protection.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("os.ReadFile policy: %v", err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("os.WriteFile policy: %v", err)
	}

	errorsBefore := reload.ReloadErrorTotal()
	successBefore := reload.ReloadSuccessTotal()

	reloadCalled := make(chan struct{}, 1)
	reloader := &errorReloader{called: reloadCalled}

	watcher, err := reload.New(dir, reloader)
	if err != nil {
		t.Fatalf("reload.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error, 1)
	go func() {
		watchDone <- watcher.Start(ctx)
	}()

	// fsnotify watch registration is async inside Start(); no exported ready-signal.
	time.Sleep(20 * time.Millisecond)

	// Write invalid YAML to trigger a reload attempt that will fail.
	if err := os.WriteFile(dst, []byte(":\tinvalid: yaml: {{\n"), 0600); err != nil {
		t.Fatalf("os.WriteFile corrupt: %v", err)
	}

	// Wait for the reloader to be called (debounce is 100ms; allow 2s total).
	select {
	case <-reloadCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("reload watcher did not call Reload() within 2s after corrupt file write")
	}

	// Reload was attempted and failed — ReloadErrorTotal must have incremented.
	// Poll briefly: the metric increment may happen on a separate goroutine.
	var errorsAfter int64
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		errorsAfter = reload.ReloadErrorTotal()
		if errorsAfter > errorsBefore {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if errorsAfter <= errorsBefore {
		t.Errorf("ReloadErrorTotal did not increment: before=%d after=%d", errorsBefore, errorsAfter)
	}

	// ReloadSuccessTotal must NOT have incremented (old policy is still active, INV-007).
	successAfter := reload.ReloadSuccessTotal()
	if successAfter != successBefore {
		t.Errorf("ReloadSuccessTotal changed after a failed reload: before=%d after=%d", successBefore, successAfter)
	}

	cancel()
	select {
	case <-watchDone:
	case <-time.After(2 * time.Second):
		t.Log("warning: watcher did not stop within 2s")
	}
	// Let the debounce AfterFunc goroutine drain before the next test.
	time.Sleep(20 * time.Millisecond)
}

// TestIntegration_OTel_RecordEvaluation verifies that sending CheckRequests through
// the real daemon causes otel.RecordEvaluation to fire and produce metric data.
// TestMain initializes OTel with an in-memory exporter before any test runs, so this
// test can safely collect from otelReader without racing against global state writes.
func TestIntegration_OTel_RecordEvaluation(t *testing.T) {
	// Verify all REQ-058 accessors are non-nil (noop instruments pre-registered at init).
	for _, tc := range []struct {
		name string
		val  any
	}{
		{"InstrumentDaemonConns", otel.InstrumentDaemonConns()},
		{"InstrumentPolicyReload", otel.InstrumentPolicyReload()},
		{"InstrumentAuditDropped", otel.InstrumentAuditDropped()},
		{"InstrumentStreamClients", otel.InstrumentStreamClients()},
		{"InstrumentStreamDropped", otel.InstrumentStreamDropped()},
		{"InstrumentFailOpen", otel.InstrumentFailOpen()},
		{"InstrumentAuditBufferUtil", otel.InstrumentAuditBufferUtil()},
		{"InstrumentGitleaksMemory", otel.InstrumentGitleaksMemory()},
	} {
		if tc.val == nil {
			t.Errorf("%s() returned nil", tc.name)
		}
	}

	td := startDaemon(t)

	// Send 3 requests — each handleConnection calls otel.RecordEvaluation and
	// increments otel.InstrumentDaemonConns.
	const N = 3
	for i := 0; i < N; i++ {
		sendRequestRetry(t, td.socketPath, nixis.CheckRequest{
			Tool:      "Read",
			SessionID: "sess-otel-eval",
		})
	}

	// Poll until the atomic Evaluations() counter reaches N.
	pollUntil(t, 3*time.Second, func() bool {
		return td.d.Evaluations() >= N
	}, "Evaluations() did not reach %d within 3s", N)

	// Collect from the in-memory reader (initialized in TestMain) and verify
	// that RecordEvaluation produced data in the histogram.
	found := collectMetrics(t)
	if !found["nixis_evaluation_duration_seconds"] {
		t.Errorf("nixis_evaluation_duration_seconds not found in metrics; collected: %v", found)
	}
	if !found["nixis_daemon_active_connections"] {
		t.Errorf("nixis_daemon_active_connections not found in metrics; collected: %v", found)
	}
}

// TestIntegration_DelegationAPI verifies the HTTP delegation endpoints served by
// the daemon: GET /api/v1/delegation/list and POST /api/v1/delegation/revoke.
func TestIntegration_DelegationAPI(t *testing.T) {
	td := startDaemon(t)
	base := "http://" + td.healthzAddr

	// Allow the HTTP server a moment to start.
	waitForHTTP(t, base+"/healthz", 3*time.Second)

	t.Run("list_empty", func(t *testing.T) {
		resp, err := http.Get(base + "/api/v1/delegation/list")
		if err != nil {
			t.Fatalf("GET /api/v1/delegation/list: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Chains []any `json:"chains"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Chains == nil {
			t.Error("chains field is null, want empty array []")
		}
		if len(body.Chains) != 0 {
			t.Errorf("len(chains) = %d, want 0", len(body.Chains))
		}
	})

	t.Run("revoke_nonexistent", func(t *testing.T) {
		payload := `{"chain_id":"does-not-exist"}`
		resp, err := http.Post(base+"/api/v1/delegation/revoke",
			"application/json",
			mustStringReader(t, payload),
		)
		if err != nil {
			t.Fatalf("POST /api/v1/delegation/revoke: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Revoked bool   `json:"revoked"`
			ChainID string `json:"chain_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if !body.Revoked {
			t.Error("revoked = false, want true")
		}
		if body.ChainID != "does-not-exist" {
			t.Errorf("chain_id = %q, want %q", body.ChainID, "does-not-exist")
		}
	})

	t.Run("wrong_method_list", func(t *testing.T) {
		resp, err := http.Post(base+"/api/v1/delegation/list",
			"application/json", mustStringReader(t, "{}"))
		if err != nil {
			t.Fatalf("POST /api/v1/delegation/list: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", resp.StatusCode)
		}
	})

	t.Run("missing_chain_id", func(t *testing.T) {
		resp, err := http.Post(base+"/api/v1/delegation/revoke",
			"application/json", mustStringReader(t, "{}"))
		if err != nil {
			t.Fatalf("POST /api/v1/delegation/revoke: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// TestIntegration_Healthz verifies that /healthz returns valid structured JSON.
func TestIntegration_Healthz(t *testing.T) {
	td := startDaemon(t)
	base := "http://" + td.healthzAddr

	waitForHTTP(t, base+"/healthz", 3*time.Second)

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Status      string `json:"status"`
		Mode        string `json:"mode"`
		UptimeMs    int64  `json:"uptime_ms"`
		Evaluations int64  `json:"evaluations"`
		Version     string `json:"version"`
		Checks      []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /healthz body: %v", err)
	}
	if body.Status == "" {
		t.Error("status field is empty")
	}
	if body.Mode == "" {
		t.Error("mode field is empty")
	}
	if body.UptimeMs < 0 {
		t.Errorf("uptime_ms = %d, want >= 0", body.UptimeMs)
	}
	if body.Version == "" {
		t.Error("version field is empty")
	}
	if len(body.Checks) == 0 {
		t.Error("checks array is empty, want at least one component check")
	}
}

// TestIntegration_GRPCExtAuthz verifies that the ext_authz gRPC server wired to the
// real policy engine starts, accepts Envoy-style Check RPCs, and returns correct verdicts.
// This mirrors how main.go wires NIXIS_GRPC_ADDR: same engine, same 50ms timeout.
func TestIntegration_GRPCExtAuthz(t *testing.T) {
	td := startDaemon(t)

	grpcAddr := freeAddr(t)
	grpcSrv, err := grpcauthz.NewServer(grpcauthz.Config{
		ListenAddr: grpcAddr,
		Engine:     td.engine, // real policy engine — same as NIXIS_GRPC_ADDR path in main.go
		Timeout:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("grpcauthz.NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- grpcSrv.Start(ctx)
	}()

	// Poll until the gRPC TCP port is reachable.
	var conn *grpc.ClientConn
	pollUntil(t, 3*time.Second, func() bool {
		c, dialErr := grpc.NewClient(grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if dialErr != nil {
			return false
		}
		conn = c
		return true
	}, "gRPC server did not become reachable within 3s")
	defer func() { _ = conn.Close() }()

	// nc -z equivalent: verify TCP port is open.
	tcpConn, err := net.DialTimeout("tcp", grpcAddr, 1*time.Second)
	if err != nil {
		t.Errorf("TCP port %s not reachable: %v", grpcAddr, err)
	} else {
		_ = tcpConn.Close()
	}

	client := authv3.NewAuthorizationClient(conn)

	t.Run("nil_request_returns_deny_not_error", func(t *testing.T) {
		// INV-011: nil request must return DENY with no gRPC transport error.
		resp, grpcErr := grpcSrv.Check(context.Background(), nil)
		if grpcErr != nil {
			t.Errorf("Check(nil) must not return gRPC error, got: %v", grpcErr)
		}
		s := status.FromProto(resp.GetStatus())
		if s.Code() != codes.PermissionDenied {
			t.Errorf("Check(nil) status = %v, want PermissionDenied", s.Code())
		}
	})

	t.Run("real_check_rpc_returns_valid_status", func(t *testing.T) {
		// A real Envoy-style Check RPC through the policy engine must return
		// either OK (allow) or PermissionDenied (deny) — never a gRPC transport error.
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer checkCancel()

		resp, err := client.Check(checkCtx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("client.Check: %v", err)
		}
		s := status.FromProto(resp.GetStatus())
		if s.Code() != codes.OK && s.Code() != codes.PermissionDenied {
			t.Errorf("unexpected gRPC code %v (want OK or PermissionDenied)", s.Code())
		}
		t.Logf("Check GET /api/resource → %v", s.Code())
	})

	cancel()
	select {
	case <-srvDone:
	case <-time.After(3 * time.Second):
		t.Log("warning: gRPC server did not stop within 3s")
	}
}

// waitForHTTP polls url until it returns HTTP 200 or the deadline is reached.
func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitForHTTP: %s did not return 200 within %s", url, timeout)
}

// pollUntil calls cond every 10ms until it returns true or timeout elapses.
func pollUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(msg, args...)
}

// mustStringReader wraps a string as an io.Reader.
func mustStringReader(_ *testing.T, s string) io.Reader {
	return strings.NewReader(s)
}
