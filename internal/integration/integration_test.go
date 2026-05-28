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

	grpcauthz "github.com/mayjain/aegis/internal/grpc"
	"github.com/mayjain/aegis/internal/otel"
	"github.com/mayjain/aegis/internal/reload"
	"github.com/mayjain/aegis/pkg/aegis"
)

// TestIntegration_HotReload verifies that the reload watcher fires when a YAML file
// is modified and increments the success counter.
func TestIntegration_HotReload(t *testing.T) {
	// Set up a watched directory with one policy file.
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

	// Capture counts before watching starts.
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

	// Trigger a change by touching the file (update mtime + content).
	time.Sleep(50 * time.Millisecond) // let watcher establish
	if err := os.WriteFile(dst, append(data, '\n'), 0600); err != nil {
		t.Fatalf("os.WriteFile trigger: %v", err)
	}

	// Wait for the debounce (100ms) + reload to complete.
	select {
	case <-reloaded:
		// Reload callback fired.
	case <-time.After(2 * time.Second):
		t.Fatal("reload watcher did not fire within 2s after file modification")
	}

	successAfter := reload.ReloadSuccessTotal()
	if successAfter <= successBefore {
		t.Errorf("ReloadSuccessTotal did not increment: before=%d after=%d", successBefore, successAfter)
	}

	cancel()
	<-watchDone
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

// TestIntegration_OTel_InstrumentsNonNil verifies that all REQ-058 OTel instrument
// accessors return non-nil instruments without reinitializing global state.
// The otel package pre-registers noop instruments at init() time, so accessors are
// always safe to call. The full metric-registration test lives in internal/otel/.
func TestIntegration_OTel_InstrumentsNonNil(t *testing.T) {
	// These accessors must never return nil — the otel package init() pre-registers noops.
	instruments := []struct {
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
	}
	for _, inst := range instruments {
		if inst.val == nil {
			t.Errorf("%s() returned nil", inst.name)
		}
	}

	// Verify daemon evaluations are counted independently of OTel.
	// Start a daemon, send N requests (one at a time with retries), confirm counter.
	td := startDaemon(t)
	const N = 3
	for i := 0; i < N; i++ {
		sendRequestRetry(t, td.socketPath, aegis.CheckRequest{
			Tool:      "Read",
			SessionID: "sess-otel-eval-count",
		})
	}
	// Poll until Evaluations() reaches N (daemon processes asynchronously).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if td.d.Evaluations() >= N {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := td.d.Evaluations()
	if got < N {
		t.Errorf("Evaluations() = %d, want >= %d", got, N)
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

// TestIntegration_GRPCListening verifies that the ext_authz gRPC server starts,
// accepts connections, and processes Check requests.
func TestIntegration_GRPCListening(t *testing.T) {
	grpcAddr := freeAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := grpcauthz.NewServer(grpcauthz.Config{
		ListenAddr: grpcAddr,
		Engine:     &allowAllEngine{},
		Timeout:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("grpcauthz.NewServer: %v", err)
	}

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- srv.Start(ctx)
	}()

	// Wait for gRPC port to be listening.
	deadline := time.Now().Add(3 * time.Second)
	var conn *grpc.ClientConn
	for time.Now().Before(deadline) {
		c, dialErr := grpc.NewClient(grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if dialErr == nil {
			conn = c
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		cancel()
		t.Fatal("gRPC server did not become reachable within 3s")
	}
	defer func() { _ = conn.Close() }()

	// Verify it is accepting real Check requests.
	client := authv3.NewAuthorizationClient(conn)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer checkCancel()

	checkResp, err := client.Check(checkCtx, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/healthz",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("client.Check: %v", err)
	}

	s := status.FromProto(checkResp.GetStatus())
	if s.Code() != codes.OK {
		t.Errorf("Check status = %v, want OK", s.Code())
	}

	// Verify the TCP port is actually open (nc -z equivalent).
	tcpConn, err := net.DialTimeout("tcp", grpcAddr, 1*time.Second)
	if err != nil {
		t.Errorf("TCP port %s not reachable: %v", grpcAddr, err)
	} else {
		_ = tcpConn.Close()
	}

	cancel()
	select {
	case <-srvDone:
	case <-time.After(3 * time.Second):
		t.Log("warning: gRPC server did not stop within 3s")
	}
}

// allowAllEngine is a test double that always returns Allow.
type allowAllEngine struct{}

func (a *allowAllEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return aegis.CheckResponse{
		Decision:       aegis.Decision{Action: aegis.ActionAllow},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
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

// mustStringReader wraps a string as an io.Reader.
func mustStringReader(_ *testing.T, s string) io.Reader {
	return strings.NewReader(s)
}
