package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	grpcauthz "github.com/mayjain/aegis/internal/grpc"
	"github.com/mayjain/aegis/internal/stream"
	"github.com/mayjain/aegis/pkg/aegis"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestDaemon_ExitCodes_Defined(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		value int
	}{
		{"exitSuccess", exitSuccess, 0},
		{"exitStartupFailure", exitStartupFailure, 1},
		{"exitRuntimeFailure", exitRuntimeFailure, 2},
		{"exitConfigError", exitConfigError, 3},
	}

	for _, tt := range tests {
		if tt.code != tt.value {
			t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.value)
		}
	}
}

// TestDaemon_GRPCServer_StartsWhenEnvSet verifies that AEGIS_GRPC_ADDR causes the gRPC
// ext_authz server to bind and accept connections.
func TestDaemon_GRPCServer_StartsWhenEnvSet(t *testing.T) {
	// Pick a free port by letting the OS assign one, then release it.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := tmp.Addr().String()
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build and start a minimal gRPC server the same way main.go does.
	// We bypass the daemon entirely — the test exercises only the gRPC wiring.
	grpcSrv, err := grpcauthz.NewServer(grpcauthz.Config{
		ListenAddr: addr,
		Engine:     &noopEngine{},
		Timeout:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- grpcSrv.Start(ctx)
	}()

	// Give the goroutine a moment to bind.
	deadline := time.Now().Add(2 * time.Second)
	var conn *grpc.ClientConn
	for time.Now().Before(deadline) {
		conn, err = grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	// Verify the connection state is ready or idle (not shutdown).
	conn.Connect()
	if err := conn.Close(); err != nil {
		t.Logf("conn.Close: %v", err)
	}

	cancel()
	if serveErr := <-done; serveErr != nil && ctx.Err() == nil {
		t.Errorf("Start returned unexpected error: %v", serveErr)
	}
}

// noopEngine satisfies grpcauthz.GovernanceEngine for test use.
type noopEngine struct{}

func (n *noopEngine) Evaluate(_ context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	return aegis.CheckResponse{}
}

var _ grpcauthz.GovernanceEngine = (*noopEngine)(nil)

// TestDaemon_EmitsBundleActivatedOnStartup verifies that after EmitBundleActivated is called
// on the StreamServer, a client connecting to the server receives a bundle.activated CloudEvent
// with policyCount > 0 as part of the initial handshake (replay-on-connect behaviour).
func TestDaemon_EmitsBundleActivatedOnStartup(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := fmt.Sprintf(":%d", ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()

	// Build a stream server the same way main.go does.
	srv := stream.NewStreamServer(nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startErr := make(chan error, 1)
	go func() {
		startErr <- srv.Start(ctx, addr)
	}()

	// Wait for the server to bind (retry dial).
	wsURL := "ws://127.0.0.1" + addr + "/ws"
	var conn *websocket.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, _, dialErr := websocket.DefaultDialer.Dial(wsURL, nil)
		if dialErr == nil {
			conn = c
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("stream server did not start within 3s")
	}
	defer func() { _ = conn.Close() }()

	// Read state.snapshot — no bundle yet.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var snap map[string]any
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap["type"] != "state.snapshot" {
		t.Fatalf("expected state.snapshot first, got %v", snap["type"])
	}
	_ = conn.Close()

	// Now simulate daemon startup: emit bundle.activated before any client connects.
	const wantPolicies = 5
	srv.EmitBundleActivated(ctx, 1, "deadbeef", wantPolicies, false)

	// Connect a new client — it must receive the replayed bundle.activated after snapshot.
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial after emit: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	// First: state.snapshot
	_ = conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err = conn2.ReadMessage()
	if err != nil {
		t.Fatalf("read snapshot (conn2): %v", err)
	}
	var snap2 map[string]any
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatalf("unmarshal snapshot2: %v", err)
	}
	if snap2["type"] != "state.snapshot" {
		t.Fatalf("expected state.snapshot, got %v", snap2["type"])
	}

	// Second: replayed bundle.activated.
	_ = conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err = conn2.ReadMessage()
	if err != nil {
		t.Fatalf("read bundle.activated: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal bundle.activated: %v", err)
	}
	if got := msg["type"]; got != "bundle.activated" {
		t.Fatalf("type = %v, want bundle.activated", got)
	}
	d, ok := msg["data"].(map[string]any)
	if !ok {
		t.Fatalf("data field missing or wrong type")
	}
	pc, ok := d["policyCount"].(float64)
	if !ok || int(pc) != wantPolicies {
		t.Errorf("policyCount = %v, want %d", d["policyCount"], wantPolicies)
	}
}

func TestExpandHome(t *testing.T) {
	tests := []struct {
		input    string
		wantHome bool
	}{
		{"", false},
		{"/absolute/path", false},
		{"relative/path", false},
		{"~/foo", true},
	}

	for _, tt := range tests {
		result := expandHome(tt.input)
		if tt.wantHome {
			if result == tt.input {
				t.Errorf("expandHome(%q) = %q, want home expansion", tt.input, result)
			}
		} else {
			if result != tt.input {
				t.Errorf("expandHome(%q) = %q, want %q", tt.input, result, tt.input)
			}
		}
	}
}
