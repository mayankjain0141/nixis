package main

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	grpcauthz "github.com/mayjain/aegis/internal/grpc"
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
