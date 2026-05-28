package grpc_test

import (
	"context"
	"net"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	grpcpkg "github.com/mayjain/aegis/internal/grpc"
	"github.com/mayjain/aegis/pkg/aegis"
)

// mockEngine is a test double for GovernanceEngine.
type mockEngine struct {
	action aegis.Action
	reason string
	delay  time.Duration
}

func (m *mockEngine) Evaluate(ctx context.Context, _ aegis.CheckRequest) aegis.CheckResponse {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return aegis.CheckResponse{Decision: aegis.Decision{Action: aegis.ActionDeny, Reason: "timeout"}}
		}
	}
	return aegis.CheckResponse{Decision: aegis.Decision{Action: m.action, Reason: m.reason}}
}

// capturingEngine records the last CheckRequest it received.
type capturingEngine struct {
	last aegis.CheckRequest
}

func (c *capturingEngine) Evaluate(_ context.Context, req aegis.CheckRequest) aegis.CheckResponse {
	c.last = req
	return aegis.CheckResponse{Decision: aegis.Decision{Action: aegis.ActionAllow}}
}

// startTestServer opens a real listener, spawns a Server.Serve goroutine, and returns a
// connected client plus a cleanup function. The cleanup cancels the context and waits for
// the goroutine to finish before returning so goleak sees no leaked goroutines.
func startTestServer(t *testing.T, engine grpcpkg.GovernanceEngine) (authv3.AuthorizationClient, func()) {
	t.Helper()

	srv, err := grpcpkg.NewServer(grpcpkg.Config{
		Engine:  engine,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := lis.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if serveErr := srv.Serve(ctx, lis); serveErr != nil && ctx.Err() == nil {
			t.Errorf("srv.Serve: %v", serveErr)
		}
	}()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		<-done
		t.Fatalf("grpc.NewClient: %v", err)
	}

	client := authv3.NewAuthorizationClient(conn)

	cleanup := func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("conn.Close: %v", closeErr)
		}
		cancel()
		<-done
	}
	return client, cleanup
}

// makeHTTPCheckRequest builds a minimal Envoy CheckRequest with the given method/path/headers.
func makeHTTPCheckRequest(method, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

func TestGRPC_AllowVerdict(t *testing.T) {
	client, cleanup := startTestServer(t, &mockEngine{action: aegis.ActionAllow})
	defer cleanup()

	resp, err := client.Check(context.Background(), makeHTTPCheckRequest("GET", "/api/foo", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.OK {
		t.Errorf("expected OK, got %v", s.Code())
	}
	if resp.GetOkResponse() == nil {
		t.Error("expected OkResponse, got nil")
	}
}

func TestGRPC_DenyVerdict(t *testing.T) {
	const reason = "policy denied"
	client, cleanup := startTestServer(t, &mockEngine{action: aegis.ActionDeny, reason: reason})
	defer cleanup()

	resp, err := client.Check(context.Background(), makeHTTPCheckRequest("POST", "/admin", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", s.Code())
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse, got nil")
	}
	if denied.GetBody() != reason {
		t.Errorf("expected body %q, got %q", reason, denied.GetBody())
	}
}

func TestGRPC_RequireApprovalVerdict(t *testing.T) {
	client, cleanup := startTestServer(t, &mockEngine{action: aegis.ActionRequireApproval})
	defer cleanup()

	resp, err := client.Check(context.Background(), makeHTTPCheckRequest("DELETE", "/resource", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", s.Code())
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected DeniedResponse, got nil")
	}
	found := false
	for _, h := range denied.GetHeaders() {
		if h.GetHeader().GetKey() == "x-aegis-approval-required" && h.GetHeader().GetValue() == "true" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected x-aegis-approval-required header")
	}
}

func TestGRPC_AuditVerdict(t *testing.T) {
	client, cleanup := startTestServer(t, &mockEngine{action: aegis.ActionAudit})
	defer cleanup()

	resp, err := client.Check(context.Background(), makeHTTPCheckRequest("GET", "/data", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.OK {
		t.Errorf("expected OK, got %v", s.Code())
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse, got nil")
	}
	found := false
	for _, h := range ok.GetHeaders() {
		if h.GetHeader().GetKey() == "x-aegis-audited" && h.GetHeader().GetValue() == "true" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected x-aegis-audited header")
	}
}

func TestGRPC_NilRequest_Deny(t *testing.T) {
	srv, err := grpcpkg.NewServer(grpcpkg.Config{
		Engine: &mockEngine{action: aegis.ActionAllow},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	resp, grpcErr := srv.Check(context.Background(), nil)
	if grpcErr != nil {
		t.Errorf("Check must never return a gRPC error, got: %v", grpcErr)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for nil request, got %v", s.Code())
	}
}

func TestGRPC_Timeout_Deny(t *testing.T) {
	// Engine delays 200ms, server timeout is 50ms — context must cancel first.
	engine := &mockEngine{action: aegis.ActionAllow, delay: 200 * time.Millisecond}
	srv, err := grpcpkg.NewServer(grpcpkg.Config{
		Engine:  engine,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	resp, grpcErr := srv.Check(context.Background(), makeHTTPCheckRequest("GET", "/slow", nil))
	if grpcErr != nil {
		t.Errorf("Check must never return a gRPC error, got: %v", grpcErr)
	}
	s := status.FromProto(resp.GetStatus())
	if s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied on timeout, got %v", s.Code())
	}
}

func TestGRPC_NilEngine_ReturnsError(t *testing.T) {
	_, err := grpcpkg.NewServer(grpcpkg.Config{Engine: nil})
	if err == nil {
		t.Error("expected error for nil engine, got nil")
	}
}

func TestGRPC_TranslationPreservesMethod(t *testing.T) {
	engine := &capturingEngine{}

	srv, err := grpcpkg.NewServer(grpcpkg.Config{
		Engine:  engine,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	_, grpcErr := srv.Check(context.Background(), makeHTTPCheckRequest("PUT", "/v1/resource", nil))
	if grpcErr != nil {
		t.Errorf("unexpected gRPC error: %v", grpcErr)
	}

	tool := engine.last.Tool
	if tool == "" {
		t.Fatal("Tool field is empty")
	}
	for _, want := range []string{"PUT", "/v1/resource"} {
		found := false
		for i := 0; i+len(want) <= len(tool); i++ {
			if tool[i:i+len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Tool %q does not contain %q", tool, want)
		}
	}
}
