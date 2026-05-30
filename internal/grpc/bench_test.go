package grpc_test

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	grpcpkg "github.com/mayjain/nixis/internal/grpc"
	"github.com/mayjain/nixis/pkg/nixis"
)

func BenchmarkGRPC_Check(b *testing.B) {
	engine := &mockEngine{action: nixis.ActionAllow}
	srv, err := grpcpkg.NewServer(grpcpkg.Config{
		Engine: engine,
	})
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/api/resource",
					Headers: map[string]string{"x-request-id": "bench-session"},
				},
			},
		},
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := srv.Check(ctx, req)
		if err != nil {
			b.Fatalf("Check: %v", err)
		}
	}
}
