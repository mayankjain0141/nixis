// Package grpc exposes Aegis governance as an Envoy ext_authz service.
package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/mayjain/aegis/pkg/aegis"
)

// GovernanceEngine evaluates policy decisions. Implemented by internal/policy.PolicyEngine.
type GovernanceEngine interface {
	Evaluate(ctx context.Context, req aegis.CheckRequest) aegis.CheckResponse
}

// Config configures the ext_authz gRPC server.
type Config struct {
	ListenAddr    string
	Engine        GovernanceEngine
	MaxConcurrent int
	Timeout       time.Duration
}

// Server implements the Envoy ext_authz Authorization service.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	engine GovernanceEngine
	cfg    Config
}

// NewServer constructs a Server. Returns an error if Engine is nil.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("engine is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 50 * time.Millisecond
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9091"
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 100
	}
	return &Server{engine: cfg.Engine, cfg: cfg}, nil
}

// Check implements envoy.service.auth.v3.Authorization.Check.
// ALL error paths return DENY — never returns a non-nil gRPC error (INV-001, INV-011).
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	if req == nil {
		return denyResponse("nil request"), nil
	}

	evalCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	aegisReq := translateRequest(req)
	aegisResp := s.engine.Evaluate(evalCtx, aegisReq)

	return translateResponse(aegisResp), nil
}

// Start binds a TCP listener on cfg.ListenAddr and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	return s.Serve(ctx, lis)
}

// Serve accepts connections on lis until ctx is cancelled. Useful for testing with custom listeners.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	srv := grpc.NewServer(
		grpc.MaxConcurrentStreams(uint32(s.cfg.MaxConcurrent)),
	)
	authv3.RegisterAuthorizationServer(srv, s)

	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()

	return srv.Serve(lis)
}
