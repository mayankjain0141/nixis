// SPDX-License-Identifier: MIT
// nixis-daemon is the Nixis governance daemon binary.
//
// It listens on a Unix domain socket, evaluates incoming CheckRequests from the
// hook binary against the loaded policy set, and writes audit records to SQLite.
//
// Usage:
//
//	nixis-daemon [-socket PATH] [-policy-dir DIR] [-audit-db PATH] [-failopen-log PATH]
//
// The gRPC ext_authz listener address is configured via the NIXIS_GRPC_ADDR environment
// variable. The stream/WebSocket server address defaults to :9090 and can be overridden
// with NIXIS_DASHBOARD_ADDR.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mayankjain0141/nixis/internal/audit"
	"github.com/mayankjain0141/nixis/internal/bundle"
	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/mayankjain0141/nixis/internal/daemon"
	"github.com/mayankjain0141/nixis/internal/delegation"
	grpcauthz "github.com/mayankjain0141/nixis/internal/grpc"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/internal/label"
	"github.com/mayankjain0141/nixis/internal/otel"
	"github.com/mayankjain0141/nixis/internal/policy"
	"github.com/mayankjain0141/nixis/internal/reload"
	"github.com/mayankjain0141/nixis/internal/secret"
	"github.com/mayankjain0141/nixis/internal/stream"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

const (
	exitSuccess        = 0 // clean shutdown
	exitStartupFailure = 1 // fatal error during init
	exitRuntimeFailure = 2 // fatal error during operation
	exitConfigError    = 3 // invalid configuration
)

func main() {
	var (
		socketPath  = flag.String("socket", "", "Unix socket path (default: $NIXIS_SOCKET_PATH or /tmp/nixis.sock)")
		policyDir   = flag.String("policy-dir", "policies", "Policy YAML directory (recursively loads all subdirectories)")
		auditDB     = flag.String("audit-db", "~/.nixis/audit.db", "Audit SQLite database path")
		failOpenLog = flag.String("failopen-log", "", "Fail-open log path (default: $NIXIS_FAILOPEN_LOG or ~/.nixis/failopen.log)")
	)
	flag.Parse()

	pidLock, err := daemon.AcquirePIDLock(filepath.Join(expandHome("~/.nixis"), "daemon.pid"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	defer func() { _ = pidLock.Unlock() }()

	cfg := daemon.Config{
		SocketPath:  *socketPath,
		PolicyDir:   *policyDir,
		AuditDBPath: expandHome(*auditDB),
		FailOpenLog: *failOpenLog,
	}

	otelCfg := otel.Config{
		Enabled:     os.Getenv("NIXIS_OTEL_ENDPOINT") != "",
		Endpoint:    os.Getenv("NIXIS_OTEL_ENDPOINT"),
		ServiceName: "nixis-daemon",
	}
	otelShutdown, err := otel.Initialize(otelCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: OTel init failed: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		if shutErr := otelShutdown(shutCtx); shutErr != nil {
			fmt.Fprintf(os.Stderr, "nixis-daemon: OTel shutdown error: %v\n", shutErr)
		}
	}()
	if otelCfg.Enabled {
		fmt.Fprintf(os.Stderr, "nixis-daemon: OTel enabled → %s\n", otelCfg.Endpoint)
	}

	auditWriter, err := audit.NewWriter(cfg.AuditDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to open audit database %q: %v\n", cfg.AuditDBPath, err)
		os.Exit(exitStartupFailure)
	}

	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to create CEL environment: %v\n", err)
		os.Exit(exitStartupFailure)
	}

	engine := policy.NewPolicyEngine(
		sessions,
		celEnv,
		policy.WithSecretScanner(secret.NewScanner()),
		policy.WithLabeler(label.NewLabeler()),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// initialPolicyCount is set to len(templates) on a successful startup load.
	// It is used after the stream server starts to emit bundle.activated.
	var initialPolicyCount int
	templates, bindings, err := bundle.ParsePolicyDir(cfg.PolicyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to parse policies from %q: %v\n", cfg.PolicyDir, err)
		fmt.Fprintf(os.Stderr, "nixis-daemon: starting with no policies (all requests will be denied)\n")
	} else {
		compiled := &nixis.CompiledBundle{
			Version:   1,
			Templates: templates,
			Bindings:  bindings,
		}
		if err := engine.Reload(ctx, compiled); err != nil {
			fmt.Fprintf(os.Stderr, "nixis-daemon: failed to load initial policies: %v\n", err)
		} else {
			initialPolicyCount = len(templates)
			// engine.Reload calls cel.CompileAll internally; skipped policies are
			// logged at WARN level by CompileAll itself. Emit a startup summary here
			// so operators see the active count without reading through log lines.
			if skipped := engine.SkippedPolicies(); len(skipped) > 0 {
				fmt.Fprintf(os.Stderr, "nixis-daemon: WARNING: %d polic(ies) inactive — undeclared CEL variables: %v\n", len(skipped), skipped)
				fmt.Fprintf(os.Stderr, "nixis-daemon: Active policies: %d of %d loaded\n", initialPolicyCount-len(skipped), initialPolicyCount)
			} else {
				fmt.Fprintf(os.Stderr, "nixis-daemon: loaded %d policies from %s\n", initialPolicyCount, cfg.PolicyDir)
			}
		}
	}
	if grpcAddr := os.Getenv("NIXIS_GRPC_ADDR"); grpcAddr != "" {
		grpcSrv, err := grpcauthz.NewServer(grpcauthz.Config{
			ListenAddr: grpcAddr,
			Engine:     engine,
			Timeout:    50 * time.Millisecond,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "nixis-daemon: failed to create gRPC server: %v\n", err)
			os.Exit(exitStartupFailure)
		}
		go func() {
			if err := grpcSrv.Start(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "nixis-daemon: gRPC server error: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "nixis-daemon: gRPC ext_authz listening on %s\n", grpcAddr)
	}

	// Start reload watcher after initial policy load (spec: started AFTER initial compile).
	reloadWatcher, rwErr := reload.NewReloadWatcher(cfg.PolicyDir, &policyReloader{
		policyDir: cfg.PolicyDir,
		engine:    engine,
		ctx:       ctx,
	})
	if rwErr != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to create reload watcher: %v\n", rwErr)
	} else {
		go func() {
			if err := reloadWatcher.Start(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "nixis-daemon: reload watcher error: %v\n", err)
			}
		}()
	}

	streamSrv := stream.NewStreamServer(nil, nil,
		stream.WithEvaluator(engine),
		stream.WithPolicyLister(engine),
		stream.WithRouteRegistrar(func(mux *http.ServeMux) {
			daemon.RegisterCheckHandler(mux, engine)
		}),
	)
	streamCtx, streamCancel := context.WithCancel(ctx)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		addr := os.Getenv("NIXIS_DASHBOARD_ADDR")
		if addr == "" {
			addr = "127.0.0.1:9090"
		}
		if err := streamSrv.Start(streamCtx, addr); err != nil && streamCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "nixis-daemon: stream server error: %v\n", err)
		}
	}()
	// Wire audit checkpoint → stream event so the dashboard Forensic Review shows live data.
	auditWriter.SetCheckpointEmitFn(func(seq int64, hash, prevHash string, eventCount int) {
		streamSrv.EmitAuditCheckpoint(ctx, seq, hash, prevHash, eventCount)
	})

	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		auditWriter.Start(ctx)
	}()

	// Graceful shutdown: cancel the stream server context and wait for it to
	// drain connections and release the TCP port before the process exits.
	// Without this wait the goroutine never gets scheduled and the port lingers
	// in TIME_WAIT, causing "address already in use" on rapid restart.
	defer func() {
		streamCancel()
		select {
		case <-streamDone:
		case <-time.After(6 * time.Second): // stream server has 5s shutdown timeout
			fmt.Fprintf(os.Stderr, "nixis-daemon: stream server drain timed out\n")
		}
	}()

	// Emit bundle.activated so the dashboard shows the policies loaded at startup.
	// The payload is stored in the stream server and replayed to each client on connect,
	// so this call is safe to make before any clients have connected.
	if initialPolicyCount > 0 {
		streamSrv.EmitBundleActivated(ctx, 1, "", initialPolicyCount, false)
	}

	// Create a delegation engine with an ephemeral key so the HTTP API is
	// available from startup. Chains are registered by the policy engine at
	// runtime; the ephemeral key is only needed to satisfy the constructor
	// (it is never used to sign or verify tokens in this context).
	delegPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to generate ephemeral delegation key: %v\n", err)
		os.Exit(exitStartupFailure)
	}
	delegEngine, err := delegation.New(delegPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: failed to create delegation engine: %v\n", err)
		os.Exit(exitStartupFailure)
	}

	delegEngine.SetEmitFn(func(eventType, chainID, reason string) {
		streamSrv.Emit(ctx, nixis.StreamEvent{
			Type:      eventType,
			SessionID: chainID,
			Reason:    reason,
			Timestamp: time.Now().UnixNano(),
		})
	})

	d := daemon.New(cfg, engine, auditWriter, streamSrv, sessions)
	d.SetDelegationEngine(delegEngine)
	d.SetAuditContext(cancel, auditDone)

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nixis-daemon: %v\n", err)
		os.Exit(exitRuntimeFailure)
	}
}

// policyReloader adapts PolicyEngine.Reload to the reload.PolicyReloader interface.
// It re-parses the policy directory and calls engine.Reload on each file-change event.
type policyReloader struct {
	policyDir string
	engine    *policy.PolicyEngine
	ctx       context.Context
}

func (r *policyReloader) Reload() error {
	templates, bindings, err := bundle.ParsePolicyDir(r.policyDir)
	if err != nil {
		return err
	}
	compiled := &nixis.CompiledBundle{
		Version:   1,
		Templates: templates,
		Bindings:  bindings,
	}
	return r.engine.Reload(r.ctx, compiled)
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return home + path[1:]
}
