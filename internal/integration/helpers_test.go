package integration_test

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mayankjain0141/nixis/internal/audit"
	"github.com/mayankjain0141/nixis/internal/bundle"
	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/mayankjain0141/nixis/internal/daemon"
	"github.com/mayankjain0141/nixis/internal/delegation"
	grpcauthz "github.com/mayankjain0141/nixis/internal/grpc"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/internal/policy"
	"github.com/mayankjain0141/nixis/internal/secret"
	"github.com/mayankjain0141/nixis/internal/stream"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// testDaemon holds the running in-process daemon and its configuration.
type testDaemon struct {
	socketPath  string
	healthzAddr string
	d           *daemon.Daemon
	// engine is the real policy engine — exposed so tests can wire the gRPC server
	// against the same engine as the daemon (mirrors main.go NIXIS_GRPC_ADDR wiring).
	engine grpcauthz.GovernanceEngine
}

// startDaemon starts a real in-process daemon wired with policy engine, audit, and delegation.
// The daemon shuts down automatically via t.Cleanup.
func startDaemon(t *testing.T) *testDaemon {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	// macOS limits Unix socket paths to 104 bytes; use /tmp with a short name.
	sockPath := shortSockPath(t)
	healthzAddr := freeAddr(t)

	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("cel.NewCELEnvironment: %v", err)
	}

	sessions := &ifc.SessionLabels{}
	engine := policy.NewPolicyEngine(sessions, celEnv, policy.WithSecretScanner(secret.NewScanner()))

	policyDir := builtinPoliciesDir(t)
	templates, bindings, parseErr := bundle.ParsePolicyDir(policyDir)
	if parseErr != nil {
		t.Logf("ParsePolicyDir skipped: %v", parseErr)
	} else {
		compiled := &nixis.CompiledBundle{Version: 1, Templates: templates, Bindings: bindings}
		if reloadErr := engine.Reload(context.Background(), compiled); reloadErr != nil {
			t.Fatalf("engine.Reload: %v", reloadErr)
		}
	}

	aw, err := audit.NewWriter(dbPath)
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		aw.Start(ctx)
	}()

	streamSrv := stream.NewStreamServer(nil, nil)
	streamCtx, streamCancel := context.WithCancel(ctx)
	go func() {
		addr := freeAddr(t)
		if serveErr := streamSrv.Start(streamCtx, addr); serveErr != nil && streamCtx.Err() == nil {
			t.Logf("streamSrv.Start: %v", serveErr)
		}
	}()

	delegPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		streamCancel()
		cancel()
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	delegEngine, err := delegation.New(delegPub)
	if err != nil {
		streamCancel()
		cancel()
		t.Fatalf("delegation.New: %v", err)
	}

	cfg := daemon.Config{
		SocketPath:  sockPath,
		PolicyDir:   policyDir,
		AuditDBPath: dbPath,
		HealthzAddr: healthzAddr,
	}

	d := daemon.New(cfg, engine, aw, streamSrv, sessions)
	d.SetDelegationEngine(delegEngine)
	d.SetAuditContext(cancel, auditDone)

	daemonDone := make(chan struct{})
	go func() {
		defer close(daemonDone)
		if runErr := d.Run(ctx); runErr != nil && ctx.Err() == nil {
			t.Logf("daemon.Run: %v", runErr)
		}
	}()

	// Poll until the Unix socket is connectable (max 5s).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("daemon did not become ready within 5s")
		}
		c, dialErr := net.Dial("unix", sockPath)
		if dialErr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Cleanup(func() {
		streamCancel()
		cancel()
		select {
		case <-daemonDone:
		case <-time.After(5 * time.Second):
			t.Log("warning: daemon did not stop within 5s")
		}
	})

	return &testDaemon{
		socketPath:  sockPath,
		healthzAddr: healthzAddr,
		d:           d,
		engine:      engine,
	}
}

// sendRequestRetry retries sendRequest up to 5 times on EOF (may occur under race
// detector due to the daemon's 50ms evaluation deadline being exceeded).
func sendRequestRetry(t *testing.T, sockPath string, req nixis.CheckRequest) nixis.CheckResponse {
	t.Helper()
	var last nixis.CheckResponse
	for attempt := 0; attempt < 5; attempt++ {
		conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
		if err != nil {
			t.Fatalf("dial unix %s: %v", sockPath, err)
		}

		payload, err := json.Marshal(req)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("json.Marshal: %v", err)
		}

		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
		_, writeErr := conn.Write(hdr[:])
		if writeErr == nil {
			_, writeErr = conn.Write(payload)
		}
		if writeErr != nil {
			_ = conn.Close()
			t.Fatalf("write: %v", writeErr)
		}

		var rhdr [4]byte
		_, readErr := readFull(conn, rhdr[:])
		if readErr != nil {
			_ = conn.Close()
			time.Sleep(20 * time.Millisecond)
			continue // retry on deadline-induced EOF
		}
		rlen := binary.BigEndian.Uint32(rhdr[:])
		rbuf := make([]byte, rlen)
		if _, readErr = readFull(conn, rbuf); readErr != nil {
			_ = conn.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		_ = conn.Close()
		if err := json.Unmarshal(rbuf, &last); err != nil {
			t.Fatalf("json.Unmarshal CheckResponse: %v", err)
		}
		return last
	}
	t.Fatalf("sendRequestRetry: all attempts failed for tool=%s", req.Tool)
	return last
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// shortSockPath creates a short temporary socket path safe for macOS (104-byte limit).
func shortSockPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("/tmp", "ae*.sock")
	if err != nil {
		t.Fatalf("shortSockPath: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path) // daemon will create it
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// freeAddr returns a free TCP address by asking the OS for one.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// builtinPoliciesDir locates the policies/builtin directory relative to this test file.
func builtinPoliciesDir(t *testing.T) string {
	t.Helper()
	// __file__ of this test is internal/integration/helpers_test.go.
	// Module root is two levels up.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../internal/integration/helpers_test.go
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	dir := filepath.Join(moduleRoot, "policies", "builtin")
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("policies/builtin not found at %s: %v", abs, err)
	}
	return abs
}
