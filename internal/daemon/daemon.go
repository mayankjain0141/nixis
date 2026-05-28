package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/delegation"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/stream"
	"github.com/mayjain/aegis/pkg/aegis"
)

// Daemon manages the lifecycle of the Aegis governance daemon.
//
// Lifecycle state machine:
//
//	INITIALIZING → LISTENING → DRAINING → FLUSHING → STOPPED
type Daemon struct {
	cfg         Config
	engine      aegis.Engine
	auditWriter *audit.Writer
	listener    net.Listener
	streamSrv   aegis.StreamTap    // nil disables streaming
	sessions    *ifc.SessionLabels // nil disables session label persistence
	delegAPI    *DelegationAPI     // nil disables delegation HTTP endpoints

	// inFlight tracks the number of in-progress connection goroutines.
	// Graceful shutdown waits for this WaitGroup before closing the audit channel.
	inFlight sync.WaitGroup

	// sem limits concurrent connection goroutines.
	sem chan struct{}

	// auditCancel and auditDone drive the audit goroutine lifecycle.
	// Populated via SetAuditContext before Run() is called.
	auditCancel context.CancelFunc
	auditDone   <-chan struct{}

	// readyCh is closed once the listener is bound. Used in tests.
	readyCh chan struct{}
}

// New constructs a Daemon from the provided config, engine, audit writer, and optional
// stream server. Pass nil for streamSrv to disable streaming. Pass nil for sessions to
// disable session label persistence.
func New(cfg Config, engine aegis.Engine, aw *audit.Writer, streamSrv *stream.StreamServer, sessions *ifc.SessionLabels) *Daemon {
	cfg.applyDefaults()
	d := &Daemon{
		cfg:         cfg,
		engine:      engine,
		auditWriter: aw,
		sessions:    sessions,
		sem:         make(chan struct{}, maxConcurrentConnections),
	}
	// Avoid storing a non-nil interface wrapping a nil *StreamServer.
	if streamSrv != nil {
		d.streamSrv = streamSrv
	}
	return d
}

// readyCh is closed by Run() once the listener is bound and accepting connections.
// Tests use this to avoid polling for the socket file.
func (d *Daemon) setReadyCh(ch chan struct{}) {
	d.readyCh = ch
}

// Run starts the daemon and blocks until the context is cancelled or a signal is received.
//
// Shutdown order (per WS-07 spec §2.8):
//  1. Stop listener (no new connections accepted).
//  2. Wait for in-flight connections to complete.
//  3. Close audit writer channel.
//  4. Flush audit to SQLite.
//  5. Close SQLite.
//  6. Remove socket file.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.reconcileFailOpenLog(); err != nil {
		// Non-fatal: log but continue.
		fmt.Fprintf(os.Stderr, "aegis-daemon: fail-open log reconciliation error: %v\n", err)
	}

	if err := d.listen(); err != nil {
		return fmt.Errorf("bind socket: %w", err)
	}

	// Signal readiness (used in tests).
	if d.readyCh != nil {
		close(d.readyCh)
	}

	// Start the /healthz endpoint.
	go d.serveHealthz(ctx)

	// Accept loop in a background goroutine — returns when listener is closed.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		d.acceptLoop()
	}()

	// Block until context is cancelled or a termination signal arrives.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
	case <-sigCh:
	}

	// Step 1: Stop accepting new connections.
	_ = d.listener.Close()

	// Wait for accept loop goroutine to exit.
	<-acceptDone

	// Steps 2-5: Wait for in-flight requests, then drain audit.
	d.shutdown()

	// Step 6: Remove the socket file.
	_ = os.Remove(d.cfg.SocketPath)

	return nil
}

// listen binds the Unix socket and sets permissions.
func (d *Daemon) listen() error {
	socketDir := filepath.Dir(d.cfg.SocketPath)
	if err := os.MkdirAll(socketDir, socketDirPermissions); err != nil {
		return err
	}

	// Remove stale socket from a prior run, if any.
	_ = os.Remove(d.cfg.SocketPath)

	l, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return err
	}

	if err := os.Chmod(d.cfg.SocketPath, socketPermissions); err != nil {
		_ = l.Close()
		return err
	}

	d.listener = l
	return nil
}

// acceptLoop accepts connections from the listener and dispatches each to handleConnection.
func (d *Daemon) acceptLoop() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			// Accept returns non-nil error when the listener is closed.
			return
		}

		// Acquire semaphore slot — blocks if maxConcurrentConnections are active.
		d.sem <- struct{}{}
		d.inFlight.Add(1)
		go func() {
			defer func() {
				<-d.sem
				d.inFlight.Done()
			}()
			d.handleConnection(conn)
		}()
	}
}

// shutdown drains in-flight connections and then flushes the audit writer.
func (d *Daemon) shutdown() {
	// Wait for all in-flight request goroutines to complete.
	d.inFlight.Wait()

	// Stream server context is cancelled by the deferred streamCancel in main.go.
	// No explicit stop needed here — the context cancellation drives shutdown.

	// The audit writer's Start() goroutine watches auditCtx for cancellation.
	// We trigger shutdown by cancelling the context that was passed to Start().
	// The caller (cmd/aegis-daemon/main.go) owns auditCtx and cancels it here.
	// However, we cannot directly cancel it from here without coupling — instead
	// we signal via the daemon's auditCancel if set.
	if d.auditCancel != nil {
		d.auditCancel()
	}

	// Wait for audit writer to drain.
	if d.auditDone != nil {
		<-d.auditDone
	}

	// Close SQLite.
	if d.auditWriter != nil {
		_ = d.auditWriter.Close()
	}
}

// SetAuditContext provides the daemon with the cancel function and done channel
// for the audit writer goroutine so graceful shutdown can flush before exit.
func (d *Daemon) SetAuditContext(cancel context.CancelFunc, done <-chan struct{}) {
	d.auditCancel = cancel
	d.auditDone = done
}

// SetDelegationEngine wires a delegation.Engine into the daemon so that the
// /api/v1/delegation/* HTTP endpoints are served alongside /healthz.
func (d *Daemon) SetDelegationEngine(engine *delegation.Engine) {
	d.delegAPI = NewDelegationAPI(engine)
}

// serveHealthz starts a minimal HTTP server on :9091 that serves /healthz and,
// when a delegation engine is wired, the /api/v1/delegation/* endpoints.
// The server shuts down when ctx is cancelled.
func (d *Daemon) serveHealthz(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if d.delegAPI != nil {
		d.delegAPI.RegisterRoutes(mux)
	}
	srv := &http.Server{
		Addr:    ":9091",
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	_ = srv.ListenAndServe()
}

// reconcileFailOpenLog reads the fail-open log from the last daemon run and
// emits a warning for each entry. This fulfils the RISK-004 reconciliation requirement.
func (d *Daemon) reconcileFailOpenLog() error {
	f, err := os.Open(d.cfg.FailOpenLog)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	var count int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry failOpenEntry
		if jsonErr := json.Unmarshal(line, &entry); jsonErr != nil {
			count++
			continue
		}
		fmt.Fprintf(os.Stderr,
			"aegis-daemon: WARN fail-open entry reconciled: session=%s tool=%s reason=%s ts=%s\n",
			entry.SessionID, entry.Tool, entry.Reason, entry.Ts.Format(time.RFC3339),
		)
		count++
	}

	if count > 0 {
		fmt.Fprintf(os.Stderr,
			"aegis-daemon: WARN aegis_failopen_total=%d — governance was bypassed during daemon downtime\n",
			count,
		)
	}

	return sc.Err()
}

// failOpenEntry mirrors the hook binary's FailOpenEntry for log parsing.
type failOpenEntry struct {
	Ts               time.Time `json:"ts"`
	SessionID        string    `json:"session_id"`
	Tool             string    `json:"tool"`
	ArgsHash         string    `json:"args_hash"`
	Reason           string    `json:"reason"`
	DeadlineExceeded bool      `json:"deadline_exceeded"`
}
