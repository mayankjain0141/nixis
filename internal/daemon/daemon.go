// SPDX-License-Identifier: MIT
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mayankjain0141/nixis/internal/audit"
	"github.com/mayankjain0141/nixis/internal/delegation"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/internal/otel"
	"github.com/mayankjain0141/nixis/internal/reload"
	"github.com/mayankjain0141/nixis/internal/stream"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// Lifecycle state machine:
//
//	INITIALIZING → LISTENING → DRAINING → FLUSHING → STOPPED
type Daemon struct {
	cfg          Config
	engine       nixis.Engine
	auditWriter  *audit.Writer
	listener     net.Listener
	streamSrv    nixis.StreamTap    // nil disables streaming
	sessions     *ifc.SessionLabels // nil disables session label persistence
	delegAPI     *DelegationAPI     // nil disables delegation HTTP endpoints
	taintHistory *ifc.TaintHistory  // nil disables taint history pruning

	reloader reload.PolicyReloader // nil until SetReloader is called

	mode        modeState
	evaluations atomic.Int64
	startTime   time.Time

	// inFlight tracks the number of in-progress connection goroutines.
	// Graceful shutdown waits for this WaitGroup before closing the audit channel.
	inFlight sync.WaitGroup

	// sem limits concurrent connection goroutines.
	sem chan struct{}

	// auditCancel and auditDone drive the audit goroutine lifecycle.
	// Populated via SetAuditContext before Run() is called.
	auditCancel context.CancelFunc
	auditDone   <-chan struct{}

	readyCh chan struct{}
}

// New constructs a Daemon from the provided config, engine, audit writer, and optional
// stream server. Pass nil for streamSrv to disable streaming. Pass nil for sessions to
// disable session label persistence.
func New(cfg Config, engine nixis.Engine, aw *audit.Writer, streamSrv *stream.StreamServer, sessions *ifc.SessionLabels) *Daemon {
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

func (d *Daemon) setReadyCh(ch chan struct{}) {
	d.readyCh = ch
}

// Mode returns the current operational mode of the daemon.
func (d *Daemon) Mode() DaemonMode {
	return d.mode.Mode()
}

// SetMode updates the daemon's operational mode with a reason string.
func (d *Daemon) SetMode(m DaemonMode, reason string) {
	d.mode.Set(m, reason)
}

// ModeWithReason returns both the current mode and the reason it was set.
func (d *Daemon) ModeWithReason() (DaemonMode, string) {
	return d.mode.Get()
}

// Evaluations returns the total number of CheckRequests handled since startup.
func (d *Daemon) Evaluations() int64 {
	return d.evaluations.Load()
}

// Run starts the daemon and blocks until the context is cancelled or a signal is received.
//
// Shutdown order:
//  1. Stop listener (no new connections accepted).
//  2. Wait for in-flight connections to complete.
//  3. Close audit writer channel.
//  4. Flush audit to SQLite.
//  5. Close SQLite.
//  6. Remove socket file.
func (d *Daemon) Run(ctx context.Context) error {
	d.startTime = time.Now()

	if err := d.reconcileFailOpenLog(); err != nil {
		// Non-fatal: log but continue.
		fmt.Fprintf(os.Stderr, "nixis-daemon: fail-open log reconciliation error: %v\n", err)
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

	// Start periodic maintenance: prune expired standing rules and taint history.
	go d.runMaintenanceLoop(ctx)

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
		otel.InstrumentDaemonConns().Add(context.Background(), 1)
		go func() {
			defer func() {
				otel.InstrumentDaemonConns().Add(context.Background(), -1)
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
	// The caller (cmd/nixis-daemon/main.go) owns auditCtx and cancels it here.
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

// SetTaintHistory wires a TaintHistory into the daemon for periodic pruning.
func (d *Daemon) SetTaintHistory(h *ifc.TaintHistory) {
	d.taintHistory = h
}

// SetReloader wires a PolicyReloader so the /reload HTTP endpoint can trigger
// a policy re-parse and engine reload on demand.
func (d *Daemon) SetReloader(r reload.PolicyReloader) {
	d.reloader = r
}

// handleReload triggers a synchronous policy reload via the wired PolicyReloader.
func (d *Daemon) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if d.reloader == nil {
		http.Error(w, "no reloader configured", http.StatusServiceUnavailable)
		return
	}
	if err := d.reloader.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"status\":\"reloaded\"}\n"))
}

// runMaintenanceLoop runs periodic cleanup tasks:
// - Prune expired standing rules from all sessions every 5 minutes
// - Prune old taint history records older than 7 days every hour
func (d *Daemon) runMaintenanceLoop(ctx context.Context) {
	ruleTicker := time.NewTicker(5 * time.Minute)
	historyTicker := time.NewTicker(1 * time.Hour)
	defer ruleTicker.Stop()
	defer historyTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ruleTicker.C:
			if d.sessions != nil {
				d.sessions.PruneExpiredRules()
			}
		case <-historyTicker.C:
			if d.taintHistory != nil {
				if _, err := d.taintHistory.PruneOlderThan(7 * 24 * time.Hour); err != nil {
					log.Printf("WARN: taint history prune failed: %v", err)
				}
			}
		}
	}
}

// HealthResponse is the structured JSON response for /healthz.
type HealthResponse struct {
	Status      string  `json:"status"`                // "healthy", "degraded", "unhealthy"
	Mode        string  `json:"mode"`                  // DaemonMode.String()
	ModeReason  string  `json:"mode_reason,omitempty"` // reason for current mode
	UptimeMs    int64   `json:"uptime_ms"`             // milliseconds since daemon start
	Evaluations int64   `json:"evaluations"`           // total evaluations served
	Version     string  `json:"version"`               // daemon version
	Checks      []Check `json:"checks"`                // component health checks
}

// Check represents a single component health check result.
type Check struct {
	Name   string `json:"name"`            // component name
	Status string `json:"status"`          // "ok" or "error"
	Error  string `json:"error,omitempty"` // error message if status is "error"
}

// serveHealthz starts a minimal HTTP server on :9091 that serves /healthz and,
// when a delegation engine is wired, the /api/v1/delegation/* endpoints.
// The server shuts down when ctx is cancelled.
func (d *Daemon) serveHealthz(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", d.handleHealthz)
	mux.HandleFunc("/reload", d.handleReload)
	if d.delegAPI != nil {
		d.delegAPI.RegisterRoutes(mux)
	}
	d.registerApprovalRoutes(mux)
	srv := &http.Server{
		Addr:         d.cfg.HealthzAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	_ = srv.ListenAndServe()
}

// handleHealthz returns a structured JSON health response.
func (d *Daemon) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	mode, reason := d.mode.Get()

	resp := HealthResponse{
		Status:      mode.HealthStatus(),
		Mode:        mode.String(),
		ModeReason:  reason,
		UptimeMs:    time.Since(d.startTime).Milliseconds(),
		Evaluations: d.evaluations.Load(),
		Version:     "v4",
		Checks:      d.runHealthChecks(),
	}

	w.Header().Set("Content-Type", "application/json")

	switch mode {
	case ModeNormal, ModeDegraded:
		w.WriteHeader(http.StatusOK)
	case ModeDenyAll, ModeReadOnly:
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

// runHealthChecks performs basic component health checks.
func (d *Daemon) runHealthChecks() []Check {
	checks := []Check{
		{Name: "listener", Status: "ok"},
		{Name: "engine", Status: "ok"},
	}

	if d.listener == nil {
		checks[0] = Check{Name: "listener", Status: "error", Error: "not bound"}
	}

	if d.engine == nil {
		checks[1] = Check{Name: "engine", Status: "error", Error: "not initialized"}
	}

	if d.auditWriter != nil {
		checks = append(checks, Check{Name: "audit", Status: "ok"})
	}

	return checks
}

// reconcileFailOpenLog reads the fail-open log from the last daemon run and
// emits a warning for each entry.
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
			"nixis-daemon: WARN fail-open entry reconciled: session=%s tool=%s reason=%s ts=%s\n",
			entry.SessionID, entry.Tool, entry.Reason, entry.Ts.Format(time.RFC3339),
		)
		count++
	}

	if count > 0 {
		fmt.Fprintf(os.Stderr,
			"nixis-daemon: WARN nixis_failopen_total=%d — governance was bypassed during daemon downtime\n",
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
