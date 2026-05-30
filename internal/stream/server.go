// SPDX-License-Identifier: MIT
// Package stream implements the WebSocket streaming server for the Nixis dashboard.
// It receives governance events via the StreamTap interface and fans them out
// to connected dashboard clients over WebSocket (RFC 6455), CloudEvents v1.0 format.
//
// Import constraint: this package MUST NOT import internal/audit or internal/policy.
// All integration is via pkg/nixis interfaces (StreamTap, SnapshotReader).
package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/mayjain/nixis/internal/otel"
	"github.com/mayjain/nixis/pkg/nixis"
)

type ipLimiter struct {
	mu       sync.Mutex
	conns    map[string]int
	attempts map[string][]time.Time
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{
		conns:    make(map[string]int),
		attempts: make(map[string][]time.Time),
	}
}

// Max 4 concurrent WS connections, max 10 upgrade attempts per minute.
func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	prev := l.attempts[ip]
	filtered := prev[:0]
	for _, t := range prev {
		if now.Sub(t) < time.Minute {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	l.attempts[ip] = filtered
	return l.conns[ip] < 4 && len(filtered) <= 10
}

func (l *ipLimiter) inc(ip string) {
	l.mu.Lock()
	l.conns[ip]++
	l.mu.Unlock()
}

func (l *ipLimiter) dec(ip string) {
	l.mu.Lock()
	if l.conns[ip] > 0 {
		l.conns[ip]--
	}
	l.mu.Unlock()
}

const (
	defaultAddr       = ":9090"
	clientChanCap     = 100
	maxClients        = 64
	heartbeatInterval = 10 * time.Second
	writeTimeout      = 5 * time.Second
	simulateBodyLimit = 64 * 1024 // 64KB max request body for /simulate
)

// Evaluator can evaluate a single CheckRequest. Implemented by *policy.PolicyEngine.
// Injected via WithEvaluator so stream does not import internal/policy.
type Evaluator interface {
	Evaluate(ctx context.Context, req nixis.CheckRequest) nixis.CheckResponse
}

// PolicyInfo is the JSON wire format for GET /policies.
type PolicyInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Layer         string `json:"layer"`
	Enabled       bool   `json:"enabled"`
	CelExpression string `json:"cel_expression,omitempty"`
	Description   string `json:"description,omitempty"`
}

// Option is a functional option for NewStreamServer.
type Option func(*StreamServer)

// WithEvaluator injects a policy evaluator, enabling the /simulate endpoint.
func WithEvaluator(e Evaluator) Option {
	return func(s *StreamServer) {
		s.evaluator = e
	}
}

// WithPolicyLister injects a policy lister, enabling the GET /policies endpoint.
func WithPolicyLister(l nixis.PolicyLister) Option {
	return func(s *StreamServer) {
		s.policyLister = l
	}
}

// RouteRegistrar is a function that registers additional handlers on the stream server's HTTP mux.
type RouteRegistrar func(mux *http.ServeMux)

// WithRouteRegistrar adds a callback that registers additional HTTP handlers on the
// stream server's mux during Start(). Used to co-locate the REST /v1/check endpoint.
func WithRouteRegistrar(r RouteRegistrar) Option {
	return func(s *StreamServer) {
		s.routeRegistrars = append(s.routeRegistrars, r)
	}
}

// client represents one connected dashboard WebSocket client.
type client struct {
	id     string
	conn   *websocket.Conn
	send   chan []byte // bounded cap=100; drop on full (never block fan-out)
	filter eventFilter
	mu     sync.Mutex // protects filter

	// backfill concurrency control: max 2 in-flight
	backfillInFlight atomic.Int32

	// done is closed once by handleWebSocket (via sync.Once) to signal writePump to exit.
	done     chan struct{}
	doneOnce sync.Once
}

// eventFilter holds server-side per-client filter state.
type eventFilter struct {
	verdicts     []string
	tools        []string
	latencyMinNs int64
	latencyMaxNs int64
}

// cloudEvent is the CloudEvents v1.0 envelope emitted on the wire.
type cloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Source          string          `json:"source"`
	Subject         string          `json:"subject,omitempty"`
	Time            string          `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	NixisSequence   uint64          `json:"nixissequence"`
	MerklePrev      string          `json:"nixismerkleprev,omitempty"`
	MerkleSelf      string          `json:"nixismerkleself,omitempty"`
	Data            json.RawMessage `json:"data"`
}

// stateSnapshot is the initial payload sent on client connect (per STREAMING_PROTOCOL.md §3).
// It is NOT a CloudEvent — it lacks specversion, id, and datacontenttype.
type stateSnapshot struct {
	Type       string `json:"type"`     // "state.snapshot"
	Sequence   uint64 `json:"sequence"` // current sequence counter
	Policies   int    `json:"policies"` // active policy count
	Version    uint64 `json:"version"`  // engine snapshot version
	BundleHash string `json:"bundleHash,omitempty"`
}

// heartbeatData is the data payload for stream.heartbeat events.
type heartbeatData struct {
	ServerTime     int64   `json:"serverTime"` // ms since Unix epoch
	Lag            int     `json:"lag"`
	Sequence       uint64  `json:"sequence"`
	Seq            uint64  `json:"seq"` // monotonic per-server counter for replay detection
	SamplingActive bool    `json:"sampling_active"`
	SampleRate     float64 `json:"sample_rate"`
}

// inboundMessage is a client → daemon message (plain JSON, not CloudEvents).
type inboundMessage struct {
	Type       string          `json:"type"`
	Filter     json.RawMessage `json:"filter,omitempty"`
	From       int64           `json:"from,omitempty"`
	To         int64           `json:"to,omitempty"`
	ClientTime int64           `json:"clientTime,omitempty"`
}

// subscribeFilter is the filter payload in subscribe.filter messages.
type subscribeFilter struct {
	Verdicts     []string `json:"verdicts"`
	Tools        []string `json:"tools"`
	LatencyMinNs int64    `json:"latencyMinNs"`
	LatencyMaxNs int64    `json:"latencyMaxNs"`
}

// droppedTotal counts events dropped for slow clients.
var droppedTotal atomic.Uint64

// StreamServer is the WebSocket fan-out hub.
// It implements nixis.StreamTap (Emit) and nixis.SnapshotReader (LoadSnapshot).
type StreamServer struct {
	addr         string
	tap          nixis.StreamTap // upstream tap (may be nil in tests — server IS the tap)
	reader       nixis.SnapshotReader
	evaluator    Evaluator          // injected via WithEvaluator; nil disables /simulate
	policyLister nixis.PolicyLister // injected via WithPolicyLister; nil disables GET /policies
	clients      sync.Map           // string → *client
	seq          sequenceCounter
	events       chan nixis.StreamEvent // internal fan-out queue
	httpSrv      *http.Server
	limiter      *ipLimiter
	ready        atomic.Bool // true after the TCP listener is fully bound

	// lastBundlePayload stores the most recent bundle.activated CloudEvent payload.
	// Replayed to each new client on connect so the dashboard always shows loaded policies.
	lastBundlePayload atomic.Pointer[[]byte]

	// routeRegistrars holds callbacks that register additional HTTP handlers.
	routeRegistrars []RouteRegistrar
}

// NewStreamServer constructs a StreamServer.
// tap: upstream event source (may be nil; callers may Emit directly).
// reader: provides current EngineSnapshot for state.snapshot on connect.
func NewStreamServer(tap nixis.StreamTap, reader nixis.SnapshotReader, opts ...Option) *StreamServer {
	addr := os.Getenv("NIXIS_DASHBOARD_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	s := &StreamServer{
		addr:    addr,
		tap:     tap,
		reader:  reader,
		events:  make(chan nixis.StreamEvent, 512),
		limiter: newIPLimiter(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start runs the HTTP server and background goroutines. Blocks until ctx is cancelled.
func (s *StreamServer) Start(ctx context.Context, addr string) error {
	if addr != "" {
		s.addr = addr
	}

	// Bind to 127.0.0.1 only — security requirement.
	ln, err := net.Listen("tcp", resolveLoopbackAddr(s.addr))
	if err != nil {
		return fmt.Errorf("stream: listen %s: %w", s.addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/simulate", s.handleSimulate)
	mux.HandleFunc("/policies", s.handlePolicies)
	mux.HandleFunc("/healthz/ready", s.handleHealthzReady)

	for _, reg := range s.routeRegistrars {
		reg(mux)
	}

	s.httpSrv = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go s.fanOut(ctx)
	go s.heartbeat(ctx)

	// Mark the server ready after the listener is bound and Serve is starting.
	s.ready.Store(true)

	errCh := make(chan error, 1)
	go func() {
		if serveErr := s.httpSrv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutCtx)
	case serveErr := <-errCh:
		return serveErr
	}
}

// resolveLoopbackAddr rewrites ":port" to "127.0.0.1:port".
func resolveLoopbackAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return "127.0.0.1:" + port
}

// Emit implements nixis.StreamTap. It is non-blocking: events are enqueued
// to the internal fan-out channel. Overflow events are dropped.
// nixissequence is assigned in the fan-out goroutine, not here.
func (s *StreamServer) Emit(ctx context.Context, event nixis.StreamEvent) {
	// Validate event type at entry — unknown types are rejected.
	if !validEventTypes[event.Type] {
		return
	}
	select {
	case s.events <- event:
	default:
		// fan-out queue full; drop. fan-out is behind — don't block caller.
		droppedTotal.Add(1)
	}
}

// LoadSnapshot implements nixis.SnapshotReader.
func (s *StreamServer) LoadSnapshot() *nixis.EngineSnapshot {
	if s.reader != nil {
		return s.reader.LoadSnapshot()
	}
	return nil
}

// fanOut reads from the internal event channel and dispatches to all clients.
// nixissequence is assigned here (per STREAMING_PROTOCOL.md §7).
func (s *StreamServer) fanOut(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.events:
			if !ok {
				return
			}
			// Assign sequence number in fan-out goroutine.
			seq := s.seq.next()
			payload, err := buildCloudEvent(event, seq)
			if err != nil {
				log.Printf("stream: marshal event %s: %v", event.Type, err)
				continue
			}
			s.broadcast(payload)
		}
	}
}

// broadcast sends payload to all connected clients (non-blocking per-client).
func (s *StreamServer) broadcast(payload []byte) {
	s.clients.Range(func(_, v any) bool {
		c := v.(*client)
		select {
		case c.send <- payload:
		default:
			// Per-client channel full — drop for this slow client.
			droppedTotal.Add(1)
		}
		return true
	})
}

// heartbeat periodically broadcasts stream.heartbeat events to all clients.
func (s *StreamServer) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq := s.seq.next()
			now := time.Now()
			data := heartbeatData{
				ServerTime:     now.UnixMilli(),
				Lag:            0,
				Sequence:       seq,
				Seq:            seq,
				SamplingActive: false,
				SampleRate:     0,
			}
			raw, err := json.Marshal(data)
			if err != nil {
				continue
			}
			evt := cloudEvent{
				SpecVersion:     "1.0",
				ID:              fmt.Sprintf("hb-%d", seq),
				Type:            "stream.heartbeat",
				Source:          "nixis-daemon/instance-001",
				Time:            now.UTC().Format(time.RFC3339Nano),
				DataContentType: "application/json",
				NixisSequence:   seq,
				Data:            raw,
			}
			payload, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			s.broadcast(payload)
		}
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Reject cross-origin upgrades (only localhost is permitted).
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		host := r.Host
		if host == "" {
			host = r.Header.Get("X-Forwarded-Host")
		}
		// Allow same-host (dashboard dev server on same machine).
		// Reject anything with a different host or scheme.
		return isAllowedOrigin(origin, host)
	},
}

// isAllowedOrigin returns true if the origin is http(s)://localhost or http(s)://127.0.0.1.
// Scheme check blocks file://, chrome-extension://, and other non-HTTP origins.
// No port matching: dev dashboard (5173) and daemon (9090) use different ports.
func isAllowedOrigin(origin, _ string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := u.Hostname()
	scheme := u.Scheme
	return (h == "localhost" || h == "127.0.0.1") &&
		(scheme == "http" || scheme == "https")
}

// isLocalhostOrigin returns true if the Origin header is http://localhost:* or http://127.0.0.1:*.
func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return (h == "localhost" || h == "127.0.0.1") && u.Scheme == "http"
}

// handleSimulate handles POST /simulate requests from the dashboard.
// It decodes a CheckRequest, calls the injected evaluator, emits the result
// to the WebSocket stream, and returns the CheckResponse as JSON.
func (s *StreamServer) handleSimulate(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	corsAllowed := origin == "" || isLocalhostOrigin(origin)

	// CORS preflight.
	if r.Method == http.MethodOptions {
		if corsAllowed && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if corsAllowed && origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if s.evaluator == nil {
		http.Error(w, "evaluator not configured", http.StatusNotImplemented)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, simulateBodyLimit)
	var req nixis.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixNano()
	}
	if req.SessionID == "" {
		req.SessionID = uuid.New().String()
	}

	start := time.Now()
	resp := s.evaluator.Evaluate(r.Context(), req)
	latencyNs := time.Since(start).Nanoseconds()
	if resp.LatencyNs == 0 {
		resp.LatencyNs = latencyNs
	}

	eventType := "policy.evaluated"
	if resp.Decision.Action == nixis.ActionDeny {
		eventType = "policy.denied"
	}
	s.Emit(r.Context(), nixis.StreamEvent{
		Type:           eventType,
		NixisSequence:  0, // assigned in fan-out goroutine
		SessionID:      req.SessionID,
		Tool:           req.Tool,
		Action:         resp.Decision.Action,
		Reason:         resp.Decision.Reason,
		Label:          resp.Decision.Labels,
		Timestamp:      req.Timestamp,
		PolicyID:       resp.Decision.PolicyID,
		EnforcingLayer: string(resp.EnforcingLayer),
		LabelState:     "fresh",
		LatencyNs:      resp.LatencyNs,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("stream: simulate response encode: %v", err)
	}
}

// handlePolicies handles GET /policies requests from the dashboard.
// It returns the current active policy list as JSON.
func (s *StreamServer) handlePolicies(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	corsAllowed := origin == "" || isLocalhostOrigin(origin)

	if r.Method == http.MethodOptions {
		if corsAllowed && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if corsAllowed && origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if s.policyLister == nil {
		http.Error(w, "policy lister not configured", http.StatusNotImplemented)
		return
	}

	summaries := s.policyLister.ListPolicies()
	policies := make([]PolicyInfo, 0, len(summaries))
	for _, ps := range summaries {
		policies = append(policies, PolicyInfo{
			ID:            ps.ID,
			Name:          ps.Name,
			Layer:         ps.Layer,
			Enabled:       ps.Enabled,
			CelExpression: ps.CelExpression,
			Description:   ps.Description,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policies); err != nil {
		log.Printf("stream: policies response encode: %v", err)
	}
}

// handleHealthzReady returns 200 once the TCP listener is bound, 503 before that.
func (s *StreamServer) handleHealthzReady(w http.ResponseWriter, r *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("starting"))
	}
}

// handleWebSocket upgrades an HTTP connection to WebSocket, sends state.snapshot,
// then pumps events to the client until disconnect.
func (s *StreamServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Per-IP rate limiting: max 4 concurrent connections, max 10 upgrades/minute.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !s.limiter.allow(ip) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote 403/400 response on failure.
		return
	}
	s.limiter.inc(ip)
	defer s.limiter.dec(ip)

	c := &client{
		id:   uuid.New().String(),
		conn: conn,
		send: make(chan []byte, clientChanCap),
		done: make(chan struct{}),
	}

	// Enforce max concurrent clients.
	count := 0
	s.clients.Range(func(_, _ any) bool { count++; return true })
	if count >= maxClients {
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "max clients"))
		_ = conn.Close()
		return
	}

	s.clients.Store(c.id, c)
	otel.InstrumentStreamClients().Add(r.Context(), 1)
	defer func() {
		_ = conn.Close()
	}()

	// Send state.snapshot immediately before any live events.
	if err := s.sendStateSnapshot(c); err != nil {
		log.Printf("stream: snapshot send error: %v", err)
		s.clients.Delete(c.id)
		otel.InstrumentStreamClients().Add(r.Context(), -1)
		c.doneOnce.Do(func() { close(c.done) })
		return
	}

	// Start writer goroutine.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		s.writePump(c)
	}()

	// Reader goroutine (this goroutine) handles inbound client messages.
	s.readPump(c)

	// Remove client from registry so no concurrent broadcast can touch c.send.
	s.clients.Delete(c.id)
	otel.InstrumentStreamClients().Add(r.Context(), -1)

	// Signal writePump to exit via done channel (sync.Once ensures exactly one close).
	c.doneOnce.Do(func() { close(c.done) })

	// Wait for writer to finish after connection is closed.
	<-writerDone
}

// sendStateSnapshot assembles and sends the initial state.snapshot message,
// followed by the most recent bundle.activated payload if one exists.
func (s *StreamServer) sendStateSnapshot(c *client) error {
	snap := stateSnapshot{
		Type:     "state.snapshot",
		Sequence: s.seq.n.Load(),
	}
	if s.reader != nil {
		if es := s.reader.LoadSnapshot(); es != nil {
			snap.Version = es.Version
		}
	}
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if err := c.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		return err
	}
	// Replay the most recent bundle.activated event so the dashboard shows loaded
	// policies even when it connects after the initial startup broadcast.
	if p := s.lastBundlePayload.Load(); p != nil {
		if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			return err
		}
		return c.conn.WriteMessage(websocket.TextMessage, *p)
	}
	return nil
}

// writePump drains the client's send channel and writes to the WebSocket.
func (s *StreamServer) writePump(c *client) {
	for {
		select {
		case <-c.done:
			return
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}
}

// readPump reads inbound messages from the client (subscribe.filter, backfill.request, ping).
func (s *StreamServer) readPump(c *client) {
	c.conn.SetReadLimit(2 * 1024 * 1024) // 2MB per STREAMING_PROTOCOL.md §1
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var msg inboundMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			// Malformed — log and discard.
			log.Printf("stream: malformed inbound message: %v", err)
			continue
		}
		switch msg.Type {
		case "subscribe.filter":
			s.handleSubscribeFilter(c, msg.Filter)
		case "backfill.request":
			go s.handleBackfill(c, msg.From, msg.To)
		case "ping":
			s.handlePing(c, msg.ClientTime)
		default:
			// Unknown inbound type — log and discard per §8.
			log.Printf("stream: unknown inbound message type: %s", msg.Type)
		}
	}
}

// handleSubscribeFilter updates the per-client filter.
func (s *StreamServer) handleSubscribeFilter(c *client, raw json.RawMessage) {
	var f subscribeFilter
	if err := json.Unmarshal(raw, &f); err != nil {
		return
	}
	c.mu.Lock()
	c.filter = eventFilter{
		verdicts:     f.Verdicts,
		tools:        f.Tools,
		latencyMinNs: f.LatencyMinNs,
		latencyMaxNs: f.LatencyMaxNs,
	}
	c.mu.Unlock()
}

// handleBackfill handles backfill.request validation and rate-limiting.
// Actual SQLite queries are out of scope (injected via reader interface).
func (s *StreamServer) handleBackfill(c *client, from, to int64) {
	// Rate limit: max 2 concurrent in-flight per client.
	if c.backfillInFlight.Add(1) > 2 {
		c.backfillInFlight.Add(-1)
		s.sendSystemError(c, "backfill_rate_limited", "backfill rate limit exceeded")
		return
	}
	defer c.backfillInFlight.Add(-1)

	// Validation constraints per STREAMING_PROTOCOL.md §6.1.
	if from < 0 || to < from {
		s.sendSystemError(c, "backfill_invalid_range", "from/to range invalid")
		return
	}
	if to-from > 1000 {
		s.sendSystemError(c, "backfill_range_too_large", "range exceeds 1000 events")
		return
	}

	// Backfill data is provided by the audit system, not available here.
	// Emit a system.error indicating unavailability for MVP-1.
	s.sendSystemError(c, "backfill_unavailable", "backfill not yet available")
}

// handlePing responds to client ping with a pong.
func (s *StreamServer) handlePing(c *client, clientTime int64) {
	pong := map[string]any{
		"type":       "pong",
		"clientTime": clientTime,
		"serverTime": time.Now().UnixMilli(),
	}
	payload, err := json.Marshal(pong)
	if err != nil {
		return
	}
	select {
	case c.send <- payload:
	default:
		droppedTotal.Add(1)
	}
}

// sendSystemError enqueues a system.error CloudEvent to a specific client.
func (s *StreamServer) sendSystemError(c *client, reason, msg string) {
	seq := s.seq.next()
	data := map[string]string{
		"subsystem": "stream",
		"error":     msg,
		"source":    reason,
		"severity":  "medium",
	}
	raw, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		log.Printf("stream: marshal error: %v", marshalErr)
		raw = []byte(`{}`)
	}
	evt := cloudEvent{
		SpecVersion:     "1.0",
		ID:              fmt.Sprintf("err-%d", seq),
		Type:            "system.error",
		Source:          "nixis-daemon/instance-001",
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		NixisSequence:   seq,
		Data:            raw,
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}
	select {
	case c.send <- payload:
	default:
		droppedTotal.Add(1)
	}
}

// EmitBundleActivated broadcasts a bundle.activated CloudEvent directly to all clients
// and stores the payload for replay to newly connecting clients.
// It bypasses the generic Emit path so the data payload matches BundleActivatedDataSchema
// (version, hash, policyCount, signatureVerified) rather than the generic StreamEvent fields.
func (s *StreamServer) EmitBundleActivated(_ context.Context, version uint64, hash string, policyCount int, signatureVerified bool) {
	seq := s.seq.next()
	data := map[string]any{
		"version":           version,
		"hash":              hash,
		"policyCount":       policyCount,
		"signatureVerified": signatureVerified,
		"previousVersion":   0,
		"adapterCount":      0,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		log.Printf("stream: marshal bundle.activated data: %v", err)
		return
	}
	evt := cloudEvent{
		SpecVersion:     "1.0",
		ID:              fmt.Sprintf("bundle-%d", seq),
		Type:            "bundle.activated",
		Source:          "nixis-daemon/instance-001",
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		NixisSequence:   seq,
		Data:            raw,
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		log.Printf("stream: marshal bundle.activated envelope: %v", err)
		return
	}
	// Store for replay to clients that connect after the initial broadcast.
	s.lastBundlePayload.Store(&payload)
	s.broadcast(payload)
}

// EmitAuditCheckpoint broadcasts an audit.checkpoint event with the chain hash,
// previous hash, and record count since the previous checkpoint.
// It bypasses the generic StreamEvent path so checkpoint-specific fields land
// in the data payload where the dashboard Zod schema expects them.
func (s *StreamServer) EmitAuditCheckpoint(_ context.Context, seq int64, hash, prevHash string, eventCount int) {
	wseq := s.seq.next()
	data := map[string]any{
		"sequence":          seq,
		"hash":              hash,
		"prev_hash":         prevHash,
		"events_since_prev": eventCount,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		log.Printf("stream: marshal audit.checkpoint data: %v", err)
		return
	}
	evt := cloudEvent{
		SpecVersion:     "1.0",
		ID:              fmt.Sprintf("ckpt-%d", wseq),
		Type:            "audit.checkpoint",
		Source:          "nixis-daemon/instance-001",
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		NixisSequence:   wseq,
		MerkleSelf:      hash,
		MerklePrev:      prevHash,
		Data:            raw,
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		log.Printf("stream: marshal audit.checkpoint envelope: %v", err)
		return
	}
	s.broadcast(payload)
}

// buildCloudEvent marshals a StreamEvent into a CloudEvents v1.0 JSON payload.
// seq is the nixissequence assigned in the fan-out goroutine.
// The data payload uses the nested structure expected by the dashboard Zod schema:
// { session_id, tool, decision: { action, reason, policy_id, enforcing_layer, labels }, label_state, latency_ns }
func buildCloudEvent(event nixis.StreamEvent, seq uint64) ([]byte, error) {
	wireType := event.Type
	if !validEventTypes[wireType] {
		wireType = normalizeEventType(wireType)
	}

	// Build labels with lowercase field names matching the dashboard SecurityLabelSchema.
	// SecurityLabel has no json tags (fields are Confidentiality/Integrity/Category),
	// so we construct the wire object explicitly.
	labels := map[string]any{
		"confidentiality": event.Label.Confidentiality,
		"integrity":       event.Label.Integrity,
		"categories":      event.Label.Category,
	}

	data := map[string]any{
		"session_id": event.SessionID,
		"tool":       event.Tool,
		"decision": map[string]any{
			"action":          event.Action,
			"reason":          event.Reason,
			"policy_id":       event.PolicyID,
			"enforcing_layer": event.EnforcingLayer,
			"labels":          labels,
		},
		"label_state": event.LabelState,
		"latency_ns":  event.LatencyNs,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("evt-%d", seq)
	if event.SessionID != "" {
		id = fmt.Sprintf("evt-%s-%d", event.SessionID[:min(8, len(event.SessionID))], seq)
	}

	evt := cloudEvent{
		SpecVersion:     "1.0",
		ID:              id,
		Type:            wireType,
		Source:          "nixis-daemon/instance-001",
		Subject:         event.Tool,
		Time:            time.Unix(0, event.Timestamp).UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		NixisSequence:   seq,
		Data:            raw,
	}

	// Non-Merkle events: stream.heartbeat and system.error omit merkle fields.
	// Other events will have merkle fields populated by the audit system.
	// Merkle fields are left empty; audit integration is pending.

	return json.Marshal(evt)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
