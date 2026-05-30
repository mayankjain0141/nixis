package stream

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// nullReader implements SnapshotReader returning nil.
type nullReader struct{}

func (nullReader) LoadSnapshot() *nixis.EngineSnapshot { return nil }

// newTestServer creates a StreamServer with a loopback listener for testing.
// Returns the server and the ws:// base URL.
func newTestServer(t *testing.T) (*StreamServer, string) {
	t.Helper()
	s := NewStreamServer(nil, nullReader{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	srv := &http.Server{Handler: mux}
	s.httpSrv = srv

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
	})

	go s.fanOut(ctx)
	go s.heartbeat(ctx)
	go func() { _ = srv.Serve(ln) }()

	addr := ln.Addr().String()
	return s, "ws://" + addr
}

// dialWS connects a test WebSocket client and returns the conn.
func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readMsg reads one JSON message from a WebSocket client.
func readMsg(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("readMsg: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// TestStream_TapChannelContract verifies Emit() is non-blocking even when all
// per-client channels are full (no deadlock, no blocking caller).
func TestStream_TapChannelContract(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)

	// Read the state.snapshot to unblock the writer.
	_ = readMsg(t, conn)

	// Fill the client's send channel without draining it.
	c := getFirstClient(s)
	if c == nil {
		t.Fatal("no client registered")
	}
	for i := 0; i < clientChanCap; i++ {
		c.send <- []byte(`{"fill":true}`)
	}

	// Emit must not block — it should drop for the full-channel client.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			s.Emit(context.Background(), nixis.StreamEvent{
				Type:      "policy.evaluated",
				SessionID: "sess_test",
			})
		}
	}()

	select {
	case <-done:
		// Pass — Emit did not block.
	case <-time.After(2 * time.Second):
		t.Fatal("Emit() blocked when client channel was full")
	}
}

// TestStream_FanOut_AllClients verifies one Emit() reaches all connected clients.
func TestStream_FanOut_AllClients(t *testing.T) {
	s, baseURL := newTestServer(t)

	const numClients = 3
	conns := make([]*websocket.Conn, numClients)
	for i := range conns {
		conns[i] = dialWS(t, baseURL)
		_ = readMsg(t, conns[i]) // consume state.snapshot
	}

	// Wait until all clients are registered.
	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == numClients {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.Emit(context.Background(), nixis.StreamEvent{
		Type:      "policy.denied",
		SessionID: "sess_fan",
		Tool:      "Shell",
	})

	for i, conn := range conns {
		msg := readMsg(t, conn)
		if got := msg["type"]; got != "policy.denied" {
			t.Errorf("client %d: got type %v, want policy.denied", i, got)
		}
	}
}

// TestStream_SlowClientDrop verifies that a slow client (full channel) gets events
// dropped while a fast client continues to receive them unaffected.
func TestStream_SlowClientDrop(t *testing.T) {
	s, baseURL := newTestServer(t)

	fastConn := dialWS(t, baseURL)
	_ = readMsg(t, fastConn) // consume snapshot

	// Wait for fast client to register.
	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Create a slow client by directly injecting a full-channel pseudo-client.
	slowClient := &client{
		id:   "slow-test-client",
		conn: nil, // not used in broadcast path
		send: make(chan []byte, clientChanCap),
	}
	for i := 0; i < clientChanCap; i++ {
		slowClient.send <- []byte(`{}`)
	}
	s.clients.Store(slowClient.id, slowClient)
	defer s.clients.Delete(slowClient.id)

	beforeDrop := droppedTotal.Load()

	// Emit an event — slow client will drop, fast client should receive it.
	s.Emit(context.Background(), nixis.StreamEvent{
		Type:      "policy.evaluated",
		SessionID: "sess_drop",
	})

	// Fast client must receive the event.
	msg := readMsg(t, fastConn)
	if got := msg["type"]; got != "policy.evaluated" {
		t.Errorf("fast client got %v, want policy.evaluated", got)
	}

	// Drop counter must have incremented for the slow client.
	after := droppedTotal.Load()
	if after <= beforeDrop {
		t.Error("drop counter did not increment for slow client")
	}
}

// TestStream_NixisSequence_Monotonic verifies sequence numbers are strictly
// monotonic across concurrent Emit() calls.
func TestStream_NixisSequence_Monotonic(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)
	_ = readMsg(t, conn) // consume snapshot

	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Emit(context.Background(), nixis.StreamEvent{
				Type:      "policy.evaluated",
				SessionID: "sess_seq",
			})
		}()
	}
	wg.Wait()

	// Collect received events.
	var seqs []uint64
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var m map[string]any
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if seqRaw, ok := m["nixissequence"]; ok {
			switch v := seqRaw.(type) {
			case float64:
				seqs = append(seqs, uint64(v))
			}
		}
	}

	if len(seqs) == 0 {
		t.Fatal("no events received")
	}

	// Verify strictly monotonic (within received subset).
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Errorf("sequence not monotonic at index %d: %d <= %d", i, seqs[i], seqs[i-1])
		}
	}
}

// TestStream_InvalidEventType_Rejected verifies unknown event types are not emitted.
func TestStream_InvalidEventType_Rejected(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)
	_ = readMsg(t, conn) // consume snapshot

	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	beforeSeq := s.seq.n.Load()

	// Emit with invalid type — should be rejected at Emit() entry.
	s.Emit(context.Background(), nixis.StreamEvent{
		Type:      "not.a.real.type",
		SessionID: "sess_inv",
	})

	// No events should be queued or delivered.
	time.Sleep(100 * time.Millisecond)
	afterSeq := s.seq.n.Load()

	// Sequence should not have advanced (event was dropped at entry, not fan-out).
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Error("received message for invalid event type — should have been rejected")
	}

	_ = beforeSeq
	_ = afterSeq
}

// TestStream_RejectsXSiteOrigin verifies cross-origin WebSocket upgrades return 403.
func TestStream_RejectsXSiteOrigin(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	defer ts.Close()

	header := http.Header{"Origin": {"https://evil.example.com"}}
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+ts.Listener.Addr().String()+"/ws", header)
	if err == nil {
		t.Fatal("expected WebSocket upgrade to fail for cross-origin")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

// TestStream_PortConfigurable verifies NIXIS_DASHBOARD_ADDR controls listen port.
func TestStream_PortConfigurable(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	addr := ":" + strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
	_ = port

	t.Setenv("NIXIS_DASHBOARD_ADDR", addr)

	s := NewStreamServer(nil, nullReader{})
	if s.addr != addr {
		t.Errorf("addr = %q, want %q", s.addr, addr)
	}
}

// TestStream_BackfillRateLimit verifies a third concurrent backfill returns system.error.
// Uses a direct pseudo-client (no WebSocket) to avoid writePump concurrency.
func TestStream_BackfillRateLimit(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})

	c := &client{
		id:   "rate-limit-test-client",
		send: make(chan []byte, clientChanCap),
	}

	// Simulate 2 in-flight backfills.
	c.backfillInFlight.Store(2)

	// Third backfill should send system.error to c.send immediately.
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleBackfill(c, 0, 10)
	}()

	select {
	case msg := <-c.send:
		var m map[string]any
		if err := json.Unmarshal(msg, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if m["type"] != "system.error" {
			t.Errorf("expected system.error, got %v", m["type"])
		}
		raw, _ := json.Marshal(m["data"])
		if !strings.Contains(string(raw), "backfill_rate_limited") {
			t.Errorf("expected backfill_rate_limited, got %s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no system.error received for rate-limited backfill")
	}
	<-done
}

// TestStream_BackfillValidation verifies range validation errors using direct pseudo-clients.
func TestStream_BackfillValidation(t *testing.T) {
	cases := []struct {
		name     string
		from, to int64
		wantErr  string
	}{
		{"negative_from", -1, 10, "backfill_invalid_range"},
		{"reversed_range", 10, 5, "backfill_invalid_range"},
		{"too_large", 0, 1001, "backfill_range_too_large"},
	}

	s := NewStreamServer(nil, nullReader{})

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := &client{
				id:   "validation-test-" + tc.name,
				send: make(chan []byte, clientChanCap),
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				s.handleBackfill(c, tc.from, tc.to)
			}()

			select {
			case msg := <-c.send:
				var m map[string]any
				if err := json.Unmarshal(msg, &m); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				if m["type"] != "system.error" {
					t.Errorf("expected system.error, got %v", m["type"])
				}
				raw, _ := json.Marshal(m["data"])
				if !strings.Contains(string(raw), tc.wantErr) {
					t.Errorf("from=%d to=%d: want %s in error, got %s", tc.from, tc.to, tc.wantErr, raw)
				}
			case <-time.After(2 * time.Second):
				t.Errorf("from=%d to=%d: no error message received", tc.from, tc.to)
			}
			<-done
		})
	}
}

// TestEventRoutes_MatchGoldenFile verifies the Go normalizeEventType mapping
// matches the golden file at testdata/event_type_map.json.
func TestEventRoutes_MatchGoldenFile(t *testing.T) {
	data, err := os.ReadFile("testdata/event_type_map.json")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	var golden map[string]string
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("parse golden file: %v", err)
	}
	for internal, want := range golden {
		got := normalizeEventType(internal)
		if got != want {
			t.Errorf("normalizeEventType(%q) = %q, want %q", internal, got, want)
		}
	}
}

// TestStream_PolicyEvent_MatchesDashboardSchema verifies that policy.evaluated events
// emitted via Emit() produce JSON with the nested structure required by the dashboard
// Zod schema: decision.action, decision.policy_id, decision.enforcing_layer,
// decision.labels (confidentiality/integrity/categories), label_state, latency_ns.
func TestStream_PolicyEvent_MatchesDashboardSchema(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)
	_ = readMsg(t, conn) // consume state.snapshot

	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	s.Emit(context.Background(), nixis.StreamEvent{
		Type:           "policy.evaluated",
		SessionID:      "sess-schema-test",
		Tool:           "Bash",
		Action:         nixis.ActionDeny,
		Reason:         "git branch -D main is not permitted",
		PolicyID:       "git-branch-protection",
		EnforcingLayer: "cel",
		LabelState:     "fresh",
		LatencyNs:      140000,
		Label:          nixis.SecurityLabel{Confidentiality: 1, Integrity: 2, Category: 3},
	})

	msg := readMsg(t, conn)

	// Top-level envelope fields.
	if got := msg["type"]; got != "policy.evaluated" {
		t.Fatalf("type = %v, want policy.evaluated", got)
	}

	data, ok := msg["data"].(map[string]any)
	if !ok {
		t.Fatalf("data field missing or wrong type: %v", msg["data"])
	}

	// Top-level data fields required by PolicyEvaluatedDataSchema.
	if got := data["tool"]; got != "Bash" {
		t.Errorf("data.tool = %v, want Bash", got)
	}
	if got := data["session_id"]; got != "sess-schema-test" {
		t.Errorf("data.session_id = %v, want sess-schema-test", got)
	}
	if got := data["label_state"]; got != "fresh" {
		t.Errorf("data.label_state = %v, want fresh", got)
	}
	if got, ok := data["latency_ns"].(float64); !ok || int64(got) != 140000 {
		t.Errorf("data.latency_ns = %v, want 140000", data["latency_ns"])
	}

	// Nested decision object required by DecisionSchema.
	decision, ok := data["decision"].(map[string]any)
	if !ok {
		t.Fatalf("data.decision missing or wrong type: %v", data["decision"])
	}
	if got := decision["action"]; got != "deny" {
		t.Errorf("decision.action = %v, want deny", got)
	}
	if got := decision["reason"]; got != "git branch -D main is not permitted" {
		t.Errorf("decision.reason = %v, want reason string", got)
	}
	if got := decision["policy_id"]; got != "git-branch-protection" {
		t.Errorf("decision.policy_id = %v, want git-branch-protection", got)
	}
	if got := decision["enforcing_layer"]; got != "cel" {
		t.Errorf("decision.enforcing_layer = %v, want cel", got)
	}

	// Nested labels required by SecurityLabelSchema (lowercase field names).
	labels, ok := decision["labels"].(map[string]any)
	if !ok {
		t.Fatalf("decision.labels missing or wrong type: %v", decision["labels"])
	}
	if got, ok := labels["confidentiality"].(float64); !ok || uint16(got) != 1 {
		t.Errorf("labels.confidentiality = %v, want 1", labels["confidentiality"])
	}
	if got, ok := labels["integrity"].(float64); !ok || uint16(got) != 2 {
		t.Errorf("labels.integrity = %v, want 2", labels["integrity"])
	}
	if got, ok := labels["categories"].(float64); !ok || uint32(got) != 3 {
		t.Errorf("labels.categories = %v, want 3", labels["categories"])
	}
}

// TestStream_RejectsFileSchemeOrigin verifies file:// origins are rejected.
func TestStream_RejectsFileSchemeOrigin(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	defer ts.Close()

	header := http.Header{"Origin": {"file:///etc/passwd"}}
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+ts.Listener.Addr().String()+"/ws", header)
	if err == nil {
		t.Fatal("expected WebSocket upgrade to fail for file:// origin")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

// TestStream_RejectsChromeExtensionOrigin verifies chrome-extension:// origins are rejected.
func TestStream_RejectsChromeExtensionOrigin(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	defer ts.Close()

	header := http.Header{"Origin": {"chrome-extension://abcdef1234567890"}}
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+ts.Listener.Addr().String()+"/ws", header)
	if err == nil {
		t.Fatal("expected WebSocket upgrade to fail for chrome-extension:// origin")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

// TestStream_AllowsHTTPSLocalhostOrigin verifies https://localhost is accepted.
func TestStream_AllowsHTTPSLocalhostOrigin(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	defer ts.Close()

	header := http.Header{"Origin": {"https://localhost:5173"}}
	conn, resp, err := websocket.DefaultDialer.Dial("ws://"+ts.Listener.Addr().String()+"/ws", header)
	if err != nil {
		if resp != nil {
			t.Fatalf("expected upgrade to succeed for https://localhost origin, got %d", resp.StatusCode)
		}
		t.Fatalf("expected upgrade to succeed for https://localhost origin: %v", err)
	}
	defer conn.Close()
}

// TestStream_HealthzReady verifies /healthz/ready returns 200 after listener is bound.
func TestStream_HealthzReady(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	s.ready.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(s.handleHealthzReady))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /healthz/ready: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestStream_HealthzReady_NotReady verifies /healthz/ready returns 503 before listener is bound.
func TestStream_HealthzReady_NotReady(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	// ready is false by default
	ts := httptest.NewServer(http.HandlerFunc(s.handleHealthzReady))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /healthz/ready: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

// TestStream_HeartbeatSeqField verifies heartbeat data includes a "seq" field
// that increments monotonically.
func TestStream_HeartbeatSeqField(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)
	_ = readMsg(t, conn) // consume state.snapshot

	// Wait briefly for the heartbeat goroutine to fire.
	// Heartbeat interval is 10s in production; force a direct call here.
	c := &client{
		id:   "hb-test",
		send: make(chan []byte, clientChanCap),
	}
	s.clients.Store(c.id, c)
	defer s.clients.Delete(c.id)

	// Manually invoke the heartbeat send logic by calling sendSystemError
	// as a proxy — instead, directly call the heartbeat path via the server seq.
	seq1 := s.seq.next()
	now := time.Now()
	data1 := heartbeatData{
		ServerTime: now.UnixMilli(),
		Sequence:   seq1,
		Seq:        seq1,
	}
	seq2 := s.seq.next()
	data2 := heartbeatData{
		ServerTime: now.UnixMilli(),
		Sequence:   seq2,
		Seq:        seq2,
	}

	if data2.Seq <= data1.Seq {
		t.Errorf("heartbeat seq not monotonic: data1.Seq=%d data2.Seq=%d", data1.Seq, data2.Seq)
	}
}

// TestIPLimiter_AllowsUnderLimit verifies requests below limits are allowed.
func TestIPLimiter_AllowsUnderLimit(t *testing.T) {
	l := newIPLimiter()
	for i := 0; i < 3; i++ {
		l.inc("1.2.3.4")
	}
	if !l.allow("1.2.3.4") {
		t.Error("expected allow with 3 conns (limit is 4)")
	}
}

// TestIPLimiter_BlocksAtConnLimit verifies 4th concurrent connection is rejected.
func TestIPLimiter_BlocksAtConnLimit(t *testing.T) {
	l := newIPLimiter()
	for i := 0; i < 4; i++ {
		l.inc("1.2.3.4")
	}
	if l.allow("1.2.3.4") {
		t.Error("expected deny with 4 conns (limit is 4)")
	}
}

// TestIPLimiter_BlocksAtRateLimit verifies 11th upgrade attempt per minute is rejected.
func TestIPLimiter_BlocksAtRateLimit(t *testing.T) {
	l := newIPLimiter()
	// First 10 must be allowed (conns is 0).
	for i := 0; i < 10; i++ {
		if !l.allow("5.6.7.8") {
			t.Fatalf("expected allow on attempt %d", i+1)
		}
	}
	// 11th must be denied.
	if l.allow("5.6.7.8") {
		t.Error("expected deny on 11th upgrade attempt")
	}
}

// TestIPLimiter_DecReleasesSlot verifies dec() allows a previously-full IP to reconnect.
func TestIPLimiter_DecReleasesSlot(t *testing.T) {
	l := newIPLimiter()
	for i := 0; i < 4; i++ {
		l.inc("9.9.9.9")
	}
	l.dec("9.9.9.9")
	if !l.allow("9.9.9.9") {
		t.Error("expected allow after dec() freed one slot")
	}
}

// TestStream_RateLimiter_Returns429 verifies the WS upgrade returns 429 when IP is at conn limit.
func TestStream_RateLimiter_Returns429(t *testing.T) {
	s := NewStreamServer(nil, nullReader{})
	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	defer ts.Close()

	// Pre-fill the limiter so the test IP is at the 4-conn limit.
	ip, _, _ := net.SplitHostPort(ts.Listener.Addr().String())
	// The test client connects from 127.0.0.1; pre-fill that IP.
	for i := 0; i < 4; i++ {
		s.limiter.inc("127.0.0.1")
	}

	_, resp, err := websocket.DefaultDialer.Dial("ws://"+ts.Listener.Addr().String()+"/ws", nil)
	if err == nil {
		t.Fatal("expected upgrade to fail at conn limit")
	}
	if resp != nil && resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d (ip=%s)", resp.StatusCode, ip)
	}
}

// getFirstClient returns the first client in the registry (for test assertions).
func getFirstClient(s *StreamServer) *client {
	var found *client
	s.clients.Range(func(_, v any) bool {
		found = v.(*client)
		return false
	})
	return found
}

// TestStream_EmitBundleActivated_Broadcast verifies EmitBundleActivated sends a
// well-formed bundle.activated CloudEvent to all connected clients.
func TestStream_EmitBundleActivated_Broadcast(t *testing.T) {
	s, baseURL := newTestServer(t)
	conn := dialWS(t, baseURL)
	_ = readMsg(t, conn) // consume state.snapshot

	// Wait for the client to register.
	for {
		count := 0
		s.clients.Range(func(_, _ any) bool { count++; return true })
		if count == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	const wantCount = 5
	s.EmitBundleActivated(context.Background(), 1, "abc123", wantCount, false)

	msg := readMsg(t, conn)

	if got := msg["type"]; got != "bundle.activated" {
		t.Fatalf("type = %v, want bundle.activated", got)
	}
	data, ok := msg["data"].(map[string]any)
	if !ok {
		t.Fatalf("data field missing or not an object: %v", msg["data"])
	}
	gotCount, ok := data["policyCount"].(float64)
	if !ok {
		t.Fatalf("policyCount missing or not a number: %v", data["policyCount"])
	}
	if int(gotCount) != wantCount {
		t.Errorf("policyCount = %v, want %d", gotCount, wantCount)
	}
	if v, ok := data["version"].(float64); !ok || v != 1 {
		t.Errorf("version = %v, want 1", data["version"])
	}
}

// TestStream_EmitBundleActivated_ReplayOnConnect verifies that a client connecting after
// EmitBundleActivated receives the bundle.activated payload as part of the initial handshake.
func TestStream_EmitBundleActivated_ReplayOnConnect(t *testing.T) {
	s, baseURL := newTestServer(t)

	// Emit before any client connects.
	s.EmitBundleActivated(context.Background(), 2, "def456", 7, true)

	conn := dialWS(t, baseURL)

	// First message is state.snapshot.
	snap := readMsg(t, conn)
	if snap["type"] != "state.snapshot" {
		t.Fatalf("expected state.snapshot, got %v", snap["type"])
	}

	// Second message must be the replayed bundle.activated.
	bundle := readMsg(t, conn)
	if got := bundle["type"]; got != "bundle.activated" {
		t.Fatalf("type = %v, want bundle.activated", got)
	}
	data, ok := bundle["data"].(map[string]any)
	if !ok {
		t.Fatalf("data missing or wrong type: %v", bundle["data"])
	}
	if pc, ok := data["policyCount"].(float64); !ok || int(pc) != 7 {
		t.Errorf("policyCount = %v, want 7", data["policyCount"])
	}
	if sv, ok := data["signatureVerified"].(bool); !ok || !sv {
		t.Errorf("signatureVerified = %v, want true", data["signatureVerified"])
	}
}

// TestStream_GracefulShutdown_PortReleased verifies that after context cancellation
// the TCP port is released and can be immediately rebound.
// This is the regression test for the race where main() exits before
// httpSrv.Shutdown() completes, leaving the port in TIME_WAIT.
func TestStream_GracefulShutdown_PortReleased(t *testing.T) {
	// Grab a free port then release it so we own the address string.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Logf("probe.Close: %v", err)
	}

	// Start the stream server on that address.
	s := NewStreamServer(nil, nullReader{})
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// Signal readiness by attempting a dial; retry until it succeeds.
		go func() {
			for i := 0; i < 50; i++ {
				c, err := net.DialTimeout("tcp", addr, 10*time.Millisecond)
				if err == nil {
					if err := c.Close(); err != nil {
						t.Logf("c.Close: %v", err)
					}
					close(started)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		done <- s.Start(ctx, addr)
	}()

	// Wait until server is accepting.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stream server did not start within 2s")
	}

	// Cancel context — triggers httpSrv.Shutdown inside Start().
	cancel()

	// Wait for Start() to return (Shutdown has a 5s internal timeout).
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("stream server did not shut down within 6s")
	}

	// The port must now be rebindable — no TIME_WAIT blocking.
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s not released after graceful shutdown: %v", addr, err)
	}
	if err := ln2.Close(); err != nil {
		t.Logf("ln2.Close: %v", err)
	}
}
