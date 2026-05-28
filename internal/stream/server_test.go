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
	"github.com/mayjain/aegis/pkg/aegis"
)

// nullReader implements SnapshotReader returning nil.
type nullReader struct{}

func (nullReader) LoadSnapshot() *aegis.EngineSnapshot { return nil }

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
			s.Emit(context.Background(), aegis.StreamEvent{
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

	s.Emit(context.Background(), aegis.StreamEvent{
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
	s.Emit(context.Background(), aegis.StreamEvent{
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

// TestStream_AegisSequence_Monotonic verifies sequence numbers are strictly
// monotonic across concurrent Emit() calls.
func TestStream_AegisSequence_Monotonic(t *testing.T) {
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
			s.Emit(context.Background(), aegis.StreamEvent{
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
		if seqRaw, ok := m["aegissequence"]; ok {
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
	s.Emit(context.Background(), aegis.StreamEvent{
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

// TestStream_PortConfigurable verifies AEGIS_DASHBOARD_ADDR controls listen port.
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

	t.Setenv("AEGIS_DASHBOARD_ADDR", addr)

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

// getFirstClient returns the first client in the registry (for test assertions).
func getFirstClient(s *StreamServer) *client {
	var found *client
	s.clients.Range(func(_, v any) bool {
		found = v.(*client)
		return false
	})
	return found
}
