package main

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/pkg/aegis"
)

// --- helpers ---

func runPolicyCostCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	policyCostCmd.ResetFlags()
	policyCostCmd.SetOut(outBuf)
	policyCostCmd.SetErr(errBuf)
	if len(args) > 0 {
		err = policyCostCmd.RunE(policyCostCmd, args)
	}
	return outBuf.String(), errBuf.String(), err
}

func runPolicyLintCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	policyLintStrict = false
	policyLintCmd.ResetFlags()
	policyLintCmd.SetOut(outBuf)
	policyLintCmd.SetErr(errBuf)
	err = policyLintCmd.RunE(policyLintCmd, args)
	return outBuf.String(), errBuf.String(), err
}

func runDelegIssueCmd(t *testing.T) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	delegationIssueCmd.ResetFlags()
	delegationIssueCmd.SetOut(outBuf)
	delegationIssueCmd.SetErr(errBuf)
	delegIssuer = "alice"
	delegAudience = "bob"
	delegExpires = time.Hour
	delegKeyFile = ""
	err = delegationIssueCmd.RunE(delegationIssueCmd, nil)
	return outBuf.String(), errBuf.String(), err
}

func runDelegVerifyCmd(t *testing.T, tokenPath string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	delegationVerifyCmd.ResetFlags()
	delegationVerifyCmd.SetOut(outBuf)
	delegationVerifyCmd.SetErr(errBuf)
	delegVerifyKeyFile = ""
	err = delegationVerifyCmd.RunE(delegationVerifyCmd, []string{tokenPath})
	return outBuf.String(), errBuf.String(), err
}

func runAuditExportCmd(t *testing.T, format, dbPath string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	auditExportCmd.ResetFlags()
	auditExportCmd.SetOut(outBuf)
	auditExportCmd.SetErr(errBuf)
	auditExportFormat = format
	auditExportFrom = ""
	auditExportTo = ""
	auditExportDB = dbPath
	err = auditExportCmd.RunE(auditExportCmd, nil)
	return outBuf.String(), errBuf.String(), err
}

func runAuditTailCmd(t *testing.T, n int, dbPath string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	auditTailCmd.ResetFlags()
	auditTailCmd.SetOut(outBuf)
	auditTailCmd.SetErr(errBuf)
	auditTailN = n
	auditTailFollow = false
	auditTailDB = dbPath
	err = auditTailCmd.RunE(auditTailCmd, nil)
	return outBuf.String(), errBuf.String(), err
}

func runBundleListCmd(t *testing.T, storeDir string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	bundleListCmd.ResetFlags()
	bundleListCmd.SetOut(outBuf)
	bundleListCmd.SetErr(errBuf)
	bundleListStoreDir = storeDir
	err = bundleListCmd.RunE(bundleListCmd, nil)
	return outBuf.String(), errBuf.String(), err
}

func runBundleRollbackCmd(t *testing.T, storeDir string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	bundleRollbackCmd.ResetFlags()
	bundleRollbackCmd.SetOut(outBuf)
	bundleRollbackCmd.SetErr(errBuf)
	bundleRollbackStoreDir = storeDir
	err = bundleRollbackCmd.RunE(bundleRollbackCmd, nil)
	return outBuf.String(), errBuf.String(), err
}

// initExportDB sets up an audit_log DB with test records and returns the path.
func initExportDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "export.db")
	db := initAuditDB(t, dbPath)
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close export db: %v", err)
		}
	}()
	insertExportRecord(t, db, 1000, "sess1", "Bash", "allow")
	insertExportRecord(t, db, 2000, "sess1", "Read", "deny")
	insertExportRecord(t, db, 3000, "sess2", "Write", "allow")
	return dbPath
}

func insertExportRecord(t *testing.T, db *sql.DB, ts int64, sessID, tool, action string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO audit_log
		(timestamp, session_id, tool, args, action, reason, policy_id, enforcing_layer,
		 label_before_c, label_before_i, label_before_k,
		 label_after_c, label_after_i, label_after_k,
		 latency_ns, chain_hash)
		VALUES (?,?,?,NULL,?,NULL,NULL,NULL,0,0,0,0,0,0,0,NULL)`,
		ts, sessID, tool, action)
	if err != nil {
		t.Fatalf("insertExportRecord: %v", err)
	}
}

// writeBundleToStore writes a fake bundle manifest in storeDir/<hash>/.
func writeBundleToStore(t *testing.T, storeDir string, m bundle.BundleManifest) {
	t.Helper()
	entryDir := filepath.Join(storeDir, m.Hash)
	if err := os.MkdirAll(entryDir, 0700); err != nil {
		t.Fatalf("mkdir bundle entry: %v", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, "manifest.json"), data, 0600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// --- policy cost and lint tests ---

func TestCLI_PolicyLint_Valid(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "valid.yaml", validPolicyYAML("test-policy", "tool == tool"))
	stdout, _, err := runPolicyLintCmd(t, dir)
	if err != nil {
		t.Fatalf("expected no error for valid policies, got: %v", err)
	}
	if !strings.Contains(stdout, "OK:") {
		t.Errorf("expected 'OK:' in output, got: %q", stdout)
	}
}

func TestCLI_PolicyCost_PrintsNumeric(t *testing.T) {
	stdout, _, err := runPolicyCostCmd(t, "tool == 'Bash'")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !strings.Contains(stdout, "cost:") {
		t.Errorf("expected 'cost:' in output, got: %q", stdout)
	}
	// Verify the output contains a numeric value after "cost:"
	var costVal int
	if _, scanErr := fmt.Sscanf(strings.TrimPrefix(strings.TrimSpace(stdout), "cost: "), "%d", &costVal); scanErr != nil {
		t.Errorf("expected numeric cost value, got: %q (scan err: %v)", stdout, scanErr)
	}
}

func TestCLI_PolicyCost_InvalidExpr(t *testing.T) {
	_, stderr, err := runPolicyCostCmd(t, "tool ==")
	if err == nil {
		t.Fatal("expected non-zero exit for invalid CEL expression")
	}
	if !strings.Contains(stderr, "parse error") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected parse error in stderr or error, got stderr=%q err=%v", stderr, err)
	}
}

// --- delegation issue/verify tests ---

func TestCLI_DelegationIssue_ProducesSignedToken(t *testing.T) {
	stdout, _, err := runDelegIssueCmd(t)
	if err != nil {
		t.Fatalf("delegation issue error: %v", err)
	}
	if !strings.Contains(stdout, "signature") {
		t.Errorf("expected 'signature' field in output JSON, got: %q", stdout)
	}
	var tf tokenFile
	if jsonErr := json.Unmarshal([]byte(stdout), &tf); jsonErr != nil {
		t.Errorf("output is not valid JSON: %v\noutput: %s", jsonErr, stdout)
	}
	if len(tf.Signature) == 0 {
		t.Error("signature field is empty")
	}
}

func TestCLI_DelegationVerify_ValidToken(t *testing.T) {
	// Issue a token first.
	stdout, _, err := runDelegIssueCmd(t)
	if err != nil {
		t.Fatalf("delegation issue: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), "token.json")
	if writeErr := os.WriteFile(tokenPath, []byte(stdout), 0600); writeErr != nil {
		t.Fatalf("write token file: %v", writeErr)
	}

	verifyOut, _, verifyErr := runDelegVerifyCmd(t, tokenPath)
	if verifyErr != nil {
		t.Fatalf("expected valid token, got error: %v\noutput: %s", verifyErr, verifyOut)
	}
	if !strings.Contains(verifyOut, "valid:") {
		t.Errorf("expected 'valid:' in output, got: %q", verifyOut)
	}
}

func TestCLI_DelegationVerify_InvalidSignature(t *testing.T) {
	// Issue a real token.
	stdout, _, err := runDelegIssueCmd(t)
	if err != nil {
		t.Fatalf("delegation issue: %v", err)
	}

	// Tamper: generate a different key pair and substitute the public key.
	var tf tokenFile
	if jsonErr := json.Unmarshal([]byte(stdout), &tf); jsonErr != nil {
		t.Fatalf("parse token: %v", jsonErr)
	}
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tf.PublicKey = []byte(wrongPub)

	tamperedBytes, err := json.Marshal(tf)
	if err != nil {
		t.Fatalf("marshal tampered token: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), "tampered.json")
	if writeErr := os.WriteFile(tokenPath, tamperedBytes, 0600); writeErr != nil {
		t.Fatalf("write tampered token: %v", writeErr)
	}

	verifyOut, _, verifyErr := runDelegVerifyCmd(t, tokenPath)
	if verifyErr == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	if !strings.Contains(verifyOut, "invalid:") {
		t.Errorf("expected 'invalid:' in output, got: %q", verifyOut)
	}
}

// --- audit export tests ---

func TestCLI_AuditExport_JSONL(t *testing.T) {
	dbPath := initExportDB(t)
	stdout, _, err := runAuditExportCmd(t, "jsonl", dbPath)
	if err != nil {
		t.Fatalf("audit export error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 JSONL lines, got %d: %q", len(lines), stdout)
	}

	requiredFields := []string{"id", "ts", "session_id", "tool", "action"}
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if jsonErr := json.Unmarshal([]byte(line), &m); jsonErr != nil {
			t.Errorf("line is not valid JSON: %v\nline: %s", jsonErr, line)
			continue
		}
		for _, f := range requiredFields {
			if _, ok := m[f]; !ok {
				t.Errorf("missing field %q in JSONL record: %s", f, line)
			}
		}
	}
}

func TestCLI_AuditExport_CSV(t *testing.T) {
	dbPath := initExportDB(t)
	stdout, _, err := runAuditExportCmd(t, "csv", dbPath)
	if err != nil {
		t.Fatalf("audit export CSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected header + at least 1 data row, got %d lines: %q", len(lines), stdout)
	}

	header := lines[0]
	expectedHeaders := []string{"id", "ts", "session_id", "tool", "action"}
	for _, h := range expectedHeaders {
		if !strings.Contains(header, h) {
			t.Errorf("expected header %q in CSV header row, got: %q", h, header)
		}
	}

	// Verify data rows exist.
	if len(lines) < 4 {
		t.Errorf("expected header + 3 data rows, got %d lines", len(lines))
	}
}

// --- audit tail tests ---

func TestCLI_AuditTail_LastN(t *testing.T) {
	dbPath := initExportDB(t)
	stdout, _, err := runAuditTailCmd(t, 3, dbPath)
	if err != nil {
		t.Fatalf("audit tail error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	// initExportDB inserted 3 records; requesting 3 should return exactly 3.
	nonEmpty := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			nonEmpty++
		}
	}
	if nonEmpty != 3 {
		t.Errorf("expected 3 JSON records from tail -n 3, got %d\noutput: %q", nonEmpty, stdout)
	}

	// Verify each line is valid JSON.
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]interface{}
		if jsonErr := json.Unmarshal([]byte(line), &m); jsonErr != nil {
			t.Errorf("tail line is not valid JSON: %v\nline: %s", jsonErr, line)
		}
	}
}

// --- bundle list/rollback tests ---

func TestCLI_BundleList_EmptyStore(t *testing.T) {
	storeDir := t.TempDir()
	stdout, _, err := runBundleListCmd(t, storeDir)
	if err != nil {
		t.Fatalf("bundle list error: %v", err)
	}
	if !strings.Contains(stdout, "no bundles") && stdout == "" {
		t.Errorf("expected 'no bundles' or empty output for empty store, got: %q", stdout)
	}
}

func TestCLI_BundleList_ShowsBundles(t *testing.T) {
	storeDir := t.TempDir()
	writeBundleToStore(t, storeDir, bundle.BundleManifest{
		Hash:     "abc12345def67890",
		Version:  1,
		StoredAt: time.Now().Add(-time.Hour),
	})
	writeBundleToStore(t, storeDir, bundle.BundleManifest{
		Hash:     "xyz98765uvw43210",
		Version:  2,
		StoredAt: time.Now(),
	})

	stdout, _, err := runBundleListCmd(t, storeDir)
	if err != nil {
		t.Fatalf("bundle list error: %v", err)
	}
	if !strings.Contains(stdout, "abc12345") {
		t.Errorf("expected first bundle hash in output, got: %q", stdout)
	}
	if !strings.Contains(stdout, "xyz98765") {
		t.Errorf("expected second bundle hash in output, got: %q", stdout)
	}
}

func TestCLI_BundleRollback_NoPrevious(t *testing.T) {
	storeDir := t.TempDir()
	// Only one bundle — no previous to roll back to.
	writeBundleToStore(t, storeDir, bundle.BundleManifest{
		Hash:     "onlyone123456789",
		Version:  1,
		StoredAt: time.Now(),
	})

	_, _, err := runBundleRollbackCmd(t, storeDir)
	if err == nil {
		t.Fatal("expected error when no previous bundle exists, got nil")
	}
	if !strings.Contains(err.Error(), "no previous bundle") {
		t.Errorf("expected 'no previous bundle' in error, got: %v", err)
	}
}

func TestCLI_BundleRollback_EmptyStore(t *testing.T) {
	storeDir := t.TempDir()
	_, _, err := runBundleRollbackCmd(t, storeDir)
	if err == nil {
		t.Fatal("expected error for empty store, got nil")
	}
	if !strings.Contains(err.Error(), "no previous bundle") {
		t.Errorf("expected 'no previous bundle' in error, got: %v", err)
	}
}

// TestCLI_BundleRollback_ActivatesBundle verifies that rollback selects the second-most-recent
// bundle and calls activateBundle with that bundle's store path.
func TestCLI_BundleRollback_ActivatesBundle(t *testing.T) {
	storeDir := t.TempDir()

	olderHash := "aabbccdd11223344"
	newerHash := "eeff99887766554433221100aabbccdd"

	writeBundleToStore(t, storeDir, bundle.BundleManifest{
		Hash:     olderHash,
		Version:  1,
		StoredAt: time.Now().Add(-2 * time.Hour),
	})
	writeBundleToStore(t, storeDir, bundle.BundleManifest{
		Hash:     newerHash,
		Version:  2,
		StoredAt: time.Now().Add(-time.Hour),
	})

	// Point bundleSocket at a non-existent socket so activateBundle fails at connect,
	// not at parse (the bundle dirs contain no YAML files so 0 templates are parsed).
	bundleSocket = "/tmp/aegis-nonexistent-rollback-test.sock"

	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	bundleRollbackCmd.ResetFlags()
	bundleRollbackCmd.SetOut(outBuf)
	bundleRollbackCmd.SetErr(errBuf)
	bundleRollbackStoreDir = storeDir
	err := bundleRollbackCmd.RunE(bundleRollbackCmd, nil)

	stdout := outBuf.String()

	// Must print the rollback announcement with the correct (older) bundle hash.
	if !strings.Contains(stdout, olderHash[:8]) {
		t.Errorf("expected output to contain rollback target hash %q, got: %q", olderHash[:8], stdout)
	}

	// Must attempt activation: the bundle dir exists so activateBundle reaches the socket
	// connect step and fails with "cannot connect", proving activateBundle was called.
	if err == nil {
		t.Fatal("expected activation error (daemon not running), got nil")
	}
	if !strings.Contains(err.Error(), "cannot connect") {
		t.Errorf("expected 'cannot connect' error from activateBundle, got: %v", err)
	}

	// Must NOT report "cannot connect" for the newer bundle — rollback must pick the older one.
	if strings.Contains(stdout, newerHash[:8]) {
		t.Errorf("output must not reference newer bundle %q as rollback target, got: %q", newerHash[:8], stdout)
	}
}

// TestCLI_AuditTail_Follow_WebSocket verifies that audit tail --follow connects to the
// daemon stream endpoint via WebSocket, receives CloudEvents of type "decision", writes
// their data payloads to stdout as JSON lines, and filters non-decision events.
func TestCLI_AuditTail_Follow_WebSocket(t *testing.T) {
	dbPath := initExportDB(t)

	// A minimal "decision" CloudEvent payload.
	decisionPayload := map[string]any{
		"session_id": "sess-tail-ws-test",
		"tool":       "Bash",
		"decision": map[string]any{
			"action":          "deny",
			"reason":          "policy denied",
			"policy_id":       "test-policy",
			"enforcing_layer": "cel",
			"labels":          map[string]any{},
		},
		"latency_ns": 1234,
	}
	dataJSON, _ := json.Marshal(decisionPayload)
	cloudEvent := map[string]any{
		"specversion":     "1.0",
		"id":              "evt-1",
		"type":            "decision",
		"source":          "/aegis/daemon",
		"time":            time.Now().UTC().Format(time.RFC3339),
		"datacontenttype": "application/json",
		"aegissequence":   uint64(1),
		"data":            json.RawMessage(dataJSON),
	}
	eventJSON, _ := json.Marshal(cloudEvent)

	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Send a heartbeat (must be filtered) then the decision event, then close.
		// Closing from the server side causes the client's ReadMessage to return an
		// error immediately, which exits tailFollowWebSocket without a long deadline wait.
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"stream.heartbeat","data":{}}`))
		_ = conn.WriteMessage(websocket.TextMessage, eventJSON)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
		_ = conn.Close()
	}))
	defer srv.Close()

	streamHost := strings.TrimPrefix(srv.URL, "http://")

	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	done := make(chan error, 1)
	go func() {
		auditTailCmd.ResetFlags()
		auditTailCmd.SetOut(outBuf)
		auditTailCmd.SetErr(errBuf)
		auditTailN = 0
		auditTailFollow = true
		auditTailDB = dbPath
		auditTailStream = streamHost
		done <- runAuditTail(auditTailCmd, nil)
	}()

	// Wait for the goroutine to finish (server closes connection after sending the event).
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runAuditTail did not exit after server closed WebSocket")
	}

	// Only read outBuf after the writer goroutine has finished — no race.
	out := outBuf.String()
	if !strings.Contains(out, "sess-tail-ws-test") {
		t.Errorf("expected session_id in streamed output; got:\n%s", out)
	}
	if !strings.Contains(out, "deny") {
		t.Errorf("expected 'deny' action in streamed output; got:\n%s", out)
	}

	// Only the decision event should be in output (heartbeat must be filtered).
	var jsonLines int
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			jsonLines++
		}
	}
	if jsonLines != 1 {
		t.Errorf("expected 1 decision JSON line (heartbeat filtered), got %d\noutput: %q", jsonLines, out)
	}
}

// TestCLI_BundleActivate_UsesCheckRequestProtocol verifies that activateBundle sends a
// framed CheckRequest (same wire protocol as `aegis simulate`) with tool="bundle_reload"
// to the daemon Unix socket, not a legacy custom bundleReloadMsg.
func TestCLI_BundleActivate_UsesCheckRequestProtocol(t *testing.T) {
	sockPath := fmt.Sprintf("/tmp/aegis-test-bundle-%d.sock", time.Now().UnixNano())
	defer func() { _ = os.Remove(sockPath) }()

	received := make(chan aegis.CheckRequest, 1)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read 4-byte length-prefix frame (same framing as simulate).
		var hdr [4]byte
		if _, err := readTestFull(conn, hdr[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(hdr[:])
		payload := make([]byte, length)
		if _, err := readTestFull(conn, payload); err != nil {
			return
		}
		var req aegis.CheckRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return
		}
		received <- req

		// Send a minimal framed CheckResponse.
		resp := aegis.CheckResponse{Decision: aegis.Decision{Action: aegis.ActionDeny, Reason: "unknown tool"}}
		respBytes, _ := json.Marshal(resp)
		var respHdr [4]byte
		binary.BigEndian.PutUint32(respHdr[:], uint32(len(respBytes)))
		_, _ = conn.Write(respHdr[:])
		_, _ = conn.Write(respBytes)
	}()

	bundleSocket = sockPath

	outBuf := &bytes.Buffer{}
	bundleActivateCmd.ResetFlags()
	bundleActivateCmd.SetOut(outBuf)
	bundleActivateCmd.SetErr(&bytes.Buffer{})

	// Use the builtin policies dir as a real parseable bundle path.
	policyDir := "../../policies/builtin"
	if err := bundleActivateCmd.RunE(bundleActivateCmd, []string{policyDir}); err != nil {
		t.Fatalf("bundle activate: %v", err)
	}

	select {
	case req := <-received:
		if req.Tool != "bundle_reload" {
			t.Errorf("tool = %q, want bundle_reload", req.Tool)
		}
		var args map[string]string
		if err := json.Unmarshal(req.Args, &args); err != nil {
			t.Errorf("args not valid JSON: %v", err)
		} else if args["bundle_path"] == "" {
			t.Error("bundle_path not set in args")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon socket did not receive CheckRequest within 3s")
	}

	if !strings.Contains(outBuf.String(), "daemon:") {
		t.Errorf("expected 'daemon:' in output, got: %q", outBuf.String())
	}
}

// readTestFull reads exactly len(buf) bytes from conn (helper for test socket servers).
func readTestFull(conn net.Conn, buf []byte) (int, error) {
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
