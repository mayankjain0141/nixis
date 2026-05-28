package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// --- Helpers ---

// runValidateCmd runs the validate subcommand with args and captures stdout/stderr.
func runValidateCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	validateCmd.ResetFlags()
	validateCmd.SetOut(outBuf)
	validateCmd.SetErr(errBuf)
	validateCmd.SetArgs(args)
	err = validateCmd.RunE(validateCmd, args)
	return outBuf.String(), errBuf.String(), err
}

// --- validate tests ---

func TestCLI_Validate_ValidPolicies(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "allow-all.yaml", validPolicyYAML("allow-all", "tool == tool"))
	stdout, _, err := runValidateCmd(t, dir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !strings.Contains(stdout, "OK:") {
		t.Errorf("expected 'OK:' in output, got: %q", stdout)
	}
}

func TestCLI_Validate_CELError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "bad.yaml", validPolicyYAML("bad-policy", "tool =="))
	_, stderr, err := runValidateCmd(t, dir)
	if err == nil {
		t.Fatal("expected error for invalid CEL, got nil")
	}
	combined := stderr + err.Error()
	if !strings.Contains(combined, "bad.yaml") && !strings.Contains(combined, "bad-policy") {
		t.Errorf("expected source reference in output, got stderr=%q err=%v", stderr, err)
	}
}

func TestCLI_Validate_NonExistentDir(t *testing.T) {
	_, _, err := runValidateCmd(t, "/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent dir, got nil")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("expected 'parse error' in message, got: %v", err)
	}
}

// --- audit verify tests ---

func TestCLI_AuditVerify_ExitCodes(t *testing.T) {
	t.Run("intact_empty_db", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "audit.db")
		initAuditDB(t, dbPath)
		outBuf := &bytes.Buffer{}
		auditDB = dbPath
		auditFrom = ""
		auditTo = ""
		auditVerifyCmd.SetOut(outBuf)
		err := auditVerifyCmd.RunE(auditVerifyCmd, nil)
		if err != nil {
			t.Fatalf("expected exit 0, got: %v", err)
		}
		if !strings.Contains(outBuf.String(), "OK:") {
			t.Errorf("expected 'OK:' in output, got: %q", outBuf.String())
		}
	})

	t.Run("unavailable_db", func(t *testing.T) {
		auditDB = "/nonexistent/path/audit.db"
		auditFrom = ""
		auditTo = ""
		err := auditVerifyCmd.RunE(auditVerifyCmd, nil)
		if err == nil {
			t.Fatal("expected error for missing db, got nil")
		}
	})

	t.Run("no_db_path", func(t *testing.T) {
		auditDB = ""
		auditFrom = ""
		auditTo = ""
		if err := os.Unsetenv("AEGIS_AUDIT_DB"); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		err := auditVerifyCmd.RunE(auditVerifyCmd, nil)
		if err == nil {
			t.Fatal("expected error when no db path set, got nil")
		}
	})
}

// --- scan tests ---

func TestCLI_Scan_OutputsAdapterYAML(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "mock-mcp-server.sh")
	mockScript := `#!/bin/sh
# Read and discard the first JSON-RPC request (initialize)
read LINE
# Respond to initialize
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}\n'
# Read and discard the second JSON-RPC request (tools/list)
read LINE
# Respond with one tool
printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file","description":"Read a file"}]}}\n'
`
	if err := os.WriteFile(scriptPath, []byte(mockScript), 0700); err != nil {
		t.Fatalf("write mock script: %v", err)
	}

	outBuf := &bytes.Buffer{}
	scanCmd.SetOut(outBuf)
	scanCmd.SetErr(&bytes.Buffer{})
	err := scanCmd.RunE(scanCmd, []string{"/bin/sh", scriptPath})
	if err != nil {
		t.Fatalf("scan command error: %v", err)
	}
	out := outBuf.String()
	if !strings.Contains(out, "tools:") {
		t.Errorf("expected 'tools:' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "read_file") {
		t.Errorf("expected tool name 'read_file' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "aegis:") {
		t.Errorf("expected aegis annotation in output, got:\n%s", out)
	}
}

// --- simulate tests ---

func TestCLI_Simulate_ConnectError(t *testing.T) {
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	simulateCmd.SetOut(outBuf)
	simulateCmd.SetErr(errBuf)
	simulateSocket = "/tmp/aegis-nonexistent-socket-ws28-test.sock"
	simulateArgs = "{}"
	simulateSession = ""
	err := simulateCmd.RunE(simulateCmd, []string{"test_tool"})
	if err == nil {
		t.Fatal("expected error when daemon not running, got nil")
	}
	if !strings.Contains(err.Error(), "cannot connect") {
		t.Errorf("expected 'cannot connect' in error message, got: %q", err.Error())
	}
}

// --- bundle activate tests ---

func TestCLI_Bundle_Activate_ParsesFile(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "test.yaml", validPolicyYAML("test-policy", "tool == tool"))

	outBuf := &bytes.Buffer{}
	bundleActivateCmd.SetOut(outBuf)
	bundleSocket = "/tmp/aegis-nonexistent-socket-ws28-bundle-test.sock"

	// RunE parses the bundle first and prints "parsed: N templates..." before
	// attempting the socket connection. Regardless of socket error, we verify parse succeeded.
	err := bundleActivateCmd.RunE(bundleActivateCmd, []string{dir})
	// err may be non-nil (socket connect failure) — that's expected in test environment.
	// We only assert that the parse output was emitted before the connection attempt.
	out := outBuf.String()
	if !strings.Contains(out, "parsed:") {
		t.Errorf("expected 'parsed:' in output after bundle file parse, got: %q (err: %v)", out, err)
	}
}

// --- helpers ---

func validPolicyYAML(name, expr string) string {
	return fmt.Sprintf(`apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: %s
spec:
  description: test policy
  matchConstraints:
    tools:
      - "*"
  validations:
    - expression: "%s"
      message: denied
      action: DENY
  defaultAction: ALLOW
`, name, expr)
}

func writePolicy(t *testing.T, dir, filename, content string) {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
}

func initAuditDB(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
	}()
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      INTEGER NOT NULL,
    session_id     TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args           TEXT,
    action         TEXT NOT NULL,
    reason         TEXT,
    policy_id      TEXT,
    enforcing_layer TEXT,
    label_before_c INTEGER,
    label_before_i INTEGER,
    label_before_k INTEGER,
    label_after_c  INTEGER,
    label_after_i  INTEGER,
    label_after_k  INTEGER,
    latency_ns     INTEGER
);`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
}

// Compile-time checks: ensure net and json are used.
var _ = net.Conn(nil)
var _ = json.RawMessage(nil)
