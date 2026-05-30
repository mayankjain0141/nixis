package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHook_AllowWithWarning_WritesLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "failopen.log")

	now := time.Now()
	entry := FailOpenEntry{
		Ts:               now,
		Tool:             "Bash",
		SessionID:        "sess-123",
		Reason:           "daemon unreachable",
		DeadlineExceeded: false,
	}

	if err := writeFailOpen(logPath, entry); err != nil {
		t.Fatalf("writeFailOpen: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}

	var got FailOpenEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &got); err != nil {
		t.Fatalf("invalid JSON in log: %v\ncontents: %s", err, data)
	}

	if got.Tool != "Bash" {
		t.Errorf("tool = %q, want Bash", got.Tool)
	}
	if got.SessionID != "sess-123" {
		t.Errorf("sessionID = %q, want sess-123", got.SessionID)
	}
	if got.Reason != "daemon unreachable" {
		t.Errorf("reason = %q, want 'daemon unreachable'", got.Reason)
	}
	if got.Ts.IsZero() {
		t.Error("timestamp must be non-zero")
	}

	// Verify append: write a second entry and check both lines are present.
	entry2 := FailOpenEntry{
		Ts:        time.Now(),
		Tool:      "Write",
		SessionID: "sess-456",
		Reason:    "evaluation timeout",
	}
	if err := writeFailOpen(logPath, entry2); err != nil {
		t.Fatalf("second writeFailOpen: %v", err)
	}

	data2, _ := os.ReadFile(logPath)
	lines := bytes.Split(bytes.TrimSpace(data2), []byte("\n"))
	if len(lines) != 2 {
		t.Errorf("expected 2 log entries, got %d:\n%s", len(lines), data2)
	}
}
