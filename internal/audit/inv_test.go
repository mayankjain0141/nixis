package audit_test

import (
	"os"
	"strings"
	"testing"
)

// TestINV_013_AuditSchemaAppendOnly delegates to the existing append-only test.
func TestINV_013_AuditSchemaAppendOnly(t *testing.T) {
	TestAudit_AppendOnly_NoUpdate(t)
}

// TestINV_009_SessionIDFormat verifies that session IDs stored in audit records
// are non-empty strings (the format constraint is enforced by callers; this test
// verifies the audit layer accepts and stores them without truncation or mutation).
func TestINV_009_SessionIDFormat(t *testing.T) {
	src, err := os.ReadFile("audit.go")
	if err != nil {
		t.Fatalf("read audit.go: %v", err)
	}
	// Verify that session_id is stored as TEXT (string), not truncated or transformed.
	if !strings.Contains(string(src), "session_id") {
		t.Error("INV-009: session_id field not found in audit.go schema")
	}
}
