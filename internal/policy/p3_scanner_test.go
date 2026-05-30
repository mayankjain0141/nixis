// SPDX-License-Identifier: MIT
package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mayjain/nixis/internal/cel"
	"github.com/mayjain/nixis/internal/classify"
	"github.com/mayjain/nixis/internal/ifc"
	"github.com/mayjain/nixis/pkg/adapters"
	"github.com/mayjain/nixis/pkg/nixis"
)

// hitScanner is a mock SecretScanner that always reports one finding.
type hitScanner struct{}

func (h *hitScanner) ShouldScan(_ []string, _ BoundaryType) bool { return true }
func (h *hitScanner) ScanBoundary(_ context.Context, _ string, _ BoundaryType) ([]Finding, nixis.SecurityLabel) {
	return []Finding{{Rule: "aws-access-key", Boundary: BoundaryToolArgs}},
		nixis.SecurityLabel{Confidentiality: 3}
}

// missScanner is a mock SecretScanner that never reports findings.
type missScanner struct{}

func (m *missScanner) ShouldScan(_ []string, _ BoundaryType) bool { return true }
func (m *missScanner) ScanBoundary(_ context.Context, _ string, _ BoundaryType) ([]Finding, nixis.SecurityLabel) {
	return nil, nixis.SecurityLabel{}
}

// captureScanner records the content passed to ScanBoundary.
type captureScanner struct {
	captured string
}

func (c *captureScanner) ShouldScan(_ []string, _ BoundaryType) bool { return true }
func (c *captureScanner) ScanBoundary(_ context.Context, content string, _ BoundaryType) ([]Finding, nixis.SecurityLabel) {
	c.captured = content
	return nil, nixis.SecurityLabel{}
}

// makeWriteEngine builds a PolicyEngine with the given SecretScanner and a
// Write+Edit adapter in the classifier so these tools pass classification.
func makeWriteEngine(t *testing.T, scanner SecretScanner) *PolicyEngine {
	t.Helper()
	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	engine := NewPolicyEngine(sessions, celEnv, WithSecretScanner(scanner))
	catalog := []adapters.AdapterDef{
		{Tool: "Write", Operation: "write", Family: "filesystem", RiskLevel: "medium", ResourceType: "file", Effects: []string{"write_files"}},
		{Tool: "Edit", Operation: "write", Family: "filesystem", RiskLevel: "medium", ResourceType: "file", Effects: []string{"write_files"}},
		{Tool: "Read", Operation: "read", Family: "filesystem", RiskLevel: "low", ResourceType: "file", Effects: []string{"read_files"}},
	}
	classifier := classify.NewClassifier(catalog)
	snap := &engineSnapshot{
		public:     nixis.EngineSnapshot{Version: 1},
		classifier: classifier,
		programs:   &cel.ProgramCache{},
		bindingIdx: bindingIndex{},
	}
	engine.applySnapshot(snap)
	return engine
}

func writeArgs(filePath, content string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"file_path": filePath, "content": content})
	return b
}

func editArgs(filePath, oldStr, newStr string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{
		"file_path":  filePath,
		"old_string": oldStr,
		"new_string": newStr,
	})
	return b
}

// TestScanner_ActionIsRequireApproval_NotDeny verifies that a Write with a
// detected secret returns ActionRequireApproval, not ActionDeny.
func TestScanner_ActionIsRequireApproval_NotDeny(t *testing.T) {
	engine := makeWriteEngine(t, &hitScanner{})
	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Write",
		SessionID: "s1",
		Args:      writeArgs("/project/main.go", "AKIAIOSFODNN7EXAMPLE123"),
	})
	if resp.Decision.Action != nixis.ActionRequireApproval {
		t.Errorf("Action = %v, want ActionRequireApproval", resp.Decision.Action)
	}
	if resp.EnforcingLayer != nixis.EnforcingLayerSecretScan {
		t.Errorf("EnforcingLayer = %v, want EnforcingLayerSecretScan", resp.EnforcingLayer)
	}
	if resp.Decision.PolicyID != "builtin:secret-scan" {
		t.Errorf("PolicyID = %q, want builtin:secret-scan", resp.Decision.PolicyID)
	}
}

// TestScanner_ExemptPath_TestGo_SkipsScanning verifies that writing to a
// _test.go file skips secret scanning entirely.
func TestScanner_ExemptPath_TestGo_SkipsScanning(t *testing.T) {
	engine := makeWriteEngine(t, &hitScanner{})
	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Write",
		SessionID: "s1",
		Args:      writeArgs("/project/internal/foo/bar_test.go", "AKIAIOSFODNN7EXAMPLE123"),
	})
	if resp.Decision.Action != nixis.ActionAllow {
		t.Errorf("Action = %v, want ActionAllow for _test.go path", resp.Decision.Action)
	}
}

// TestScanner_ExemptPath_Testdata_SkipsScanning verifies that writing to a
// testdata directory skips secret scanning.
func TestScanner_ExemptPath_Testdata_SkipsScanning(t *testing.T) {
	engine := makeWriteEngine(t, &hitScanner{})
	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Write",
		SessionID: "s1",
		Args:      writeArgs("/project/testdata/bundle_signing_key.pem", "-----BEGIN RSA PRIVATE KEY-----"),
	})
	if resp.Decision.Action != nixis.ActionAllow {
		t.Errorf("Action = %v, want ActionAllow for testdata path", resp.Decision.Action)
	}
}

// TestScanner_PartialScan_OversizedContent_RequiresApproval verifies that
// content over 1MB returns ActionRequireApproval with the scan-limit reason.
func TestScanner_PartialScan_OversizedContent_RequiresApproval(t *testing.T) {
	engine := makeWriteEngine(t, &missScanner{})
	bigContent := strings.Repeat("a", (1<<20)+1) // 1MB + 1 byte, no secrets
	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Write",
		SessionID: "s1",
		Args:      writeArgs("/project/main.go", bigContent),
	})
	if resp.Decision.Action != nixis.ActionRequireApproval {
		t.Errorf("Action = %v, want ActionRequireApproval for oversized content", resp.Decision.Action)
	}
	if !strings.Contains(resp.Decision.Reason, "1MB scan limit") {
		t.Errorf("Reason = %q, want to contain '1MB scan limit'", resp.Decision.Reason)
	}
}

// TestScanner_EditNewStringOnly_OldStringIgnored verifies that only new_string
// is scanned, not old_string, so a clean edit with a dirty old string is allowed.
func TestScanner_EditNewStringOnly_OldStringIgnored(t *testing.T) {
	cap := &captureScanner{}
	engine := makeWriteEngine(t, cap)
	resp := engine.Evaluate(context.Background(), nixis.CheckRequest{
		Tool:      "Edit",
		SessionID: "s1",
		Args:      editArgs("/project/main.go", "AKIAIOSFODNN7EXAMPLE", "clean replacement"),
	})
	if resp.Decision.Action != nixis.ActionAllow {
		t.Errorf("Action = %v, want ActionAllow when new_string is clean", resp.Decision.Action)
	}
	if strings.Contains(cap.captured, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("old_string leaked into scan content: %q", cap.captured)
	}
	if cap.captured != "clean replacement" {
		t.Errorf("captured = %q, want 'clean replacement'", cap.captured)
	}
}

// TestExtractFilePath_WriteTool verifies that extractFilePath parses the
// file_path field from Write tool JSON arguments.
func TestExtractFilePath_WriteTool(t *testing.T) {
	args := []byte(`{"file_path":"/project/main.go","content":"hello"}`)
	got := extractFilePath("Write", args)
	if got != "/project/main.go" {
		t.Errorf("extractFilePath = %q, want /project/main.go", got)
	}
}

// TestIsExemptPath_TestGo_ReturnsTrue verifies _test.go paths are exempt.
func TestIsExemptPath_TestGo_ReturnsTrue(t *testing.T) {
	if !isExemptPath("internal/foo/bar_test.go") {
		t.Error("expected bar_test.go to be exempt")
	}
}

// TestIsExemptPath_ProductionFile_ReturnsFalse verifies production Go files are not exempt.
func TestIsExemptPath_ProductionFile_ReturnsFalse(t *testing.T) {
	if isExemptPath("internal/foo/bar.go") {
		t.Error("expected bar.go to NOT be exempt")
	}
}
