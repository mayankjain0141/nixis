package secret

import (
	"context"
	"strings"
	"testing"

	policy "github.com/mayankjain0141/nixis/internal/policy"
)

// TestShouldScan_MessageContent verifies that ShouldScan triggers on the
// message_content effect at BoundaryToolArgs.
func TestShouldScan_MessageContent(t *testing.T) {
	s := NewScanner()
	if !s.ShouldScan([]string{"message_content"}, policy.BoundaryToolArgs) {
		t.Error("ShouldScan must return true for message_content effect at BoundaryToolArgs")
	}
}

// TestShouldScan_SendMessage_Effects verifies that SendMessage effects trigger ShouldScan.
// This is the combined effect set that SendMessage carries in the catalog.
func TestShouldScan_SendMessage_Effects(t *testing.T) {
	s := NewScanner()
	effects := []string{"content_internal", "message_content"}
	if !s.ShouldScan(effects, policy.BoundaryToolArgs) {
		t.Error("ShouldScan must return true for SendMessage's effect set at BoundaryToolArgs")
	}
}

// TestSecret_SendMessage_Detected verifies that a secret embedded in SendMessage content
// is detected and that Finding.Redacted does NOT contain the raw secret value.
func TestSecret_SendMessage_Detected(t *testing.T) {
	rawSecret := "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	content := "Please use this token: " + rawSecret

	detector := &staticDetector{
		findings: []finding{
			{ruleID: "github-pat", secret: rawSecret, startColumn: 22, endColumn: 22 + len(rawSecret)},
		},
	}
	s := newScannerWithDetector(detector)

	findings, label := s.ScanBoundary(context.Background(), content, policy.BoundaryToolArgs)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for secret in SendMessage content, got none")
	}
	for _, f := range findings {
		if f.Redacted == rawSecret {
			t.Errorf("Finding.Redacted must not equal the raw secret")
		}
		if strings.Contains(f.Redacted, rawSecret) {
			t.Errorf("Finding.Redacted must not contain the raw secret — got %q", f.Redacted)
		}
	}
	if label.Confidentiality == 0 {
		t.Error("label must signal DENY (Confidentiality > 0) when secret is detected")
	}
}
