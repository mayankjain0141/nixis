package secret

import (
	"context"
	"strings"
	"testing"
	"time"

	policy "github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
)

// panicDetector is a test double that always panics.
type panicDetector struct{}

func (panicDetector) detectString(_ string) []finding {
	panic("injected panic from panicDetector")
}

// slowDetector is a test double that blocks indefinitely.
type slowDetector struct {
	block chan struct{}
}

func newSlowDetector() *slowDetector {
	return &slowDetector{block: make(chan struct{})}
}

func (d *slowDetector) detectString(_ string) []finding {
	<-d.block
	return nil
}

func (d *slowDetector) unblock() { close(d.block) }

// staticDetector returns a pre-configured list of findings.
type staticDetector struct {
	findings []finding
}

func (d *staticDetector) detectString(_ string) []finding {
	return d.findings
}

// newScannerWithDetector injects a test detector bypassing sync.Once.
func newScannerWithDetector(td detectorIface) *Scanner {
	return &Scanner{testDetector: td}
}

// isZeroLabel returns true when the label carries no security signal.
func isZeroLabel(l aegis.SecurityLabel) bool {
	return l.Confidentiality == 0 && l.Integrity == 0 && l.Category == 0
}

// TestSecret_Detect_NoLeakInAudit verifies:
//  1. A real Gitleaks scan detects a known GitHub PAT.
//  2. Finding.Redacted does NOT equal or contain the raw secret value.
func TestSecret_Detect_NoLeakInAudit(t *testing.T) {
	s := NewScanner()
	rawSecret := "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	content := "GITHUB_TOKEN=" + rawSecret

	findings, label := s.ScanBoundary(context.Background(), content, policy.BoundaryToolArgs)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for known GitHub PAT, got none")
	}
	for _, f := range findings {
		if f.Redacted == rawSecret {
			t.Errorf("Finding.Redacted must not equal the raw secret")
		}
		if strings.Contains(f.Redacted, rawSecret) {
			t.Errorf("Finding.Redacted must not contain the raw secret — got %q", f.Redacted)
		}
		if f.Rule == "" {
			t.Error("Finding.Rule must be non-empty")
		}
	}
	if label.Confidentiality == 0 {
		t.Error("label must signal DENY (Confidentiality > 0) when secrets are detected")
	}
}

// TestSecret_Panic_ReturnsDeny verifies a panicking detector is recovered and
// returns DENY without propagating the panic.
func TestSecret_Panic_ReturnsDeny(t *testing.T) {
	s := newScannerWithDetector(panicDetector{})

	findings, label := s.ScanBoundary(context.Background(), "anything", policy.BoundaryToolArgs)

	if findings != nil {
		t.Errorf("expected nil findings after panic, got %v", findings)
	}
	if label.Confidentiality == 0 {
		t.Error("label must signal DENY (Confidentiality > 0) after detector panic")
	}
}

// TestSecret_Timeout_ReturnsDeny verifies that a scan exceeding the 50 ms
// internal deadline returns DENY.
func TestSecret_Timeout_ReturnsDeny(t *testing.T) {
	slow := newSlowDetector()
	t.Cleanup(slow.unblock) // prevent goroutine leak after test

	s := newScannerWithDetector(slow)

	// Give the test 500ms; the internal scanTimeout (50ms) should fire first.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	findings, label := s.ScanBoundary(ctx, "anything", policy.BoundaryToolArgs)

	if findings != nil {
		t.Errorf("expected nil findings on timeout, got %v", findings)
	}
	if label.Confidentiality == 0 {
		t.Error("label must signal DENY (Confidentiality > 0) on timeout")
	}
}

// TestSecret_ShouldScan_OnlyOutbound verifies ShouldScan returns true only for
// outbound boundaries or inbound responses with write effects.
func TestSecret_ShouldScan_OnlyOutbound(t *testing.T) {
	s := NewScanner()

	if !s.ShouldScan(nil, policy.BoundaryToolArgs) {
		t.Error("ShouldScan must return true for BoundaryToolArgs")
	}
	if !s.ShouldScan(nil, policy.BoundaryFileContent) {
		t.Error("ShouldScan must return true for BoundaryFileContent")
	}
	if s.ShouldScan(nil, policy.BoundaryToolResponse) {
		t.Error("ShouldScan must return false for BoundaryToolResponse with no write effects")
	}
	if !s.ShouldScan([]string{"write:file"}, policy.BoundaryToolResponse) {
		t.Error("ShouldScan must return true for BoundaryToolResponse with write effect")
	}
}

// TestSecret_NoFindings_CleanContent verifies clean content produces nil findings
// and a zero-value SecurityLabel.
func TestSecret_NoFindings_CleanContent(t *testing.T) {
	s := newScannerWithDetector(&staticDetector{findings: nil})

	findings, label := s.ScanBoundary(context.Background(), "hello world", policy.BoundaryToolArgs)

	if findings != nil {
		t.Errorf("expected nil findings for clean content, got %v", findings)
	}
	if !isZeroLabel(label) {
		t.Errorf("expected zero label for clean content, got %+v", label)
	}
}
