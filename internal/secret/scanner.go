// Package secret implements secret detection for Aegis using Gitleaks.
package secret

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mayjain/aegis/internal/ifc"
	policy "github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const scanTimeout = 50 * time.Millisecond

// detectorIface allows injecting a test double.
type detectorIface interface {
	detectString(content string) []finding
}

// finding holds the subset of gitleaks report.Finding we need.
type finding struct {
	ruleID      string
	secret      string
	startColumn int
	endColumn   int
}

// realDetector wraps the gitleaks Detector and converts its findings.
type realDetector struct {
	d *detect.Detector
}

func (r *realDetector) detectString(content string) []finding {
	raw := r.d.DetectString(content)
	if len(raw) == 0 {
		return nil
	}
	out := make([]finding, len(raw))
	for i, f := range raw {
		out[i] = finding{
			ruleID:      f.RuleID,
			secret:      f.Secret,
			startColumn: f.StartColumn,
			endColumn:   f.EndColumn,
		}
	}
	return out
}

// Scanner implements the SecretScanner interface defined in internal/policy.
type Scanner struct {
	once     sync.Once
	detector detectorIface // nil if init failed

	// testDetector, if non-nil, overrides the real Gitleaks detector.
	// Used only by tests via newScannerWithDetector.
	testDetector detectorIface
}

// NewScanner returns a new Scanner. Gitleaks is initialized lazily on first use.
func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) init() {
	s.once.Do(func() {
		if s.testDetector != nil {
			s.detector = s.testDetector
			return
		}
		d, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			log.Printf("aegis/secret: gitleaks init failed — scanner disabled")
			return
		}
		s.detector = &realDetector{d: d}
	})
}

// ShouldScan returns true only when the boundary warrants scanning.
// Outbound tool arguments and file content writes always need scanning.
// Inbound tool responses are scanned only when they carry write effects.
func (s *Scanner) ShouldScan(effects []string, boundary policy.BoundaryType) bool {
	switch boundary {
	case policy.BoundaryToolArgs, policy.BoundaryFileContent:
		return true
	case policy.BoundaryToolResponse:
		for _, e := range effects {
			if strings.HasPrefix(e, "write:") || e == "write" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// ScanBoundary scans content for secrets within the given trust boundary.
// It enforces a 50 ms deadline per scan. On panic or timeout it returns DENY.
// The raw secret value NEVER appears in any returned Finding or log line.
func (s *Scanner) ScanBoundary(ctx context.Context, content string, boundary policy.BoundaryType) ([]policy.Finding, aegis.SecurityLabel) {
	s.init()

	if s.detector == nil {
		return nil, aegis.SecurityLabel{}
	}

	// Check context before scanning.
	if err := ctx.Err(); err != nil {
		return nil, denyLabel()
	}

	// Apply a per-scan deadline.
	deadline := time.Now().Add(scanTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// panicScan runs the detector with panic recovery.
	// It signals timeout via a separate goroutine that closes done.
	type scanResult struct {
		findings []finding
		panicked bool
	}

	ch := make(chan scanResult, 1)
	go func() {
		var r scanResult
		defer func() {
			if rec := recover(); rec != nil {
				r.panicked = true
				ch <- r
			}
		}()
		r.findings = s.detector.detectString(content)
		ch <- r
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil, denyLabel()
	case <-ctx.Done():
		return nil, denyLabel()
	case r := <-ch:
		if r.panicked {
			return nil, denyLabel()
		}
		if len(r.findings) == 0 {
			return nil, aegis.SecurityLabel{}
		}
		out := make([]policy.Finding, 0, len(r.findings))
		for _, f := range r.findings {
			out = append(out, policy.Finding{
				Boundary:    boundary,
				Rule:        f.ruleID,
				Category:    ifc.CatCredentials,
				Redacted:    redact(f.secret),
				StartOffset: f.startColumn,
				EndOffset:   f.endColumn,
			})
		}
		return out, denyLabel()
	}
}

// denyLabel returns the SecurityLabel that signals a detected secret.
// Confidentiality=3 (highest) with credentials category bit set.
func denyLabel() aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: 3,
		Category:        ifc.CatCredentials,
	}
}

// redact produces a safe display form: first4...last4.
// The raw secret string NEVER passes through any log or return value.
func redact(secret string) string {
	const minLen = 8
	if len(secret) <= minLen {
		return "****"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}
