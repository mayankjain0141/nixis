package secret

import (
	"context"
	"testing"

	policy "github.com/mayjain/aegis/internal/policy"
)

// BenchmarkSecret_ScanTypical benchmarks a scan of clean content (no secrets)
// using the real Gitleaks detector. Target: <100μs, ≤2 allocs.
func BenchmarkSecret_ScanTypical(b *testing.B) {
	s := NewScanner()
	// Force initialization before the benchmark loop.
	s.ScanBoundary(context.Background(), "warm up", policy.BoundaryToolArgs)

	content := "the quick brown fox jumps over the lazy dog — no secrets here"
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.ScanBoundary(ctx, content, policy.BoundaryToolArgs)
	}
}
