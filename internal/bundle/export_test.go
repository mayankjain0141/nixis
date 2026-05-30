// export_test.go exposes internal BundleLoader fields and methods for white-box testing.
// This file is compiled only during tests.
package bundle

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/mayankjain0141/nixis/pkg/nixis"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
)

// SetParseDirFn injects a custom parseDirFn into a BundleLoader for testing.
func SetParseDirFn(bl *BundleLoader, fn func(string) ([]policy_types.PolicyTemplate, []policy_types.PolicyBinding, error)) {
	bl.parseDirFn = fn
}

// SetEvalFn injects a custom evalFn into a BundleLoader for testing.
func SetEvalFn(bl *BundleLoader, fn func(*nixis.CompiledBundle, nixis.CheckRequest) nixis.Action) {
	bl.testEvalFn = fn
}

// SetTestVectors replaces the TestVectors in a BundleLoader's config for testing.
func SetTestVectors(bl *BundleLoader, vectors []TestVector) {
	bl.cfg.TestVectors = vectors
}

// RunOnce drives a single tryActivate cycle on the BundleLoader.
func RunOnce(bl *BundleLoader, ctx context.Context) {
	bl.tryActivate(ctx)
}

// VerifyContent exposes the BundleLoader's key verification for direct testing.
// It computes SHA-256(content) before calling Verify, matching the loader's hot path.
func VerifyContent(bl *BundleLoader, content, sig []byte) bool {
	digest := sha256.Sum256(content)
	return bl.keys.Verify(digest[:], sig)
}

// ResetLastMtime clears the lastMtime so the next fetch treats the file as changed.
func ResetLastMtime(bl *BundleLoader) {
	bl.lastMtime = time.Time{}
}

// StoreCount returns the number of bundles currently in the content-addressable store.
func StoreCount(bl *BundleLoader) int {
	return bl.store.count()
}
