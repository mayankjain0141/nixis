package aegis

import "context"

// Engine is the top-level governance evaluation contract.
// Implementations MUST be safe for concurrent use from N goroutines.
// Implementations MUST return a deny decision on internal failure (fail-secure).
// Evaluate MUST NOT return an error — failures encode as Deny decisions.
type Engine interface {
	Evaluate(ctx context.Context, req CheckRequest) CheckResponse
	// Reload atomically swaps the EngineSnapshot.
	// Called by: WS-14 (fsnotify reload) and WS-11 (bundle activation).
	// MUST NOT be called by any other code path.
	// INV-005: only this method calls atomic.Pointer.Store().
	Reload(ctx context.Context, bundle *CompiledBundle) error
}
