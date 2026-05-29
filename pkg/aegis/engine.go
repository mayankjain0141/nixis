// SPDX-License-Identifier: MIT
package aegis

import "context"

// Engine is the top-level governance evaluation contract.
//
// Concurrency: all methods MUST be safe for concurrent use from any number of goroutines.
//
// Evaluate contract:
//   - MUST NOT return an error; internal failures encode as [ActionDeny] decisions (INV-011).
//   - MUST NOT call time.Now() or any randomness source in the decision path (INV-010).
//   - MUST complete in zero heap allocations on the hot path (INV-006).
//
// Reload contract:
//   - On success, atomically replaces the active [EngineSnapshot] so all subsequent
//     Evaluate calls see the new policy set (INV-005).
//   - On failure, the engine MUST remain in its previous state; the failing bundle is
//     never installed (INV-007).
//   - Only [Engine.Reload] may call atomic.Pointer.Store() on the snapshot pointer;
//     no other method or goroutine may do so (INV-005).
type Engine interface {
	Evaluate(ctx context.Context, req CheckRequest) CheckResponse
	// Reload atomically swaps the EngineSnapshot.
	// Called by: WS-14 (fsnotify reload) and WS-11 (bundle activation).
	// MUST NOT be called by any other code path.
	// INV-005: only this method calls atomic.Pointer.Store().
	Reload(ctx context.Context, bundle *CompiledBundle) error
}
