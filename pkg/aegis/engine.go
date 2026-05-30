// SPDX-License-Identifier: MIT
package aegis

import "context"

// Engine is the top-level governance evaluation contract.
//
// Concurrency: all methods MUST be safe for concurrent use from any number of goroutines.
//
// Evaluate contract:
//   - MUST NOT return an error; internal failures encode as [ActionDeny] decisions.
//   - MUST NOT call time.Now() or any randomness source in the decision path.
//   - MUST complete in zero heap allocations on the hot path.
//
// Reload contract:
//   - On success, atomically replaces the active [EngineSnapshot] so all subsequent
//     Evaluate calls see the new policy set.
//   - On failure, the engine MUST remain in its previous state; the failing bundle is
//     never installed.
//   - Only [Engine.Reload] may call atomic.Pointer.Store() on the snapshot pointer;
//     no other method or goroutine may do so.
type Engine interface {
	Evaluate(ctx context.Context, req CheckRequest) CheckResponse
	// Reload atomically swaps the EngineSnapshot.
	// MUST NOT be called by any other code path.
	Reload(ctx context.Context, bundle *CompiledBundle) error
}
