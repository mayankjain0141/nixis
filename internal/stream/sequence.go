// SPDX-License-Identifier: MIT
package stream

import "sync/atomic"

// sequenceCounter assigns monotonically increasing nixissequence values
// in the fan-out goroutine at Emit() time — NOT in evaluation goroutines.
// This is the sole place sequence numbers are assigned (per §7 STREAMING_PROTOCOL.md).
type sequenceCounter struct {
	n atomic.Uint64
}

func (c *sequenceCounter) next() uint64 {
	return c.n.Add(1)
}
