// SPDX-License-Identifier: MIT
package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToBurst(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, 1.0)

	for i := 0; i < 5; i++ {
		if !rl.Allow("sess1") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	if rl.Allow("sess1") {
		t.Error("request beyond burst should be denied")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, 10.0) // 10 tokens/sec refill

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow("sess1")
	}
	if rl.Allow("sess1") {
		t.Fatal("should be rate limited after exhausting burst")
	}

	// Manipulate lastSeen to simulate time passing (1 second = 10 tokens refilled, capped at 5)
	rl.mu.Lock()
	rl.buckets["sess1"].lastSeen = time.Now().Add(-1 * time.Second)
	rl.mu.Unlock()

	if !rl.Allow("sess1") {
		t.Error("should be allowed after refill period")
	}
}

func TestRateLimiter_IndependentSessions(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(2, 1.0)

	// Exhaust session A
	rl.Allow("A")
	rl.Allow("A")
	if rl.Allow("A") {
		t.Error("session A should be limited")
	}

	// Session B should still have its own full bucket
	if !rl.Allow("B") {
		t.Error("session B should be allowed (independent bucket)")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(50, 20.0)

	var wg sync.WaitGroup
	var allowed, denied int64
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("sess-%d", id%5)
			result := rl.Allow(sessionID)
			mu.Lock()
			if result {
				allowed++
			} else {
				denied++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if allowed == 0 {
		t.Error("expected some requests to be allowed")
	}
	total := allowed + denied
	if total != 100 {
		t.Errorf("total = %d, want 100", total)
	}
}

func TestRateLimiter_PrunesStale(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(10, 1.0)
	rl.staleAfter = 100 * time.Millisecond

	rl.Allow("stale-session")

	// Simulate staleness
	rl.mu.Lock()
	rl.buckets["stale-session"].lastSeen = time.Now().Add(-200 * time.Millisecond)
	rl.mu.Unlock()

	// Trigger prune by adding a new session
	rl.Allow("fresh-session")

	rl.mu.Lock()
	_, staleExists := rl.buckets["stale-session"]
	_, freshExists := rl.buckets["fresh-session"]
	rl.mu.Unlock()

	if staleExists {
		t.Error("stale session should have been pruned")
	}
	if !freshExists {
		t.Error("fresh session should exist")
	}
}

func TestRateLimiter_ZeroBurst(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(0, 0)

	if rl.Allow("any") {
		t.Error("zero burst limiter should deny all requests")
	}
}
