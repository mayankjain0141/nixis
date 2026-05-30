// SPDX-License-Identifier: MIT
package daemon

import (
	"sync"
	"time"
)

// RateLimiter implements per-session token bucket rate limiting.
// Each session gets an independent bucket with a configurable burst size
// and sustained refill rate. Stale sessions are pruned after 5 minutes
// of inactivity.
type RateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	burstSize int
	refillRate float64 // tokens per second
	staleAfter time.Duration
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter with the given burst capacity and
// sustained refill rate (tokens/second). burstSize caps the maximum tokens
// available at any instant; refillRate controls how quickly tokens regenerate.
func NewRateLimiter(burstSize int, refillRate float64) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		burstSize:  burstSize,
		refillRate: refillRate,
		staleAfter: 5 * time.Minute,
	}
	return rl
}

// Allow checks whether the given session is permitted to proceed.
// Returns true if a token is available (request allowed), false if the
// session's bucket is exhausted (rate limited).
func (r *RateLimiter) Allow(sessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b, exists := r.buckets[sessionID]
	if !exists {
		b = &bucket{
			tokens:   float64(r.burstSize),
			lastSeen: now,
		}
		r.buckets[sessionID] = b
		r.pruneStale(now)
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens += elapsed * r.refillRate
		if b.tokens > float64(r.burstSize) {
			b.tokens = float64(r.burstSize)
		}
		b.lastSeen = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// pruneStale removes sessions that have been inactive longer than staleAfter.
// Called under the mutex lock during Allow to amortize cleanup cost.
func (r *RateLimiter) pruneStale(now time.Time) {
	for id, b := range r.buckets {
		if now.Sub(b.lastSeen) > r.staleAfter {
			delete(r.buckets, id)
		}
	}
}
