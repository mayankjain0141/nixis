package delegation

import "time"

// CanonicalBytesForTest exposes canonicalBytes for external tests.
func (t *DelegationToken) CanonicalBytesForTest() []byte {
	return t.canonicalBytes()
}

// BuildChainForTest exposes buildChain for external tests.
func BuildChainForTest(tokens []DelegationToken, now time.Time) (*Chain, error) {
	return buildChain(tokens, now)
}

// HasActiveChain reports whether chainID is present in the active-chains map.
func (e *Engine) HasActiveChain(chainID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.activeChains[chainID]
	return ok
}
