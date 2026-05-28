package delegation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
)

const maxChainDepth = 8

// Engine validates Ed25519 delegation chains and tracks active chains for TTL expiry.
type Engine struct {
	trustedKeys  []ed25519.PublicKey
	mu           sync.RWMutex
	activeChains map[string]*Chain
}

// New creates a delegation Engine with the given trusted public keys (up to 3).
func New(trustedKeys ...ed25519.PublicKey) (*Engine, error) {
	if len(trustedKeys) == 0 {
		return nil, fmt.Errorf("delegation engine requires at least one trusted public key")
	}
	if len(trustedKeys) > 3 {
		return nil, fmt.Errorf("delegation engine accepts at most 3 trusted public keys, got %d", len(trustedKeys))
	}
	return &Engine{
		trustedKeys:  trustedKeys,
		activeChains: make(map[string]*Chain),
	}, nil
}

// Validate implements policy.DelegationValidator.
// Each aegis.DelegationRef carries a TokenID (used to look up the serialised token)
// and an Issuer. For this implementation, TokenID is expected to be a JSON-encoded
// DelegationToken so the chain can be fully reconstructed from the DelegationRef slice.
func (e *Engine) Validate(chain []aegis.DelegationRef, now time.Time) error {
	if len(chain) == 0 {
		return nil
	}
	if len(chain) > maxChainDepth {
		return fmt.Errorf("chain depth %d exceeds maximum of %d", len(chain), maxChainDepth)
	}

	tokens := make([]DelegationToken, 0, len(chain))
	for i, ref := range chain {
		tok, err := e.decodeAndVerify(ref, i)
		if err != nil {
			return err
		}
		tokens = append(tokens, tok)
	}

	if _, err := buildChain(tokens, now); err != nil {
		return err
	}
	return nil
}

// decodeAndVerify decodes a DelegationToken from a DelegationRef and verifies
// its Ed25519 signature. Signature is verified before any other parsing (per spec).
func (e *Engine) decodeAndVerify(ref aegis.DelegationRef, idx int) (DelegationToken, error) {
	// TokenID carries the JSON-encoded token; Issuer is informational.
	var tok DelegationToken
	if err := json.Unmarshal([]byte(ref.TokenID), &tok); err != nil {
		return DelegationToken{}, fmt.Errorf("token at index %d: failed to decode: %w", idx, err)
	}

	// Verify signature before any further validation (spec requirement).
	msg := tok.canonicalBytes()
	sig := tok.Signature

	if !e.verifyWithAnyKey(msg, sig) {
		return DelegationToken{}, fmt.Errorf("token at index %d: signature verification failed", idx)
	}

	return tok, nil
}

// verifyWithAnyKey tries each trusted key in sequence; returns true if any verifies.
func (e *Engine) verifyWithAnyKey(msg, sig []byte) bool {
	for _, key := range e.trustedKeys {
		if verifySignature(key, msg, sig) {
			return true
		}
	}
	return false
}

// Register adds a validated chain to the active-chains map for TTL tracking.
func (e *Engine) Register(chainID string, chain *Chain) {
	e.mu.Lock()
	e.activeChains[chainID] = chain
	e.mu.Unlock()
}

// StartExpiryChecker starts a background goroutine that removes expired chains
// from the active map every interval. The goroutine stops when ctx is cancelled.
func (e *Engine) StartExpiryChecker(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				e.removeExpired(t)
			}
		}
	}()
}

// removeExpired scans the active chains and removes those with all tokens expired.
func (e *Engine) removeExpired(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, chain := range e.activeChains {
		if isChainExpired(chain, now) {
			log.Printf("delegation: expiring chain %s (expired at %v)", id, chain.tokens[len(chain.tokens)-1].ExpiresAt)
			delete(e.activeChains, id)
		}
	}
}

// isChainExpired returns true if any token in the chain has expired.
func isChainExpired(chain *Chain, now time.Time) bool {
	for _, tok := range chain.tokens {
		if now.After(tok.ExpiresAt) {
			return true
		}
	}
	return false
}
