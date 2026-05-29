// SPDX-License-Identifier: MIT
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

// EmitFn is called when a delegation lifecycle event occurs.
// eventType is one of "delegation.revoked" or "delegation.expired".
// If nil, events are logged only.
type EmitFn func(eventType string, chainID string, reason string)

// Engine validates Ed25519 delegation chains and tracks active chains for TTL expiry.
type Engine struct {
	trustedKeys  []ed25519.PublicKey
	mu           sync.RWMutex
	activeChains map[string]*Chain
	emitFn       EmitFn // optional; set via SetEmitFn after construction
}

// SetEmitFn sets the function used to emit delegation CloudEvents.
// Safe to call concurrently; replaces any previously set function.
func (e *Engine) SetEmitFn(fn EmitFn) {
	e.mu.Lock()
	e.emitFn = fn
	e.mu.Unlock()
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
		// DeclassificationGate requires a non-empty AuditRef — spec Responsibility 6.
		if ref.DeclassificationGate != "" && ref.AuditRef == "" {
			return fmt.Errorf("token at index %d (issuer %s): DeclassificationGate %q requires non-empty AuditRef",
				i, ref.Issuer, ref.DeclassificationGate)
		}

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

// Revoke explicitly removes a chain from the active-chains map and emits a
// delegation.revoked event via the registered EmitFn (if set).
func (e *Engine) Revoke(chainID string) {
	e.mu.Lock()
	delete(e.activeChains, chainID)
	emit := e.emitFn
	e.mu.Unlock()
	log.Printf("delegation.revoked: chain %s explicitly revoked", chainID)
	if emit != nil {
		emit("delegation.revoked", chainID, "explicit_revocation")
	}
}

// ValidateChain decodes, verifies, and builds a Chain from the given DelegationRef
// slice. Returns the validated Chain (with pre-computed ceiling) alongside any error.
func (e *Engine) ValidateChain(chain []aegis.DelegationRef, now time.Time) (*Chain, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	if len(chain) > maxChainDepth {
		return nil, fmt.Errorf("chain depth %d exceeds maximum of %d", len(chain), maxChainDepth)
	}

	tokens := make([]DelegationToken, 0, len(chain))
	for i, ref := range chain {
		tok, err := e.decodeAndVerify(ref, i)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
	}

	return buildChain(tokens, now)
}

// ApplyCeiling returns true if the CheckRequest falls within the given EffectiveCeiling.
// Returns false (deny) if the ceiling has expired or the request exceeds it.
func (e *Engine) ApplyCeiling(req aegis.CheckRequest, ceiling EffectiveCeiling) bool {
	if time.Now().After(ceiling.ExpiresAt) {
		return false
	}
	// If no capability constraints are declared the ceiling permits everything.
	if len(ceiling.Capabilities) == 0 {
		return true
	}
	// Reject if the requested tool is not in the declared capability list.
	for _, cap := range ceiling.Capabilities {
		if cap == req.Tool {
			return true
		}
	}
	return false
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
	var expired []string
	for id, chain := range e.activeChains {
		if isChainExpired(chain, now) {
			log.Printf("delegation: expiring chain %s (expired at %v)", id, chain.tokens[len(chain.tokens)-1].ExpiresAt)
			delete(e.activeChains, id)
			expired = append(expired, id)
		}
	}
	emit := e.emitFn
	e.mu.Unlock()
	if emit != nil {
		for _, id := range expired {
			emit("delegation.expired", id, "ttl_elapsed")
		}
	}
}

// ActiveChainInfo describes a chain currently tracked by the Engine.
type ActiveChainInfo struct {
	ChainID   string    `json:"chain_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListActive returns metadata for all chains currently in the active map.
func (e *Engine) ListActive() []ActiveChainInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.activeChains) == 0 {
		return []ActiveChainInfo{}
	}
	out := make([]ActiveChainInfo, 0, len(e.activeChains))
	for id, chain := range e.activeChains {
		ceil := chain.Ceiling()
		out = append(out, ActiveChainInfo{
			ChainID:   id,
			ExpiresAt: ceil.ExpiresAt,
		})
	}
	return out
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
