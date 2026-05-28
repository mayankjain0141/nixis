// Package delegation implements Ed25519 delegation chain validation for Aegis.
package delegation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// CapabilitySet is a bitfield representing a set of granted capabilities.
type CapabilitySet struct {
	Operations uint16
	Effects    uint16
	Resources  uint16
	MaxRisk    uint8
}

// ReadOnlyCeiling is applied automatically when chain depth exceeds 2 hops.
var ReadOnlyCeiling = CapabilitySet{
	Operations: 1 << 0, // read-only operation
	Effects:    0,
	Resources:  0xFFFF,
	MaxRisk:    0,
}

// Intersect returns the bitwise AND intersection of two CapabilitySets.
// MaxRisk takes the minimum of the two values.
func (cs CapabilitySet) Intersect(other CapabilitySet) CapabilitySet {
	return CapabilitySet{
		Operations: cs.Operations & other.Operations,
		Effects:    cs.Effects & other.Effects,
		Resources:  cs.Resources & other.Resources,
		MaxRisk:    min(cs.MaxRisk, other.MaxRisk),
	}
}

// IsSubsetOf returns true if cs is a subset of other (cs cannot exceed other).
func (cs CapabilitySet) IsSubsetOf(other CapabilitySet) bool {
	return cs.Operations&^other.Operations == 0 &&
		cs.Effects&^other.Effects == 0 &&
		cs.Resources&^other.Resources == 0 &&
		cs.MaxRisk <= other.MaxRisk
}

// DelegationToken is a signed unit of delegation authority.
type DelegationToken struct {
	Issuer       string
	Audience     string
	Capabilities CapabilitySet
	MaxDepth     int
	ExpiresAt    time.Time
	ParentHash   [32]byte // SHA-256 of parent token's canonical form
	Signature    []byte   // Ed25519 over: Issuer+Audience+Capabilities+ExpiresAt+ParentHash
}

// CanonicalBytes returns the deterministic byte encoding of the token fields
// covered by the signature (all fields except Signature itself).
// Used by the CLI to sign and verify tokens.
func (t *DelegationToken) CanonicalBytes() []byte {
	return t.canonicalBytes()
}

// canonicalBytes returns the deterministic byte encoding of the token
// fields that are covered by the signature: all fields except Signature itself.
func (t *DelegationToken) canonicalBytes() []byte {
	// Fixed size: len(Issuer) + len(Audience) + 2+2+2+1 (caps) + 8 (unix nano) + 32 (hash)
	// Plus 4-byte length prefixes for variable-length strings.
	issuerBytes := []byte(t.Issuer)
	audienceBytes := []byte(t.Audience)

	buf := make([]byte, 4+len(issuerBytes)+4+len(audienceBytes)+2+2+2+1+8+4+32)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(issuerBytes)))
	offset += 4
	copy(buf[offset:], issuerBytes)
	offset += len(issuerBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(audienceBytes)))
	offset += 4
	copy(buf[offset:], audienceBytes)
	offset += len(audienceBytes)

	binary.BigEndian.PutUint16(buf[offset:], t.Capabilities.Operations)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], t.Capabilities.Effects)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], t.Capabilities.Resources)
	offset += 2
	buf[offset] = t.Capabilities.MaxRisk
	offset++

	binary.BigEndian.PutUint64(buf[offset:], uint64(t.ExpiresAt.UnixNano()))
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:], uint32(t.MaxDepth))
	offset += 4

	copy(buf[offset:], t.ParentHash[:])

	return buf
}

// Hash returns the SHA-256 of the token's canonical form (for chaining).
func (t *DelegationToken) Hash() [32]byte {
	return sha256.Sum256(t.canonicalBytes())
}

// verifySignature checks the Ed25519 signature. Returns true if sig is a valid
// signature over msg under pub. Rejects immediately if sig is the wrong length.
// ed25519.Verify uses constant-time operations internally.
func verifySignature(pub ed25519.PublicKey, msg []byte, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// EffectiveCeiling summarises the validated authority available to a delegation chain.
type EffectiveCeiling struct {
	Capabilities []string
	MaxDepth     int
	ExpiresAt    time.Time
}

// Chain is a validated delegation chain with a pre-computed capability ceiling.
type Chain struct {
	tokens  []DelegationToken
	ceiling CapabilitySet
	depth   int
}

// Permits returns true if the chain's ceiling permits the given operation.
func (c *Chain) Permits(ops, effects, resources uint16, maxRisk uint8) bool {
	return c.ceiling.Operations&ops == ops &&
		c.ceiling.Effects&effects == effects &&
		c.ceiling.Resources&resources == resources &&
		c.ceiling.MaxRisk >= maxRisk
}

// Ceiling returns the pre-computed EffectiveCeiling for this chain.
// ExpiresAt is the earliest expiry across all tokens.
func (c *Chain) Ceiling() EffectiveCeiling {
	earliest := c.tokens[0].ExpiresAt
	for _, tok := range c.tokens[1:] {
		if tok.ExpiresAt.Before(earliest) {
			earliest = tok.ExpiresAt
		}
	}
	return EffectiveCeiling{
		MaxDepth:  c.depth,
		ExpiresAt: earliest,
	}
}

// buildChain constructs and validates a Chain from a slice of DelegationTokens.
// Precondition: signatures have already been verified.
func buildChain(tokens []DelegationToken, now time.Time) (*Chain, error) {
	depth := len(tokens)

	// Validate TTL for every token.
	for i, tok := range tokens {
		if now.After(tok.ExpiresAt) {
			return nil, fmt.Errorf("token at index %d expired at %v", i, tok.ExpiresAt)
		}
	}

	// Validate parent-hash chain integrity.
	for i := 1; i < len(tokens); i++ {
		expected := tokens[i-1].Hash()
		if subtle.ConstantTimeCompare(expected[:], tokens[i].ParentHash[:]) != 1 {
			return nil, fmt.Errorf("chain integrity violation: token %d has invalid ParentHash", i)
		}
	}

	// Compute capability ceiling via monotone intersection.
	ceiling := tokens[0].Capabilities
	for i := 1; i < len(tokens); i++ {
		child := tokens[i].Capabilities
		if !child.IsSubsetOf(ceiling) {
			return nil, fmt.Errorf("capability expansion: token %d attempts to grant capabilities not held by parent", i)
		}
		ceiling = ceiling.Intersect(child)
	}

	// Deep delegation restriction: depth > 2 applies ReadOnlyCeiling.
	if depth > 2 {
		ceiling = ReadOnlyCeiling
	}

	return &Chain{
		tokens:  tokens,
		ceiling: ceiling,
		depth:   depth,
	}, nil
}
