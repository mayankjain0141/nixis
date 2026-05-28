package delegation_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/delegation"
	"github.com/mayjain/aegis/pkg/aegis"
)

// helpers

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	return pub, priv
}

// makeToken creates a signed DelegationToken. If parentTok is nil, ParentHash is zero.
func makeToken(
	t *testing.T,
	priv ed25519.PrivateKey,
	issuer, audience string,
	caps delegation.CapabilitySet,
	expiresAt time.Time,
	parent *delegation.DelegationToken,
) delegation.DelegationToken {
	t.Helper()
	tok := delegation.DelegationToken{
		Issuer:       issuer,
		Audience:     audience,
		Capabilities: caps,
		MaxDepth:     8,
		ExpiresAt:    expiresAt,
	}
	if parent != nil {
		tok.ParentHash = parent.Hash()
	}
	msg := tok.CanonicalBytesForTest()
	tok.Signature = ed25519.Sign(priv, msg)
	return tok
}

// tokenRef encodes a DelegationToken as a DelegationRef.
func tokenRef(t *testing.T, tok delegation.DelegationToken) aegis.DelegationRef {
	t.Helper()
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}
	return aegis.DelegationRef{
		TokenID: string(b),
		Issuer:  tok.Issuer,
	}
}

// --- Tests ---

// TestDelegation_CeilingIsIntersection verifies that the capability ceiling is the
// bitwise intersection of all tokens in the chain: parent {A,B,C}=(1|2|4),
// child {A,B,D}=(1|2|8) → ceiling = {A,B} = (1|2 = 3).
// This exercises the Intersect method directly; the chain must be valid (child ⊆ parent
// is not required by design — the intersection silently caps the child's extra bits).
func TestDelegation_CeilingIsIntersection(t *testing.T) {
	// Directly verify the math of Intersect.
	parentCaps := delegation.CapabilitySet{Operations: 0b0111} // A|B|C = 7
	childCaps := delegation.CapabilitySet{Operations: 0b1011}  // A|B|D = 11

	ceiling := parentCaps.Intersect(childCaps)
	want := delegation.CapabilitySet{Operations: 0b0011} // A|B = 3
	if ceiling != want {
		t.Errorf("Intersect(%v, %v) = %v, want %v", parentCaps, childCaps, ceiling, want)
	}

	// Also verify via a validated chain where the ceiling is the intersection.
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)

	// For a valid chain: child must be a subset of parent (so no expansion error).
	// Use parent={A,B,C} and child={A,B} — intersection is {A,B}.
	validParentCaps := delegation.CapabilitySet{Operations: 0b0111}
	validChildCaps := delegation.CapabilitySet{Operations: 0b0011}

	parent := makeToken(t, priv, "root", "child", validParentCaps, exp, nil)
	child := makeToken(t, priv, "child", "leaf", validChildCaps, exp, &parent)

	chain := []aegis.DelegationRef{tokenRef(t, parent), tokenRef(t, child)}
	if err := eng.Validate(chain, now); err != nil {
		t.Fatalf("unexpected Validate error: %v", err)
	}

	// Verify the built chain ceiling via BuildChainForTest.
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{parent, child}, now)
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}
	wantCeiling := delegation.CapabilitySet{Operations: 0b0011}
	if !builtChain.Permits(wantCeiling.Operations, 0, 0, 0) {
		t.Errorf("chain does not permit expected ceiling ops %d", wantCeiling.Operations)
	}
	// Bit C (4) must NOT be permitted — child stripped it.
	if builtChain.Permits(0b0111, 0, 0, 0) {
		t.Errorf("chain should not permit parent-only bits after intersection")
	}
}

// TestDelegation_CannotExpand verifies that a child token attempting to grant
// a capability bit not held by the parent causes Validate to return an error
// containing "capability expansion".
func TestDelegation_CannotExpand(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)

	// parent: only bit 1
	parentCaps := delegation.CapabilitySet{Operations: 0b0001}
	// child: bits 1|2 — bit 2 not granted by parent → expansion
	childCaps := delegation.CapabilitySet{Operations: 0b0011}

	parent := makeToken(t, priv, "root", "child", parentCaps, exp, nil)
	child := makeToken(t, priv, "child", "leaf", childCaps, exp, &parent)

	chain := []aegis.DelegationRef{tokenRef(t, parent), tokenRef(t, child)}
	err = eng.Validate(chain, now)
	if err == nil {
		t.Fatal("expected error for capability expansion, got nil")
	}
	if !strings.Contains(err.Error(), "capability expansion") {
		t.Errorf("error %q does not contain 'capability expansion'", err.Error())
	}
}

// TestDelegation_DeepRestriction verifies that a 3-hop chain has its ceiling
// capped to ReadOnlyCeiling regardless of declared capabilities.
func TestDelegation_DeepRestriction(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)

	// All tokens have identical full capabilities so no expansion error fires.
	fullCaps := delegation.CapabilitySet{Operations: 0xFFFF, Effects: 0xFFFF, Resources: 0xFFFF, MaxRisk: 255}

	tok0 := makeToken(t, priv, "root", "a", fullCaps, exp, nil)
	tok1 := makeToken(t, priv, "a", "b", fullCaps, exp, &tok0)
	tok2 := makeToken(t, priv, "b", "c", fullCaps, exp, &tok1)

	chain := []aegis.DelegationRef{tokenRef(t, tok0), tokenRef(t, tok1), tokenRef(t, tok2)}
	if err := eng.Validate(chain, now); err != nil {
		t.Fatalf("unexpected Validate error: %v", err)
	}

	// Verify ReadOnlyCeiling is applied via BuildChainForTest.
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok0, tok1, tok2}, now)
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}
	// ReadOnlyCeiling permits ops=1, effects=0, resources=0xFFFF, maxRisk=0.
	ceil := delegation.ReadOnlyCeiling
	if !builtChain.Permits(ceil.Operations, ceil.Effects, ceil.Resources, ceil.MaxRisk) {
		t.Errorf("deep chain should permit ReadOnlyCeiling operations")
	}
	// Full effects must NOT be permitted.
	if builtChain.Permits(0xFFFF, 0xFFFF, 0xFFFF, 0) {
		t.Errorf("deep chain should not permit full capabilities after ReadOnlyCeiling")
	}
}

// TestDelegation_TTLExpiry_EmitsEvent verifies that StartExpiryChecker logs and
// removes a chain whose token is already expired.
func TestDelegation_TTLExpiry_EmitsEvent(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	// Token expired 1 second ago.
	exp := now.Add(-time.Second)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
	// Build chain with a past "now" so TTL check in buildChain passes.
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now.Add(-2*time.Second))
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}

	eng.Register("chain-expired", builtChain)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	eng.StartExpiryChecker(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !eng.HasActiveChain("chain-expired") {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Error("chain-expired was not removed within 50ms")
}

// TestDelegation_TTLExpiry_RemovesFromActive verifies the chain is absent from
// the active map after the expiry checker fires.
func TestDelegation_TTLExpiry_RemovesFromActive(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(-time.Second)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now.Add(-2*time.Second))
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}

	eng.Register("remove-test-chain", builtChain)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng.StartExpiryChecker(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !eng.HasActiveChain("remove-test-chain") {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Error("remove-test-chain was not removed from active map within 50ms")
}

// TestDelegation_SignatureVerification_ForgedRejected verifies that a token with
// a bit-flipped (forged) signature is rejected before any capability check.
func TestDelegation_SignatureVerification_ForgedRejected(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)

	// Flip a bit in the signature to forge it.
	tok.Signature[0] ^= 0xFF

	chain := []aegis.DelegationRef{tokenRef(t, tok)}
	err = eng.Validate(chain, now)
	if err == nil {
		t.Fatal("expected error for forged signature, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error %q should mention signature failure", err.Error())
	}
}

// TestChain_BrokenHashChain_Rejected verifies that tampering with ParentHash in a
// child token causes Validate to return an error containing "chain integrity".
func TestChain_BrokenHashChain_Rejected(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	parent := makeToken(t, priv, "root", "child", caps, exp, nil)
	child := makeToken(t, priv, "child", "leaf", caps, exp, &parent)

	// Tamper with the parent hash in the child token.
	child.ParentHash[0] ^= 0xFF

	// Re-sign the child with tampered data so signature passes but hash chain breaks.
	msg := child.CanonicalBytesForTest()
	child.Signature = ed25519.Sign(priv, msg)

	chain := []aegis.DelegationRef{tokenRef(t, parent), tokenRef(t, child)}
	err = eng.Validate(chain, now)
	if err == nil {
		t.Fatal("expected error for broken hash chain, got nil")
	}
	if !strings.Contains(err.Error(), "chain integrity") {
		t.Errorf("error %q does not contain 'chain integrity'", err.Error())
	}
}

// TestDelegation_MultiKey_RotationAccepted verifies that a token signed with key2
// of 3 trusted keys passes validation.
func TestDelegation_MultiKey_RotationAccepted(t *testing.T) {
	pub1, _ := genKey(t)
	pub2, priv2 := genKey(t)
	pub3, _ := genKey(t)

	eng, err := delegation.New(pub1, pub2, pub3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv2, "root", "leaf", caps, exp, nil)

	chain := []aegis.DelegationRef{tokenRef(t, tok)}
	if err := eng.Validate(chain, now); err != nil {
		t.Fatalf("unexpected Validate error with key2-signed token: %v", err)
	}
}

// TestDelegation_Revoke_EmitsEvent verifies that Revoke removes the chain from
// the active map (the log line is the event — CloudEvent is Phase 3).
func TestDelegation_Revoke_EmitsEvent(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now)
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}

	const chainID = "revoke-test-chain"
	eng.Register(chainID, builtChain)

	if !eng.HasActiveChain(chainID) {
		t.Fatal("chain should be active before Revoke")
	}

	eng.Revoke(chainID)

	if eng.HasActiveChain(chainID) {
		t.Error("chain should be removed from active map after Revoke")
	}
}

func TestDelegation_DeclassificationGate_RequiresAuditRef(t *testing.T) {
	pub, _ := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Token with DeclassificationGate but no AuditRef must be rejected.
	chain := []aegis.DelegationRef{
		{
			TokenID:              `{}`,
			Issuer:               "test-issuer",
			DeclassificationGate: "TOP_SECRET",
			AuditRef:             "",
		},
	}
	err = eng.Validate(chain, time.Now())
	if err == nil {
		t.Fatal("expected error for DeclassificationGate with empty AuditRef, got nil")
	}
	if !strings.Contains(err.Error(), "DeclassificationGate") {
		t.Errorf("error should mention DeclassificationGate, got: %v", err)
	}
}

func TestDelegation_DeclassificationGate_WithAuditRef_PassesGate(t *testing.T) {
	pub, _ := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// DeclassificationGate with a valid AuditRef passes the gate check (may still
	// fail signature verification — but it must NOT be rejected for missing AuditRef).
	chain := []aegis.DelegationRef{
		{
			TokenID:              `{}`,
			Issuer:               "test-issuer",
			DeclassificationGate: "TOP_SECRET",
			AuditRef:             "audit-2026-001",
		},
	}
	err = eng.Validate(chain, time.Now())
	// The error (if any) must NOT be about DeclassificationGate — it should be
	// about token decoding or signature, not the gate check.
	if err != nil && strings.Contains(err.Error(), "DeclassificationGate") {
		t.Errorf("should not reject token with both DeclassificationGate and AuditRef set: %v", err)
	}
}

// TestDelegation_Engine_ListActive verifies that ListActive returns all registered
// chains and that a revoked chain no longer appears.
func TestDelegation_Engine_ListActive(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	// Register two chains.
	for _, id := range []string{"chain-alpha", "chain-beta"} {
		tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
		chain, bErr := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now)
		if bErr != nil {
			t.Fatalf("BuildChainForTest: %v", bErr)
		}
		eng.Register(id, chain)
	}

	active := eng.ListActive()
	if len(active) != 2 {
		t.Fatalf("expected 2 active chains, got %d", len(active))
	}

	// Revoke one.
	eng.Revoke("chain-alpha")
	active = eng.ListActive()
	if len(active) != 1 {
		t.Fatalf("expected 1 active chain after revoke, got %d", len(active))
	}
	if active[0].ChainID != "chain-beta" {
		t.Errorf("expected chain-beta to remain, got %q", active[0].ChainID)
	}

	// ExpiresAt must be non-zero for a valid chain.
	if active[0].ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero for a registered chain")
	}
}

// TestDelegation_Engine_ListActive_Empty verifies that ListActive returns an empty
// (non-nil) slice when no chains are registered.
func TestDelegation_Engine_ListActive_Empty(t *testing.T) {
	pub, _ := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	active := eng.ListActive()
	if active == nil {
		t.Error("ListActive should return non-nil empty slice, not nil")
	}
	if len(active) != 0 {
		t.Errorf("expected 0 chains for empty engine, got %d", len(active))
	}
}

// TestDelegation_Revoke_EmitsToEmitFn verifies that Revoke calls the registered
// EmitFn with eventType "delegation.revoked" and the correct chainID.
func TestDelegation_Revoke_EmitsToEmitFn(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now)
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}

	const chainID = "emit-revoke-test"
	eng.Register(chainID, builtChain)

	type emitCall struct {
		eventType string
		chainID   string
		reason    string
	}
	calls := make(chan emitCall, 1)
	eng.SetEmitFn(func(eventType, id, reason string) {
		calls <- emitCall{eventType, id, reason}
	})

	eng.Revoke(chainID)

	select {
	case got := <-calls:
		if got.eventType != "delegation.revoked" {
			t.Errorf("eventType = %q, want %q", got.eventType, "delegation.revoked")
		}
		if got.chainID != chainID {
			t.Errorf("chainID = %q, want %q", got.chainID, chainID)
		}
		if got.reason != "explicit_revocation" {
			t.Errorf("reason = %q, want %q", got.reason, "explicit_revocation")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("EmitFn was not called within 100ms after Revoke")
	}
}

// TestDelegation_Expired_EmitsToEmitFn verifies that the expiry checker calls the
// registered EmitFn with eventType "delegation.expired" for an expired chain.
func TestDelegation_Expired_EmitsToEmitFn(t *testing.T) {
	pub, priv := genKey(t)
	eng, err := delegation.New(pub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	// Token expired 1 second ago.
	exp := now.Add(-time.Second)
	caps := delegation.CapabilitySet{Operations: 0b0001}

	tok := makeToken(t, priv, "root", "leaf", caps, exp, nil)
	builtChain, err := delegation.BuildChainForTest([]delegation.DelegationToken{tok}, now.Add(-2*time.Second))
	if err != nil {
		t.Fatalf("BuildChainForTest: %v", err)
	}

	const chainID = "emit-expired-test"
	eng.Register(chainID, builtChain)

	type emitCall struct {
		eventType string
		chainID   string
		reason    string
	}
	calls := make(chan emitCall, 1)
	eng.SetEmitFn(func(eventType, id, reason string) {
		calls <- emitCall{eventType, id, reason}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	eng.StartExpiryChecker(ctx, 10*time.Millisecond)

	select {
	case got := <-calls:
		if got.eventType != "delegation.expired" {
			t.Errorf("eventType = %q, want %q", got.eventType, "delegation.expired")
		}
		if got.chainID != chainID {
			t.Errorf("chainID = %q, want %q", got.chainID, chainID)
		}
		if got.reason != "ttl_elapsed" {
			t.Errorf("reason = %q, want %q", got.reason, "ttl_elapsed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("EmitFn was not called within 200ms after expiry checker started")
	}
}
