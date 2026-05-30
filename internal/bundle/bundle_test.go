package bundle_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/mayjain/nixis/internal/bundle"
)

// --- ActivationFSM ---

func TestActivationFSM_InitialState(t *testing.T) {
	f := bundle.NewActivationFSM()
	if got := f.State(); got != bundle.StateIdle {
		t.Fatalf("expected StateIdle, got %s", got)
	}
}

func TestActivationFSM_ValidTransition(t *testing.T) {
	f := bundle.NewActivationFSM()
	if err := f.Transition(bundle.StateIdle, bundle.StateFetching); err != nil {
		t.Fatalf("expected Idle→Fetching to succeed, got: %v", err)
	}
	if got := f.State(); got != bundle.StateFetching {
		t.Fatalf("expected StateFetching, got %s", got)
	}
}

func TestActivationFSM_InvalidTransition(t *testing.T) {
	f := bundle.NewActivationFSM()
	err := f.Transition(bundle.StateIdle, bundle.StateActivating)
	// StateActivating is not a valid destination from StateIdle in the test — the FSM
	// does not encode a transition table; it only rejects transitions where current != from.
	// So Idle→Activating would succeed unless we assert current != from.
	// Per spec, Transition checks current == from, so let's do an actual mismatch:
	// Force state to Fetching, then try Transition(Idle, Activating).
	_ = err // first call (Idle→Activating) succeeds since current IS Idle

	f2 := bundle.NewActivationFSM()
	if err2 := f2.Transition(bundle.StateIdle, bundle.StateFetching); err2 != nil {
		t.Fatal(err2)
	}
	// Now current is Fetching. Transition(Idle, Activating) should fail.
	if err3 := f2.Transition(bundle.StateIdle, bundle.StateActivating); err3 == nil {
		t.Fatal("expected error transitioning from Idle when current is Fetching")
	}
}

func TestActivationFSM_Concurrent(t *testing.T) {
	// 100 goroutines each attempt Transition(StateIdle, StateFetching).
	// Exactly one should succeed; the rest should get errors.
	// This test primarily exercises the race detector.
	f := bundle.NewActivationFSM()
	var wg sync.WaitGroup
	successes := make([]int, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := f.Transition(bundle.StateIdle, bundle.StateFetching)
			if err == nil {
				successes[idx] = 1
			}
		}(i)
	}
	wg.Wait()

	total := 0
	for _, v := range successes {
		total += v
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 successful Idle→Fetching transition, got %d", total)
	}
	if got := f.State(); got != bundle.StateFetching {
		t.Fatalf("expected StateFetching after concurrent transitions, got %s", got)
	}
}

// --- KeySource ---

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestKeySource_SingleKey_Verifies(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks, err := bundle.NewKeySource(pub)
	if err != nil {
		t.Fatalf("NewKeySource: %v", err)
	}
	msg := []byte("test-message")
	sig := ed25519.Sign(priv, msg)
	if !ks.Verify(msg, sig) {
		t.Fatal("expected Verify to return true for a valid signature")
	}
}

func TestKeySource_MultiKey_AnyVerifies(t *testing.T) {
	pub1, _ := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)

	ks, err := bundle.NewKeySource(pub1, pub2)
	if err != nil {
		t.Fatalf("NewKeySource: %v", err)
	}
	msg := []byte("signed-by-key2")
	sig := ed25519.Sign(priv2, msg)
	if !ks.Verify(msg, sig) {
		t.Fatal("expected Verify to return true when signed by any key in the set")
	}
}

func TestKeySource_Empty_ReturnsError(t *testing.T) {
	_, err := bundle.NewKeySource()
	if err == nil {
		t.Fatal("expected error when creating KeySource with no keys")
	}
}
