// Package bundle implements the policy bundle distribution and activation subsystem.
// Phase 1 delivers only: the 8-state ActivationFSM, the Ed25519 KeySource,
// and the BundleLoader interface with its RawBundle type.
package bundle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ActivationState represents one of eight lifecycle states of a policy bundle activation.
type ActivationState int32

const (
	StateIdle           ActivationState = iota // waiting for a new bundle
	StateFetching                              // HTTP GET in progress
	StateVerifying                             // Ed25519 signature check
	StateParsing                               // YAML / tar decode
	StateCompiling                             // CEL compilation
	StateHealthChecking                        // post-compile health probe
	StateActivating                            // atomically swapping the live policy set
	StateRollingBack                           // reverting to the previous bundle on failure
)

// String returns a human-readable name for the state.
func (s ActivationState) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateFetching:
		return "Fetching"
	case StateVerifying:
		return "Verifying"
	case StateParsing:
		return "Parsing"
	case StateCompiling:
		return "Compiling"
	case StateHealthChecking:
		return "HealthChecking"
	case StateActivating:
		return "Activating"
	case StateRollingBack:
		return "RollingBack"
	default:
		return fmt.Sprintf("ActivationState(%d)", int32(s))
	}
}

// ActivationFSM guards state transitions for a bundle activation lifecycle.
// The current state is stored as an atomic int32; mu serialises compare-and-swap
// transitions so no two callers can race on the same source state.
type ActivationFSM struct {
	state atomic.Int32
	mu    sync.Mutex
}

// NewActivationFSM returns an FSM in StateIdle.
func NewActivationFSM() *ActivationFSM {
	f := &ActivationFSM{}
	f.state.Store(int32(StateIdle))
	return f
}

// State returns the current ActivationState.
func (f *ActivationFSM) State() ActivationState {
	return ActivationState(f.state.Load())
}

// Transition moves the FSM from `from` to `to`. It returns an error if the
// current state is not `from`. The mu lock ensures only one transition fires
// at a time, preventing lost-update races on the (read-current → check → store) path.
func (f *ActivationFSM) Transition(from, to ActivationState) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	current := ActivationState(f.state.Load())
	if current != from {
		return fmt.Errorf("bundle FSM: cannot transition %s→%s: current state is %s",
			from, to, current)
	}
	f.state.Store(int32(to))
	return nil
}

// KeySource holds one or more Ed25519 public keys used to verify bundle signatures.
// Verification succeeds when ANY key in the set produces a valid signature,
// enabling key rotation without a flag day.
type KeySource struct {
	keys []ed25519.PublicKey
}

// NewKeySource creates a KeySource from one or more public keys.
// At least one key is required; an empty call returns an error.
func NewKeySource(keys ...ed25519.PublicKey) (*KeySource, error) {
	if len(keys) == 0 {
		return nil, errors.New("bundle: KeySource requires at least one public key")
	}
	copied := make([]ed25519.PublicKey, len(keys))
	for i, k := range keys {
		c := make([]byte, len(k))
		copy(c, k)
		copied[i] = c
	}
	return &KeySource{keys: copied}, nil
}

// Verify returns true if the signature over message is valid under ANY key in the source.
func (k *KeySource) Verify(message, sig []byte) bool {
	for _, pub := range k.keys {
		if ed25519.Verify(pub, message, sig) {
			return true
		}
	}
	return false
}

// RawBundle is the output of a successful BundleLoader.Load call.
// Verification precedes parsing — callers may trust that Data has been
// signature-checked before any content is inspected. (INV-009)
type RawBundle struct {
	Data    []byte // raw bundle bytes (tar.gz)
	Etag    string // HTTP ETag for conditional GET
	Version uint64 // monotone bundle version from the manifest
}

// BundleLoader fetches and verifies policy bundles from a remote source.
type BundleLoader interface {
	// Load fetches a bundle from sourceURL and verifies its signature with keys
	// before returning the raw bytes. Verification happens BEFORE parsing (INV-009).
	Load(ctx context.Context, sourceURL string, keys *KeySource) (*RawBundle, error)
}
