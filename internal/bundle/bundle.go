// Package bundle implements the policy bundle distribution and activation subsystem.
package bundle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ActivationState represents a lifecycle state in the bundle activation FSM.
// String values are used so states are self-documenting in logs and metrics.
type ActivationState string

const (
	StateIdle           ActivationState = "idle"
	StateDownloading    ActivationState = "downloading"
	StateVerifying      ActivationState = "verifying"
	StateStaging        ActivationState = "staging"
	StateCompiling      ActivationState = "compiling"
	StateHealthChecking ActivationState = "health_checking"
	StateActivating     ActivationState = "activating"
	StateRollback       ActivationState = "rollback"
	StateDenyAll        ActivationState = "deny_all"

	// StateFetching is an alias kept for backward compatibility with Phase 1 code.
	StateFetching    ActivationState = "fetching"
	StateParsing     ActivationState = "parsing"
	StateRollingBack ActivationState = "rolling_back"
)

// ActivationFSM guards state transitions for a bundle activation lifecycle.
// The current state is stored atomically; mu serialises compare-and-swap
// transitions so no two callers can race on the same source state.
type ActivationFSM struct {
	state atomic.Value // holds ActivationState string
	mu    sync.Mutex
}

// NewActivationFSM returns an FSM in StateIdle.
func NewActivationFSM() *ActivationFSM {
	f := &ActivationFSM{}
	f.state.Store(StateIdle)
	return f
}

// State returns the current ActivationState.
func (f *ActivationFSM) State() ActivationState {
	return f.state.Load().(ActivationState)
}

// Transition moves the FSM from `from` to `to`. It returns an error if the
// current state is not `from`. The mu lock ensures only one transition fires
// at a time, preventing lost-update races on the (read-current → check → store) path.
func (f *ActivationFSM) Transition(from, to ActivationState) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	current := f.state.Load().(ActivationState)
	if current != from {
		return fmt.Errorf("bundle FSM: cannot transition %s→%s: current state is %s",
			from, to, current)
	}
	f.state.Store(to)
	return nil
}

// force sets the FSM state unconditionally. Used only in rollback paths.
func (f *ActivationFSM) force(to ActivationState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state.Store(to)
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

// RawBundle is the output of a successful bundle load.
// Verification precedes parsing — callers may trust that Data has been
// signature-checked before any content is inspected. (INV-009)
type RawBundle struct {
	Data    []byte // raw bundle bytes (tar.gz)
	Etag    string // HTTP ETag for conditional GET
	Version uint64 // monotone bundle version from the manifest
}

// BundleLoaderIface fetches and verifies policy bundles from a remote source.
// The name avoids collision with the concrete BundleLoader struct below.
type BundleLoaderIface interface {
	// Load fetches a bundle from sourceURL and verifies its signature with keys
	// before returning the raw bytes. Verification happens BEFORE parsing (INV-009).
	Load(ctx context.Context, sourceURL string, keys *KeySource) (*RawBundle, error)
}

// Policy layer constants. Lower LayerPriority value = higher precedence (evaluated first).
// ceiling overrides team overrides project overrides cel (the default).
const (
	LayerCeiling = "ceiling"
	LayerTeam    = "team"
	LayerProject = "project"
	LayerCEL     = "cel"
)

// LayerPriority maps each layer name to its evaluation order.
// Lower number = higher priority. ceiling fires before team, team before project, project before cel.
var LayerPriority = map[string]int{
	LayerCeiling: 0,
	LayerTeam:    1,
	LayerProject: 2,
	LayerCEL:     3,
}
