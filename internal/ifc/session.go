package ifc

import (
	"sync"
	"sync/atomic"

	"github.com/mayjain/aegis/pkg/aegis"
)

// maxUint64Label is the packed representation of the maximum SecurityLabel.
// Used as the default ceiling value (unconstrained).
const maxUint64Label uint64 = 0xFFFFFFFFFFFFFFFF

// stateOrdinal encodes the label lifecycle state as a monotone uint32.
// States only advance — never retreat. Ordinal comparisons enforce this.
const (
	stateOrdinalFresh        uint32 = 0
	stateOrdinalEscalated    uint32 = 1
	stateOrdinalTainted      uint32 = 2
	stateOrdinalDeclassified uint32 = 3
)

// sessionData holds per-session mutable state.
// All fields accessed atomically or under the sync.Map contract.
type sessionData struct {
	label   atomic.Uint64 // packed current label — CAS-updated by Elevate
	ceiling atomic.Uint64 // packed max allowed label; maxUint64Label = unconstrained
	state   atomic.Uint32 // monotone state ordinal (stateOrdinal* constants)
}

// SessionLabels is a concurrent-safe registry of per-session IFC labels.
// Each session label is updated via CAS (compare-and-swap) loops.
// Direct Store() on the label field is FORBIDDEN outside session init. RISK-002.
type SessionLabels struct {
	// sync.Map: sessionID (string) → *sessionData
	entries sync.Map
}

// loadOrCreate returns the sessionData for the given sessionID, creating it if absent.
func (s *SessionLabels) loadOrCreate(sessionID string) *sessionData {
	val, _ := s.entries.LoadOrStore(sessionID, &sessionData{})
	return val.(*sessionData)
}

// advanceState advances the session state monotonically (states never retreat).
func advanceState(entry *sessionData, next uint32) {
	for {
		old := entry.state.Load()
		if old >= next {
			return
		}
		if entry.state.CompareAndSwap(old, next) {
			return
		}
	}
}

// Elevate raises the session label to incorporate the accessed resource label.
//
// This is a session taint operation, NOT a lattice Join. Key difference:
//   - Elevate: Integrity = max(session.I, resource.I) — integrity goes UP
//   - Join:    Integrity = min(a.I, b.I)              — integrity goes DOWN
//
// Implementation uses a CAS retry loop. Direct Store() is FORBIDDEN — it
// would create a race window where a concurrent Elevate could overwrite a
// higher label with a stale lower one. RISK-002 mitigation.
//
// Returns the new (post-elevation) label.
func (s *SessionLabels) Elevate(sessionID string, resource aegis.SecurityLabel) aegis.SecurityLabel {
	entry := s.loadOrCreate(sessionID)
	var result aegis.SecurityLabel
	for {
		old := entry.label.Load()
		current := unpackLabel(old)
		elevated := elevateLabel(current, resource)
		newPacked := packLabel(elevated)
		if newPacked == old {
			result = current
			break
		}
		if entry.label.CompareAndSwap(old, newPacked) {
			result = elevated
			break
		}
		// CAS lost — another goroutine updated concurrently; retry.
	}
	// Advance state (non-blocking, monotone).
	if result.Category&TaintBit != 0 {
		advanceState(entry, stateOrdinalTainted)
	} else if result.Confidentiality != 0 || result.Integrity != 0 || result.Category != 0 {
		advanceState(entry, stateOrdinalEscalated)
	}
	return result
}

// Current returns the current label for the session.
// Returns the zero SecurityLabel (minimum privilege) if the session is unknown.
func (s *SessionLabels) Current(sessionID string) aegis.SecurityLabel {
	val, ok := s.entries.Load(sessionID)
	if !ok {
		return aegis.SecurityLabel{}
	}
	return unpackLabel(val.(*sessionData).label.Load())
}

// LabelState returns the label lifecycle state for the session.
//
// State transitions (monotone — states only advance, never retreat):
//   - fresh:             no resource access yet (zero label)
//   - escalated:         label raised by normal resource access
//   - tainted_by_secret: TaintBit set in Category (set by TaintWithSecret)
//   - declassified:      DeclassificationGate applied (label unchanged; annotation-only)
func (s *SessionLabels) LabelState(sessionID string) LabelState {
	val, ok := s.entries.Load(sessionID)
	if !ok {
		return LabelStateFresh
	}
	entry := val.(*sessionData)
	switch entry.state.Load() {
	case stateOrdinalTainted:
		return LabelStateTaintedBySecret
	case stateOrdinalDeclassified:
		return LabelStateDeclassified
	case stateOrdinalEscalated:
		return LabelStateEscalated
	default:
		return LabelStateFresh
	}
}

// TaintWithSecret elevates the session label with the secret taint sentinel.
// Sets TaintBit in Category and transitions LabelState to tainted_by_secret.
// Returns the new label. Uses CAS loop per RISK-002.
func (s *SessionLabels) TaintWithSecret(sessionID string) aegis.SecurityLabel {
	taintLabel := aegis.SecurityLabel{Category: TaintBit}
	return s.Elevate(sessionID, taintLabel)
}

// InitWithCeiling initialises a child session with a starting label and ceiling
// derived from the parent's current label. Ceiling is immutable after init.
// If parentLabel is zero (unconstrained), ceiling = maxUint64Label.
func (s *SessionLabels) InitWithCeiling(sessionID string, parentLabel aegis.SecurityLabel) {
	entry := s.loadOrCreate(sessionID)
	packed := packLabel(parentLabel)
	ceiling := packed
	if ceiling == 0 {
		ceiling = maxUint64Label
	}
	// Direct Store is safe here: InitWithCeiling is called once at session creation
	// before the session entry is published to other goroutines. This is the sole
	// legitimate Store() call on the label outside of the CAS winner path.
	entry.label.Store(0)
	entry.ceiling.Store(ceiling)
}

// Ceiling returns the label ceiling for the session.
// Returns the maximum SecurityLabel (unconstrained) if not set.
func (s *SessionLabels) Ceiling(sessionID string) aegis.SecurityLabel {
	val, ok := s.entries.Load(sessionID)
	if !ok {
		return unpackLabel(maxUint64Label)
	}
	entry := val.(*sessionData)
	c := entry.ceiling.Load()
	if c == 0 {
		return unpackLabel(maxUint64Label)
	}
	return unpackLabel(c)
}

// CheckCeiling returns true if the proposed label is within the session ceiling.
func (s *SessionLabels) CheckCeiling(sessionID string, proposed aegis.SecurityLabel) bool {
	ceiling := s.Ceiling(sessionID)
	return Dominates(ceiling, proposed)
}

// markDeclassified records that the session has had DeclassificationGate applied.
// The label itself is NOT modified (RISK-026 mitigation).
func (s *SessionLabels) markDeclassified(sessionID string) {
	entry := s.loadOrCreate(sessionID)
	advanceState(entry, stateOrdinalDeclassified)
}
