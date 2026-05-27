package ifc

import (
	"sync"
	"sync/atomic"

	"github.com/mayjain/aegis/pkg/aegis"
)

// maxUint64Label is the packed representation of the unconstrained ceiling.
// All bits set means every dimension is at its maximum — any label passes CheckCeiling.
const maxUint64Label uint64 = 0xFFFFFFFFFFFFFFFF

// stateOrdinals encode the label lifecycle state machine as a monotonically
// increasing uint32 so that atomic CAS can enforce "states never retreat."
const (
	stateOrdinalFresh        uint32 = 0
	stateOrdinalEscalated    uint32 = 1
	stateOrdinalTainted      uint32 = 2
	stateOrdinalDeclassified uint32 = 3
)

// sessionData holds per-session mutable state.
// Fields are accessed only via atomic primitives.
type sessionData struct {
	label   atomic.Uint64 // packed current label — CAS-updated by Elevate only
	ceiling atomic.Uint64 // packed ceiling; 0 = not yet set (treated as maxUint64Label)
	state   atomic.Uint32 // monotone state ordinal (see stateOrdinal* constants)
}

// SessionLabels is a concurrent-safe registry of per-session IFC labels.
//
// Label updates use a CAS retry loop (Elevate). Direct Store() on the label
// field is FORBIDDEN except in the CAS winner path. RISK-002 mitigation.
type SessionLabels struct {
	entries sync.Map // sessionID (string) → *sessionData
}

// getOrCreate returns the *sessionData for sessionID, creating it atomically if absent.
// It avoids allocating a new sessionData on cache hits by trying Load first.
func (s *SessionLabels) getOrCreate(sessionID string) *sessionData {
	if v, ok := s.entries.Load(sessionID); ok {
		return v.(*sessionData)
	}
	fresh := &sessionData{}
	if v, loaded := s.entries.LoadOrStore(sessionID, fresh); loaded {
		// Another goroutine stored first; use their entry.
		return v.(*sessionData)
	}
	return fresh
}

// advanceState advances the session state monotonically.
// It loops until the CAS succeeds or we observe that the state is already >= next.
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

// Elevate raises the session label to incorporate the resource label (session taint).
//
// This is NOT the lattice Join. The key difference:
//   - Elevate: Integrity = max(session.I, resource.I) — integrity goes UP
//   - Join:    Integrity = min(a.I, b.I)              — integrity goes DOWN
//
// Implementation: CAS retry loop. Direct Store() on entry.label is FORBIDDEN —
// a lost CAS that issues Store() would overwrite a higher concurrent label with
// a stale lower one, silently downgrading the session. RISK-002.
//
// Returns the new (post-elevation) label.
func (s *SessionLabels) Elevate(sessionID string, resource aegis.SecurityLabel) aegis.SecurityLabel {
	entry := s.getOrCreate(sessionID)

	var result aegis.SecurityLabel
	for {
		old := entry.label.Load()
		current := unpackLabel(old)
		elevated := elevateLabel(current, resource)
		newPacked := packLabel(elevated)

		if newPacked == old {
			// No change needed — label already dominates resource in all dimensions.
			result = current
			break
		}
		if entry.label.CompareAndSwap(old, newPacked) {
			// CAS won — we own the write.
			result = elevated
			break
		}
		// CAS lost — another goroutine updated first. Reload and retry.
	}

	// Advance state machine monotonically after label is committed.
	if result.Category&TaintBit != 0 {
		advanceState(entry, stateOrdinalTainted)
	} else if result.Confidentiality != 0 || result.Integrity != 0 || result.Category != 0 {
		advanceState(entry, stateOrdinalEscalated)
	}

	return result
}

// Current returns the current label for sessionID.
// Returns the zero SecurityLabel (minimum privilege) for unknown sessions.
func (s *SessionLabels) Current(sessionID string) aegis.SecurityLabel {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return aegis.SecurityLabel{}
	}
	return unpackLabel(v.(*sessionData).label.Load())
}

// LabelState returns the lifecycle state for sessionID.
//
// State machine (monotone — states only advance, never retreat):
//   - fresh:             no resource access yet
//   - escalated:         label raised by normal resource access
//   - tainted_by_secret: TaintBit set in Category (via TaintWithSecret)
//   - declassified:      DeclassificationGate applied (label unchanged; annotation only)
func (s *SessionLabels) LabelState(sessionID string) LabelState {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return LabelStateFresh
	}
	switch v.(*sessionData).state.Load() {
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

// TaintWithSecret sets TaintBit in the session category and transitions state
// to tainted_by_secret. Uses the CAS loop in Elevate. RISK-002.
func (s *SessionLabels) TaintWithSecret(sessionID string) aegis.SecurityLabel {
	return s.Elevate(sessionID, aegis.SecurityLabel{Category: TaintBit})
}

// InitWithCeiling initialises a new child session with label=zero and ceiling=parentLabel.
// Concurrent calls for the same sessionID are safe: the ceiling is written once
// via a CAS that only fires on a zero (unset) ceiling.
// If parentLabel is zero (unconstrained), the ceiling is set to maxUint64Label.
func (s *SessionLabels) InitWithCeiling(sessionID string, parentLabel aegis.SecurityLabel) {
	entry := s.getOrCreate(sessionID)

	packed := packLabel(parentLabel)
	ceiling := packed
	if ceiling == 0 {
		ceiling = maxUint64Label
	}

	// CAS from 0 → ceiling. If a concurrent InitWithCeiling already set it,
	// the CAS fails and we leave the earlier value intact (first writer wins).
	entry.ceiling.CompareAndSwap(0, ceiling)
}

// Ceiling returns the label ceiling for sessionID.
// Returns the maximum SecurityLabel (unconstrained) when no ceiling is set.
func (s *SessionLabels) Ceiling(sessionID string) aegis.SecurityLabel {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return unpackLabel(maxUint64Label)
	}
	c := v.(*sessionData).ceiling.Load()
	if c == 0 {
		return unpackLabel(maxUint64Label)
	}
	return unpackLabel(c)
}

// CheckCeiling returns true if proposed is within the session ceiling.
func (s *SessionLabels) CheckCeiling(sessionID string, proposed aegis.SecurityLabel) bool {
	return Dominates(s.Ceiling(sessionID), proposed)
}

// markDeclassified advances the session state to declassified.
// The label itself is NOT modified — this is annotation-only. RISK-026.
func (s *SessionLabels) markDeclassified(sessionID string) {
	entry := s.getOrCreate(sessionID)
	advanceState(entry, stateOrdinalDeclassified)
}
