// SPDX-License-Identifier: MIT
package ifc

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
)

// ApprovalState is the permission layer state machine.
// Transitions: none → pending → standing_rule → session_granted
type ApprovalState uint32

const (
	ApprovalNone           ApprovalState = 0 // no approval granted
	ApprovalPending        ApprovalState = 1 // approval request shown, awaiting response
	ApprovalStandingRule   ApprovalState = 2 // one or more standing rules active
	ApprovalSessionGranted ApprovalState = 3 // blanket session approval ("allow all")
)

// StandingRule is a domain-scoped or path-scoped approval with TTL.
type StandingRule struct {
	RuleID    string    // UUID for audit trail
	Effect    string    // "network_egress", "content_publish", etc.
	Pattern   string    // glob: "*.github.com", "/tmp/**"
	ExpiresAt time.Time // TTL (default: 30 min or session end)
	GrantedAt time.Time // when rule was created
	GrantedBy string    // approver identifier for audit
}

// SessionSnapshot is a point-in-time read of session state for sink enforcement.
type SessionSnapshot struct {
	SessionID     string
	Label         aegis.SecurityLabel
	IsTainted     bool
	ApprovalState ApprovalState
	StandingRules []StandingRule // defensive copy
}

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
// Fields are accessed only via atomic primitives or under mutex protection.
type sessionData struct {
	// === LABEL STATE (existing fields — unchanged) ===
	label   atomic.Uint64 // packed current label — CAS-updated by Elevate only
	ceiling atomic.Uint64 // packed ceiling; 0 = not yet set (treated as maxUint64Label)
	state   atomic.Uint32 // monotone state ordinal (see stateOrdinal* constants)

	// === APPROVAL STATE (new — atomic because single-value enum) ===
	approvalState atomic.Uint32 // ApprovalState enum

	// === STANDING RULES (new — mutex-protected) ===
	rulesMu       sync.RWMutex
	standingRules []StandingRule
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

// Snapshot returns a point-in-time SessionSnapshot for sink enforcement.
//
// ATOMICITY GUARANTEE: This is NOT a single atomic read. It performs three
// separate reads: label, approvalState, and standingRules (under RLock).
// TAINT SAFETY: Snapshot() is called AFTER maybeTaint() in the evaluation pipeline.
func (s *SessionLabels) Snapshot(sessionID string) SessionSnapshot {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return SessionSnapshot{
			SessionID:     sessionID,
			Label:         aegis.SecurityLabel{},
			IsTainted:     false,
			ApprovalState: ApprovalNone,
			StandingRules: nil,
		}
	}
	entry := v.(*sessionData)

	label := unpackLabel(entry.label.Load())
	isTainted := (label.Category & TaintBit) != 0
	approvalState := ApprovalState(entry.approvalState.Load())

	entry.rulesMu.RLock()
	rules := make([]StandingRule, len(entry.standingRules))
	copy(rules, entry.standingRules)
	entry.rulesMu.RUnlock()

	return SessionSnapshot{
		SessionID:     sessionID,
		Label:         label,
		IsTainted:     isTainted,
		ApprovalState: approvalState,
		StandingRules: rules,
	}
}

// IsTainted returns true if the session has TaintBit set in its category.
// Fast path for callers that only need the taint bit.
func (s *SessionLabels) IsTainted(sessionID string) bool {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return false
	}
	label := unpackLabel(v.(*sessionData).label.Load())
	return (label.Category & TaintBit) != 0
}

// SetApprovalState updates the session's approval state.
func (s *SessionLabels) SetApprovalState(sessionID string, state ApprovalState) {
	entry := s.getOrCreate(sessionID)
	entry.approvalState.Store(uint32(state))
}

// AddStandingRule appends a standing approval rule and sets ApprovalState to StandingRule.
func (s *SessionLabels) AddStandingRule(sessionID string, rule StandingRule) {
	entry := s.getOrCreate(sessionID)

	entry.rulesMu.Lock()
	entry.standingRules = append(entry.standingRules, rule)
	entry.rulesMu.Unlock()

	// Transition to standing_rule state (idempotent if already there)
	for {
		old := entry.approvalState.Load()
		if ApprovalState(old) >= ApprovalStandingRule {
			return
		}
		if entry.approvalState.CompareAndSwap(old, uint32(ApprovalStandingRule)) {
			return
		}
	}
}

// MatchesStandingRule checks if any non-expired standing rule matches the effect and resource.
// Returns (true, &rule) on match, (false, nil) on no match.
func (s *SessionLabels) MatchesStandingRule(sessionID, effect, resource string) (bool, *StandingRule) {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return false, nil
	}
	entry := v.(*sessionData)

	now := time.Now()
	// Normalize: lowercase and strip trailing dot (DNS allows trailing dots)
	resource = strings.TrimSuffix(strings.ToLower(resource), ".")

	entry.rulesMu.RLock()
	defer entry.rulesMu.RUnlock()

	for i := range entry.standingRules {
		rule := &entry.standingRules[i]

		// Skip expired rules
		if now.After(rule.ExpiresAt) {
			continue
		}

		// Effect must match (exact match only)
		if rule.Effect != effect {
			continue
		}

		// Pattern matching
		pattern := strings.TrimSuffix(strings.ToLower(rule.Pattern), ".")
		if matchesPattern(pattern, resource) {
			return true, rule
		}
	}
	return false, nil
}

// matchesPattern implements glob semantics for standing rules.
func matchesPattern(pattern, target string) bool {
	// Exact match
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}

	// Domain wildcard: *.github.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		// Match "api.github.com" but NOT "evil.api.github.com"
		if strings.HasSuffix(target, suffix) {
			patternDots := strings.Count(suffix, ".")
			targetDots := strings.Count(target, ".")
			return targetDots == patternDots
		}
		// Also match exact domain: "*.github.com" matches "github.com"
		if target == pattern[2:] {
			return true
		}
		return false
	}

	// Path wildcard: /tmp/**
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(target, prefix)
	}

	// Single-character wildcard (basic glob): use filepath.Match
	matched, err := filepath.Match(pattern, target)
	return err == nil && matched
}

// PruneExpiredRules removes all expired standing rules from all sessions.
// If no rules remain for a session, ApprovalState transitions back to ApprovalNone.
func (s *SessionLabels) PruneExpiredRules() {
	now := time.Now()

	s.entries.Range(func(key, value any) bool {
		entry := value.(*sessionData)

		entry.rulesMu.Lock()
		// Filter out expired rules in-place
		n := 0
		for i := range entry.standingRules {
			if now.Before(entry.standingRules[i].ExpiresAt) {
				entry.standingRules[n] = entry.standingRules[i]
				n++
			}
		}
		entry.standingRules = entry.standingRules[:n]
		hasRules := n > 0
		entry.rulesMu.Unlock()

		// If no rules remain, demote ApprovalState to none (if currently standing_rule)
		if !hasRules {
			for {
				old := entry.approvalState.Load()
				if ApprovalState(old) != ApprovalStandingRule {
					break
				}
				if entry.approvalState.CompareAndSwap(old, uint32(ApprovalNone)) {
					break
				}
			}
		}
		return true
	})
}
