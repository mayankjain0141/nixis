// SPDX-License-Identifier: MIT
package ifc

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mayankjain0141/nixis/pkg/nixis"
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

// ApprovalState is the permission layer state machine.
// Transitions: none → pending → standing_rule → session_granted
// Backward transitions only occur on StandingRule expiration (standing_rule → none).
type ApprovalState uint32

const (
	ApprovalNone           ApprovalState = 0 // no approval granted
	ApprovalPending        ApprovalState = 1 // approval request shown to user, awaiting response
	ApprovalStandingRule   ApprovalState = 2 // one or more standing rules active
	ApprovalSessionGranted ApprovalState = 3 // blanket session approval ("allow all")
)

// StandingRule is a domain-scoped or path-scoped approval with TTL.
// Created when user grants approval for a pattern (e.g., "allow *.github.com").
type StandingRule struct {
	Effect          string    // "network_egress", "file_write", etc.
	ResourcePattern string    // glob: "*.github.com", "/tmp/**"
	ExpiresAt       time.Time // TTL (default: 30 min or session end)
	GrantedAt       time.Time // when rule was created
	GrantedBy       string    // approver identifier for audit
}

// SessionSnapshot is a point-in-time read of session state for sink enforcement.
// All fields are copied — mutations to the session do not affect the snapshot.
//
// ATOMICITY GUARANTEE: This is NOT a single atomic read. It performs three
// separate reads: label, approvalState, and standingRules (under RLock).
//
// KNOWN LIMITATION: A race exists where ApprovalState is granted
// between the TaintBit read and the ApprovalState read. This can cause ONE spurious
// REQUIRE_APPROVAL response when the user has just granted approval. This is an
// accepted limitation: the NEXT request from the same session will see the granted
// approval. This is a UX imperfection, not a security flaw.
type SessionSnapshot struct {
	Label         nixis.SecurityLabel
	IsTainted     bool
	ApprovalState ApprovalState
	StandingRules []StandingRule // defensive copy
}

// sessionData holds per-session mutable state.
// Fields are accessed only via atomic primitives or under mutex protection.
type sessionData struct {
	// === LABEL STATE (existing fields — unchanged) ===
	label   atomic.Uint64 // packed current label — CAS-updated by Elevate only
	ceiling atomic.Uint64 // packed ceiling; 0 = not yet set (treated as maxUint64Label)
	state   atomic.Uint32 // monotone state ordinal (see stateOrdinal* constants)

	// === APPROVAL STATE (new — atomic because single-value enum, read on hot path) ===
	// Written by declassification layer; read on sink enforcement path.
	approvalState atomic.Uint32 // ApprovalState enum

	// === STANDING RULES (new — mutex-protected because slice mutation is not atomic) ===
	// RWMutex: concurrent reads allowed during sink checks, exclusive on add/prune.
	rulesMu       sync.RWMutex
	standingRules []StandingRule

	// === PROJECT ROOT (immutable once set — first non-empty write wins) ===
	projectRoot     string    // filesystem root of the project; immutable after first set
	projectRootOnce sync.Once // ensures projectRoot is written exactly once
}

// SessionLabels is a concurrent-safe registry of per-session IFC labels.
//
// Label updates use a CAS retry loop (Elevate). Direct Store() on the label
// field is FORBIDDEN except in the CAS winner path.
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
// a stale lower one, silently downgrading the session.
//
// Returns the new (post-elevation) label.
func (s *SessionLabels) Elevate(sessionID string, resource nixis.SecurityLabel) nixis.SecurityLabel {
	entry := s.getOrCreate(sessionID)

	var result nixis.SecurityLabel
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
func (s *SessionLabels) Current(sessionID string) nixis.SecurityLabel {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return nixis.SecurityLabel{}
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
// to tainted_by_secret. Uses the CAS loop in Elevate.
func (s *SessionLabels) TaintWithSecret(sessionID string) nixis.SecurityLabel {
	return s.Elevate(sessionID, nixis.SecurityLabel{Category: TaintBit})
}

// InitWithCeiling initialises a new child session with label=zero and ceiling=parentLabel.
// Concurrent calls for the same sessionID are safe: the ceiling is written once
// via a CAS that only fires on a zero (unset) ceiling.
// If parentLabel is zero (unconstrained), the ceiling is set to maxUint64Label.
func (s *SessionLabels) InitWithCeiling(sessionID string, parentLabel nixis.SecurityLabel) {
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
func (s *SessionLabels) Ceiling(sessionID string) nixis.SecurityLabel {
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
func (s *SessionLabels) CheckCeiling(sessionID string, proposed nixis.SecurityLabel) bool {
	return Dominates(s.Ceiling(sessionID), proposed)
}

// markDeclassified advances the session state to declassified.
// The label itself is NOT modified — this is annotation-only.
func (s *SessionLabels) markDeclassified(sessionID string) {
	entry := s.getOrCreate(sessionID)
	advanceState(entry, stateOrdinalDeclassified)
}

// IsTainted returns true if the session's TaintBit category bit is set.
// This is a fast path for callers that only need the taint bit, not the full snapshot.
func (s *SessionLabels) IsTainted(sessionID string) bool {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return false
	}
	label := unpackLabel(v.(*sessionData).label.Load())
	return (label.Category & TaintBit) != 0
}

// Snapshot returns a point-in-time SessionSnapshot for sink enforcement.
//
// ATOMICITY GUARANTEE: This is NOT a single atomic read. It performs three
// separate reads: label, approvalState, and standingRules (under RLock).
// The snapshot may observe:
//   - label from time T1
//   - approvalState from time T2 (T2 >= T1)
//   - standingRules from time T3 (T3 >= T2)
//
// TAINT SAFETY: Snapshot() is called AFTER maybeTaint() in the evaluation pipeline.
// By the time Snapshot() runs, any taint from the current request's resource access
// is already committed to the session label. This guarantees read-your-writes
// consistency for the current request.
func (s *SessionLabels) Snapshot(sessionID string) SessionSnapshot {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return SessionSnapshot{
			Label:         nixis.SecurityLabel{},
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
		Label:         label,
		IsTainted:     isTainted,
		ApprovalState: approvalState,
		StandingRules: rules,
	}
}

// SetApprovalState updates the session's approval state.
// Transitions are NOT validated — caller must ensure forward-only progression.
// This method is called from declassification/approval handlers, not hot path.
func (s *SessionLabels) SetApprovalState(sessionID string, state ApprovalState) {
	entry := s.getOrCreate(sessionID)
	entry.approvalState.Store(uint32(state))
}

// AddStandingRule appends a standing approval rule and sets ApprovalState to ApprovalStandingRule.
// Uses a CAS loop to ensure ApprovalState only moves forward (never demotes SessionGranted).
func (s *SessionLabels) AddStandingRule(sessionID string, rule StandingRule) {
	entry := s.getOrCreate(sessionID)

	entry.rulesMu.Lock()
	entry.standingRules = append(entry.standingRules, rule)
	entry.rulesMu.Unlock()

	// Transition to standing_rule state (idempotent if already there or higher)
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
//
// GLOB SEMANTICS:
//   - "*.github.com" matches "api.github.com" but NOT "evil.api.github.com" (single-level wildcard)
//   - "*.github.com" also matches "github.com" (exact base domain)
//   - "/tmp/**" matches "/tmp/foo" and "/tmp/foo/bar" (recursive path wildcard)
//   - Exact strings match exactly
//
// Resource and pattern are lowercased and trailing dots are stripped before matching
// (handles trailing-dot DNS normalization).
func (s *SessionLabels) MatchesStandingRule(sessionID, effect, resource string) (bool, *StandingRule) {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return false, nil
	}
	entry := v.(*sessionData)

	now := time.Now()
	resource = strings.TrimSuffix(strings.ToLower(resource), ".")

	entry.rulesMu.RLock()
	defer entry.rulesMu.RUnlock()

	for i := range entry.standingRules {
		rule := &entry.standingRules[i]

		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			continue
		}

		if rule.Effect != effect {
			continue
		}

		pattern := strings.TrimSuffix(strings.ToLower(rule.ResourcePattern), ".")
		if matchesPattern(pattern, resource) {
			return true, rule
		}
	}
	return false, nil
}

// PruneExpiredRules removes all expired standing rules from all sessions.
// If no rules remain for a session, ApprovalState transitions back to ApprovalNone
// (only if it was ApprovalStandingRule — does not demote ApprovalSessionGranted).
//
// Must be invoked by a background goroutine in the daemon every 5 minutes.
func (s *SessionLabels) PruneExpiredRules() {
	now := time.Now()

	s.entries.Range(func(key, value any) bool {
		entry := value.(*sessionData)

		entry.rulesMu.Lock()
		n := 0
		for i := range entry.standingRules {
			if entry.standingRules[i].ExpiresAt.IsZero() || now.Before(entry.standingRules[i].ExpiresAt) {
				entry.standingRules[n] = entry.standingRules[i]
				n++
			}
		}
		entry.standingRules = entry.standingRules[:n]
		hasRules := n > 0
		entry.rulesMu.Unlock()

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

// SetProjectRoot sets the project root for a session if not already set.
// Idempotent — only the first call with a non-empty root takes effect.
// Subsequent calls (including concurrent ones) are no-ops.
func (s *SessionLabels) SetProjectRoot(sessionID, root string) {
	if root == "" {
		return
	}
	entry := s.getOrCreate(sessionID)
	entry.projectRootOnce.Do(func() {
		entry.projectRoot = root
	})
}

// ProjectRoot returns the project root for a session, or empty string if not set.
func (s *SessionLabels) ProjectRoot(sessionID string) string {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return ""
	}
	return v.(*sessionData).projectRoot
}

// matchesPattern implements our glob semantics for standing rule matching.
//
// Pattern and target must already be lowercased and trailing-dot-stripped by the caller.
func matchesPattern(pattern, target string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}

	// Domain wildcard: *.github.com
	// "*.github.com" matches "api.github.com" (one level) but NOT "evil.api.github.com" (two levels).
	// Also matches exact base "github.com".
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		// Exact base match: "*.github.com" matches "github.com"
		if target == pattern[2:] {
			return true
		}
		// Single-level subdomain: count dots to enforce exactly one level of wildcard
		if strings.HasSuffix(target, suffix) {
			patternDots := strings.Count(suffix, ".")
			targetDots := strings.Count(target, ".")
			return targetDots == patternDots
		}
		return false
	}

	// Path recursive wildcard: /tmp/**
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(target, prefix)
	}

	// Fallback: filepath.Match for single-character and bracket glob patterns
	matched, err := filepath.Match(pattern, target)
	return err == nil && matched
}
