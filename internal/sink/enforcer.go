// SPDX-License-Identifier: MIT
// Package sink implements sink enforcement for tainted sessions.
package sink

import (
	"strings"
	"time"

	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/aegis"
)

// restrictedEffects is the set of effects that require gating for tainted sessions.
// Includes SendMessage effects (EffectContentInternal, EffectMessageContent).
var restrictedEffects = map[string]bool{
	classify.EffectNetworkEgress:       true,
	classify.EffectContentPublish:      true,
	classify.EffectProcessCoordination: true,
	classify.EffectContentInternal:     true,
	classify.EffectMessageContent:      true,
}

// IsRestrictedEffect returns true if the effect requires sink gating.
func IsRestrictedEffect(effect string) bool {
	return restrictedEffects[effect]
}

// Decision returns the enforcement action for a tainted session attempting a sink operation.
//
// Parameters:
//   - snap: must be obtained via SessionLabels.Snapshot() for atomic state read
//   - effects: from VerdictEntry.Effects (adapter classification)
//   - resources: ALL canonical resource paths/URLs from tool args
//   - containsNetworkCmd: true if Bash command contains network-capable binaries
//
// Decision logic:
//  1. Untainted sessions (snap.IsTainted == false) -> Allow unconditionally
//  2. Tainted sessions with no restricted effect -> Allow
//  3. Tainted + restricted effect:
//     - ApprovalSessionGranted -> Allow
//     - ApprovalStandingRule + ALL resources match rules -> Allow
//     - Otherwise -> RequireApproval
func Decision(
	snap ifc.SessionSnapshot,
	effects []string,
	resources []string,
	containsNetworkCmd bool,
) aegis.Action {
	// INV-SINK-1: untainted session bypasses all sink enforcement
	if !snap.IsTainted {
		return aegis.ActionAllow
	}

	// INV-SINK-2: check if operation requires gating
	requiresGating := containsNetworkCmd
	if !requiresGating {
		for _, eff := range effects {
			if restrictedEffects[eff] {
				requiresGating = true
				break
			}
		}
	}
	if !requiresGating {
		return aegis.ActionAllow
	}

	// INV-SINK-3: tainted session + restricted effect -> check approval state
	switch snap.ApprovalState {
	case ifc.ApprovalNone:
		return aegis.ActionRequireApproval
	case ifc.ApprovalSessionGranted:
		return aegis.ActionAllow
	case ifc.ApprovalStandingRule:
		if matchesAllResources(snap.StandingRules, effects, resources) {
			return aegis.ActionAllow
		}
		return aegis.ActionRequireApproval
	case ifc.ApprovalPending:
		return aegis.ActionRequireApproval
	}
	// Unreachable: all ApprovalState values are handled above
	return aegis.ActionRequireApproval
}

// matchesAllResources returns true if ALL resources are covered by standing rules.
func matchesAllResources(rules []ifc.StandingRule, effects []string, resources []string) bool {
	// Empty resource list = unknown resource -> require approval
	if len(resources) == 0 {
		return false
	}

	// Every resource must match at least one non-expired rule
	for _, resource := range resources {
		if !resourceMatchesAnyRule(rules, effects, resource) {
			return false
		}
	}
	return true
}

// resourceMatchesAnyRule checks if a single resource matches any non-expired rule.
func resourceMatchesAnyRule(rules []ifc.StandingRule, effects []string, resource string) bool {
	now := time.Now()
	for _, rule := range rules {
		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			continue // expired
		}
		if !effectMatches(rule.Effect, effects) {
			continue
		}
		if PatternMatches(rule.Pattern, resource) {
			return true
		}
	}
	return false
}

// effectMatches returns true if the rule's effect is in the effects list.
func effectMatches(ruleEffect string, effects []string) bool {
	for _, e := range effects {
		if e == ruleEffect {
			return true
		}
	}
	return false
}

// PatternMatches checks if resource matches the rule pattern.
// Patterns:
//   - "*.github.com" matches "api.github.com", "raw.github.com"
//   - "/tmp/**" matches "/tmp/foo/bar"
//   - exact string matches exactly
func PatternMatches(pattern, resource string) bool {
	pattern = strings.ToLower(pattern)
	resource = strings.ToLower(resource)

	// Domain wildcard: *.github.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		return strings.HasSuffix(resource, suffix)
	}

	// Path wildcard: /tmp/**
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(resource, prefix)
	}

	// Exact match
	return pattern == resource
}

// FindRestrictedEffect returns the name of the first restricted effect found,
// or "network_egress" if containsNetworkCmd is true.
func FindRestrictedEffect(effects []string, containsNetworkCmd bool) string {
	if containsNetworkCmd {
		return classify.EffectNetworkEgress
	}
	for _, eff := range effects {
		if restrictedEffects[eff] {
			return eff
		}
	}
	return "unknown_sink"
}
