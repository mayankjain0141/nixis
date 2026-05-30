// SPDX-License-Identifier: MIT
package sink

import (
	"net"
	"strings"
	"time"

	"github.com/mayjain/nixis/internal/classify"
	"github.com/mayjain/nixis/internal/ifc"
	"github.com/mayjain/nixis/pkg/nixis"
)

// restrictedEffects are the effect types that require human approval when a
// session is tainted. R3: includes EffectContentInternal and EffectMessageContent
// to block SendMessage as an exfiltration vector.
var restrictedEffects = map[string]bool{
	classify.EffectNetworkEgress:       true,
	classify.EffectContentPublish:      true,
	classify.EffectProcessCoordination: true,
	classify.EffectContentInternal:     true, // SendMessage to another agent
	classify.EffectMessageContent:      true, // SendMessage message body
}

// IsRestrictedEffect reports whether the effect requires sink gating for tainted sessions.
func IsRestrictedEffect(effect string) bool {
	return restrictedEffects[effect]
}

// isExternal returns true if the resource refers to an external (non-private) host.
// Localhost, RFC-1918 ranges, link-local, and docker-internal are treated as internal.
// Justified by training cases T-LEG-086/087/088: localhost DB/cache access must be allowed
// even from a tainted session to preserve legitimate development workflows.
func isExternal(resource string) bool {
	r := resource
	for _, prefix := range []string{"https://", "http://", "ws://", "wss://", "ftp://", "ssh://"} {
		if strings.HasPrefix(r, prefix) {
			r = r[len(prefix):]
			break
		}
	}
	// Handle bracketed IPv6 before generic port/path stripping: [::1]:6379 → ::1
	if strings.HasPrefix(r, "[") {
		end := strings.Index(r, "]")
		if end > 0 {
			r = r[1:end]
		}
	} else {
		// Strip port, path, query, fragment for non-IPv6 hosts
		if idx := strings.IndexAny(r, "/:?#"); idx >= 0 {
			r = r[:idx]
		}
	}
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return false
	}
	if r == "localhost" || strings.HasSuffix(r, ".localhost") || r == "host.docker.internal" {
		return false
	}
	ip := net.ParseIP(r)
	if ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
	}
	return true // domain names: conservative, treat as external
}

func isExternalResource(resources []string) bool {
	for _, r := range resources {
		if isExternal(r) {
			return true
		}
	}
	return false
}

// Decision returns the sink enforcement action for a tainted session.
//
// snap must be obtained via sessions.Snapshot() for consistent taint+approval state.
// effects comes from VerdictEntry.Effects (adapter classification).
// resources is ALL extracted resource paths/URLs from LabeledRequest.ResourcePaths.
// containsNetworkCmd is true if a Bash command contains network-capable binaries.
//
// Returns:
//
//	ActionAllow — session not tainted, not a restricted sink, or internal resource
//	ActionDeny  — tainted session attempting external network egress without approval
func Decision(snap ifc.SessionSnapshot, effects []string, resources []string, containsNetworkCmd bool) nixis.Action {
	// INV-SINK-1: untainted session bypasses all sink enforcement
	if !snap.IsTainted {
		return nixis.ActionAllow
	}

	// INV-SINK-2: check if this operation requires gating
	if !isRestrictedSink(effects, containsNetworkCmd) {
		return nixis.ActionAllow
	}

	// INV-SINK-3: tainted session + restricted effect → check approval state
	switch snap.ApprovalState {
	case ifc.ApprovalSessionGranted:
		return nixis.ActionAllow
	case ifc.ApprovalStandingRule:
		if allResourcesCovered(snap.StandingRules, effects, resources) {
			return nixis.ActionAllow
		}
	case ifc.ApprovalPending:
		// Already waiting for user response — do not re-prompt.
	case ifc.ApprovalNone:
		// No approval granted.
	}

	// External resource from tainted session → deny (exfiltration risk).
	// Internal/localhost → allow (preserves legitimate local service access).
	// Unknown destination with network cmd → deny (conservative).
	if isExternalResource(resources) || (containsNetworkCmd && len(resources) == 0) {
		return nixis.ActionDeny
	}
	return nixis.ActionAllow
}

// isRestrictedSink returns true if any effect in the list is a restricted sink,
// or if the Bash command contains network-capable binaries.
func isRestrictedSink(effects []string, containsNetworkCmd bool) bool {
	if containsNetworkCmd {
		return true
	}
	for _, eff := range effects {
		if restrictedEffects[eff] {
			return true
		}
	}
	return false
}

// allResourcesCovered returns true if ALL resources are covered by at least one
// non-expired standing rule whose Effect matches an effect in the effects list.
//
// When resources is empty (unknown resource), returns false → RequireApproval.
func allResourcesCovered(rules []ifc.StandingRule, effects []string, resources []string) bool {
	if len(resources) == 0 {
		return false
	}
	for _, res := range resources {
		if !resourceMatchesAnyRule(rules, effects, res) {
			return false
		}
	}
	return true
}

// resourceMatchesAnyRule checks if a single resource matches at least one non-expired
// standing rule whose effect is in the effects list.
func resourceMatchesAnyRule(rules []ifc.StandingRule, effects []string, resource string) bool {
	now := time.Now()
	for _, rule := range rules {
		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			continue
		}
		if !effectMatches(rule.Effect, effects) {
			continue
		}
		if matchesPattern(rule.ResourcePattern, resource) {
			return true
		}
	}
	return false
}

// effectMatches reports whether ruleEffect appears in the effects list.
func effectMatches(ruleEffect string, effects []string) bool {
	for _, e := range effects {
		if e == ruleEffect {
			return true
		}
	}
	return false
}

// matchesPattern checks if resource matches the standing rule pattern.
//
// Patterns:
//   - "*.github.com"  single-level wildcard: matches "api.github.com", NOT "evil.api.github.com"
//   - "/tmp/**"       recursive path wildcard: matches "/tmp/foo/bar"
//   - exact string    matches exactly
//
// Both pattern and resource are lowercased before comparison.
func matchesPattern(pattern, resource string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	resource = strings.TrimSuffix(strings.ToLower(resource), ".")

	if !strings.Contains(pattern, "*") {
		return pattern == resource
	}

	// Domain wildcard: *.github.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		// Exact base domain: *.github.com matches github.com
		if resource == pattern[2:] {
			return true
		}
		// Single-level subdomain: count dots to enforce one wildcard level
		if strings.HasSuffix(resource, suffix) {
			return strings.Count(resource, ".") == strings.Count(suffix, ".")
		}
		return false
	}

	// Path recursive wildcard: /tmp/**
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(resource, prefix)
	}

	return false
}

// PatternMatches is exported for testing.
func PatternMatches(pattern, resource string) bool {
	return matchesPattern(pattern, resource)
}

// IsExternal is exported for testing.
func IsExternal(resource string) bool {
	return isExternal(resource)
}
