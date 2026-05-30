// SPDX-License-Identifier: MIT
// Package resource implements daemon-side trusted resource labeling for Nixis.
//
// The hook sends SecurityLabel{0,0,0} — it cannot be trusted to classify resources.
// This package derives SecurityLabel from the tool name and decoded arguments,
// giving the IFC layer actual objects to reason about.
//
// Hot path: Label() is called once per evaluation. It uses pre-compiled patterns
// and O(1) lookups — no allocations on the common path.
package resource

import (
	"github.com/mayjain/nixis/internal/ifc"
	"github.com/mayjain/nixis/pkg/nixis"
)

// ResourceLabeler derives a trusted SecurityLabel from a tool invocation.
// The daemon uses this instead of the caller-supplied SecurityLabel.
type ResourceLabeler interface {
	// Label derives the resource's SecurityLabel from the tool and its decoded arguments.
	// Returns the zero label for resources with no special sensitivity.
	Label(tool string, args map[string]any) nixis.SecurityLabel

	// IsSink returns true if the tool+args represent an exfiltration-capable sink
	// (external network, messaging, file write outside project scope).
	IsSink(tool string, args map[string]any) bool
}

// RuleBasedLabeler classifies resources using deterministic path/domain/tool rules.
// Immutable after construction — safe for concurrent use.
type RuleBasedLabeler struct {
	pathRules   []pathRule
	domainRules []domainRule
	toolSinks   map[string]bool
}

// NewRuleBasedLabeler constructs a labeler with the default rule set.
func NewRuleBasedLabeler() *RuleBasedLabeler {
	return &RuleBasedLabeler{
		pathRules:   defaultPathRules(),
		domainRules: defaultDomainRules(),
		toolSinks:   defaultToolSinks(),
	}
}

// Label derives a SecurityLabel from the tool invocation.
//
// Strategy:
//  1. Extract file paths from args (Read/Write path, Bash command targets)
//  2. Extract URLs/domains from args (WebFetch url, Bash curl/wget targets)
//  3. Return the highest-sensitivity label found across all extracted resources
func (r *RuleBasedLabeler) Label(tool string, args map[string]any) nixis.SecurityLabel {
	var result nixis.SecurityLabel

	paths := ExtractPaths(tool, args)
	for _, p := range paths {
		label := r.labelPath(p)
		result = elevateMax(result, label)
	}

	domains := ExtractDomains(tool, args)
	for _, d := range domains {
		label := r.labelDomain(d)
		result = elevateMax(result, label)
	}

	return result
}

// IsSink returns true if this tool+args combination represents an external sink
// that a tainted session should not be allowed to reach.
func (r *RuleBasedLabeler) IsSink(tool string, args map[string]any) bool {
	if r.toolSinks[tool] {
		return true
	}

	if tool == "Bash" {
		return r.isBashSink(args)
	}

	// MCP tools are external services
	if len(tool) > 5 && tool[:5] == "mcp__" {
		return true
	}

	return false
}

// labelPath returns the SecurityLabel for a file path based on pattern matching.
func (r *RuleBasedLabeler) labelPath(path string) nixis.SecurityLabel {
	for i := range r.pathRules {
		if r.pathRules[i].matches(path) {
			return r.pathRules[i].label
		}
	}
	return nixis.SecurityLabel{}
}

// labelDomain returns the SecurityLabel for a domain/URL based on pattern matching.
func (r *RuleBasedLabeler) labelDomain(domain string) nixis.SecurityLabel {
	for i := range r.domainRules {
		if r.domainRules[i].matches(domain) {
			return r.domainRules[i].label
		}
	}
	return nixis.SecurityLabel{}
}

// isBashSink checks if a Bash command targets an external network destination.
func (r *RuleBasedLabeler) isBashSink(args map[string]any) bool {
	cmd, ok := args["command"]
	if !ok {
		return false
	}
	cmdStr, ok := cmd.(string)
	if !ok {
		return false
	}
	return commandIsSink(cmdStr)
}

// elevateMax returns the label with maximum values in each dimension (same as session Elevate).
func elevateMax(a, b nixis.SecurityLabel) nixis.SecurityLabel {
	c := a.Confidentiality
	if b.Confidentiality > c {
		c = b.Confidentiality
	}
	i := a.Integrity
	if b.Integrity > i {
		i = b.Integrity
	}
	return nixis.SecurityLabel{
		Confidentiality: c,
		Integrity:       i,
		Category:        a.Category | b.Category,
	}
}

// IsSecretCategory returns true if the label's category bits include credentials or security keys.
// Used by the evaluation pipeline to trigger automatic session tainting.
func IsSecretCategory(label nixis.SecurityLabel) bool {
	return label.Category&(ifc.CatCredentials|ifc.CatSecurityKey) != 0
}

// compile-time interface check
var _ ResourceLabeler = (*RuleBasedLabeler)(nil)
