// SPDX-License-Identifier: MIT
package sink_test

import (
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/sink"
	"github.com/mayjain/aegis/pkg/aegis"
)

func futureRule(effect, pattern string) ifc.StandingRule {
	return ifc.StandingRule{
		Effect:          effect,
		ResourcePattern: pattern,
		ExpiresAt:       time.Now().Add(time.Hour),
	}
}

func expiredRule(effect, pattern string) ifc.StandingRule {
	return ifc.StandingRule{
		Effect:          effect,
		ResourcePattern: pattern,
		ExpiresAt:       time.Now().Add(-time.Hour),
	}
}

func TestDecision(t *testing.T) {
	tests := []struct {
		name               string
		snap               ifc.SessionSnapshot
		effects            []string
		resources          []string
		containsNetworkCmd bool
		want               aegis.Action
	}{
		// --- untainted sessions always allow ---
		{
			name:    "untainted_any_restricted_effect",
			snap:    ifc.SessionSnapshot{IsTainted: false},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionAllow,
		},
		{
			name:    "fresh_session_zero_snapshot",
			snap:    ifc.SessionSnapshot{},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionAllow,
		},

		// --- tainted + non-restricted effects ---
		{
			name:    "tainted_read_files",
			snap:    ifc.SessionSnapshot{IsTainted: true},
			effects: []string{classify.EffectReadFiles},
			want:    aegis.ActionAllow,
		},
		{
			name:    "tainted_write_files",
			snap:    ifc.SessionSnapshot{IsTainted: true},
			effects: []string{classify.EffectWriteFiles},
			want:    aegis.ActionAllow,
		},
		{
			name:    "tainted_exec_process_no_network_cmd",
			snap:    ifc.SessionSnapshot{IsTainted: true},
			effects: []string{classify.EffectExecProcess},
			want:    aegis.ActionAllow,
		},

		// --- tainted + restricted effect + ApprovalNone ---
		{
			name:    "tainted_network_egress_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionRequireApproval,
		},
		{
			name:    "tainted_content_publish_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectContentPublish},
			want:    aegis.ActionRequireApproval,
		},
		{
			name:    "tainted_process_coordination_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectProcessCoordination},
			want:    aegis.ActionRequireApproval,
		},
		{
			name:    "tainted_content_internal_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectContentInternal},
			want:    aegis.ActionRequireApproval,
		},
		{
			name:    "tainted_message_content_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectMessageContent},
			want:    aegis.ActionRequireApproval,
		},

		// --- tainted + ApprovalSessionGranted ---
		{
			name:    "tainted_network_egress_session_granted",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalSessionGranted},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionAllow,
		},
		{
			name:    "tainted_content_publish_session_granted",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalSessionGranted},
			effects: []string{classify.EffectContentPublish},
			want:    aegis.ActionAllow,
		},

		// --- tainted + ApprovalStandingRule + single resource ---
		{
			name: "tainted_standing_rule_domain_match",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"api.github.com"},
			want:      aegis.ActionAllow,
		},
		{
			name: "tainted_standing_rule_domain_mismatch",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"evil.com"},
			want:      aegis.ActionRequireApproval,
		},
		{
			name: "tainted_standing_rule_effect_mismatch",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectContentPublish},
			resources: []string{"api.github.com"},
			want:      aegis.ActionRequireApproval,
		},
		{
			name: "tainted_standing_rule_expired",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{expiredRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"api.github.com"},
			want:      aegis.ActionRequireApproval,
		},

		// --- tainted + multi-resource ---
		{
			name: "tainted_standing_rule_multi_resource_all_match",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"api.github.com", "raw.github.com"},
			want:      aegis.ActionAllow,
		},
		{
			name: "tainted_standing_rule_multi_resource_partial_match",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"api.github.com", "evil.com"},
			want:      aegis.ActionRequireApproval,
		},
		{
			name: "tainted_empty_resources_require_approval",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{},
			want:      aegis.ActionRequireApproval,
		},

		// --- ApprovalPending ---
		{
			name:    "tainted_approval_pending_no_double_prompt",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalPending},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionRequireApproval,
		},

		// --- containsNetworkCmd ---
		{
			name:               "tainted_bash_network_cmd_triggers_gating",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			want:               aegis.ActionRequireApproval,
		},
		{
			name:               "tainted_bash_no_network_cmd_allowed",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: false,
			want:               aegis.ActionAllow,
		},
		{
			name:               "untainted_bash_network_cmd_allowed",
			snap:               ifc.SessionSnapshot{IsTainted: false},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			want:               aegis.ActionAllow,
		},

		// --- multiple effects, one restricted ---
		{
			name: "tainted_multiple_effects_one_restricted",
			snap: ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{
				classify.EffectReadFiles,
				classify.EffectNetworkEgress,
				classify.EffectExecProcess,
			},
			want: aegis.ActionRequireApproval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sink.Decision(tt.snap, tt.effects, tt.resources, tt.containsNetworkCmd)
			if got != tt.want {
				t.Errorf("Decision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		pattern  string
		resource string
		want     bool
	}{
		// domain wildcard — single level
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "raw.github.com", true},
		{"*.github.com", "github.com", true},           // exact base domain also matches
		{"*.github.com", "evil.api.github.com", false}, // two levels — no match
		{"*.github.com", "notgithub.com", false},
		{"*.github.com", "API.GITHUB.COM", true}, // case-insensitive
		{"*.github.com", "raw.githubusercontent.com", false},

		// path wildcard
		{"/tmp/**", "/tmp/foo", true},
		{"/tmp/**", "/tmp/foo/bar/baz", true},
		{"/tmp/**", "/var/tmp/foo", false},

		// exact match
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "raw.github.com", false},

		// edge cases
		{"", "", true},
		{"", "something", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"__"+tt.resource, func(t *testing.T) {
			got := sink.PatternMatches(tt.pattern, tt.resource)
			if got != tt.want {
				t.Errorf("PatternMatches(%q, %q) = %v, want %v", tt.pattern, tt.resource, got, tt.want)
			}
		})
	}
}

func TestIsRestrictedEffect(t *testing.T) {
	restricted := []string{
		classify.EffectNetworkEgress,
		classify.EffectContentPublish,
		classify.EffectProcessCoordination,
		classify.EffectContentInternal,
		classify.EffectMessageContent,
	}
	for _, eff := range restricted {
		if !sink.IsRestrictedEffect(eff) {
			t.Errorf("IsRestrictedEffect(%q) = false, want true", eff)
		}
	}

	nonRestricted := []string{
		classify.EffectReadFiles,
		classify.EffectWriteFiles,
		classify.EffectExecProcess,
		classify.EffectStateChange,
		classify.EffectCredentialUse,
	}
	for _, eff := range nonRestricted {
		if sink.IsRestrictedEffect(eff) {
			t.Errorf("IsRestrictedEffect(%q) = true, want false", eff)
		}
	}
}
