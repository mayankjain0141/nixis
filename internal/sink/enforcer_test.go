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

func TestIsExternal(t *testing.T) {
	tests := []struct {
		resource string
		want     bool
	}{
		// localhost variants → internal
		{"localhost", false},
		{"http://localhost", false},
		{"http://localhost:5432", false},
		{"http://localhost/path", false},
		{"foo.localhost", false},
		{"host.docker.internal", false},
		// loopback IPs → internal
		{"127.0.0.1", false},
		{"http://127.0.0.1:3306", false},
		{"::1", false},
		{"http://[::1]:6379", false},
		// RFC-1918 → internal
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		// link-local → internal
		{"169.254.1.1", false},
		// external domains → external
		{"github.com", true},
		{"evil.com", true},
		{"https://github.com/org/repo", true},
		// external IPs → external
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		// empty → not external (conservative: no resource = not a known external sink)
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			got := sink.IsExternal(tt.resource)
			if got != tt.want {
				t.Errorf("IsExternal(%q) = %v, want %v", tt.resource, got, tt.want)
			}
		})
	}
}

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

		// --- tainted + restricted effect + ApprovalNone + external resource → deny ---
		{
			name:      "tainted_network_egress_no_approval_external",
			snap:      ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"github.com"},
			want:      aegis.ActionDeny,
		},
		{
			name:      "tainted_content_publish_no_approval_external",
			snap:      ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:   []string{classify.EffectContentPublish},
			resources: []string{"evil.com"},
			want:      aegis.ActionDeny,
		},
		{
			name:      "tainted_process_coordination_no_approval_external",
			snap:      ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:   []string{classify.EffectProcessCoordination},
			resources: []string{"external.service.com"},
			want:      aegis.ActionDeny,
		},
		// internal/localhost effects (no specific external resource) → allow
		{
			name:    "tainted_content_internal_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectContentInternal},
			want:    aegis.ActionAllow,
		},
		{
			name:    "tainted_message_content_no_approval",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{classify.EffectMessageContent},
			want:    aegis.ActionAllow,
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
			want:      aegis.ActionDeny, // external resource not covered by rule → deny
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
			want:      aegis.ActionDeny, // external resource, effect mismatch → deny
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
			want:      aegis.ActionDeny, // external resource, expired rule → deny
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
			want:      aegis.ActionDeny, // evil.com is external and not covered → deny
		},
		{
			name: "tainted_empty_resources_no_network_cmd_allow",
			snap: ifc.SessionSnapshot{
				IsTainted:     true,
				ApprovalState: ifc.ApprovalStandingRule,
				StandingRules: []ifc.StandingRule{futureRule(classify.EffectNetworkEgress, "*.github.com")},
			},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{},
			want:      aegis.ActionAllow, // no external resource identified → allow (internal assumed)
		},

		// --- ApprovalPending + external resource → deny ---
		{
			name:      "tainted_approval_pending_external",
			snap:      ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalPending},
			effects:   []string{classify.EffectNetworkEgress},
			resources: []string{"external.com"},
			want:      aegis.ActionDeny,
		},
		// ApprovalPending + no external resource → allow (not exfiltration)
		{
			name:    "tainted_approval_pending_no_resource",
			snap:    ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalPending},
			effects: []string{classify.EffectNetworkEgress},
			want:    aegis.ActionAllow,
		},

		// --- containsNetworkCmd ---
		{
			name:               "tainted_bash_network_cmd_no_resources_deny",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{},
			want:               aegis.ActionDeny, // unknown destination + network cmd → conservative deny
		},
		{
			name:               "tainted_bash_network_cmd_localhost_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{"localhost"},
			want:               aegis.ActionAllow, // localhost → allow even with network cmd
		},
		{
			name:               "tainted_bash_network_cmd_external_deny",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{"evil.com"},
			want:               aegis.ActionDeny,
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

		// --- multiple effects, one restricted + external resource → deny ---
		{
			name: "tainted_multiple_effects_one_restricted_external",
			snap: ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects: []string{
				classify.EffectReadFiles,
				classify.EffectNetworkEgress,
				classify.EffectExecProcess,
			},
			resources: []string{"evil.com"},
			want:      aegis.ActionDeny,
		},

		// --- T-LEG-086/087/088: localhost DB/cache access — allow even in tainted session ---
		{
			name:               "tainted_localhost_psql_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{"localhost"},
			want:               aegis.ActionAllow,
		},
		{
			name:               "tainted_localhost_mysqldump_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{"localhost"},
			want:               aegis.ActionAllow,
		},
		{
			name:               "tainted_localhost_redis_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectExecProcess},
			containsNetworkCmd: true,
			resources:          []string{"localhost"},
			want:               aegis.ActionAllow,
		},

		// --- TestDecision_TaintedLocalhost_Allow: various internal hosts ---
		{
			name:               "tainted_127_0_0_1_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"127.0.0.1"},
			want:               aegis.ActionAllow,
		},
		{
			name:               "tainted_rfc1918_192_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"192.168.1.100"},
			want:               aegis.ActionAllow,
		},
		{
			name:               "tainted_docker_internal_allow",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"host.docker.internal"},
			want:               aegis.ActionAllow,
		},

		// --- TestDecision_TaintedExternal_Deny ---
		{
			name:               "tainted_external_github_deny",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"github.com"},
			want:               aegis.ActionDeny,
		},
		{
			name:               "tainted_external_evil_deny",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"evil.com"},
			want:               aegis.ActionDeny,
		},
		{
			name:               "tainted_external_ip_deny",
			snap:               ifc.SessionSnapshot{IsTainted: true, ApprovalState: ifc.ApprovalNone},
			effects:            []string{classify.EffectNetworkEgress},
			containsNetworkCmd: false,
			resources:          []string{"8.8.8.8"},
			want:               aegis.ActionDeny,
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
