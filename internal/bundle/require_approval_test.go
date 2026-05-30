// SPDX-License-Identifier: MIT
package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildCombinedExpression_DenyAction_ReturnsFalse(t *testing.T) {
	m := &policyManifest{}
	m.Spec.Validations = []struct {
		Expression string `yaml:"expression"`
		Message    string `yaml:"message"`
		Action     string `yaml:"action"`
	}{
		{Expression: `tool == "Bash"`, Action: "DENY"},
	}
	expr, requireApproval := buildCombinedExpression(m)
	if expr == "" {
		t.Fatal("expected non-empty expression")
	}
	if requireApproval {
		t.Errorf("DENY action should return requireApproval=false, got true")
	}
}

func TestBuildCombinedExpression_RequireApprovalAction_ReturnsTrue(t *testing.T) {
	m := &policyManifest{}
	m.Spec.Validations = []struct {
		Expression string `yaml:"expression"`
		Message    string `yaml:"message"`
		Action     string `yaml:"action"`
	}{
		{Expression: `tool == "Bash"`, Action: "REQUIRE_APPROVAL"},
	}
	expr, requireApproval := buildCombinedExpression(m)
	if expr == "" {
		t.Fatal("expected non-empty expression")
	}
	if !requireApproval {
		t.Errorf("REQUIRE_APPROVAL action should return requireApproval=true, got false")
	}
}

func TestBuildCombinedExpression_MixedActions_DenyTakesPrecedence(t *testing.T) {
	m := &policyManifest{}
	m.Spec.Validations = []struct {
		Expression string `yaml:"expression"`
		Message    string `yaml:"message"`
		Action     string `yaml:"action"`
	}{
		{Expression: `tool == "Write"`, Action: "DENY"},
		{Expression: `tool == "Bash"`, Action: "REQUIRE_APPROVAL"},
	}
	expr, requireApproval := buildCombinedExpression(m)
	if expr == "" {
		t.Fatal("expected non-empty expression")
	}
	if requireApproval {
		t.Errorf("DENY takes precedence over REQUIRE_APPROVAL; requireApproval should be false, got true")
	}
}

func TestParsePolicyFile_RequireApproval_SetsBinding(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: ra-policy
spec:
  description: "Require approval policy"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'tool == "Bash"'
      message: 'Bash requires approval'
      action: REQUIRE_APPROVAL
  defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ra-policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if binding == nil {
		t.Fatal("expected non-nil binding")
	}
	if !binding.RequireApproval {
		t.Errorf("binding.RequireApproval = false, want true for REQUIRE_APPROVAL policy")
	}
}

func TestParsePolicyFile_Message_PropagatedToBinding(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: msg-policy
spec:
  description: "Policy with message"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'tool == "Bash"'
      message: 'human readable message'
      action: DENY
  defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "msg-policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if binding == nil {
		t.Fatal("expected non-nil binding")
	}
	if binding.Message != "human readable message" {
		t.Errorf("binding.Message = %q, want %q", binding.Message, "human readable message")
	}
}
