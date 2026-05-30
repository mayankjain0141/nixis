// SPDX-License-Identifier: MIT
package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mayankjain0141/nixis/internal/cel"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
)

const bashUnmatchedNetworkCmdYAML = `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: bash-unmatched-network-cmd
  annotations:
    nixis.io/default-enabled: "true"
    nixis.io/bundle: builtin
spec:
  description: "Require approval when unrecognized Bash command uses a network-capable binary (excludes plain git commands)"
  matchConstraints:
    tools: ["Bash"]
  variables:
    - name: isGitOnly
      expression: >-
        has(args.command) && args.command.startsWith("git ")
  validations:
    - expression: '!resource_matched && resource_network_cmd && !isGitOnly'
      message: 'Unrecognized Bash command with network capability requires approval (unknown target domain/path)'
      action: REQUIRE_APPROVAL
  defaultAction: ALLOW
`

const readUnmatchedSensitivePathYAML = `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: read-unmatched-sensitive-path
  annotations:
    nixis.io/default-enabled: "true"
    nixis.io/bundle: builtin
spec:
  description: "Require approval for Read on unrecognized paths matching credential file name patterns"
  matchConstraints:
    tools: ["Read"]
  variables:
    - name: looksSensitive
      expression: >-
        has(args.file_path) &&
        args.file_path.matches(".*(shadow|passwd|authorized_keys|id_rsa|id_ed25519|id_ecdsa|id_dsa|\\.pem|\\.key|\\.pfx|\\.p12|\\.jks|client_secret|service_account.*\\.json|\\.gnupg|credentials\\.json).*")
  validations:
    - expression: '!resource_matched && looksSensitive'
      message: 'Reading an unrecognized file matching a credential file name pattern requires approval'
      action: REQUIRE_APPROVAL
  defaultAction: ALLOW
`

const bashUnmatchedLongCommandYAML = `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: bash-unmatched-long-command
  annotations:
    nixis.io/default-enabled: "true"
    nixis.io/bundle: builtin
spec:
  description: "Require approval for unusually long unrecognized Bash commands — possible obfuscation"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: '!resource_matched && has(args.command) && size(args.command) > 1000'
      message: 'Unusually long unrecognized Bash command requires approval — possible obfuscation or encoded payload'
      action: REQUIRE_APPROVAL
  defaultAction: ALLOW
`

func celCompiles(t *testing.T, expr string) {
	t.Helper()
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	rawEnv := cel.RawEnv(celEnv)
	parsedAst, parseIssues := rawEnv.Parse(expr)
	if parseIssues != nil && parseIssues.Err() != nil {
		t.Fatalf("CEL parse failed: %v", parseIssues.Err())
	}
	_, checkIssues := rawEnv.Check(parsedAst)
	if checkIssues != nil && checkIssues.Err() != nil {
		t.Fatalf("CEL type-check failed: %v", checkIssues.Err())
	}
}

func writeTempPolicy(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
}

// TestP5Policy1_BashUnmatchedNetwork_ParsesCorrectly verifies that bash-unmatched-network-cmd
// parses as REQUIRE_APPROVAL with a non-empty, CEL-valid expression.
func TestP5Policy1_BashUnmatchedNetwork_ParsesCorrectly(t *testing.T) {
	path := writeTempPolicy(t, "bash-unmatched-network-cmd", bashUnmatchedNetworkCmdYAML)
	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}

	if !binding.RequireApproval {
		t.Error("bash-unmatched-network-cmd must be REQUIRE_APPROVAL (RequireApproval=true)")
	}
	if tmpl.Expression == "" {
		t.Error("expression must be non-empty")
	}

	celCompiles(t, tmpl.Expression)
}

// TestP5Policy2_ReadUnmatchedSensitive_ParsesCorrectly verifies that read-unmatched-sensitive-path
// parses as REQUIRE_APPROVAL with scope targeting the Read tool.
func TestP5Policy2_ReadUnmatchedSensitive_ParsesCorrectly(t *testing.T) {
	path := writeTempPolicy(t, "read-unmatched-sensitive-path", readUnmatchedSensitivePathYAML)
	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}

	if !binding.RequireApproval {
		t.Error("read-unmatched-sensitive-path must be REQUIRE_APPROVAL (RequireApproval=true)")
	}

	hasRead := false
	for _, tool := range binding.Scope.Tools {
		if tool == "Read" {
			hasRead = true
			break
		}
	}
	if !hasRead {
		t.Errorf("Scope.Tools must contain 'Read', got %v", binding.Scope.Tools)
	}

	celCompiles(t, tmpl.Expression)
}

// TestP5Policy3_BashLongCommand_ParsesCorrectly verifies that bash-unmatched-long-command
// parses as REQUIRE_APPROVAL with a non-empty, CEL-valid expression.
func TestP5Policy3_BashLongCommand_ParsesCorrectly(t *testing.T) {
	path := writeTempPolicy(t, "bash-unmatched-long-command", bashUnmatchedLongCommandYAML)
	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}

	if !binding.RequireApproval {
		t.Error("bash-unmatched-long-command must be REQUIRE_APPROVAL (RequireApproval=true)")
	}
	if tmpl.Expression == "" {
		t.Error("expression must be non-empty")
	}

	celCompiles(t, tmpl.Expression)
}

// TestP5_AllThreePolicies_LoadWithoutError verifies that all 3 P5 policies parse without
// errors and produce valid templates. Each policy is parsed individually (ifc-fallback.yaml
// is a multi-document YAML; ParsePolicyDir reads only the first document per file).
func TestP5_AllThreePolicies_LoadWithoutError(t *testing.T) {
	policies := []struct {
		name    string
		content string
	}{
		{"bash-unmatched-network-cmd", bashUnmatchedNetworkCmdYAML},
		{"read-unmatched-sensitive-path", readUnmatchedSensitivePathYAML},
		{"bash-unmatched-long-command", bashUnmatchedLongCommandYAML},
	}

	dir := t.TempDir()
	for _, p := range policies {
		path := filepath.Join(dir, p.name+".yaml")
		if err := os.WriteFile(path, []byte(p.content), 0644); err != nil {
			t.Fatalf("write %s: %v", p.name, err)
		}
	}

	templates, _, err := ParsePolicyDir(dir)
	if err != nil {
		t.Fatalf("ParsePolicyDir: %v", err)
	}

	wantNames := []string{
		"bash-unmatched-network-cmd",
		"read-unmatched-sensitive-path",
		"bash-unmatched-long-command",
	}

	found := make(map[string]bool)
	for _, tmpl := range templates {
		found[tmpl.Name] = true
	}

	for _, name := range wantNames {
		if !found[name] {
			t.Errorf("policy %q not found after loading dir; found: %v", name, allNames(templates))
		}
	}
}

func allNames(templates []policy_types.PolicyTemplate) []string {
	names := make([]string, len(templates))
	for i, t := range templates {
		names[i] = t.Name
	}
	return names
}
