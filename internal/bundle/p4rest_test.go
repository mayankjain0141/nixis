package bundle

import (
	"os"
	"strings"
	"testing"

	"github.com/mayankjain0141/nixis/internal/cel"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
)

// celCompileCheck is a helper that parses and type-checks a CEL expression,
// failing the test if either step errors.
func celCompileCheck(t *testing.T, expr string) {
	t.Helper()
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	rawEnv := cel.RawEnv(celEnv)
	parsedAst, parseIssues := rawEnv.Parse(expr)
	if parseIssues != nil && parseIssues.Err() != nil {
		t.Fatalf("CEL parse failed for %q: %v", expr, parseIssues.Err())
	}
	_, checkIssues := rawEnv.Check(parsedAst)
	if checkIssues != nil && checkIssues.Err() != nil {
		t.Fatalf("CEL type-check failed for %q: %v", expr, checkIssues.Err())
	}
}

// parsePolicyByName loads the named policy from a multi-document YAML file using
// ParsePolicyFileAll and returns the matching template and binding.
func parsePolicyByName(t *testing.T, path, name string) (*policy_types.PolicyTemplate, *policy_types.PolicyBinding) {
	t.Helper()
	templates, bindings, err := ParsePolicyFileAll(path)
	if err != nil {
		t.Fatalf("ParsePolicyFileAll(%q): %v", path, err)
	}
	for i := range templates {
		if templates[i].ID == name {
			return &templates[i], &bindings[i]
		}
	}
	t.Fatalf("policy %q not found in %s (loaded %d policies)", name, path, len(templates))
	return nil, nil
}

// TestP4Policy1_CredentialExec_ParsesCorrectly verifies that semantic-credential-exec
// loads as REQUIRE_APPROVAL and references the label.hasCategory function with CatCredentials.
func TestP4Policy1_CredentialExec_ParsesCorrectly(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	tmpl, binding := parsePolicyByName(t, path, "semantic-credential-exec")

	if !binding.RequireApproval {
		t.Error("semantic-credential-exec must be REQUIRE_APPROVAL, not DENY (RequireApproval=false)")
	}

	if !strings.Contains(tmpl.Expression, "label.hasCategory") {
		t.Errorf("expression must use label.hasCategory, got: %q", tmpl.Expression)
	}

	if !strings.Contains(tmpl.Expression, "resource_cat") {
		t.Errorf("expression must reference resource_cat, got: %q", tmpl.Expression)
	}

	celCompileCheck(t, tmpl.Expression)
	t.Logf("semantic-credential-exec expression: %s", tmpl.Expression)
}

// TestP4Policy2_SecurityKeyAccess_ParsesCorrectly verifies that semantic-security-key-access
// loads as REQUIRE_APPROVAL and references label.hasCategory with CatSecurityKey.
func TestP4Policy2_SecurityKeyAccess_ParsesCorrectly(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	tmpl, binding := parsePolicyByName(t, path, "semantic-security-key-access")

	if !binding.RequireApproval {
		t.Error("semantic-security-key-access must be REQUIRE_APPROVAL (RequireApproval=false)")
	}

	if !strings.Contains(tmpl.Expression, "label.hasCategory") {
		t.Errorf("expression must use label.hasCategory, got: %q", tmpl.Expression)
	}

	// 1073741824 = CatSecurityKey = 1 << 30
	if !strings.Contains(tmpl.Expression, "1073741824") {
		t.Errorf("expression must reference CatSecurityKey (1073741824), got: %q", tmpl.Expression)
	}

	celCompileCheck(t, tmpl.Expression)
	t.Logf("semantic-security-key-access expression: %s", tmpl.Expression)
}

// TestP4Policy4_TaintedNetwork_ParsesCorrectly verifies that semantic-tainted-network-write
// loads as REQUIRE_APPROVAL, references categories (TaintBit), and exempts WebFetch/WebSearch.
func TestP4Policy4_TaintedNetwork_ParsesCorrectly(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	tmpl, binding := parsePolicyByName(t, path, "semantic-tainted-network-write")

	if !binding.RequireApproval {
		t.Error("semantic-tainted-network-write must be REQUIRE_APPROVAL (RequireApproval=false)")
	}

	if !strings.Contains(tmpl.Expression, "categories") {
		t.Errorf("expression must reference categories (session-level TaintBit check), got: %q", tmpl.Expression)
	}

	// 2147483648 = TaintBit = 1 << 31
	if !strings.Contains(tmpl.Expression, "2147483648") {
		t.Errorf("expression must reference TaintBit (2147483648), got: %q", tmpl.Expression)
	}

	// WebFetch and WebSearch must be exempted
	if !strings.Contains(tmpl.Expression, "WebFetch") || !strings.Contains(tmpl.Expression, "WebSearch") {
		t.Errorf("expression must exempt WebFetch and WebSearch, got: %q", tmpl.Expression)
	}

	celCompileCheck(t, tmpl.Expression)
	t.Logf("semantic-tainted-network-write expression: %s", tmpl.Expression)
}

// TestP4Policy5_CredentialWrite_ParsesCorrectly verifies that semantic-credential-write
// loads as REQUIRE_APPROVAL and has matchConstraints.tools = [Write, Edit].
func TestP4Policy5_CredentialWrite_ParsesCorrectly(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	tmpl, binding := parsePolicyByName(t, path, "semantic-credential-write")

	if !binding.RequireApproval {
		t.Error("semantic-credential-write must be REQUIRE_APPROVAL (RequireApproval=false)")
	}

	hasWrite := false
	hasEdit := false
	for _, tool := range binding.Scope.Tools {
		if tool == "Write" {
			hasWrite = true
		}
		if tool == "Edit" {
			hasEdit = true
		}
	}
	if !hasWrite || !hasEdit {
		t.Errorf("binding.Scope.Tools must contain Write and Edit, got: %v", binding.Scope.Tools)
	}

	if !strings.Contains(tmpl.Expression, "label.hasCategory") {
		t.Errorf("expression must use label.hasCategory, got: %q", tmpl.Expression)
	}

	celCompileCheck(t, tmpl.Expression)
	t.Logf("semantic-credential-write expression: %s | tools: %v", tmpl.Expression, binding.Scope.Tools)
}

// TestSemanticCategoriesFile_LoadsAllFivePolicies verifies that ParsePolicyFileAll
// loads all 5 policies (Policy 3 + Policies 1/2/4/5) from the multi-document YAML.
func TestSemanticCategoriesFile_LoadsAllFivePolicies(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	templates, bindings, err := ParsePolicyFileAll(path)
	if err != nil {
		t.Fatalf("ParsePolicyFileAll: %v", err)
	}
	if len(templates) != 5 {
		names := make([]string, len(templates))
		for i, tmpl := range templates {
			names[i] = tmpl.ID
		}
		t.Errorf("expected 5 policies in semantic-categories.yaml, got %d: %v", len(templates), names)
	}
	if len(templates) != len(bindings) {
		t.Errorf("template count (%d) != binding count (%d)", len(templates), len(bindings))
	}

	expected := map[string]bool{
		"semantic-cloud-metadata-deny":   false,
		"semantic-credential-exec":       false,
		"semantic-security-key-access":   false,
		"semantic-tainted-network-write": false,
		"semantic-credential-write":      false,
	}
	for _, tmpl := range templates {
		if _, ok := expected[tmpl.ID]; ok {
			expected[tmpl.ID] = true
		} else {
			t.Errorf("unexpected policy ID: %q", tmpl.ID)
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("policy %q not found in file", name)
		}
	}
}
