package bundle

import (
	"os"
	"strings"
	"testing"

	"github.com/mayankjain0141/nixis/internal/cel"
)

// TestP4Policy3_CloudMetadataDeny_ParsesCorrectly verifies that the semantic cloud
// metadata deny policy loads, parses as DENY (not REQUIRE_APPROVAL), and compiles
// via the CEL environment.
func TestP4Policy3_CloudMetadataDeny_ParsesCorrectly(t *testing.T) {
	path := "../../policies/builtin/semantic-categories.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("semantic-categories.yaml not found")
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}

	// Policy 3 is DENY — RequireApproval must be false.
	if binding.RequireApproval {
		t.Error("semantic-cloud-metadata-deny must be DENY, not REQUIRE_APPROVAL (RequireApproval=true)")
	}

	// Expression must contain the DENY negation wrapper: !(...)
	if !strings.HasPrefix(tmpl.Expression, "!(") {
		t.Errorf("DENY expression must start with !(...), got: %q", tmpl.Expression)
	}

	// Expression must reference resource semantic variables (not raw command strings).
	if !strings.Contains(tmpl.Expression, "resource_conf") && !strings.Contains(tmpl.Expression, "resource_type") {
		t.Errorf("expression must reference resource_conf or resource_type, got: %q", tmpl.Expression)
	}

	// Expression must compile in the CEL environment — this catches typos and
	// references to undeclared variables.
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	rawEnv := cel.RawEnv(celEnv)
	parsedAst, parseIssues := rawEnv.Parse(tmpl.Expression)
	if parseIssues != nil && parseIssues.Err() != nil {
		t.Fatalf("CEL parse failed: %v", parseIssues.Err())
	}
	_, checkIssues := rawEnv.Check(parsedAst)
	if checkIssues != nil && checkIssues.Err() != nil {
		t.Fatalf("CEL type-check failed: %v", checkIssues.Err())
	}
}

// TestP4Policy3_CloudMetadataDeny_ExpressionStructure verifies the combined DENY
// expression produced by buildCombinedExpression for the semantic-categories policy.
func TestP4Policy3_CloudMetadataDeny_ExpressionStructure(t *testing.T) {
	content := `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: semantic-cloud-metadata-deny
  annotations:
    nixis.io/default-enabled: "true"
    nixis.io/bundle: builtin
spec:
  description: "Deny exec operations targeting cloud metadata endpoints"
  validations:
    - expression: >-
        resource_type == "cloud_metadata" &&
        resource_conf >= 2000 &&
        effects.exists(e, e == "exec_process")
      message: "Exec targeting cloud metadata endpoint denied unconditionally — credential theft risk."
      action: DENY
  defaultAction: ALLOW
`
	dir := t.TempDir()
	path := dir + "/semantic-categories.yaml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}

	// DENY policy → RequireApproval must be false.
	if binding.RequireApproval {
		t.Error("DENY policy must not set RequireApproval=true")
	}

	// DENY expression is wrapped: !(original_expr).
	if !strings.HasPrefix(tmpl.Expression, "!(") || !strings.HasSuffix(tmpl.Expression, ")") {
		t.Errorf("DENY expression must be wrapped in !(...), got: %q", tmpl.Expression)
	}

	// The expression must compile in CEL.
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment: %v", err)
	}
	rawEnv := cel.RawEnv(celEnv)

	parsedAst, parseIssues := rawEnv.Parse(tmpl.Expression)
	if parseIssues != nil && parseIssues.Err() != nil {
		t.Fatalf("CEL parse error: %v", parseIssues.Err())
	}
	_, checkIssues := rawEnv.Check(parsedAst)
	if checkIssues != nil && checkIssues.Err() != nil {
		t.Fatalf("CEL type-check error: %v", checkIssues.Err())
	}

	t.Logf("Expression: %s", tmpl.Expression)
	t.Logf("RequireApproval: %v", binding.RequireApproval)
}
