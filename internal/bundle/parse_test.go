package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePolicyFile_Valid(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: test-policy
spec:
  description: "Test policy"
  matchConstraints:
    tools: ["Bash", "Write"]
  variables:
    - name: isTest
      expression: 'true'
  validations:
    - expression: 'bash.isGitForcePush(request.args.command)'
      message: 'Force push detected'
      action: DENY
  defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test-policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	template, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile failed: %v", err)
	}

	if template == nil {
		t.Fatal("expected template, got nil")
	}
	if binding == nil {
		t.Fatal("expected binding, got nil")
	}

	if template.ID != "test-policy" {
		t.Errorf("template.ID = %q, want %q", template.ID, "test-policy")
	}
	if template.Name != "test-policy" {
		t.Errorf("template.Name = %q, want %q", template.Name, "test-policy")
	}
	if template.Description != "Test policy" {
		t.Errorf("template.Description = %q, want %q", template.Description, "Test policy")
	}
	expectedExpr := `!(bash.isGitForcePush(args["command"]))`
	if template.Expression != expectedExpr {
		t.Errorf("template.Expression = %q, want %q", template.Expression, expectedExpr)
	}
	if template.SourceFile != path {
		t.Errorf("template.SourceFile = %q, want %q", template.SourceFile, path)
	}

	if binding.TemplateID != "test-policy" {
		t.Errorf("binding.TemplateID = %q, want %q", binding.TemplateID, "test-policy")
	}
	if len(binding.Scope.Tools) != 2 {
		t.Errorf("len(binding.Scope.Tools) = %d, want 2", len(binding.Scope.Tools))
	}
	if binding.Layer != "cel" {
		t.Errorf("binding.Layer = %q, want %q", binding.Layer, "cel")
	}
}

func TestParsePolicyFile_NonPolicy(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyBinding
metadata:
  name: not-a-template
`
	dir := t.TempDir()
	path := filepath.Join(dir, "binding.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	template, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile failed: %v", err)
	}

	if template != nil {
		t.Errorf("expected nil template for non-PolicyTemplate, got %+v", template)
	}
	if binding != nil {
		t.Errorf("expected nil binding for non-PolicyTemplate, got %+v", binding)
	}
}

func TestParsePolicyDir_LoadsBuiltin(t *testing.T) {
	builtinDir := "../../policies/builtin"
	if _, err := os.Stat(builtinDir); os.IsNotExist(err) {
		t.Skip("policies/builtin directory not found")
	}

	templates, bindings, err := ParsePolicyDir(builtinDir)
	if err != nil {
		t.Fatalf("ParsePolicyDir failed: %v", err)
	}

	if len(templates) == 0 {
		t.Error("expected at least one template, got none")
	}
	if len(bindings) == 0 {
		t.Error("expected at least one binding, got none")
	}
	if len(templates) != len(bindings) {
		t.Errorf("template count (%d) != binding count (%d)", len(templates), len(bindings))
	}

	t.Logf("Loaded %d policy templates from %s", len(templates), builtinDir)
	for _, tmpl := range templates {
		t.Logf("  - %s: %s", tmpl.ID, tmpl.Description)
	}
}

// TestParsePolicyFile_AllImported validates that every file under policies/imported/
// parses without a YAML error. Any non-nil error from ParsePolicyFile is a failure.
// Also validates that every file produces a non-nil template (not silently dropped).
func TestParsePolicyFile_AllImported(t *testing.T) {
	importedDir := "../../policies/imported"
	if _, err := os.Stat(importedDir); os.IsNotExist(err) {
		t.Skip("policies/imported directory not found")
	}

	var total, parsed, nilTemplate, failed int
	var failures, nilFiles []string

	err := filepath.WalkDir(importedDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		total++
		template, binding, parseErr := ParsePolicyFile(path)
		if parseErr != nil {
			failed++
			failures = append(failures, fmt.Sprintf("FAIL %s: %v", path, parseErr))
			return nil
		}
		if template == nil || binding == nil {
			nilTemplate++
			nilFiles = append(nilFiles, path)
		} else {
			parsed++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	t.Logf("Total YAML files: %d | Parsed as PolicyTemplate: %d | Nil (non-template/no-expr): %d | Errors: %d",
		total, parsed, nilTemplate, failed)

	for _, f := range failures {
		t.Error(f)
	}
	for _, f := range nilFiles {
		t.Errorf("policy file returned nil template (silently dropped): %s", f)
	}

	if failed > 0 || nilTemplate > 0 {
		t.Fatalf("%d parse errors and %d silently dropped files out of %d", failed, nilTemplate, total)
	}
}

// TestParsePolicyDir_ImportedCount calls ParsePolicyDir on policies/imported/ and
// asserts the loaded count equals the number of YAML files found by WalkDir.
func TestParsePolicyDir_ImportedCount(t *testing.T) {
	importedDir := "../../policies/imported"
	if _, err := os.Stat(importedDir); os.IsNotExist(err) {
		t.Skip("policies/imported directory not found")
	}

	// Count expected files via WalkDir (errors here skip non-critical entries)
	var expectedCount int
	if walkErr := filepath.WalkDir(importedDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			expectedCount++
		}
		return nil
	}); walkErr != nil {
		t.Fatalf("WalkDir count failed: %v", walkErr)
	}

	templates, bindings, err := ParsePolicyDir(importedDir)
	if err != nil {
		t.Fatalf("ParsePolicyDir failed: %v", err)
	}
	if len(templates) != len(bindings) {
		t.Errorf("template count (%d) != binding count (%d)", len(templates), len(bindings))
	}

	t.Logf("YAML files on disk: %d | Loaded as PolicyTemplate: %d", expectedCount, len(templates))

	if len(templates) != expectedCount {
		t.Errorf("ParsePolicyDir loaded %d templates, expected %d (one per YAML file)",
			len(templates), expectedCount)
	}
}

// TestParsePolicyFile_ImportTodoStub_DENY verifies that an IMPORT_TODO stub with
// action: DENY and expression: "false" is loaded as a real template. The stub
// expression !(false) evaluates to true (allow), making it a registered no-op
// that operators can see in the active policy list.
func TestParsePolicyFile_ImportTodoStub_DENY(t *testing.T) {
	content := `# IMPORT_TODO: unsupported schema type "object" — manual review required
# imported from: agentwall via aegis policy import
apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-deny-policy
    annotations:
        aegis.io/imported-from: aegis-import-123.yaml
        aegis.io/severity: high
spec:
    description: 'AgentWall constraint stub'
    matchConstraints:
        tools:
            - query_database
    validations:
        - expression: "false"
          message: AgentWall constraint violation
          action: DENY
    defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "stub-deny.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile error: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("DENY stub returned nil — policy silently dropped, operators cannot see it")
	}
	if tmpl.ID != "stub-deny-policy" {
		t.Errorf("ID = %q, want stub-deny-policy", tmpl.ID)
	}
	// expression: "false" under DENY → !(false) = always-allow stub
	if tmpl.Expression != "!(false)" {
		t.Errorf("Expression = %q, want !(false)", tmpl.Expression)
	}
	t.Logf("DENY stub loaded: id=%s expr=%s tools=%v", tmpl.ID, tmpl.Expression, binding.Scope.Tools)
}

// TestParsePolicyFile_ImportTodoStub_RequireApproval verifies stubs with REQUIRE_APPROVAL.
func TestParsePolicyFile_ImportTodoStub_RequireApproval(t *testing.T) {
	content := `# IMPORT_TODO: Falco kernel macro — manual review required
# imported from: rules via aegis policy import
apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-require-approval-policy
    annotations:
        aegis.io/falco-tags: maturity_incubating,host
        aegis.io/severity: low
        aegis.io/source-rule: Launch Suspicious Network Tool on Host
spec:
    description: |
        Detect network tools launched without filters.
        Host equivalent of the container rule.
    matchConstraints:
        tools:
            - Bash
    validations:
        - expression: "false"
          message: 'Falco rule violated: Launch Suspicious Network Tool on Host'
          action: REQUIRE_APPROVAL
    defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "stub-ra.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile error: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("REQUIRE_APPROVAL stub returned nil — policy silently dropped")
	}
	if tmpl.Expression != "!(false)" {
		t.Errorf("Expression = %q, want !(false)", tmpl.Expression)
	}
	// Multi-line description with | block scalar must be trimmed of trailing newline
	if strings.HasSuffix(tmpl.Description, "\n") {
		t.Errorf("Description has trailing newline: %q", tmpl.Description)
	}
	t.Logf("REQUIRE_APPROVAL stub loaded: id=%s expr=%s", tmpl.ID, tmpl.Expression)
}

// TestParsePolicyFile_ImportTodoStub_AUDIT verifies stubs with AUDIT action.
func TestParsePolicyFile_ImportTodoStub_AUDIT(t *testing.T) {
	content := `# IMPORT_TODO: mutate rule — Aegis does not mutate requests
# imported from: policies via aegis policy import
apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-audit-policy
    annotations:
        aegis.io/imported-from: aegis-import-456.yaml
        kyverno.io/category: Istio
spec:
    description: In order for Istio to include namespaces in ambient mode, the label must be set.
    matchConstraints:
        tools: []
    validations:
        - expression: "false"
          message: 'IMPORT_TODO: mutate rule'
          action: AUDIT
    defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "stub-audit.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile error: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("AUDIT stub returned nil — policy silently dropped")
	}
	if tmpl.Expression != "!(false)" {
		t.Errorf("Expression = %q, want !(false)", tmpl.Expression)
	}
	_ = binding
	t.Logf("AUDIT stub loaded: id=%s expr=%s tools=%v", tmpl.ID, tmpl.Expression, binding.Scope.Tools)
}

// TestParsePolicyFile_MultiLineDescription verifies that multi-line YAML block scalar
// descriptions (|) have trailing whitespace/newlines trimmed.
func TestParsePolicyFile_MultiLineDescription(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
    name: multi-line-desc-policy
spec:
    description: |
        First line of description.
        Second line with details.
        Third line trailing newline follows.
    matchConstraints:
        tools:
            - Bash
    validations:
        - expression: 'true'
          action: DENY
    defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "multi-line.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, _, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile error: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}
	if strings.HasSuffix(tmpl.Description, "\n") {
		t.Errorf("Description has trailing newline: %q", tmpl.Description)
	}
	if !strings.Contains(tmpl.Description, "First line") {
		t.Errorf("Description missing content: %q", tmpl.Description)
	}
}

// TestParsePolicyFile_AegisAnnotations verifies that aegis.io/* and third-party
// annotations (kyverno.io/*, aegis.io/falco-tags, etc.) do not cause parse errors.
func TestParsePolicyFile_AegisAnnotations(t *testing.T) {
	content := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
    name: annotated-policy
    annotations:
        aegis.io/imported-from: aegis-import-789.yaml
        aegis.io/severity: high
        aegis.io/source: open-policy-agent/gatekeeper-library
        aegis.io/original-kind: K8sAllowedRepos
        aegis.io/falco-tags: maturity_stable,network,process
        kyverno.io/category: Security
spec:
    description: Policy with many annotations
    matchConstraints:
        tools:
            - Bash
    validations:
        - expression: 'tool == "Bash"'
          action: DENY
    defaultAction: ALLOW
`
	dir := t.TempDir()
	path := filepath.Join(dir, "annotated.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile error: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}
	if tmpl.ID != "annotated-policy" {
		t.Errorf("ID = %q, want annotated-policy", tmpl.ID)
	}
}

func TestParsePolicyDir_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()

	readmeContent := "# Not a policy\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readmeContent), 0644); err != nil {
		t.Fatalf("failed to write README: %v", err)
	}

	policyContent := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: test-policy
spec:
  validations:
    - expression: 'true'
      action: DENY
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	templates, bindings, err := ParsePolicyDir(dir)
	if err != nil {
		t.Fatalf("ParsePolicyDir failed: %v", err)
	}

	if len(templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(templates))
	}
	if len(bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(bindings))
	}
}
