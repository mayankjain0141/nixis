package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePolicyFile_Valid(t *testing.T) {
	content := `apiVersion: nixis.io/v1
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
	content := `apiVersion: nixis.io/v1
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
# imported from: agentwall via nixis policy import
apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-deny-policy
    annotations:
        nixis.io/imported-from: nixis-import-123.yaml
        nixis.io/severity: high
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
# imported from: rules via nixis policy import
apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-require-approval-policy
    annotations:
        nixis.io/falco-tags: maturity_incubating,host
        nixis.io/severity: low
        nixis.io/source-rule: Launch Suspicious Network Tool on Host
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
	content := `# IMPORT_TODO: mutate rule — Nixis does not mutate requests
# imported from: policies via nixis policy import
apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
    name: stub-audit-policy
    annotations:
        nixis.io/imported-from: nixis-import-456.yaml
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
	content := `apiVersion: nixis.io/v1
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

// TestParsePolicyFile_NixisAnnotations verifies that nixis.io/* and third-party
// annotations (kyverno.io/*, nixis.io/falco-tags, etc.) do not cause parse errors.
func TestParsePolicyFile_NixisAnnotations(t *testing.T) {
	content := `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
    name: annotated-policy
    annotations:
        nixis.io/imported-from: nixis-import-789.yaml
        nixis.io/severity: high
        nixis.io/source: open-policy-agent/gatekeeper-library
        nixis.io/original-kind: K8sAllowedRepos
        nixis.io/falco-tags: maturity_stable,network,process
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

	policyContent := `apiVersion: nixis.io/v1
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

// TestParsePolicyFile_Params_ExtractsDefaults verifies that a policy with a params:
// section has its defaults resolved and stored in PolicyTemplate.Params.
func TestParsePolicyFile_Params_ExtractsDefaults(t *testing.T) {
	content := `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: params-policy
spec:
  description: "Policy with params"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: '!(targetPort in params.devPorts) && targetPort > 0'
      message: 'requires approval'
      action: REQUIRE_APPROVAL
  defaultAction: AUDIT
  params:
    devPorts:
      type: array
      default: [3000, 5173, 8080]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "params-policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, _, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}
	if tmpl.Params == nil {
		t.Fatal("expected non-nil Params, got nil")
	}
	devPorts, ok := tmpl.Params["devPorts"]
	if !ok {
		t.Fatal("expected devPorts in Params")
	}
	ports, ok := devPorts.([]any)
	if !ok {
		t.Fatalf("expected devPorts to be []any, got %T", devPorts)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	// Ports are stored as int64 after validation.
	want := []int64{3000, 5173, 8080}
	for i, p := range ports {
		n, ok := p.(int64)
		if !ok {
			t.Errorf("port[%d] is %T, want int64", i, p)
			continue
		}
		if n != want[i] {
			t.Errorf("port[%d] = %d, want %d", i, n, want[i])
		}
	}
}

// TestParsePolicyFile_Params_NoParams verifies that a policy without params:
// produces a nil Params field (no allocation for param-free policies).
func TestParsePolicyFile_Params_NoParams(t *testing.T) {
	content := `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: no-params-policy
spec:
  description: "No params"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'tool == "Bash"'
      action: DENY
`
	dir := t.TempDir()
	path := filepath.Join(dir, "no-params.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tmpl, _, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}
	if tmpl.Params != nil {
		t.Errorf("expected nil Params for policy without params:, got %v", tmpl.Params)
	}
}

// TestParsePolicyFile_Params_RejectsWellKnownPorts verifies that devPorts values
// below 1024 (well-known ports) cause ParsePolicyFile to return an error.
func TestParsePolicyFile_Params_RejectsWellKnownPorts(t *testing.T) {
	content := `apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: bad-ports-policy
spec:
  description: "Bad ports"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'true'
      action: AUDIT
  params:
    devPorts:
      type: array
      default: [443, 3000, 8080]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-ports.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := ParsePolicyFile(path)
	if err == nil {
		t.Fatal("expected error for well-known port 443, got nil")
	}
	if !strings.Contains(err.Error(), "well-known port") {
		t.Errorf("error message should mention 'well-known port', got: %v", err)
	}
}

// TestParsePolicyFile_DevPortCleanup_LoadsWithParams verifies that the real
// dev-port-cleanup builtin policy loads without error and has non-nil Params.
func TestParsePolicyFile_DevPortCleanup_LoadsWithParams(t *testing.T) {
	path := "../../policies/builtin/dev-port-cleanup.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("dev-port-cleanup.yaml not found")
	}

	tmpl, binding, err := ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if tmpl == nil || binding == nil {
		t.Fatal("expected non-nil template and binding")
	}
	if tmpl.Params == nil {
		t.Error("dev-port-cleanup should have non-nil Params (it declares devPorts)")
	}
	devPorts, ok := tmpl.Params["devPorts"]
	if !ok {
		t.Error("dev-port-cleanup Params should contain devPorts")
	}
	ports, ok := devPorts.([]any)
	if !ok || len(ports) == 0 {
		t.Errorf("devPorts should be a non-empty []any, got %T len=%d", devPorts, len(ports))
	}
}
