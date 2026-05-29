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
// parses without a YAML error. Files that are valid YAML but not aegis PolicyTemplates
// (wrong kind/apiVersion) are accepted as returning (nil, nil, nil). Any non-nil error
// from ParsePolicyFile is reported as a failure.
func TestParsePolicyFile_AllImported(t *testing.T) {
	importedDir := "../../policies/imported"
	if _, err := os.Stat(importedDir); os.IsNotExist(err) {
		t.Skip("policies/imported directory not found")
	}

	var total, parsed, skipped, failed int
	var failures []string

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
		if template != nil && binding != nil {
			parsed++
		} else {
			skipped++ // valid YAML, not a PolicyTemplate (wrong kind/apiVersion)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	t.Logf("Total YAML files: %d | Parsed as PolicyTemplate: %d | Skipped (non-template): %d | Failures: %d",
		total, parsed, skipped, failed)

	for _, f := range failures {
		t.Error(f)
	}

	if failed > 0 {
		t.Fatalf("%d of %d imported policy files failed to parse", failed, total)
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
