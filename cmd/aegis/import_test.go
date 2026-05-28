package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestImport_DetectsPolicyLayerFormat(t *testing.T) {
	input := `layerName: mcp-server-protection
description: MCP server integrity policies
policies:
  - id: pol-001
    name: Drift Detection Alert
    rule: tool_definition_changed
    action: deny
    severity: high
`

	format := detectFormat([]byte(input))
	if format != formatPolicyLayer {
		t.Errorf("expected formatPolicyLayer, got %v", format)
	}
}

func TestImport_DetectsGenericFormat(t *testing.T) {
	input := `policies:
  - id: "block-secrets"
    name: "Block secret writes"
    expression: '!args.content.contains("API_KEY=")'
    action: DENY
    tools: ["Write", "Edit"]
`

	format := detectFormat([]byte(input))
	if format != formatGeneric {
		t.Errorf("expected formatGeneric, got %v", format)
	}
}

func TestImport_DetectsUnknownFormat(t *testing.T) {
	input := `something: else
random: data
`
	format := detectFormat([]byte(input))
	if format != formatUnknown {
		t.Errorf("expected formatUnknown, got %v", format)
	}
}

func TestImport_TranslatesSimpleRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		wantCEL     string
		wantComment string
	}{
		{
			name:        "tool_definition_changed",
			rule:        "tool_definition_changed",
			wantCEL:     `tool.name != "" && tool.fingerprint != tool.expected_fingerprint`,
			wantComment: "",
		},
		{
			name:        "response_size_bytes gt",
			rule:        "response_size_bytes > 1048576",
			wantCEL:     "response.size > 1048576",
			wantComment: "IMPORT_TODO: response.size is a Phase 2 variable",
		},
		{
			name:        "response_size_bytes gte",
			rule:        "response_size_bytes >= 500000",
			wantCEL:     "response.size >= 500000",
			wantComment: "IMPORT_TODO: response.size is a Phase 2 variable",
		},
		{
			name:        "tool_name equals",
			rule:        `tool_name == "bash"`,
			wantCEL:     `tool == "bash"`,
			wantComment: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cel, comment := translateRule(tt.rule)
			if cel != tt.wantCEL {
				t.Errorf("CEL mismatch:\ngot:  %s\nwant: %s", cel, tt.wantCEL)
			}
			if tt.wantComment != "" && !strings.Contains(comment, tt.wantComment) {
				t.Errorf("comment should contain %q, got %q", tt.wantComment, comment)
			}
			if tt.wantComment == "" && comment != "" {
				t.Errorf("expected no comment, got %q", comment)
			}
		})
	}
}

func TestImport_UntranslatableRule(t *testing.T) {
	cel, comment := translateRule("complex_custom_function(foo, bar) && baz > 42")

	if cel != "false" {
		t.Errorf("untranslatable rule should produce 'false', got %q", cel)
	}

	if !strings.Contains(comment, "IMPORT_TODO") {
		t.Errorf("untranslatable rule should have IMPORT_TODO comment, got %q", comment)
	}
	if !strings.Contains(comment, "could not be automatically translated") {
		t.Errorf("comment should mention translation failure, got %q", comment)
	}
}

func TestImport_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "policies.yaml")
	outDir := filepath.Join(tmpDir, "output")

	input := `layerName: test-layer
policies:
  - id: test-pol
    name: Test Policy
    rule: tool_definition_changed
    action: deny
    severity: high
    description: A test policy
`
	if err := os.WriteFile(sourcePath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	manifests, comments, err := convertPolicyLayer([]byte(input), sourcePath)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}

	var stdout bytes.Buffer
	testCmd := &cobra.Command{}
	testCmd.SetOut(&stdout)

	importDryRun = true
	importOutDir = outDir
	defer func() {
		importDryRun = false
		importOutDir = "./policies/imported"
	}()

	if err := printDryRun(testCmd, manifests, comments); err != nil {
		t.Fatalf("printDryRun failed: %v", err)
	}

	output := stdout.String()

	if !strings.Contains(output, "apiVersion: aegis.io/v1") {
		t.Error("dry-run output should contain apiVersion")
	}
	if !strings.Contains(output, "kind: PolicyTemplate") {
		t.Error("dry-run output should contain kind")
	}
	if !strings.Contains(output, "test-pol") {
		t.Error("dry-run output should contain policy ID")
	}
	if !strings.Contains(output, "dry-run: would create") {
		t.Error("dry-run output should indicate no files written")
	}

	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Error("dry-run should not create output directory")
	}
}

func TestImport_WritesOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "policies.yaml")
	outDir := filepath.Join(tmpDir, "imported")

	input := `policies:
  - id: "gen-pol-1"
    name: "Generic Policy One"
    expression: 'tool == "Bash"'
    action: DENY
  - id: "gen-pol-2"
    name: "Generic Policy Two"
    expression: 'args.count > 10'
    action: AUDIT
`
	if err := os.WriteFile(sourcePath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	manifests, comments, err := convertGeneric([]byte(input), sourcePath)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}

	importOutDir = outDir
	defer func() {
		importOutDir = "./policies/imported"
	}()

	var stdout bytes.Buffer
	testCmd := &cobra.Command{}
	testCmd.SetOut(&stdout)

	if err := writeManifests(testCmd, manifests, comments, sourcePath); err != nil {
		t.Fatalf("writeManifests failed: %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 files, got %d", len(entries))
	}

	fileNames := make(map[string]bool)
	for _, e := range entries {
		fileNames[e.Name()] = true
	}

	if !fileNames["gen-pol-1.yaml"] {
		t.Error("missing gen-pol-1.yaml")
	}
	if !fileNames["gen-pol-2.yaml"] {
		t.Error("missing gen-pol-2.yaml")
	}

	content, err := os.ReadFile(filepath.Join(outDir, "gen-pol-1.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "# imported from:") {
		t.Error("generated file should have import comment header")
	}
	if !strings.Contains(contentStr, "apiVersion: aegis.io/v1") {
		t.Error("generated file should have apiVersion")
	}
	if !strings.Contains(contentStr, "action: DENY") {
		t.Error("generated file should have correct action")
	}
}

func TestImport_PolicyLayerConversion(t *testing.T) {
	input := `layerName: mcp-server-protection
description: MCP server integrity policies
policies:
  - id: pol-001
    name: Drift Detection Alert
    rule: tool_definition_changed
    action: deny
    severity: high
    description: Alert on MCP tool definition changes
  - id: pol-002
    name: Oversized Response
    rule: response_size_bytes > 1048576
    action: audit
    severity: low
`

	manifests, comments, err := convertPolicyLayer([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	m1 := manifests[0]
	if m1.Metadata.Name != "pol-001" {
		t.Errorf("first policy ID: got %s, want pol-001", m1.Metadata.Name)
	}
	if m1.Spec.Validations[0].Action != "DENY" {
		t.Errorf("first policy action: got %s, want DENY", m1.Spec.Validations[0].Action)
	}
	if !strings.Contains(m1.Spec.Validations[0].Expression, "tool.fingerprint") {
		t.Errorf("first policy should translate tool_definition_changed")
	}
	if comments[0] != "" {
		t.Errorf("tool_definition_changed should not have comment, got %q", comments[0])
	}

	m2 := manifests[1]
	if m2.Metadata.Name != "pol-002" {
		t.Errorf("second policy ID: got %s, want pol-002", m2.Metadata.Name)
	}
	if m2.Spec.Validations[0].Action != "AUDIT" {
		t.Errorf("second policy action: got %s, want AUDIT", m2.Spec.Validations[0].Action)
	}
	if !strings.Contains(comments[1], "IMPORT_TODO") {
		t.Errorf("response_size rule should have IMPORT_TODO, got %q", comments[1])
	}
}

func TestImport_GenericConversion(t *testing.T) {
	input := `policies:
  - id: "block-secrets"
    name: "Block secret writes"
    expression: '!args.content.contains("API_KEY=")'
    action: DENY
    tools: ["Write", "Edit"]
    severity: high
`

	manifests, comments, err := convertGeneric([]byte(input), "generic.yaml")
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m.APIVersion != "aegis.io/v1" {
		t.Errorf("apiVersion: got %s, want aegis.io/v1", m.APIVersion)
	}
	if m.Kind != "PolicyTemplate" {
		t.Errorf("kind: got %s, want PolicyTemplate", m.Kind)
	}
	if m.Metadata.Name != "block-secrets" {
		t.Errorf("name: got %s, want block-secrets", m.Metadata.Name)
	}

	tools := m.Spec.MatchConstraints.Tools
	if len(tools) != 2 || tools[0] != "Write" || tools[1] != "Edit" {
		t.Errorf("tools: got %v, want [Write Edit]", tools)
	}

	if m.Spec.Validations[0].Expression != `!args.content.contains("API_KEY=")` {
		t.Errorf("expression not preserved: got %s", m.Spec.Validations[0].Expression)
	}

	if comments[0] != "" {
		t.Errorf("generic policy should not have comment, got %q", comments[0])
	}
}

func TestImport_NormalizeAction(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"deny", "DENY"},
		{"DENY", "DENY"},
		{"Deny", "DENY"},
		{"audit", "AUDIT"},
		{"AUDIT", "AUDIT"},
		{"allow", "ALLOW"},
		{"", "ALLOW"},
		{"REQUIRE_APPROVAL", "REQUIRE_APPROVAL"},
	}

	for _, tt := range tests {
		got := normalizeAction(tt.input)
		if got != tt.want {
			t.Errorf("normalizeAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestImport_NormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"", "low"},
	}

	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
