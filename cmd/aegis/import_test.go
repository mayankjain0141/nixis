package main

import (
	"archive/zip"
	"bytes"
	"fmt"
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

// ---- settings.json tests ----

func TestImport_DetectsSettingsJSON(t *testing.T) {
	input := `{
	  "permissions": {
	    "allow": ["Bash(npm run test *)"],
	    "deny": ["Bash(curl *)", "Read(./.env)", "WebFetch"]
	  }
	}`

	format := detectFormatWithName("settings.json", []byte(input))
	if format != formatSettingsJSON {
		t.Errorf("expected formatSettingsJSON, got %v", format)
	}
}

func TestImport_DetectsSettingsJSONByContent(t *testing.T) {
	// Even without settings.json filename, JSON with permissions.deny should detect
	input := `{"permissions":{"deny":["Bash(rm -rf *)"],"allow":[]}}`

	format := detectFormatWithName("project-config.json", []byte(input))
	if format != formatSettingsJSON {
		t.Errorf("expected formatSettingsJSON by content, got %v", format)
	}
}

func TestImport_TranslatesSettingsJSONDeny(t *testing.T) {
	tests := []struct {
		rule    string
		wantCEL string
	}{
		{
			rule:    "Bash(curl *)",
			wantCEL: `tool == "Bash" && request.args.command.matches("curl .*")`,
		},
		{
			rule:    "Read(./.env)",
			wantCEL: `tool == "Read" && request.args.path.matches("\\./\\.env")`,
		},
		{
			rule:    "WebFetch",
			wantCEL: `tool == "WebFetch"`,
		},
		{
			rule:    "Write(/tmp/**)",
			wantCEL: `tool == "Write" && request.args.path.matches("/tmp/.*")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			cel, _ := translateSettingsRule(tt.rule)
			if cel != tt.wantCEL {
				t.Errorf("CEL mismatch:\ngot:  %s\nwant: %s", cel, tt.wantCEL)
			}
		})
	}
}

func TestImport_ConvertsSettingsJSON(t *testing.T) {
	input := `{
	  "permissions": {
	    "allow": ["Bash(npm run test *)"],
	    "deny": ["Bash(curl *)", "WebFetch"]
	  }
	}`

	manifests, comments, err := convertSettingsJSON([]byte(input), "settings.json")
	if err != nil {
		t.Fatalf("convertSettingsJSON failed: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests (one per deny rule), got %d", len(manifests))
	}

	// First deny: Bash(curl *)
	m0 := manifests[0]
	if m0.Spec.Validations[0].Action != "DENY" {
		t.Errorf("expected DENY action, got %s", m0.Spec.Validations[0].Action)
	}
	if !strings.Contains(m0.Spec.Validations[0].Expression, `tool == "Bash"`) {
		t.Errorf("expected Bash tool check, got %s", m0.Spec.Validations[0].Expression)
	}

	// allow rules must NOT produce manifests
	_ = comments
}

func TestImport_GlobToRegex(t *testing.T) {
	tests := []struct {
		glob  string
		regex string
	}{
		{"curl *", "curl .*"},
		{"./.env", "\\./\\.env"},
		{"/tmp/**", "/tmp/.*"},
		{"*.yaml", ".*\\.yaml"},
		{"file?.txt", "file.\\.txt"},
	}

	for _, tt := range tests {
		got := globToRegex(tt.glob)
		if got != tt.regex {
			t.Errorf("globToRegex(%q) = %q, want %q", tt.glob, got, tt.regex)
		}
	}
}

// ---- AgentWall v2 tests ----

func TestImport_DetectsAgentWall(t *testing.T) {
	input := `version: "2"
default_action: deny
tools:
  - name: query_database
    action: allow
    risk: high
`

	format := detectFormat([]byte(input))
	if format != formatAgentWall {
		t.Errorf("expected formatAgentWall, got %v", format)
	}
}

func TestImport_TranslatesAgentWallDeny(t *testing.T) {
	input := `version: "2"
default_action: deny
tools:
  - name: dangerous_tool
    action: deny
    risk: critical
`

	manifests, _, err := convertAgentWall([]byte(input), "agentwall.yaml")
	if err != nil {
		t.Fatalf("convertAgentWall failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest for deny tool, got %d", len(manifests))
	}

	m := manifests[0]
	if m.Spec.Validations[0].Action != "DENY" {
		t.Errorf("expected DENY, got %s", m.Spec.Validations[0].Action)
	}
	if !strings.Contains(m.Spec.Validations[0].Expression, `tool == "dangerous_tool"`) {
		t.Errorf("expected tool match expression, got %s", m.Spec.Validations[0].Expression)
	}
	if m.Metadata.Annotations["aegis.io/severity"] != "critical" {
		t.Errorf("expected critical severity, got %s", m.Metadata.Annotations["aegis.io/severity"])
	}
}

func TestImport_TranslatesAgentWallSchemaConstraints(t *testing.T) {
	input := `version: "2"
tools:
  - name: query_database
    action: allow
    risk: high
    parameters:
      - name: options
        type: object
        schema:
          type: object
          properties:
            query:
              type: string
              pattern: "^SELECT.*"
            limit:
              type: integer
              maximum: 100
`

	manifests, _, err := convertAgentWall([]byte(input), "agentwall.yaml")
	if err != nil {
		t.Fatalf("convertAgentWall failed: %v", err)
	}

	// Expect at least 2 manifests: one for query pattern, one for limit maximum
	if len(manifests) < 2 {
		t.Fatalf("expected at least 2 manifests for schema constraints, got %d", len(manifests))
	}

	// Verify at least one has a matches() call for the query pattern
	hasPattern := false
	hasLimit := false
	for _, m := range manifests {
		expr := m.Spec.Validations[0].Expression
		if strings.Contains(expr, "matches") && strings.Contains(expr, "SELECT") {
			hasPattern = true
		}
		if strings.Contains(expr, "> 100") || strings.Contains(expr, ">100") {
			hasLimit = true
		}
	}

	if !hasPattern {
		t.Error("expected a manifest with query pattern constraint")
	}
	if !hasLimit {
		t.Error("expected a manifest with limit maximum constraint")
	}
}

// ---- mcp-visor tests ----

func TestImport_DetectsMCPVisor(t *testing.T) {
	input := `deny_path:
  - "/etc/passwd"
  - "/etc/shadow"
deny_command_pattern:
  - ".*rm\\s+-rf.*"
`

	format := detectFormat([]byte(input))
	if format != formatMCPVisor {
		t.Errorf("expected formatMCPVisor, got %v", format)
	}
}

func TestImport_DetectsMCPVisorByAllowPath(t *testing.T) {
	input := `allow_path:
  - "/tmp/*"
  - "/home/user/project/*"
`

	format := detectFormat([]byte(input))
	if format != formatMCPVisor {
		t.Errorf("expected formatMCPVisor for allow_path-only file, got %v", format)
	}
}

func TestImport_TranslatesMCPVisorDenyPath(t *testing.T) {
	input := `deny_path:
  - "/etc/passwd"
  - "/etc/shadow"
  - "~/.ssh/*"
`

	manifests, _, err := convertMCPVisor([]byte(input), "visor.yaml")
	if err != nil {
		t.Fatalf("convertMCPVisor failed: %v", err)
	}

	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests for 3 deny_path entries, got %d", len(manifests))
	}

	for _, m := range manifests {
		expr := m.Spec.Validations[0].Expression
		if !strings.Contains(expr, `tool.matches("Read|Write|Edit")`) {
			t.Errorf("deny_path CEL should restrict to file tools, got: %s", expr)
		}
		if !strings.Contains(expr, "request.args.path.matches") {
			t.Errorf("deny_path CEL should match on path, got: %s", expr)
		}
		if m.Spec.Validations[0].Action != "DENY" {
			t.Errorf("deny_path should produce DENY action, got %s", m.Spec.Validations[0].Action)
		}
	}
}

func TestImport_TranslatesMCPVisorDenyCommand(t *testing.T) {
	input := `deny_command_pattern:
  - ".*rm\\s+-rf.*"
  - ".*curl.*\\|.*sh.*"
`

	manifests, _, err := convertMCPVisor([]byte(input), "visor.yaml")
	if err != nil {
		t.Fatalf("convertMCPVisor failed: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	for _, m := range manifests {
		expr := m.Spec.Validations[0].Expression
		if !strings.Contains(expr, `tool == "Bash"`) {
			t.Errorf("deny_command_pattern should restrict to Bash, got: %s", expr)
		}
		if !strings.Contains(expr, "request.args.command.matches") {
			t.Errorf("deny_command_pattern should match on command, got: %s", expr)
		}
	}
}

func TestImport_TranslatesMCPVisorAllowPath(t *testing.T) {
	input := `allow_path:
  - "/tmp/*"
`

	manifests, _, err := convertMCPVisor([]byte(input), "visor.yaml")
	if err != nil {
		t.Fatalf("convertMCPVisor failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m.Spec.Validations[0].Action != "REQUIRE_APPROVAL" {
		t.Errorf("allow_path should produce REQUIRE_APPROVAL, got %s", m.Spec.Validations[0].Action)
	}
	if !strings.Contains(m.Spec.Validations[0].Expression, "!request.args.path.matches") {
		t.Errorf("allow_path CEL should negate the path match, got: %s", m.Spec.Validations[0].Expression)
	}
}

func TestImport_TranslatesMCPVisorQueryPattern(t *testing.T) {
	input := `deny_query_pattern:
  - ".*DROP\\s+TABLE.*"
`

	manifests, _, err := convertMCPVisor([]byte(input), "visor.yaml")
	if err != nil {
		t.Fatalf("convertMCPVisor failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, "request.args.query.matches") {
		t.Errorf("deny_query_pattern should match query, got: %s", expr)
	}
}

// ---- Checkov format tests ----

func TestImport_DetectsCheckovFormat(t *testing.T) {
	input := `metadata:
  name: "Ensure S3 bucket has encryption enabled"
  id: "CKV2_CUSTOM_1"
  category: "ENCRYPTION"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "server_side_encryption_configuration"
  operator: "exists"
`
	format := detectFormat([]byte(input))
	if format != formatCheckov {
		t.Errorf("expected formatCheckov, got %v", format)
	}
}

func TestImport_DetectsCheckovFormatWithLogical(t *testing.T) {
	input := `metadata:
  name: "Ensure container is not running as root"
  id: "CKV2_CUSTOM_2"
  category: "GENERAL_SECURITY"
definition:
  and:
    - cond_type: "attribute"
      resource_types: ["kubernetes_deployment"]
      attribute: "spec.template.spec.containers.securityContext.runAsNonRoot"
      operator: "equals"
      value: "true"
`
	format := detectFormat([]byte(input))
	if format != formatCheckov {
		t.Errorf("expected formatCheckov for and-based definition, got %v", format)
	}
}

func TestImport_TranslatesCheckovNotExists(t *testing.T) {
	input := `metadata:
  name: "Ensure privileged containers are not used"
  id: "CKV_CUSTOM_3"
  category: "GENERAL_SECURITY"
definition:
  cond_type: "attribute"
  resource_types:
    - "kubernetes_deployment"
  attribute: "privileged"
  operator: "not_exists"
`
	manifests, _, err := convertCheckov([]byte(input), "checkov-test.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	m := manifests[0]
	if m.Spec.Validations[0].Action != "DENY" {
		t.Errorf("not_exists should produce DENY, got %s", m.Spec.Validations[0].Action)
	}
	expr := m.Spec.Validations[0].Expression
	if !strings.Contains(expr, `content.contains("privileged")`) {
		t.Errorf("not_exists should check content.contains(attr), got: %s", expr)
	}
	if !strings.Contains(expr, `\.yaml$`) {
		t.Errorf("kubernetes_deployment should match yaml files, got: %s", expr)
	}
}

func TestImport_TranslatesCheckovRegexMatch(t *testing.T) {
	input := `metadata:
  name: "Deny eval in scripts"
  id: "CKV_CUSTOM_4"
  category: "GENERAL_SECURITY"
definition:
  cond_type: "attribute"
  resource_types:
    - "dockerfile"
  attribute: "cmd"
  operator: "regex_match"
  value: "eval\\s*\\("
`
	manifests, _, err := convertCheckov([]byte(input), "checkov-test.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, ".matches(") {
		t.Errorf("regex_match should use .matches(), got: %s", expr)
	}
	if manifests[0].Spec.Validations[0].Action != "DENY" {
		t.Errorf("regex_match should produce DENY, got %s", manifests[0].Spec.Validations[0].Action)
	}
}

func TestImport_TranslatesCheckovDockerfile(t *testing.T) {
	input := `metadata:
  name: "Ensure Dockerfile does not use latest tag"
  id: "CKV_CUSTOM_5"
  category: "SUPPLY_CHAIN"
definition:
  cond_type: "attribute"
  resource_types:
    - "dockerfile"
  attribute: "image"
  operator: "not_contains"
  value: ":latest"
`
	manifests, _, err := convertCheckov([]byte(input), "checkov-test.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	m := manifests[0]
	tools := m.Spec.MatchConstraints.Tools
	if len(tools) == 0 || (tools[0] != "Write" && tools[0] != "Edit") {
		t.Errorf("dockerfile policy should target Write/Edit tools, got: %v", tools)
	}
	expr := m.Spec.Validations[0].Expression
	if !strings.Contains(expr, `[Dd]ockerfile`) {
		t.Errorf("dockerfile resource should match Dockerfile path pattern, got: %s", expr)
	}
	if m.Spec.Validations[0].Action != "DENY" {
		t.Errorf("not_contains should produce DENY, got %s", m.Spec.Validations[0].Action)
	}
}

func TestImport_TranslatesCheckovLogicalAnd(t *testing.T) {
	input := `metadata:
  name: "Ensure containers have security context"
  id: "CKV2_CUSTOM_6"
  category: "GENERAL_SECURITY"
definition:
  and:
    - cond_type: "attribute"
      resource_types: ["kubernetes_deployment"]
      attribute: "securityContext"
      operator: "exists"
    - cond_type: "attribute"
      resource_types: ["kubernetes_deployment"]
      attribute: "runAsNonRoot"
      operator: "equals"
      value: "true"
`
	manifests, _, err := convertCheckov([]byte(input), "checkov-test.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 combined manifest for and conditions, got %d", len(manifests))
	}
	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, "&&") {
		t.Errorf("and conditions should join with &&, got: %s", expr)
	}
}

func TestImport_CheckovNumericSkipped(t *testing.T) {
	input := `metadata:
  name: "Port range check"
  id: "CKV_CUSTOM_7"
  category: "NETWORK"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_security_group"
  attribute: "from_port"
  operator: "greater_than"
  value: "22"
`
	manifests, comments, err := convertCheckov([]byte(input), "checkov-test.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest with IMPORT_TODO, got %d", len(manifests))
	}
	if manifests[0].Spec.Validations[0].Expression != "false" {
		t.Errorf("numeric operator should produce 'false' CEL, got: %s", manifests[0].Spec.Validations[0].Expression)
	}
	if len(comments) == 0 || !strings.Contains(comments[0], "IMPORT_TODO") {
		t.Errorf("numeric operator should have IMPORT_TODO comment, got: %v", comments)
	}
}

func TestImport_CheckovAnnotationsPresent(t *testing.T) {
	input := `metadata:
  name: "S3 encryption check"
  id: "CKV2_CUSTOM_1"
  category: "ENCRYPTION"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "server_side_encryption_configuration"
  operator: "exists"
`
	manifests, _, err := convertCheckov([]byte(input), "my-policy.yaml")
	if err != nil {
		t.Fatalf("convertCheckov failed: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("expected at least 1 manifest")
	}
	m := manifests[0]
	if m.Metadata.Annotations["aegis.io/checkov-id"] != "CKV2_CUSTOM_1" {
		t.Errorf("expected checkov-id annotation, got: %v", m.Metadata.Annotations)
	}
	if m.Metadata.Annotations["aegis.io/imported-from"] != "my-policy.yaml" {
		t.Errorf("expected imported-from annotation, got: %v", m.Metadata.Annotations)
	}
}

// ---- catalog generate-from-catalog tests ----

func TestImport_GeneratesFromCatalog(t *testing.T) {
	entries := []catalogEntry{
		{Tool: "rm -rf", Family: "bash", RiskLevel: "critical"},
		{Tool: "kubectl delete", Family: "bash", RiskLevel: "high"},
		{Tool: "ls", Family: "bash", RiskLevel: "none"},
		{Tool: "git log", Family: "bash", RiskLevel: "none"},
		{Tool: "shutdown", Family: "bash", RiskLevel: "critical"},
	}

	manifests, comments := generateCatalogPolicies(entries)

	// Only high/critical should be included
	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests (rm -rf, kubectl delete, shutdown), got %d", len(manifests))
	}
	if len(comments) != len(manifests) {
		t.Errorf("comments count %d != manifests count %d", len(comments), len(manifests))
	}

	// Verify actions: critical → DENY, high → REQUIRE_APPROVAL
	byName := map[string]aegisManifest{}
	for _, m := range manifests {
		byName[m.Metadata.Name] = m
	}

	rmManifest, ok := byName["catalog-auto-rm--rf"]
	if !ok {
		// sanitizeID replaces spaces and special chars
		for k, v := range byName {
			if strings.Contains(k, "rm") {
				rmManifest = v
				ok = true
				break
			}
		}
	}
	if !ok {
		t.Fatalf("no manifest found for rm -rf; keys: %v", func() []string {
			var ks []string
			for k := range byName {
				ks = append(ks, k)
			}
			return ks
		}())
	}
	if rmManifest.Spec.Validations[0].Action != "DENY" {
		t.Errorf("critical risk should produce DENY, got %s", rmManifest.Spec.Validations[0].Action)
	}

	for _, m := range manifests {
		if strings.Contains(m.Metadata.Name, "kubectl") {
			if m.Spec.Validations[0].Action != "REQUIRE_APPROVAL" {
				t.Errorf("high risk should produce REQUIRE_APPROVAL, got %s", m.Spec.Validations[0].Action)
			}
		}
	}
}

func TestImport_GeneratesFromCatalogAnnotations(t *testing.T) {
	entries := []catalogEntry{
		{Tool: "terraform destroy", Family: "bash", RiskLevel: "critical"},
	}

	manifests, _ := generateCatalogPolicies(entries)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m.Metadata.Annotations["aegis.io/source"] != "pkg/adapters/catalog.json" {
		t.Errorf("expected catalog source annotation, got %v", m.Metadata.Annotations)
	}
	if m.Metadata.Annotations["aegis.io/risk-level"] != "critical" {
		t.Errorf("expected risk-level annotation, got %v", m.Metadata.Annotations)
	}
	if !strings.Contains(m.Spec.Validations[0].Expression, "terraform destroy") {
		t.Errorf("expression should reference tool name, got: %s", m.Spec.Validations[0].Expression)
	}
}

func TestImport_GeneratesFromCatalogBashCEL(t *testing.T) {
	entries := []catalogEntry{
		{Tool: "kubectl delete", Family: "bash", RiskLevel: "high"},
	}

	manifests, _ := generateCatalogPolicies(entries)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `tool == "Bash"`) {
		t.Errorf("bash family should check tool == Bash, got: %s", expr)
	}
	if !strings.Contains(expr, "startsWith") {
		t.Errorf("bash family should use startsWith for command, got: %s", expr)
	}
}

// ---- GitHub URL parsing tests (no HTTP) ----

func TestImport_GitHubURLDetection(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		{"https://github.com/owner/repo", true},
		{"github.com/owner/repo", true},
		{"http://github.com/owner/repo", true},
		{"/local/path/policies.yaml", false},
		{"policies.yaml", false},
		{"https://example.com/policy.yaml", false},
	}

	for _, tt := range tests {
		got := isGitHubURL(tt.source)
		if got != tt.want {
			t.Errorf("isGitHubURL(%q) = %v, want %v", tt.source, got, tt.want)
		}
	}
}

func TestImport_ParseGitHubURL(t *testing.T) {
	tests := []struct {
		source    string
		wantOwner string
		wantRepo  string
		wantRef   string
	}{
		{
			source:    "https://github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantRef:   "HEAD",
		},
		{
			source:    "github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantRef:   "HEAD",
		},
		{
			source:    "https://github.com/owner/repo/tree/main",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantRef:   "main",
		},
		{
			source:    "https://github.com/owner/repo/tree/feature/my-branch",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantRef:   "feature/my-branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			ref, err := parseGitHubURL(tt.source)
			if err != nil {
				t.Fatalf("parseGitHubURL(%q) returned error: %v", tt.source, err)
			}
			if ref.owner != tt.wantOwner {
				t.Errorf("owner: got %q, want %q", ref.owner, tt.wantOwner)
			}
			if ref.repo != tt.wantRepo {
				t.Errorf("repo: got %q, want %q", ref.repo, tt.wantRepo)
			}
			if ref.ref != tt.wantRef {
				t.Errorf("ref: got %q, want %q", ref.ref, tt.wantRef)
			}
		})
	}
}

// ---- Kyverno tests ----

func TestImport_DetectsKyvernoFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  importFormat
	}{
		{
			name: "ClusterPolicy",
			input: `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-pod-deletion
spec:
  validationFailureAction: Enforce
  rules: []
`,
			want: formatKyverno,
		},
		{
			name: "Policy",
			input: `apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: restrict-secrets
spec:
  validationFailureAction: Audit
  rules: []
`,
			want: formatKyverno,
		},
		{
			name: "v2beta1 ClusterPolicy",
			input: `apiVersion: kyverno.io/v2beta1
kind: ClusterPolicy
metadata:
  name: some-policy
spec:
  rules: []
`,
			want: formatKyverno,
		},
		{
			name: "non-kyverno",
			input: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
`,
			want: formatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat([]byte(tt.input))
			if got != tt.want {
				t.Errorf("detectFormat = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImport_TranslatesKyvernoDelete(t *testing.T) {
	input := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-pod-deletion
  annotations:
    policies.kyverno.io/severity: high
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/description: "Prevents pod deletion without approval"
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-deletion
      match:
        any:
        - resources:
            kinds: [Pod]
            operations: [DELETE]
      validate:
        message: "Deleting pods requires approval"
        deny:
          conditions:
            any: []
`

	manifests, _, err := convertKyverno([]byte(input), "restrict-pod-deletion.yaml")
	if err != nil {
		t.Fatalf("convertKyverno failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	expr := m.Spec.Validations[0].Expression
	if !strings.Contains(expr, `tool == "Bash"`) {
		t.Errorf("CEL should target Bash tool, got: %s", expr)
	}
	if !strings.Contains(strings.ToLower(expr), "kubectl") {
		t.Errorf("CEL should reference kubectl, got: %s", expr)
	}
	if !strings.Contains(strings.ToLower(expr), "delete") {
		t.Errorf("CEL should match delete operation, got: %s", expr)
	}
}

func TestImport_TranslatesKyvernoEnforce(t *testing.T) {
	enforce := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-policy
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-ns-deletion
      match:
        any:
        - resources:
            kinds: [Namespace]
            operations: [DELETE]
      validate:
        message: "Namespace deletion blocked"
        deny:
          conditions:
            any: []
`

	audit := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: audit-policy
spec:
  validationFailureAction: Audit
  rules:
    - name: audit-ns-creation
      match:
        any:
        - resources:
            kinds: [Namespace]
            operations: [CREATE]
      validate:
        message: "Namespace creation audited"
        deny:
          conditions:
            any: []
`

	enforceManifests, _, err := convertKyverno([]byte(enforce), "enforce.yaml")
	if err != nil {
		t.Fatalf("convertKyverno (Enforce) failed: %v", err)
	}
	if len(enforceManifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(enforceManifests))
	}
	if enforceManifests[0].Spec.Validations[0].Action != "DENY" {
		t.Errorf("Enforce should produce DENY, got %s", enforceManifests[0].Spec.Validations[0].Action)
	}

	auditManifests, _, err := convertKyverno([]byte(audit), "audit.yaml")
	if err != nil {
		t.Fatalf("convertKyverno (Audit) failed: %v", err)
	}
	if len(auditManifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(auditManifests))
	}
	if auditManifests[0].Spec.Validations[0].Action != "AUDIT" {
		t.Errorf("Audit should produce AUDIT, got %s", auditManifests[0].Spec.Validations[0].Action)
	}
}

func TestImport_TranslatesKyvernoSeverity(t *testing.T) {
	tests := []struct {
		severity   string
		vfa        string
		wantAction string
	}{
		{severity: "critical", vfa: "Audit", wantAction: "DENY"},
		{severity: "high", vfa: "Audit", wantAction: "DENY"},
		{severity: "medium", vfa: "Audit", wantAction: "REQUIRE_APPROVAL"},
		{severity: "medium", vfa: "Enforce", wantAction: "DENY"},
		{severity: "low", vfa: "Enforce", wantAction: "AUDIT"},
	}

	for _, tt := range tests {
		t.Run(tt.severity+"/"+tt.vfa, func(t *testing.T) {
			input := fmt.Sprintf(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: severity-test
  annotations:
    policies.kyverno.io/severity: %s
spec:
  validationFailureAction: %s
  rules:
    - name: check-pod
      match:
        any:
        - resources:
            kinds: [Pod]
            operations: [DELETE]
      validate:
        message: "test"
        deny:
          conditions:
            any: []
`, tt.severity, tt.vfa)

			manifests, _, err := convertKyverno([]byte(input), "test.yaml")
			if err != nil {
				t.Fatalf("convertKyverno failed: %v", err)
			}
			if len(manifests) == 0 {
				t.Fatal("expected at least 1 manifest")
			}
			got := manifests[0].Spec.Validations[0].Action
			if got != tt.wantAction {
				t.Errorf("severity=%s vfa=%s: got action %s, want %s", tt.severity, tt.vfa, got, tt.wantAction)
			}
		})
	}
}

func TestImport_SkipsMutateRules(t *testing.T) {
	input := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: mutate-policy
spec:
  validationFailureAction: Enforce
  rules:
    - name: add-labels
      match:
        any:
        - resources:
            kinds: [Pod]
      mutate:
        patchStrategicMerge:
          metadata:
            labels:
              env: production
`

	manifests, comments, err := convertKyverno([]byte(input), "mutate.yaml")
	if err != nil {
		t.Fatalf("convertKyverno failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 IMPORT_TODO manifest for mutate rule, got %d", len(manifests))
	}

	// Expression must be "false" for IMPORT_TODO
	if manifests[0].Spec.Validations[0].Expression != "false" {
		t.Errorf("mutate rule should produce 'false' expression, got %s", manifests[0].Spec.Validations[0].Expression)
	}
	if !strings.Contains(comments[0], "IMPORT_TODO") {
		t.Errorf("mutate rule should have IMPORT_TODO comment, got %q", comments[0])
	}
	if !strings.Contains(comments[0], "mutate") {
		t.Errorf("IMPORT_TODO comment should mention mutate, got %q", comments[0])
	}
}

func TestImport_KyvernoJMESPathConditions(t *testing.T) {
	input := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-prod-deletion
  annotations:
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-namespace
      match:
        any:
        - resources:
            kinds: [Pod]
            operations: [DELETE]
      validate:
        message: "Deleting pods in production requires approval"
        deny:
          conditions:
            any:
            - key: "{{ request.namespace }}"
              operator: Equals
              value: production
`

	manifests, comments, err := convertKyverno([]byte(input), "restrict-prod.yaml")
	if err != nil {
		t.Fatalf("convertKyverno failed: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("expected at least 1 manifest even with JMESPath conditions")
	}

	// Should still generate a kubectl pattern match
	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `tool == "Bash"`) {
		t.Errorf("should generate Bash tool match even with JMESPath conditions, got: %s", expr)
	}
	// Should have IMPORT_TODO comment about JMESPath
	if !strings.Contains(comments[0], "IMPORT_TODO") {
		t.Errorf("JMESPath conditions should produce IMPORT_TODO comment, got %q", comments[0])
	}
}

func TestImport_KyvernoMultipleKinds(t *testing.T) {
	input := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-deletions
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-deletes
      match:
        any:
        - resources:
            kinds: [Pod, Deployment, Service]
            operations: [DELETE]
      validate:
        message: "Deletion requires approval"
        deny:
          conditions:
            any: []
`

	manifests, _, err := convertKyverno([]byte(input), "multi-kind.yaml")
	if err != nil {
		t.Fatalf("convertKyverno failed: %v", err)
	}
	// Should produce one manifest per kind
	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests (one per kind), got %d", len(manifests))
	}
}

func TestImport_KyvernoMetadataPreserved(t *testing.T) {
	input := `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: my-policy
  annotations:
    policies.kyverno.io/severity: high
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/description: "Test description"
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-pod
      match:
        any:
        - resources:
            kinds: [Pod]
            operations: [DELETE]
      validate:
        message: "Custom message"
        deny:
          conditions:
            any: []
`

	manifests, _, err := convertKyverno([]byte(input), "meta-test.yaml")
	if err != nil {
		t.Fatalf("convertKyverno failed: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("expected at least 1 manifest")
	}

	m := manifests[0]
	if m.Spec.Description != "Test description" {
		t.Errorf("description should be from annotation, got %q", m.Spec.Description)
	}
	if m.Metadata.Annotations["aegis.io/severity"] != "high" {
		t.Errorf("severity annotation: got %q, want high", m.Metadata.Annotations["aegis.io/severity"])
	}
	if m.Metadata.Annotations["kyverno.io/category"] != "Pod Security" {
		t.Errorf("category annotation: got %q, want 'Pod Security'", m.Metadata.Annotations["kyverno.io/category"])
	}
	if m.Spec.Validations[0].Message != "Custom message" {
		t.Errorf("message should come from validate.message, got %q", m.Spec.Validations[0].Message)
	}
}

func TestImport_ExtractPolicyFiles(t *testing.T) {
	// Build an in-memory zip with known files
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addZipFile := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		_, _ = w.Write([]byte(content))
	}

	addZipFile("repo-main/policies.yaml", `layerName: test
policies:
  - id: p1
    rule: tool_definition_changed
    action: deny
`)
	addZipFile("repo-main/README.md", "# README") // should be skipped
	addZipFile("repo-main/settings.json", `{"permissions":{"deny":["WebFetch"],"allow":[]}}`)
	addZipFile("repo-main/logo.png", "\x89PNG") // should be skipped

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	paths, err := extractPolicyFiles(buf.Bytes())
	if err != nil {
		t.Fatalf("extractPolicyFiles failed: %v", err)
	}
	defer func() {
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}()

	if len(paths) != 2 {
		t.Fatalf("expected 2 extracted files (.yaml and .json), got %d", len(paths))
	}
}

// ---- Sigma format tests ----

func TestImport_DetectsSigmaFormat(t *testing.T) {
	input := `title: Suspicious Rm Command
id: abc123
status: stable
description: Detects suspicious rm usage
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'rm -rf /'
            - 'rm -rf ~'
    condition: selection
level: high
`
	format := detectFormat([]byte(input))
	if format != formatSigma {
		t.Errorf("expected formatSigma, got %v", format)
	}
}

func TestImport_TranslatesSigmaContains(t *testing.T) {
	input := `title: Test Contains
id: test-contains-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'rm -rf'
            - 'dangerous'
    condition: selection
level: high
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `.contains("rm -rf")`) {
		t.Errorf("expected .contains() CEL, got: %s", expr)
	}
	if !strings.Contains(expr, ` || `) {
		t.Errorf("expected OR for multiple values, got: %s", expr)
	}
}

func TestImport_TranslatesSigmaRegex(t *testing.T) {
	input := `title: Test Regex
id: test-regex-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|re: '.*curl.*\\|.*sh.*'
    condition: selection
level: medium
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `.matches(`) {
		t.Errorf("expected .matches() CEL for regex, got: %s", expr)
	}
}

func TestImport_TranslatesSigmaConditionFilter(t *testing.T) {
	input := `title: Test Filter
id: test-filter-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'rm -rf'
    filter:
        CommandLine|contains: '--dry-run'
    condition: selection and not filter
level: high
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, "&&") {
		t.Errorf("expected AND in condition, got: %s", expr)
	}
	if !strings.Contains(expr, "!(") {
		t.Errorf("expected negation for filter, got: %s", expr)
	}
}

func TestImport_TranslatesSigmaLevel(t *testing.T) {
	tests := []struct {
		level      string
		wantAction string
	}{
		{"critical", "DENY"},
		{"high", "DENY"},
		{"medium", "REQUIRE_APPROVAL"},
		{"low", "AUDIT"},
		{"informational", "AUDIT"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			input := fmt.Sprintf(`title: Test Level
id: test-level-%s
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: %s
`, tt.level, tt.level)

			manifests, _, err := convertSigma([]byte(input), "test.yaml")
			if err != nil {
				t.Fatalf("convertSigma failed: %v", err)
			}

			got := manifests[0].Spec.Validations[0].Action
			if got != tt.wantAction {
				t.Errorf("level %q: got action %q, want %q", tt.level, got, tt.wantAction)
			}
		})
	}
}

func TestImport_TranslatesSigmaLogsource(t *testing.T) {
	tests := []struct {
		category  string
		wantTools []string
	}{
		{"process_creation", []string{"Bash"}},
		{"file_event", []string{"Read", "Write", "Edit"}},
		{"network_connection", []string{"Bash"}},
		{"other", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			input := fmt.Sprintf(`title: Test Logsource
id: test-logsource-%s
logsource:
    category: %s
    product: linux
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: low
`, tt.category, tt.category)

			manifests, _, err := convertSigma([]byte(input), "test.yaml")
			if err != nil {
				t.Fatalf("convertSigma failed: %v", err)
			}

			got := manifests[0].Spec.MatchConstraints.Tools
			if len(got) != len(tt.wantTools) {
				t.Errorf("category %q: got %d tools, want %d", tt.category, len(got), len(tt.wantTools))
				return
			}
			for i, tool := range tt.wantTools {
				if got[i] != tool {
					t.Errorf("category %q: tool[%d] = %q, want %q", tt.category, i, got[i], tool)
				}
			}
		})
	}
}

func TestImport_TranslatesSigmaStartsWith(t *testing.T) {
	input := `title: Test StartsWith
id: test-startswith-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|startswith: '/bin/bash'
    condition: selection
level: low
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `.startsWith("/bin/bash")`) {
		t.Errorf("expected .startsWith() CEL, got: %s", expr)
	}
}

func TestImport_TranslatesSigmaEndsWith(t *testing.T) {
	input := `title: Test EndsWith
id: test-endswith-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|endswith: '.sh'
    condition: selection
level: low
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `.endsWith(".sh")`) {
		t.Errorf("expected .endsWith() CEL, got: %s", expr)
	}
}

func TestImport_TranslatesSigmaContainsAll(t *testing.T) {
	input := `title: Test ContainsAll
id: test-containsall-001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'curl'
            - 'http'
    condition: selection
level: high
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, ` && `) {
		t.Errorf("expected AND for |all modifier, got: %s", expr)
	}
	if !strings.Contains(expr, `.contains("curl")`) {
		t.Errorf("expected curl check, got: %s", expr)
	}
	if !strings.Contains(expr, `.contains("http")`) {
		t.Errorf("expected http check, got: %s", expr)
	}
}

func TestImport_TranslatesSigma1OfThem(t *testing.T) {
	input := `title: Test 1 of them
id: test-1ofthem-001
logsource:
    category: process_creation
    product: linux
detection:
    selection1:
        CommandLine|contains: 'curl'
    selection2:
        CommandLine|contains: 'wget'
    condition: 1 of them
level: medium
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, ` || `) {
		t.Errorf("expected OR for '1 of them', got: %s", expr)
	}
}

func TestImport_TranslatesSigmaAllOfThem(t *testing.T) {
	input := `title: Test all of them
id: test-allofthem-001
logsource:
    category: process_creation
    product: linux
detection:
    selection1:
        CommandLine|contains: 'sudo'
    selection2:
        CommandLine|contains: 'rm'
    condition: all of them
level: high
`
	manifests, _, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, ` && `) {
		t.Errorf("expected AND for 'all of them', got: %s", expr)
	}
}

func TestImport_SigmaUnmappableFieldAddsComment(t *testing.T) {
	input := `title: Test Unmappable Field
id: test-unmappable-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: high
`
	_, comments, err := convertSigma([]byte(input), "test.yaml")
	if err != nil {
		t.Fatalf("convertSigma failed: %v", err)
	}

	if len(comments) == 0 || !strings.Contains(comments[0], "IMPORT_TODO") {
		t.Errorf("expected IMPORT_TODO comment for unmappable field, got: %v", comments)
	}
}

// ---- Falco tests ----

func TestImport_DetectsFalcoFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  importFormat
	}{
		{
			name: "rule item",
			input: `- rule: Terminal shell in container
  condition: spawned_process and container
  priority: WARNING
`,
			want: formatFalco,
		},
		{
			name: "macro item",
			input: `- macro: shell_procs
  condition: proc.name in (bash, sh)
`,
			want: formatFalco,
		},
		{
			name: "list item",
			input: `- list: shell_binaries
  items: [bash, sh, zsh]
`,
			want: formatFalco,
		},
		{
			name: "mixed items",
			input: `- list: shell_binaries
  items: [bash, sh]
- macro: shell_procs
  condition: proc.name in (shell_binaries)
- rule: Shell in container
  condition: shell_procs and container
  priority: ERROR
`,
			want: formatFalco,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat([]byte(tt.input))
			if got != tt.want {
				t.Errorf("detectFormat: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImport_TranslatesFalcoCmdlineContains(t *testing.T) {
	input := `- rule: Dangerous rm command
  desc: Detects rm -rf execution
  condition: proc.cmdline contains "rm -rf"
  priority: CRITICAL
  tags: [process]
`
	manifests, comments, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `tool == "Bash"`) {
		t.Errorf("expected Bash tool check, got: %s", expr)
	}
	if !strings.Contains(expr, `request.args.command.contains("rm -rf")`) {
		t.Errorf("expected command contains check, got: %s", expr)
	}
	if comments[0] != "" {
		t.Errorf("expected no comment for translatable condition, got: %q", comments[0])
	}
}

func TestImport_TranslatesFalcoCmdlineStartswith(t *testing.T) {
	input := `- rule: Curl exfiltration
  condition: proc.cmdline startswith "curl"
  priority: WARNING
`
	manifests, _, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `request.args.command.startsWith("curl")`) {
		t.Errorf("expected startsWith check, got: %s", expr)
	}
}

func TestImport_TranslatesFalcoProcName(t *testing.T) {
	input := `- rule: Netcat Remote Code Execution
  desc: Detects netcat with -e flag
  condition: proc.name in (nc, ncat, netcat, socat)
  priority: CRITICAL
`
	manifests, comments, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `tool == "Bash"`) {
		t.Errorf("expected Bash tool check, got: %s", expr)
	}
	if !strings.Contains(expr, "nc|ncat|netcat|socat") {
		t.Errorf("expected alternation pattern with nc/ncat/netcat/socat, got: %s", expr)
	}
	if !strings.Contains(expr, "matches") {
		t.Errorf("expected matches() call, got: %s", expr)
	}
	if comments[0] != "" {
		t.Errorf("expected no comment for translatable proc.name in, got: %q", comments[0])
	}
}

func TestImport_TranslatesFalcoPriority(t *testing.T) {
	tests := []struct {
		priority   string
		wantAction string
	}{
		{"EMERGENCY", "DENY"},
		{"ALERT", "DENY"},
		{"CRITICAL", "DENY"},
		{"ERROR", "DENY"},
		{"WARNING", "REQUIRE_APPROVAL"},
		{"NOTICE", "REQUIRE_APPROVAL"},
		{"INFO", "AUDIT"},
		{"DEBUG", "AUDIT"},
		{"", "AUDIT"},
	}

	for _, tt := range tests {
		t.Run(tt.priority, func(t *testing.T) {
			got := falcoPriorityToAction(tt.priority)
			if got != tt.wantAction {
				t.Errorf("falcoPriorityToAction(%q) = %q, want %q", tt.priority, got, tt.wantAction)
			}
		})
	}
}

func TestImport_ResolvesFalcoList(t *testing.T) {
	input := `- list: netcat_bins
  items: [nc, ncat, netcat]
- rule: Netcat detected
  condition: proc.name in (netcat_bins)
  priority: CRITICAL
`
	manifests, comments, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest (no manifest for list items), got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	// After resolving the list, the condition becomes proc.name in (nc, ncat, netcat)
	// which should translate to a matches() call.
	if !strings.Contains(expr, "nc|ncat|netcat") {
		t.Errorf("expected list items resolved into pattern, got: %s", expr)
	}
	if comments[0] != "" {
		t.Errorf("expected no comment after list resolution, got: %q", comments[0])
	}
}

func TestImport_FalcoKernelOnlyConditionIsImportTODO(t *testing.T) {
	input := `- rule: Container escape via proc
  condition: container.id != "" and proc.pid != 1
  priority: CRITICAL
`
	manifests, comments, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if expr != "false" {
		t.Errorf("kernel-only condition should produce 'false', got: %s", expr)
	}
	if !strings.Contains(comments[0], "IMPORT_TODO") {
		t.Errorf("kernel-only condition should have IMPORT_TODO comment, got: %q", comments[0])
	}
}

func TestImport_FalcoFdNameStartswith(t *testing.T) {
	input := `- rule: Read sensitive file
  condition: fd.name startswith "/etc/shadow"
  priority: ERROR
  tags: [filesystem]
`
	manifests, comments, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	expr := manifests[0].Spec.Validations[0].Expression
	if !strings.Contains(expr, `request.args.path.startsWith("/etc/shadow")`) {
		t.Errorf("expected path startsWith check, got: %s", expr)
	}
	if comments[0] != "" {
		t.Errorf("expected no comment, got: %q", comments[0])
	}

	// filesystem tag → Read/Write/Edit tools
	tools := manifests[0].Spec.MatchConstraints.Tools
	if len(tools) != 3 || tools[0] != "Read" || tools[1] != "Write" || tools[2] != "Edit" {
		t.Errorf("filesystem tag should produce [Read Write Edit] tools, got: %v", tools)
	}
}

func TestImport_FalcoSkipsDisabledRules(t *testing.T) {
	disabled := false
	_ = disabled
	input := `- rule: Disabled rule
  condition: proc.cmdline contains "disabled"
  priority: WARNING
  enabled: false
- rule: Enabled rule
  condition: proc.cmdline contains "enabled"
  priority: CRITICAL
`
	manifests, _, err := convertFalco([]byte(input), "falco.yaml")
	if err != nil {
		t.Fatalf("convertFalco failed: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest (disabled rule skipped), got %d", len(manifests))
	}
	if !strings.Contains(manifests[0].Metadata.Annotations["aegis.io/source-rule"], "Enabled rule") {
		t.Errorf("expected only enabled rule in output, got source-rule: %s", manifests[0].Metadata.Annotations["aegis.io/source-rule"])
	}
}

func TestImport_FalcoTagsToTools(t *testing.T) {
	tests := []struct {
		tags  []string
		tools []string
	}{
		{[]string{"container", "filesystem"}, []string{"Read", "Write", "Edit"}},
		{[]string{"network", "mitre_exfiltration"}, []string{"Bash"}},
		{[]string{"process", "T1059"}, []string{"Bash"}},
		{[]string{"container", "mitre_execution"}, []string{}},
	}

	for _, tt := range tests {
		got := falcoTagsToTools(tt.tags)
		if len(got) != len(tt.tools) {
			t.Errorf("falcoTagsToTools(%v) = %v, want %v", tt.tags, got, tt.tools)
			continue
		}
		for i := range got {
			if got[i] != tt.tools[i] {
				t.Errorf("falcoTagsToTools(%v)[%d] = %q, want %q", tt.tags, i, got[i], tt.tools[i])
			}
		}
	}
}

// ---- Checkov tests ----


