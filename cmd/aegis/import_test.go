package main

import (
	"archive/zip"
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
