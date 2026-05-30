// SPDX-License-Identifier: MIT
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var importOutDir string
var importDryRun bool
var importLLMAssist bool
var importLLMModel string
var importLLMMaxRetries int

var importCmd = &cobra.Command{
	Use:   "import <source>",
	Short: "Import external policy formats to native Nixis YAML",
	Long: `Import policies from external formats and convert them to native Nixis YAML.

Supported formats:
  - PolicyLayer YAML (detected by layerName + policies[].rule fields)
  - Generic allow/deny YAML (detected by policies[].expression field)
  - settings.json deny list (Claude Code native permissions format)
  - AgentWall YAML v2 (version: "2" + tools[].action)
  - mcp-visor YAML (deny_path, deny_command_pattern, etc.)

Sources:
  - Local file path
  - GitHub repo URL: https://github.com/owner/repo or github.com/owner/repo

Examples:
  nixis policy import policies.yaml                 # import to ./policies/imported/
  nixis policy import policies.yaml --out policies/ # import to custom directory
  nixis policy import policies.yaml --dry-run       # show what would be created
  nixis policy import https://github.com/owner/repo # fetch from GitHub`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	importCmd.Flags().StringVar(&importOutDir, "out", "./policies/imported", "Output directory for imported policies")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Print converted policies without writing files")
	importCmd.Flags().BoolVar(&importLLMAssist, "llm-assist", false, "Use Claude API to translate IMPORT_TODO markers to CEL (requires ANTHROPIC_API_KEY)")
	importCmd.Flags().StringVar(&importLLMModel, "llm-model", "claude-opus-4-7", "Claude model to use for LLM-assisted translation")
	importCmd.Flags().IntVar(&importLLMMaxRetries, "llm-max-retries", 3, "Maximum CEL repair attempts per IMPORT_TODO")
	policyCmd.AddCommand(importCmd)
}

type importFormat int

const (
	formatUnknown       importFormat = iota
	formatPolicyLayer                // layerName + policies[].rule
	formatGeneric                    // policies[].expression
	formatSettingsJSON               // {"permissions":{"deny":[...]}}
	formatAgentWall                  // version: "2" + tools[].action
	formatMCPVisor                   // deny_path / deny_command_pattern / etc.
	formatKyverno                    // apiVersion: kyverno.io/* + kind: ClusterPolicy/Policy
	formatSigma                      // logsource + detection with condition (SigmaHQ format)
	formatFalco                      // YAML array with rule/macro/list items
	formatCheckov                    // metadata.id starting with CKV + definition key
	formatOPAGatekeeper              // apiVersion: templates.gatekeeper.sh/v1
)

// ---- format-specific input structs ----

type policyLayerFile struct {
	LayerName   string              `yaml:"layerName"`
	Description string              `yaml:"description"`
	Policies    []policyLayerPolicy `yaml:"policies"`
}

type policyLayerPolicy struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Rule        string `yaml:"rule"`
	Action      string `yaml:"action"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type genericPolicyFile struct {
	Policies []genericPolicy `yaml:"policies"`
}

type genericPolicy struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Expression string   `yaml:"expression"`
	Action     string   `yaml:"action"`
	Tools      []string `yaml:"tools"`
	Severity   string   `yaml:"severity"`
}

type settingsJSON struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
}

type agentWallFile struct {
	Version       string          `yaml:"version"`
	DefaultAction string          `yaml:"default_action"`
	Tools         []agentWallTool `yaml:"tools"`
}

type agentWallTool struct {
	Name       string           `yaml:"name"`
	Action     string           `yaml:"action"`
	Risk       string           `yaml:"risk"`
	Parameters []agentWallParam `yaml:"parameters"`
}

type agentWallParam struct {
	Name   string                 `yaml:"name"`
	Type   string                 `yaml:"type"`
	Schema map[string]interface{} `yaml:"schema"`
}

type mcpVisorFile struct {
	DenyPath           []string `yaml:"deny_path"`
	AllowPath          []string `yaml:"allow_path"`
	DenyCommandPattern []string `yaml:"deny_command_pattern"`
	DenyQueryPattern   []string `yaml:"deny_query_pattern"`
	MaxFileSize        int64    `yaml:"max_file_size"`
	MaxRows            int64    `yaml:"max_rows"`
}

// ---- Checkov input structs ----

type checkovFile struct {
	Metadata   checkovMetadata   `yaml:"metadata"`
	Definition checkovDefinition `yaml:"definition"`
}

type checkovMetadata struct {
	Name     string `yaml:"name"`
	ID       string `yaml:"id"`
	Category string `yaml:"category"`
}

// checkovDefinition handles both a flat condition and logical and/or groupings.
type checkovDefinition struct {
	// Flat condition fields
	CondType      string   `yaml:"cond_type"`
	ResourceTypes []string `yaml:"resource_types"`
	Attribute     string   `yaml:"attribute"`
	Operator      string   `yaml:"operator"`
	Value         string   `yaml:"value"`
	// Logical groupings
	And []checkovDefinition `yaml:"and"`
	Or  []checkovDefinition `yaml:"or"`
}

// ---- catalog JSON structs ----

type catalogEntry struct {
	Tool         string   `json:"tool"`
	Family       string   `json:"family"`
	Operation    string   `json:"operation"`
	Effects      []string `json:"effects"`
	ResourceType string   `json:"resource_type"`
	RiskLevel    string   `json:"risk_level"`
}

// ---- output structs ----

type aegisManifest struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   aegisMetadata   `yaml:"metadata"`
	Spec       aegisPolicySpec `yaml:"spec"`
}

type aegisMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type aegisPolicySpec struct {
	Description      string                `yaml:"description"`
	MatchConstraints aegisMatchConstraints `yaml:"matchConstraints"`
	Validations      []aegisValidation     `yaml:"validations"`
	DefaultAction    string                `yaml:"defaultAction,omitempty"`
}

type aegisMatchConstraints struct {
	Tools []string `yaml:"tools"`
}

type aegisValidation struct {
	Expression string `yaml:"expression"`
	Message    string `yaml:"message"`
	Action     string `yaml:"action"`
}

// ---- GitHub URL support ----

type githubRef struct {
	owner string
	repo  string
	ref   string
}

// isGitHubURL returns true if source looks like a GitHub repo reference.
func isGitHubURL(source string) bool {
	s := strings.TrimPrefix(source, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.HasPrefix(s, "github.com/")
}

// parseGitHubURL extracts owner, repo, and ref from a GitHub URL.
func parseGitHubURL(source string) (githubRef, error) {
	s := strings.TrimPrefix(source, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(s, "/")

	parts := strings.SplitN(s, "/", 4)
	if len(parts) < 2 {
		return githubRef{}, fmt.Errorf("invalid GitHub URL: need at least owner/repo")
	}

	ref := githubRef{
		owner: parts[0],
		repo:  parts[1],
		ref:   "HEAD",
	}

	// https://github.com/owner/repo/tree/branch
	if len(parts) >= 4 && parts[2] == "tree" {
		ref.ref = parts[3]
	}

	return ref, nil
}

// fetchGitHub downloads a repository zip from GitHub and extracts policy files.
// Returns a list of local temp file paths.
func fetchGitHub(ctx context.Context, source string) ([]string, error) {
	ref, err := parseGitHubURL(source)
	if err != nil {
		return nil, err
	}

	zipURL := fmt.Sprintf("https://codeload.github.com/%s/%s/zip/refs/heads/%s", ref.owner, ref.repo, ref.ref)
	if ref.ref == "HEAD" {
		zipURL = fmt.Sprintf("https://codeload.github.com/%s/%s/zip/HEAD", ref.owner, ref.repo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d for %s", resp.StatusCode, zipURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read GitHub archive body: %w", err)
	}

	return extractPolicyFiles(body)
}

// extractPolicyFiles reads a zip archive from memory and writes policy candidate
// files to temp files. Returns the temp file paths.
func extractPolicyFiles(zipData []byte) ([]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open zip archive: %w", err)
	}

	var paths []string
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}

		name := strings.ToLower(filepath.Base(f.Name))
		ext := strings.ToLower(filepath.Ext(f.Name))

		isPolicy := ext == ".yaml" || ext == ".yml"
		isSettings := name == "settings.json" || ext == ".json"
		if !isPolicy && !isSettings {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			continue
		}

		tmp, err := os.CreateTemp("", "nixis-import-*"+ext)
		if err != nil {
			continue
		}
		if _, err := tmp.Write(data); err != nil {
			_ = tmp.Close()
			continue
		}
		_ = tmp.Close()
		paths = append(paths, tmp.Name())
	}

	return paths, nil
}

// ---- format detection ----

func detectFormat(data []byte) importFormat {
	return detectFormatWithName("", data)
}

func detectFormatWithName(filename string, data []byte) importFormat {
	// settings.json: by filename or JSON with permissions.deny
	basename := strings.ToLower(filepath.Base(filename))
	if basename == "settings.json" {
		var s settingsJSON
		if json.Unmarshal(data, &s) == nil && len(s.Permissions.Deny) > 0 {
			return formatSettingsJSON
		}
	}
	// Try JSON permissions structure regardless of filename
	var s settingsJSON
	if json.Unmarshal(data, &s) == nil && len(s.Permissions.Deny) > 0 {
		return formatSettingsJSON
	}

	// Probe YAML for all other formats
	var probe struct {
		// Base fields
		LayerName string `yaml:"layerName"`
		Version   string `yaml:"version"`
		Policies  []struct {
			Rule       string `yaml:"rule"`
			Expression string `yaml:"expression"`
			Action     string `yaml:"action"`
		} `yaml:"policies"`
		Tools []struct {
			Action string `yaml:"action"`
		} `yaml:"tools"`
		DenyPath           []string `yaml:"deny_path"`
		DenyCommandPattern []string `yaml:"deny_command_pattern"`
		DenyQueryPattern   []string `yaml:"deny_query_pattern"`
		AllowPath          []string `yaml:"allow_path"`
		// Checkov fields
		Metadata struct {
			ID string `yaml:"id"`
		} `yaml:"metadata"`
		Definition struct {
			CondType string        `yaml:"cond_type"`
			And      []interface{} `yaml:"and"`
			Or       []interface{} `yaml:"or"`
		} `yaml:"definition"`
		// Sigma fields
		Logsource struct {
			Category string `yaml:"category"`
			Product  string `yaml:"product"`
			Service  string `yaml:"service"`
		} `yaml:"logsource"`
		Detection map[string]interface{} `yaml:"detection"`
		// Kyverno / OPA fields
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
	}

	// Falco: check BEFORE probe unmarshal since Falco YAML is a sequence (not mapping)
	var falcoItemsEarly []falcoItem
	if yaml.Unmarshal(data, &falcoItemsEarly) == nil && len(falcoItemsEarly) > 0 {
		for _, item := range falcoItemsEarly {
			if item.Rule != "" || item.Macro != "" || item.List != "" {
				return formatFalco
			}
		}
	}

	if err := yaml.Unmarshal(data, &probe); err != nil {
		return formatUnknown
	}

	// Checkov: metadata.id starts with "CKV" + definition has cond_type or and/or
	if strings.HasPrefix(probe.Metadata.ID, "CKV") &&
		(probe.Definition.CondType != "" || len(probe.Definition.And) > 0 || len(probe.Definition.Or) > 0) {
		return formatCheckov
	}

	// AgentWall v2: version "2" + tools with action field
	if probe.Version == "2" && len(probe.Tools) > 0 {
		for _, t := range probe.Tools {
			if t.Action != "" {
				return formatAgentWall
			}
		}
	}

	// mcp-visor: any of the known top-level keys
	if len(probe.DenyPath) > 0 || len(probe.DenyCommandPattern) > 0 ||
		len(probe.DenyQueryPattern) > 0 || len(probe.AllowPath) > 0 {
		return formatMCPVisor
	}

	// PolicyLayer: layerName + policies[].rule
	if probe.LayerName != "" && len(probe.Policies) > 0 {
		for _, p := range probe.Policies {
			if p.Rule != "" {
				return formatPolicyLayer
			}
		}
	}

	// Generic: policies[].expression
	if len(probe.Policies) > 0 {
		for _, p := range probe.Policies {
			if p.Expression != "" {
				return formatGeneric
			}
		}
	}

	if (probe.Logsource.Category != "" || probe.Logsource.Product != "") && len(probe.Detection) > 0 {
		if _, hasCondition := probe.Detection["condition"]; hasCondition {
			return formatSigma
		}
	}

	if strings.Contains(probe.APIVersion, "kyverno.io") &&
		(probe.Kind == "ClusterPolicy" || probe.Kind == "Policy") {
		return formatKyverno
	}

	if strings.HasPrefix(probe.APIVersion, "templates.gatekeeper.sh") && probe.Kind == "ConstraintTemplate" {
		return formatOPAGatekeeper
	}
	return formatUnknown
}

// ---- main entry point ----

func runImport(cmd *cobra.Command, args []string) error {
	source := args[0]

	if isGitHubURL(source) {
		return runImportGitHub(cmd, source)
	}

	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}

	detectedFormat := detectFormatWithName(source, data)
	manifests, comments, err := convertFile(data, source)
	if err != nil {
		return err
	}

	manifests, comments = applyLLMAssist(cmd.Context(), manifests, comments, importFormatName(detectedFormat))

	if importDryRun {
		if err := printDryRun(cmd, manifests, comments); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# imported %d policies from 1 file\n", len(manifests))
		return nil
	}

	if err := writeManifests(cmd, manifests, comments, source); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %d policies from 1 file\n", len(manifests))
	return nil
}

func runImportGitHub(cmd *cobra.Command, source string) error {
	paths, err := fetchGitHub(cmd.Context(), source)
	if err != nil {
		return fmt.Errorf("fetch GitHub repo: %w", err)
	}
	defer func() {
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}()

	var allManifests []aegisManifest
	var allComments []string
	fileCount := 0

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		detectedFormat := detectFormatWithName(path, data)
		manifests, comments, err := convertFile(data, path)
		if err != nil || len(manifests) == 0 {
			continue
		}
		manifests, comments = applyLLMAssist(cmd.Context(), manifests, comments, importFormatName(detectedFormat))
		allManifests = append(allManifests, manifests...)
		allComments = append(allComments, comments...)
		fileCount++
	}

	if len(allManifests) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no recognizable policy files found in %s\n", source)
		return nil
	}

	if importDryRun {
		if err := printDryRun(cmd, allManifests, allComments); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# imported %d policies from %d files\n", len(allManifests), fileCount)
		return nil
	}

	if err := writeManifests(cmd, allManifests, allComments, source); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %d policies from %d files\n", len(allManifests), fileCount)
	return nil
}

// importFormatName returns the human-readable name for an importFormat value.
// Used in LLM prompts and IMPORT_REVIEW comments.
func importFormatName(f importFormat) string {
	switch f {
	case formatPolicyLayer:
		return "policy-layer"
	case formatGeneric:
		return "generic"
	case formatSettingsJSON:
		return "settings-json"
	case formatAgentWall:
		return "agentwall-v2"
	case formatMCPVisor:
		return "mcp-visor"
	case formatKyverno:
		return "kyverno"
	case formatSigma:
		return "sigma"
	case formatFalco:
		return "falco"
	case formatCheckov:
		return "checkov"
	case formatOPAGatekeeper:
		return "opa-gatekeeper"
	case formatUnknown:
		return "unknown"
	}
	return "unknown"
}

// convertFile detects the format and delegates conversion.
func convertFile(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	format := detectFormatWithName(sourcePath, data)
	switch format {
	case formatPolicyLayer:
		return convertPolicyLayer(data, sourcePath)
	case formatGeneric:
		return convertGeneric(data, sourcePath)
	case formatSettingsJSON:
		return convertSettingsJSON(data, sourcePath)
	case formatAgentWall:
		return convertAgentWall(data, sourcePath)
	case formatMCPVisor:
		return convertMCPVisor(data, sourcePath)
	case formatCheckov:
		return convertCheckov(data, sourcePath)
	case formatSigma:
		return convertSigma(data, sourcePath)
	case formatKyverno:
		return convertKyverno(data, sourcePath)
	case formatFalco:
		return convertFalco(data, sourcePath)
	case formatOPAGatekeeper:
		return convertOPAGatekeeper(data, sourcePath)
	case formatUnknown:
		return nil, nil, fmt.Errorf("unknown policy format in %s: file must contain a recognized policy structure", filepath.Base(sourcePath))
	}
	return nil, nil, fmt.Errorf("unhandled format in %s", filepath.Base(sourcePath))
}

// ---- PolicyLayer converter ----

func convertPolicyLayer(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var file policyLayerFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("parse PolicyLayer YAML: %w", err)
	}

	manifests := make([]aegisManifest, 0, len(file.Policies))
	comments := make([]string, 0, len(file.Policies))

	for _, p := range file.Policies {
		cel, comment := translateRule(p.Rule)
		action := normalizeAction(p.Action)
		severity := normalizeSeverity(p.Severity)

		desc := p.Description
		if desc == "" {
			desc = p.Name
		}

		m := aegisManifest{
			APIVersion: "nixis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: p.ID,
				Annotations: map[string]string{
					"nixis.io/imported-from": filepath.Base(sourcePath),
					"nixis.io/severity":      severity,
				},
			},
			Spec: aegisPolicySpec{
				Description: desc,
				MatchConstraints: aegisMatchConstraints{
					Tools: []string{},
				},
				Validations: []aegisValidation{
					{
						Expression: cel,
						Message:    fmt.Sprintf("%s: %s", p.Name, desc),
						Action:     action,
					},
				},
				DefaultAction: "ALLOW",
			},
		}

		manifests = append(manifests, m)
		comments = append(comments, comment)
	}

	return manifests, comments, nil
}

// ---- Generic converter ----

func convertGeneric(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var file genericPolicyFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("parse generic YAML: %w", err)
	}

	manifests := make([]aegisManifest, 0, len(file.Policies))
	comments := make([]string, 0, len(file.Policies))

	for _, p := range file.Policies {
		action := normalizeAction(p.Action)
		severity := normalizeSeverity(p.Severity)

		tools := p.Tools
		if tools == nil {
			tools = []string{}
		}

		name := p.Name
		if name == "" {
			name = p.ID
		}

		m := aegisManifest{
			APIVersion: "nixis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: p.ID,
				Annotations: map[string]string{
					"nixis.io/imported-from": filepath.Base(sourcePath),
					"nixis.io/severity":      severity,
				},
			},
			Spec: aegisPolicySpec{
				Description: name,
				MatchConstraints: aegisMatchConstraints{
					Tools: tools,
				},
				Validations: []aegisValidation{
					{
						Expression: p.Expression,
						Message:    name,
						Action:     action,
					},
				},
				DefaultAction: "ALLOW",
			},
		}

		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	return manifests, comments, nil
}

// ---- settings.json converter ----

func convertSettingsJSON(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var s settingsJSON
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil, fmt.Errorf("parse settings.json: %w", err)
	}

	manifests := make([]aegisManifest, 0, len(s.Permissions.Deny))
	comments := make([]string, 0, len(s.Permissions.Deny))

	for i, rule := range s.Permissions.Deny {
		cel, comment := translateSettingsRule(rule)
		id := fmt.Sprintf("settings-deny-%03d", i+1)

		m := aegisManifest{
			APIVersion: "nixis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: id,
				Annotations: map[string]string{
					"nixis.io/imported-from": filepath.Base(sourcePath),
					"nixis.io/severity":      "medium",
					"nixis.io/source-rule":   rule,
				},
			},
			Spec: aegisPolicySpec{
				Description: fmt.Sprintf("Deny rule imported from settings.json: %s", rule),
				MatchConstraints: aegisMatchConstraints{
					Tools: []string{},
				},
				Validations: []aegisValidation{
					{
						Expression: cel,
						Message:    fmt.Sprintf("Blocked by imported settings.json rule: %s", rule),
						Action:     "DENY",
					},
				},
				DefaultAction: "ALLOW",
			},
		}

		manifests = append(manifests, m)
		comments = append(comments, comment)
	}

	return manifests, comments, nil
}

// translateSettingsRule converts a Claude Code settings.json deny rule to CEL.
// Patterns: "Bash(pattern)", "Read(path)", "Write(path)", "ToolName"
func translateSettingsRule(rule string) (cel string, comment string) {
	// Match "ToolName(pattern)" form
	parenIdx := strings.Index(rule, "(")
	if parenIdx > 0 && strings.HasSuffix(rule, ")") {
		toolName := rule[:parenIdx]
		pattern := rule[parenIdx+1 : len(rule)-1]
		regex := globToRegex(pattern)

		switch toolName {
		case "Bash":
			return fmt.Sprintf(`tool == "Bash" && request.args.command.matches(%q)`, regex), ""
		case "Read":
			return fmt.Sprintf(`tool == "Read" && request.args.path.matches(%q)`, regex), ""
		case "Write":
			return fmt.Sprintf(`tool == "Write" && request.args.path.matches(%q)`, regex), ""
		case "Edit":
			return fmt.Sprintf(`tool == "Edit" && request.args.path.matches(%q)`, regex), ""
		default:
			return fmt.Sprintf(`tool == %q && request.args.matches(%q)`, toolName, regex),
				fmt.Sprintf("IMPORT_TODO: parameter field for %s is unknown — verify request.args field name", toolName)
		}
	}

	// Bare tool name — unconditional deny
	return fmt.Sprintf(`tool == %q`, rule), ""
}

// globToRegex converts a shell-style glob pattern to a regex string.
func globToRegex(glob string) string {
	var sb strings.Builder
	i := 0
	for i < len(glob) {
		ch := glob[i]
		// Check for "**" before "*"
		if ch == '*' && i+1 < len(glob) && glob[i+1] == '*' {
			sb.WriteString(".*")
			i += 2
			continue
		}
		switch ch {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteByte('.')
		case '.':
			sb.WriteString("\\.")
		default:
			sb.WriteByte(ch)
		}
		i++
	}
	return sb.String()
}

// ---- AgentWall v2 converter ----

func convertAgentWall(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var file agentWallFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("parse AgentWall YAML: %w", err)
	}

	manifests := make([]aegisManifest, 0)
	comments := make([]string, 0)

	for _, tool := range file.Tools {
		severity := normalizeAgentWallRisk(tool.Risk)

		if strings.ToLower(tool.Action) == "deny" {
			id := fmt.Sprintf("agentwall-%s-deny", sanitizeID(tool.Name))
			m := aegisManifest{
				APIVersion: "nixis.io/v1",
				Kind:       "PolicyTemplate",
				Metadata: aegisMetadata{
					Name: id,
					Annotations: map[string]string{
						"nixis.io/imported-from": filepath.Base(sourcePath),
						"nixis.io/severity":      severity,
					},
				},
				Spec: aegisPolicySpec{
					Description: fmt.Sprintf("AgentWall deny rule for tool %s", tool.Name),
					MatchConstraints: aegisMatchConstraints{
						Tools: []string{},
					},
					Validations: []aegisValidation{
						{
							Expression: fmt.Sprintf(`tool == %q`, tool.Name),
							Message:    fmt.Sprintf("Tool %s is denied by AgentWall policy", tool.Name),
							Action:     "DENY",
						},
					},
					DefaultAction: "ALLOW",
				},
			}
			manifests = append(manifests, m)
			comments = append(comments, "")
			continue
		}

		// action: allow with parameter schema constraints
		for _, param := range tool.Parameters {
			schema, _ := param.Schema["properties"].(map[string]interface{})
			required, _ := param.Schema["required"].([]interface{})

			for fieldName, fieldDef := range schema {
				fieldMap, ok := fieldDef.(map[string]interface{})
				if !ok {
					continue
				}

				cels, comment := agentWallFieldCEL(tool.Name, param.Name, fieldName, fieldMap)
				for _, cel := range cels {
					id := fmt.Sprintf("agentwall-%s-%s-%s", sanitizeID(tool.Name), sanitizeID(param.Name), sanitizeID(fieldName))
					m := aegisManifest{
						APIVersion: "nixis.io/v1",
						Kind:       "PolicyTemplate",
						Metadata: aegisMetadata{
							Name: id,
							Annotations: map[string]string{
								"nixis.io/imported-from": filepath.Base(sourcePath),
								"nixis.io/severity":      severity,
							},
						},
						Spec: aegisPolicySpec{
							Description: fmt.Sprintf("AgentWall constraint: %s.%s.%s", tool.Name, param.Name, fieldName),
							MatchConstraints: aegisMatchConstraints{
								Tools: []string{tool.Name},
							},
							Validations: []aegisValidation{
								{
									Expression: cel,
									Message:    fmt.Sprintf("AgentWall constraint violation on %s.%s", param.Name, fieldName),
									Action:     "DENY",
								},
							},
							DefaultAction: "ALLOW",
						},
					}
					manifests = append(manifests, m)
					comments = append(comments, comment)
				}
			}

			// Required field checks
			for _, req := range required {
				reqStr, ok := req.(string)
				if !ok {
					continue
				}
				id := fmt.Sprintf("agentwall-%s-%s-required-%s", sanitizeID(tool.Name), sanitizeID(param.Name), sanitizeID(reqStr))
				cel := fmt.Sprintf(`tool == %q && request.args.%s == ""`, tool.Name, reqStr)
				m := aegisManifest{
					APIVersion: "nixis.io/v1",
					Kind:       "PolicyTemplate",
					Metadata: aegisMetadata{
						Name: id,
						Annotations: map[string]string{
							"nixis.io/imported-from": filepath.Base(sourcePath),
							"nixis.io/severity":      severity,
						},
					},
					Spec: aegisPolicySpec{
						Description: fmt.Sprintf("AgentWall required field: %s.%s.%s", tool.Name, param.Name, reqStr),
						MatchConstraints: aegisMatchConstraints{
							Tools: []string{tool.Name},
						},
						Validations: []aegisValidation{
							{
								Expression: cel,
								Message:    fmt.Sprintf("Required field %s is missing", reqStr),
								Action:     "DENY",
							},
						},
						DefaultAction: "ALLOW",
					},
				}
				manifests = append(manifests, m)
				comments = append(comments, "")
			}
		}
	}

	return manifests, comments, nil
}

func agentWallFieldCEL(toolName, paramName, fieldName string, fieldDef map[string]interface{}) ([]string, string) {
	fieldType, _ := fieldDef["type"].(string)
	var cels []string
	var comment string

	switch fieldType {
	case "string":
		if pattern, ok := fieldDef["pattern"].(string); ok {
			cels = append(cels, fmt.Sprintf(`tool == %q && request.args.%s.matches(%q)`, toolName, fieldName, pattern))
		}
	case "integer", "number":
		if max, ok := fieldDef["maximum"]; ok {
			cels = append(cels, fmt.Sprintf(`tool == %q && request.args.%s > %v`, toolName, fieldName, max))
		}
		if min, ok := fieldDef["minimum"]; ok {
			cels = append(cels, fmt.Sprintf(`tool == %q && request.args.%s < %v`, toolName, fieldName, min))
		}
	default:
		comment = fmt.Sprintf("IMPORT_TODO: unsupported schema type %q for field %s — manual review required", fieldType, fieldName)
		cels = append(cels, "false")
	}

	return cels, comment
}

func normalizeAgentWallRisk(risk string) string {
	switch strings.ToLower(risk) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// ---- mcp-visor converter ----

func convertMCPVisor(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var file mcpVisorFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("parse mcp-visor YAML: %w", err)
	}

	manifests := make([]aegisManifest, 0)
	comments := make([]string, 0)

	// deny_path rules
	for i, pattern := range file.DenyPath {
		id := fmt.Sprintf("mcpvisor-deny-path-%03d", i+1)
		cel := fmt.Sprintf(`tool.matches("Read|Write|Edit") && request.args.path.matches(%q)`, pattern)
		m := newMCPVisorManifest(id, "Deny path: "+pattern, cel, "DENY", "high", filepath.Base(sourcePath))
		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	// allow_path rules — deny anything NOT in the allow list (REQUIRE_APPROVAL)
	for i, pattern := range file.AllowPath {
		id := fmt.Sprintf("mcpvisor-require-approval-path-%03d", i+1)
		cel := fmt.Sprintf(`tool.matches("Read|Write|Edit") && !request.args.path.matches(%q)`, pattern)
		m := newMCPVisorManifest(id, "Require approval for paths not matching: "+pattern, cel, "REQUIRE_APPROVAL", "medium", filepath.Base(sourcePath))
		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	// deny_command_pattern rules
	for i, pattern := range file.DenyCommandPattern {
		id := fmt.Sprintf("mcpvisor-deny-cmd-%03d", i+1)
		cel := fmt.Sprintf(`tool == "Bash" && request.args.command.matches(%q)`, pattern)
		m := newMCPVisorManifest(id, "Deny command pattern: "+pattern, cel, "DENY", "high", filepath.Base(sourcePath))
		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	// deny_query_pattern rules
	for i, pattern := range file.DenyQueryPattern {
		id := fmt.Sprintf("mcpvisor-deny-query-%03d", i+1)
		cel := fmt.Sprintf(`request.args.query.matches(%q)`, pattern)
		m := newMCPVisorManifest(id, "Deny query pattern: "+pattern, cel, "DENY", "high", filepath.Base(sourcePath))
		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	// max_file_size and max_rows are skipped — no CEL function available
	if file.MaxFileSize > 0 {
		comments = appendSkipComment(comments, "IMPORT_TODO: max_file_size constraint skipped — no file size CEL function currently available")
	}
	if file.MaxRows > 0 {
		comments = appendSkipComment(comments, "IMPORT_TODO: max_rows constraint skipped — no row count CEL function currently available")
	}

	return manifests, comments, nil
}

func newMCPVisorManifest(id, desc, cel, action, severity, source string) aegisManifest {
	return aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name: id,
			Annotations: map[string]string{
				"nixis.io/imported-from": source,
				"nixis.io/severity":      severity,
			},
		},
		Spec: aegisPolicySpec{
			Description: desc,
			MatchConstraints: aegisMatchConstraints{
				Tools: []string{},
			},
			Validations: []aegisValidation{
				{
					Expression: cel,
					Message:    desc,
					Action:     action,
				},
			},
			DefaultAction: "ALLOW",
		},
	}
}

func appendSkipComment(comments []string, msg string) []string {
	if len(comments) > 0 {
		comments[len(comments)-1] = msg
	}
	return comments
}

// ---- Checkov converter ----

// resourceToFilePattern maps Checkov resource_types to file path regex patterns.
var resourceToFilePattern = map[string]string{
	"aws_s3_bucket":           `\.tf$`,
	"aws_iam_policy":          `\.tf$|policy\.json$`,
	"aws_security_group":      `\.tf$`,
	"aws_instance":            `\.tf$`,
	"aws_lambda_function":     `\.tf$`,
	"aws_rds_instance":        `\.tf$`,
	"aws_kms_key":             `\.tf$`,
	"kubernetes_deployment":   `\.yaml$|\.yml$`,
	"kubernetes_pod":          `\.yaml$|\.yml$`,
	"kubernetes_container":    `\.yaml$|\.yml$`,
	"kubernetes_daemonset":    `\.yaml$|\.yml$`,
	"kubernetes_statefulset":  `\.yaml$|\.yml$`,
	"kubernetes_job":          `\.yaml$|\.yml$`,
	"kubernetes_cronjob":      `\.yaml$|\.yml$`,
	"dockerfile":              `(?i)[Dd]ockerfile`,
	"cloudformation":          `\.yaml$|\.json$|\.template$`,
	"helm":                    `values\.yaml$|Chart\.yaml$`,
	"terraform":               `\.tf$|\.tfvars$`,
	"docker_container":        `(?i)[Dd]ockerfile|docker-compose\.yml$`,
	"azurerm_storage_account": `\.tf$`,
	"google_storage_bucket":   `\.tf$`,
}

// convertCheckov translates a single Checkov YAML custom policy file.
func convertCheckov(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var file checkovFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("parse Checkov YAML: %w", err)
	}

	id := sanitizeID(file.Metadata.ID)
	if id == "" {
		id = "checkov-unknown"
	}
	name := file.Metadata.Name
	if name == "" {
		name = file.Metadata.ID
	}

	var manifests []aegisManifest
	var comments []string

	// Determine file pattern from resource_types (use first known mapping)
	filePattern := checkovFilePattern(file.Definition.ResourceTypes)

	// Handle logical and/or at top level (depth-1 only; deeper → IMPORT_TODO)
	if len(file.Definition.And) > 0 || len(file.Definition.Or) > 0 {
		cels, comment := translateCheckovLogical(&file.Definition, filePattern, file.Metadata.ID)
		if comment != "" {
			comments = append(comments, comment)
		} else {
			comments = append(comments, "")
		}
		for _, cel := range cels {
			m := checkovManifest(id, name, file.Metadata.Category, cel, "DENY", filepath.Base(sourcePath), file.Metadata.ID)
			manifests = append(manifests, m)
		}
		return manifests, comments, nil
	}

	// Flat condition
	cel, comment, action := translateCheckovCondition(&file.Definition, filePattern)
	manifests = append(manifests, checkovManifest(id, name, file.Metadata.Category, cel, action, filepath.Base(sourcePath), file.Metadata.ID))
	comments = append(comments, comment)

	return manifests, comments, nil
}

// checkovFilePattern returns the combined file pattern for a list of resource_types.
func checkovFilePattern(resourceTypes []string) string {
	seen := map[string]bool{}
	var patterns []string
	for _, rt := range resourceTypes {
		if p, ok := resourceToFilePattern[strings.ToLower(rt)]; ok && !seen[p] {
			patterns = append(patterns, p)
			seen[p] = true
		}
	}
	if len(patterns) == 0 {
		return `.*`
	}
	if len(patterns) == 1 {
		return patterns[0]
	}
	return strings.Join(patterns, "|")
}

// translateCheckovCondition translates a single flat Checkov condition to CEL.
func translateCheckovCondition(def *checkovDefinition, filePattern string) (cel, comment, action string) {
	attr := def.Attribute
	op := def.Operator
	val := def.Value

	switch op {
	case "exists":
		// Content SHOULD contain the attribute name
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.contains(%q)`,
			filePattern, attr,
		)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: exists check is approximate — verifies string presence of %q in file content", attr)
		return

	case "not_exists":
		// Content must NOT contain the attribute
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.contains(%q)`,
			filePattern, attr,
		)
		action = "DENY"
		return

	case "equals":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: equals check looks for string %q — may need more precise matching", val)
		return

	case "not_equals":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: not_equals check looks for absence of %q — may need more precise matching", val)
		return

	case "contains":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "DENY"
		return

	case "not_contains":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "DENY"
		return

	case "regex_match":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.matches(%q)`,
			filePattern, val,
		)
		action = "DENY"
		return

	case "not_regex_match":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.matches(%q)`,
			filePattern, val,
		)
		action = "AUDIT"
		return

	case "starting_with":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "DENY"
		comment = fmt.Sprintf("IMPORT_TODO: starting_with translated as content.contains(%q) — verify pattern", val)
		return

	case "not_starting_with":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: not_starting_with translated as !content.contains(%q) — verify pattern", val)
		return

	case "ending_with":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "DENY"
		comment = fmt.Sprintf("IMPORT_TODO: ending_with translated as content.contains(%q) — verify pattern", val)
		return

	case "not_ending_with":
		cel = fmt.Sprintf(
			`request.args.path.matches(%q) && !request.args.content.contains(%q)`,
			filePattern, val,
		)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: not_ending_with translated as !content.contains(%q) — verify pattern", val)
		return

	case "greater_than", "less_than", "greater_than_or_equal", "less_than_or_equal":
		cel = "false"
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: numeric operator %q requires value parsing — manual review required for attribute %q", op, attr)
		return

	case "within":
		cel = fmt.Sprintf(`request.args.path.matches(%q) && !request.args.content.contains(%q)`, filePattern, val)
		action = "AUDIT"
		comment = fmt.Sprintf("IMPORT_TODO: within operator translated as content.contains(%q) — verify allowed set", val)
		return

	case "not_within":
		cel = fmt.Sprintf(`request.args.path.matches(%q) && request.args.content.contains(%q)`, filePattern, val)
		action = "DENY"
		comment = fmt.Sprintf("IMPORT_TODO: not_within operator translated as content.contains(%q) — verify denied set", val)
		return
	}

	// Unknown operator
	cel = "false"
	action = "AUDIT"
	comment = fmt.Sprintf("IMPORT_TODO: unsupported Checkov operator %q — manual review required", op)
	return
}

// translateCheckovLogical handles and/or logical groups (one level deep only).
func translateCheckovLogical(def *checkovDefinition, filePattern, policyID string) ([]string, string) {
	conditions := def.And
	if len(conditions) == 0 {
		conditions = def.Or
	}

	var cels []string
	var todos []string

	for i := range conditions {
		child := &conditions[i]
		// Reject deeper nesting
		if len(child.And) > 0 || len(child.Or) > 0 {
			return []string{"false"}, fmt.Sprintf("IMPORT_TODO: %s has nested and/or deeper than 1 level — manual review required", policyID)
		}
		fp := checkovFilePattern(child.ResourceTypes)
		if fp == `.*` {
			fp = filePattern
		}
		cel, comment, _ := translateCheckovCondition(child, fp)
		cels = append(cels, cel)
		if comment != "" {
			todos = append(todos, comment)
		}
	}

	combined := strings.Join(cels, " && ")
	if len(def.Or) > 0 {
		combined = strings.Join(cels, " || ")
	}

	return []string{combined}, strings.Join(todos, "; ")
}

func checkovManifest(id, name, category, cel, action, source, originalID string) aegisManifest {
	severity := "medium"
	cat := strings.ToLower(category)
	if strings.Contains(cat, "encryption") || strings.Contains(cat, "iam") || strings.Contains(cat, "secret") {
		severity = "high"
	}
	return aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name: id,
			Annotations: map[string]string{
				"nixis.io/imported-from":  source,
				"nixis.io/severity":       severity,
				"nixis.io/checkov-id":     originalID,
				"nixis.io/checkov-source": "checkov-custom-policy",
			},
		},
		Spec: aegisPolicySpec{
			Description: name,
			MatchConstraints: aegisMatchConstraints{
				Tools: []string{"Write", "Edit"},
			},
			Validations: []aegisValidation{
				{
					Expression: cel,
					Message:    fmt.Sprintf("Checkov policy %s: %s", originalID, name),
					Action:     action,
				},
			},
			DefaultAction: "ALLOW",
		},
	}
}

// ---- catalog generate-from-catalog command ----

var generateCatalogOutDir string

var generateFromCatalogCmd = &cobra.Command{
	Use:   "generate-from-catalog",
	Short: "Generate Nixis policies from pkg/adapters/catalog.json for high and critical risk entries",
	Long: `Reads pkg/adapters/catalog.json and generates Nixis PolicyTemplate YAML files
for every entry with risk_level "high" or "critical".

Example:
  nixis policy generate-from-catalog --out policies/imported/catalog-generated/`,
	Args: cobra.NoArgs,
	RunE: runGenerateFromCatalog,
}

func init() {
	generateFromCatalogCmd.Flags().StringVar(&generateCatalogOutDir, "out", "./policies/imported/catalog-generated", "Output directory for generated policies")
	generateFromCatalogCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Print generated policies without writing files")
	policyCmd.AddCommand(generateFromCatalogCmd)
}

func runGenerateFromCatalog(cmd *cobra.Command, _ []string) error {
	// Resolve catalog path relative to cwd or standard location
	catalogPath := "pkg/adapters/catalog.json"
	if _, err := os.Stat(catalogPath); os.IsNotExist(err) {
		// Try searching up two levels
		catalogPath = "../../pkg/adapters/catalog.json"
		if _, err2 := os.Stat(catalogPath); os.IsNotExist(err2) {
			return fmt.Errorf("catalog.json not found at pkg/adapters/catalog.json or ../../pkg/adapters/catalog.json")
		}
	}

	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return fmt.Errorf("read catalog: %w", err)
	}

	var entries []catalogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parse catalog JSON: %w", err)
	}

	manifests, comments := generateCatalogPolicies(entries)

	if importDryRun {
		if err := printDryRun(cmd, manifests, comments); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# generated %d policies from catalog\n", len(manifests))
		return nil
	}

	if err := os.MkdirAll(generateCatalogOutDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	for i, m := range manifests {
		filename := m.Metadata.Name + ".yaml"
		outPath := filepath.Join(generateCatalogOutDir, filename)

		yamlData, err := yaml.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal policy %s: %w", m.Metadata.Name, err)
		}

		var content strings.Builder
		if i < len(comments) && comments[i] != "" {
			content.WriteString("# ")
			content.WriteString(comments[i])
			content.WriteString("\n")
		}
		content.WriteString("# auto-generated from pkg/adapters/catalog.json via nixis policy generate-from-catalog\n")
		content.Write(yamlData)

		if err := os.WriteFile(outPath, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outPath)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "generated %d policies to %s\n", len(manifests), generateCatalogOutDir)
	return nil
}

// generateCatalogPolicies creates Nixis manifests for high/critical catalog entries.
func generateCatalogPolicies(entries []catalogEntry) ([]aegisManifest, []string) {
	var manifests []aegisManifest
	var comments []string

	for _, e := range entries {
		if e.RiskLevel != "high" && e.RiskLevel != "critical" {
			continue
		}

		id := "catalog-auto-" + sanitizeID(e.Tool)
		toolName := e.Tool
		action := "REQUIRE_APPROVAL"
		if e.RiskLevel == "critical" {
			action = "DENY"
		}

		// Build CEL: for Bash family tools check command prefix, others check tool name
		var cel string
		if e.Family == "bash" {
			cel = fmt.Sprintf(`tool == "Bash" && request.args.command.startsWith(%q)`, toolName)
		} else {
			cel = fmt.Sprintf(`tool == %q`, toolName)
		}

		desc := fmt.Sprintf("Require approval for %s (%s risk level: %s)", toolName, e.Family, e.RiskLevel)
		if action == "DENY" {
			desc = fmt.Sprintf("Deny critically-risky %s (%s)", toolName, e.Family)
		}

		m := aegisManifest{
			APIVersion: "nixis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: id,
				Annotations: map[string]string{
					"nixis.io/source":     "pkg/adapters/catalog.json",
					"nixis.io/risk-level": e.RiskLevel,
					"nixis.io/family":     e.Family,
					"nixis.io/severity":   e.RiskLevel,
				},
			},
			Spec: aegisPolicySpec{
				Description: desc,
				MatchConstraints: aegisMatchConstraints{
					Tools: []string{"Bash"},
				},
				Validations: []aegisValidation{
					{
						Expression: cel,
						Message:    fmt.Sprintf("%s is classified as %s risk — approval required", toolName, e.RiskLevel),
						Action:     action,
					},
				},
				DefaultAction: "ALLOW",
			},
		}
		manifests = append(manifests, m)
		comments = append(comments, "")
	}

	return manifests, comments
}

// ---- rule translation helpers ----

var responseSizeRegex = regexp.MustCompile(`^response_size_bytes\s*([><=!]+)\s*(\d+)$`)
var toolNameRegex = regexp.MustCompile(`^tool_name\s*==\s*"([^"]+)"$`)

func translateRule(rule string) (cel string, comment string) {
	rule = strings.TrimSpace(rule)

	switch rule {
	case "tool_definition_changed":
		return `tool.name != "" && tool.fingerprint != tool.expected_fingerprint`, ""
	}

	if m := responseSizeRegex.FindStringSubmatch(rule); m != nil {
		op := m[1]
		val := m[2]
		return fmt.Sprintf("response.size %s %s", op, val),
			"IMPORT_TODO: response.size is a Phase 2 variable — verify this expression works in your deployment"
	}

	if m := toolNameRegex.FindStringSubmatch(rule); m != nil {
		return fmt.Sprintf(`tool == "%s"`, m[1]), ""
	}

	return "false", fmt.Sprintf("IMPORT_TODO: manual review required — rule '%s' could not be automatically translated", rule)
}

func normalizeAction(action string) string {
	switch strings.ToLower(action) {
	case "deny":
		return "DENY"
	case "audit":
		return "AUDIT"
	case "allow", "":
		return "ALLOW"
	default:
		return strings.ToUpper(action)
	}
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "":
		return "low"
	default:
		return strings.ToLower(severity)
	}
}

// sanitizeID replaces characters that are invalid in policy IDs with hyphens.
func sanitizeID(s string) string {
	var sb strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
			sb.WriteRune(ch)
		} else {
			sb.WriteByte('-')
		}
	}
	return strings.ToLower(sb.String())
}

// ---- LLM assist post-processing ----

// applyLLMAssist iterates over manifests and for each one whose comment contains an
// IMPORT_TODO marker, attempts LLM-assisted translation. On success the expression is
// replaced, the comment is updated to IMPORT_REVIEW, and llm-confidence is added.
// On failure the original expression and IMPORT_TODO comment are preserved.
//
// format is the human-readable source format name used in the LLM prompt and cache entry
// (e.g. "opa-gatekeeper", "sigma", "falco"). It may be empty.
func applyLLMAssist(ctx context.Context, manifests []aegisManifest, comments []string, format string) ([]aegisManifest, []string) {
	if !importLLMAssist {
		return manifests, comments
	}

	translator, err := NewLLMTranslator(importLLMModel, importLLMMaxRetries)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "llm-assist: failed to create translator: %v\n", err)
		return manifests, comments
	}

	for i := range manifests {
		comment := ""
		if i < len(comments) {
			comment = comments[i]
		}
		if !strings.Contains(comment, "IMPORT_TODO") {
			continue
		}
		if len(manifests[i].Spec.Validations) == 0 {
			continue
		}

		// Build a snippet from the policy name, format hint, and the current IMPORT_TODO comment.
		// This gives the LLM the context needed to generate a meaningful CEL expression.
		snippet := buildLLMSnippet(manifests[i], comment, format)

		celExpr, attempts, translateErr := translator.Translate(ctx, snippet, format)
		if translateErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "llm-assist: %s: %v (keeping IMPORT_TODO)\n",
				manifests[i].Metadata.Name, translateErr)
			continue
		}

		// Replace the expression with the LLM-generated one.
		manifests[i].Spec.Validations[0].Expression = celExpr

		// Add llm-confidence annotation.
		if manifests[i].Metadata.Annotations == nil {
			manifests[i].Metadata.Annotations = make(map[string]string)
		}
		manifests[i].Metadata.Annotations["nixis.io/llm-confidence"] = "medium"

		// Replace IMPORT_TODO comment with IMPORT_REVIEW.
		reviewComment := fmt.Sprintf("IMPORT_REVIEW: LLM-translated from %s — verify semantics (attempts: %d)", format, attempts)
		if i < len(comments) {
			comments[i] = reviewComment
		}
	}

	return manifests, comments
}

// buildLLMSnippet constructs a natural-language description of what the policy should
// do, combining the manifest name, description, IMPORT_TODO comment, and source format.
// This is the text sent to the LLM as the snippet to translate.
func buildLLMSnippet(m aegisManifest, comment, format string) string {
	var sb strings.Builder
	if m.Metadata.Name != "" {
		sb.WriteString("Policy name: ")
		sb.WriteString(m.Metadata.Name)
		sb.WriteString("\n")
	}
	if m.Spec.Description != "" {
		sb.WriteString("Description: ")
		sb.WriteString(m.Spec.Description)
		sb.WriteString("\n")
	}
	if format != "" {
		sb.WriteString("Source format: ")
		sb.WriteString(format)
		sb.WriteString("\n")
	}
	if len(m.Spec.Validations) > 0 {
		if msg := m.Spec.Validations[0].Message; msg != "" {
			sb.WriteString("Original message: ")
			sb.WriteString(msg)
			sb.WriteString("\n")
		}
	}
	if comment != "" {
		sb.WriteString("Translation note: ")
		sb.WriteString(comment)
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}

// ---- output helpers ----

func printDryRun(cmd *cobra.Command, manifests []aegisManifest, comments []string) error {
	for i, m := range manifests {
		if i < len(comments) && comments[i] != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# %s\n", comments[i])
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# imported from: %s via nixis policy import\n",
			m.Metadata.Annotations["nixis.io/imported-from"])

		data, err := yaml.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal policy %s: %w", m.Metadata.Name, err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n---\n", data)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# dry-run: would create %d policy files in %s\n", len(manifests), importOutDir)
	return nil
}

func writeManifests(cmd *cobra.Command, manifests []aegisManifest, comments []string, sourcePath string) error {
	if err := os.MkdirAll(importOutDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	for i, m := range manifests {
		filename := m.Metadata.Name + ".yaml"
		outPath := filepath.Join(importOutDir, filename)

		data, err := yaml.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal policy %s: %w", m.Metadata.Name, err)
		}

		var content strings.Builder
		if i < len(comments) && comments[i] != "" {
			// Format multi-line comments: prefix each line with "# "
			for _, line := range strings.Split(comments[i], "\n") {
				content.WriteString("# ")
				content.WriteString(line)
				content.WriteString("\n")
			}
		}
		content.WriteString("# imported from: ")
		content.WriteString(filepath.Base(sourcePath))
		content.WriteString(" via nixis policy import\n")
		content.Write(data)

		if err := os.WriteFile(outPath, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outPath)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %d policies to %s\n", len(manifests), importOutDir)
	return nil
}

// ---- Sigma translator ----

type sigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}
type sigmaDetection struct {
	Condition string `yaml:"condition"`
	// Remaining fields are selection groups parsed dynamically
}

// ---- output structs ----
type sigmaRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Level          string         `yaml:"level"`
	Tags           []string       `yaml:"tags"`
	Logsource      sigmaLogsource `yaml:"logsource"`
	Detection      sigmaDetection `yaml:"detection"`
	Falsepositives []string       `yaml:"falsepositives"`
}

func convertSigma(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var rule sigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, nil, fmt.Errorf("parse Sigma YAML: %w", err)
	}

	// Parse detection as raw map to get selection groups
	var detectionRaw map[string]interface{}
	var rawRule struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if err := yaml.Unmarshal(data, &rawRule); err != nil {
		return nil, nil, fmt.Errorf("parse Sigma detection: %w", err)
	}
	detectionRaw = rawRule.Detection

	condition, _ := detectionRaw["condition"].(string)
	if condition == "" {
		return nil, nil, fmt.Errorf("sigma rule missing detection.condition")
	}

	cel, comment := translateSigmaDetection(detectionRaw, condition)
	action := sigmaLevelToAction(rule.Level)
	tools := sigmaLogsourceToTools(rule.Logsource)

	id := sanitizeID(rule.ID)
	if id == "" {
		id = sanitizeID(rule.Title)
	}
	if id == "" {
		id = "sigma-" + sanitizeID(filepath.Base(sourcePath))
	}

	desc := rule.Description
	if desc == "" {
		desc = rule.Title
	}

	severity := sigmaLevelToSeverity(rule.Level)

	annotations := map[string]string{
		"nixis.io/imported-from": filepath.Base(sourcePath),
		"nixis.io/severity":      severity,
		"nixis.io/source-format": "sigma",
	}
	if rule.ID != "" {
		annotations["nixis.io/sigma-id"] = rule.ID
	}
	if len(rule.Tags) > 0 {
		annotations["nixis.io/sigma-tags"] = strings.Join(rule.Tags, ",")
	}

	m := aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name:        id,
			Annotations: annotations,
		},
		Spec: aegisPolicySpec{
			Description: desc,
			MatchConstraints: aegisMatchConstraints{
				Tools: tools,
			},
			Validations: []aegisValidation{
				{
					Expression: cel,
					Message:    fmt.Sprintf("Sigma: %s", rule.Title),
					Action:     action,
				},
			},
			DefaultAction: "ALLOW",
		},
	}

	return []aegisManifest{m}, []string{comment}, nil
}
func buildSigmaOneOf(pattern string, selections map[string]string) (string, string) {
	pattern = strings.TrimSpace(pattern)

	if pattern == "them" || pattern == "*" {
		var cels []string
		for _, cel := range selections {
			if cel != "" && cel != "true" {
				cels = append(cels, cel)
			}
		}
		if len(cels) == 0 {
			return "true", "IMPORT_TODO: no valid selections for '1 of them'"
		}
		return "(" + strings.Join(cels, " || ") + ")", ""
	}

	prefix := strings.TrimSuffix(pattern, "*")
	var cels []string
	for name, cel := range selections {
		if strings.HasPrefix(name, prefix) && cel != "" && cel != "true" {
			cels = append(cels, cel)
		}
	}
	if len(cels) == 0 {
		return "true", fmt.Sprintf("IMPORT_TODO: no selections match pattern %q", pattern)
	}
	return "(" + strings.Join(cels, " || ") + ")", ""
}
func sigmaToCELField(field string) string {
	field = strings.ToLower(field)
	switch field {
	case "commandline", "command_line", "cmd":
		return "request.args.command"
	case "image", "parentimage", "originalfilename", "currentdirectory":
		return ""
	case "user", "username", "accountname":
		return ""
	case "targetfilename", "filepath", "filename", "path":
		return "request.args.file_path"
	case "destinationip", "destinationhostname", "destinationport":
		return ""
	case "sourceip", "sourcehostname", "sourceport":
		return ""
	case "hashes", "md5", "sha1", "sha256", "imphash":
		return ""
	case "processid", "parentprocessid", "pid", "ppid":
		return ""
	case "queryname", "query":
		return "request.args.query"
	default:
		return ""
	}
}
func translateSigmaField(fieldModifier string, val interface{}) (cel string, comment string) {
	parts := strings.Split(fieldModifier, "|")
	fieldName := parts[0]
	modifiers := parts[1:]

	celField := sigmaToCELField(fieldName)
	if celField == "" {
		return "", fmt.Sprintf("IMPORT_TODO: field %q cannot be mapped to Nixis context", fieldName)
	}

	values := extractSigmaValues(val)
	if len(values) == 0 {
		return "", fmt.Sprintf("IMPORT_TODO: field %q has no values", fieldName)
	}

	matchAll := false
	matchType := "contains"

	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "contains":
			matchType = "contains"
		case "startswith":
			matchType = "startswith"
		case "endswith":
			matchType = "endswith"
		case "re":
			matchType = "regex"
		case "all":
			matchAll = true
		case "base64offset", "windash", "wide", "base64", "cidr":
			return "", fmt.Sprintf("IMPORT_TODO: modifier |%s not supported", mod)
		}
	}

	var exprs []string
	for _, v := range values {
		expr := buildSigmaFieldExpr(celField, v, matchType)
		exprs = append(exprs, expr)
	}

	if len(exprs) == 0 {
		return "true", ""
	}

	if matchAll || len(exprs) == 1 {
		return strings.Join(exprs, " && "), ""
	}

	return "(" + strings.Join(exprs, " || ") + ")", ""
}
func sigmaLevelToAction(level string) string {
	switch strings.ToLower(level) {
	case "critical", "high":
		return "DENY"
	case "medium":
		return "REQUIRE_APPROVAL"
	default:
		return "AUDIT"
	}
}
func escapeStringForCEL(s string) string {
	return strings.ReplaceAll(s, `\`, `\\`)
}
func translateSigmaSelection(name string, val interface{}) (cel string, comment string) {
	valMap, isMap := val.(map[string]interface{})
	if !isMap {
		return "true", fmt.Sprintf("IMPORT_TODO: selection %q has unsupported format", name)
	}

	var conditions []string
	var comments []string

	for fieldModifier, fieldVal := range valMap {
		fieldCEL, fieldComment := translateSigmaField(fieldModifier, fieldVal)
		if fieldCEL != "" {
			conditions = append(conditions, fieldCEL)
		}
		if fieldComment != "" {
			comments = append(comments, fieldComment)
		}
	}

	if len(conditions) == 0 {
		return "true", strings.Join(comments, "; ")
	}

	cel = strings.Join(conditions, " && ")
	if len(comments) > 0 {
		comment = strings.Join(comments, "; ")
	}
	return cel, comment
}
func extractSigmaValues(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}
func sigmaLogsourceToTools(ls sigmaLogsource) []string {
	switch strings.ToLower(ls.Category) {
	case "process_creation":
		return []string{"Bash"}
	case "file_event", "file_access", "file_delete", "file_rename", "file_change":
		return []string{"Read", "Write", "Edit"}
	case "network_connection", "dns_query", "firewall":
		return []string{"Bash"}
	default:
		return []string{}
	}
}
func sigmaLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "informational", "":
		return "low"
	default:
		return "low"
	}
}
func buildSigmaAllOf(pattern string, selections map[string]string) (string, string) {
	pattern = strings.TrimSpace(pattern)

	if pattern == "them" || pattern == "*" {
		var cels []string
		for _, cel := range selections {
			if cel != "" && cel != "true" {
				cels = append(cels, cel)
			}
		}
		if len(cels) == 0 {
			return "true", "IMPORT_TODO: no valid selections for 'all of them'"
		}
		return strings.Join(cels, " && "), ""
	}

	prefix := strings.TrimSuffix(pattern, "*")
	var cels []string
	for name, cel := range selections {
		if strings.HasPrefix(name, prefix) && cel != "" && cel != "true" {
			cels = append(cels, cel)
		}
	}
	if len(cels) == 0 {
		return "true", fmt.Sprintf("IMPORT_TODO: no selections match pattern %q", pattern)
	}
	return strings.Join(cels, " && "), ""
}

// ---- rule translation helpers ----
func translateSigmaDetection(detection map[string]interface{}, condition string) (cel string, comment string) {
	selections := make(map[string]string)
	var comments []string

	for key, val := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		selCEL, selComment := translateSigmaSelection(key, val)
		selections[key] = selCEL
		if selComment != "" {
			comments = append(comments, selComment)
		}
	}

	resultCEL, condComment := translateSigmaCondition(condition, selections)
	if condComment != "" {
		comments = append(comments, condComment)
	}

	if len(comments) > 0 {
		comment = strings.Join(comments, "; ")
	}

	return resultCEL, comment
}
func translateSigmaCondition(condition string, selections map[string]string) (cel string, comment string) {
	condition = strings.TrimSpace(condition)

	if sel, ok := selections[condition]; ok {
		return sel, ""
	}

	if strings.HasPrefix(condition, "1 of ") {
		pattern := strings.TrimPrefix(condition, "1 of ")
		return buildSigmaOneOf(pattern, selections)
	}

	if strings.HasPrefix(condition, "all of ") {
		pattern := strings.TrimPrefix(condition, "all of ")
		return buildSigmaAllOf(pattern, selections)
	}

	if strings.Contains(condition, " and not ") {
		parts := strings.SplitN(condition, " and not ", 2)
		if len(parts) == 2 {
			selCEL, selExists := selections[strings.TrimSpace(parts[0])]
			filterCEL, filterExists := selections[strings.TrimSpace(parts[1])]
			if selExists && filterExists {
				return fmt.Sprintf("(%s) && !(%s)", selCEL, filterCEL), ""
			}
		}
	}

	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		var cels []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "not ") {
				inner := strings.TrimPrefix(p, "not ")
				if sel, ok := selections[inner]; ok {
					cels = append(cels, fmt.Sprintf("!(%s)", sel))
				}
			} else if sel, ok := selections[p]; ok {
				cels = append(cels, sel)
			}
		}
		if len(cels) > 0 {
			return strings.Join(cels, " && "), ""
		}
	}

	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		var cels []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if sel, ok := selections[p]; ok {
				cels = append(cels, sel)
			}
		}
		if len(cels) > 0 {
			return "(" + strings.Join(cels, " || ") + ")", ""
		}
	}

	return "true", fmt.Sprintf("IMPORT_TODO: complex condition %q requires manual translation", condition)
}
func buildSigmaFieldExpr(field, value, matchType string) string {
	escaped := escapeStringForCEL(value)
	switch matchType {
	case "contains":
		return fmt.Sprintf(`%s.contains(%q)`, field, escaped)
	case "startswith":
		return fmt.Sprintf(`%s.startsWith(%q)`, field, escaped)
	case "endswith":
		return fmt.Sprintf(`%s.endsWith(%q)`, field, escaped)
	case "regex":
		return fmt.Sprintf(`%s.matches(%q)`, field, escaped)
	default:
		return fmt.Sprintf(`%s.contains(%q)`, field, escaped)
	}
}

// ---- Kyverno translator ----

type kyvernoConditionSet struct {
	Any []kyvernoCondition `yaml:"any"`
	All []kyvernoCondition `yaml:"all"`
}
type kyvernoMatchResource struct {
	Resources kyvernoResources `yaml:"resources"`
}
type kyvernoResources struct {
	Kinds      []string `yaml:"kinds"`
	Operations []string `yaml:"operations"`
	Namespaces []string `yaml:"namespaces"`
}
type kyvernoPolicySpec struct {
	ValidationFailureAction string        `yaml:"validationFailureAction"`
	Rules                   []kyvernoRule `yaml:"rules"`
}
type kyvernoMatch struct {
	Any []kyvernoMatchResource `yaml:"any"`
	All []kyvernoMatchResource `yaml:"all"`
}
type kyvernoMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations"`
}
type kyvernoValidate struct {
	Message string      `yaml:"message"`
	Deny    kyvernoDeny `yaml:"deny"`
}
type kyvernoCondition struct {
	Key      string `yaml:"key"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

// ---- output structs ----
type kyvernoDeny struct {
	Conditions kyvernoConditionSet `yaml:"conditions"`
}
type kyvernoPolicy struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   kyvernoMetadata   `yaml:"metadata"`
	Spec       kyvernoPolicySpec `yaml:"spec"`
}
type kyvernoRule struct {
	Name     string                 `yaml:"name"`
	Match    kyvernoMatch           `yaml:"match"`
	Validate kyvernoValidate        `yaml:"validate"`
	Mutate   map[string]interface{} `yaml:"mutate"`
	Generate map[string]interface{} `yaml:"generate"`
}

func kyvernoKindToKubectlPattern(kind string, operations []string) string {
	// NOTE: Use \\s (double backslash) so the output YAML contains \s,
	// which CEL then passes to the RE2 regex engine as whitespace class.
	// Single \s in Go string → \s in YAML → CEL parse error (invalid escape).
	// Double \\s in Go string → \\s in YAML → CEL sees \s → RE2 whitespace match.
	kindMap := map[string]string{
		"Pod":              `kubectl.*(delete\\s+pod|exec|run)`,
		"Deployment":       `kubectl.*(delete\\s+deployment|scale|rollout)`,
		"Service":          `kubectl.*(delete\\s+service|expose)`,
		"ConfigMap":        `kubectl.*(delete\\s+configmap|create\\s+configmap)`,
		"Secret":           `kubectl.*(get\\s+secret|create\\s+secret)`,
		"Namespace":        `kubectl.*(delete\\s+namespace|create\\s+namespace)`,
		"ClusterRole":      `kubectl.*(create\\s+clusterrole|delete\\s+clusterrole)`,
		"Node":             `kubectl.*(drain|cordon|delete\\s+node)`,
		"PersistentVolume": `kubectl.*delete\\s+pv`,
	}

	opPatterns := map[string]string{
		"DELETE": `kubectl.*delete.*`,
		"CREATE": `kubectl.*(create|run|apply).*`,
		"UPDATE": `kubectl.*(patch|edit|set).*`,
	}

	// If operations are specified, derive pattern from operations
	if len(operations) > 0 {
		var parts []string
		seen := map[string]bool{}
		for _, op := range operations {
			if p, ok := opPatterns[strings.ToUpper(op)]; ok && !seen[p] {
				parts = append(parts, p)
				seen[p] = true
			}
		}
		if len(parts) == 1 {
			return parts[0]
		}
		if len(parts) > 1 {
			return strings.Join(parts, "|")
		}
	}

	// Fall back to kind-based pattern
	if p, ok := kindMap[kind]; ok {
		return p
	}
	return `kubectl.*`
}

// kyvernoSeverityToAction maps Kyverno annotation severity to Nixis action,
// potentially overriding the validationFailureAction-derived action.
func kyvernoImportTODO(id, reason, description, severity, category, source string) (aegisManifest, string) {
	annots := map[string]string{
		"nixis.io/imported-from": source,
		"nixis.io/severity":      severity,
	}
	if category != "" {
		annots["kyverno.io/category"] = category
	}
	m := aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name:        id,
			Annotations: annots,
		},
		Spec: aegisPolicySpec{
			Description: description,
			MatchConstraints: aegisMatchConstraints{
				Tools: []string{},
			},
			Validations: []aegisValidation{
				{
					Expression: "false",
					Message:    fmt.Sprintf("IMPORT_TODO: %s — manual review required", reason),
					Action:     "AUDIT",
				},
			},
			DefaultAction: "ALLOW",
		},
	}
	return m, fmt.Sprintf("IMPORT_TODO: %s", reason)
}
func kyvernoSeverityToAction(severity, baseAction string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "DENY"
	case "medium":
		if baseAction == "DENY" {
			return "DENY"
		}
		return "REQUIRE_APPROVAL"
	case "low":
		return "AUDIT"
	default:
		return baseAction
	}
}

// kyvernoValidationFailureActionToAction maps Kyverno's validationFailureAction to Nixis action.
func convertKyverno(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	var pol kyvernoPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, nil, fmt.Errorf("parse Kyverno YAML: %w", err)
	}

	annotations := pol.Metadata.Annotations
	severity := normalizeSeverity(annotations["policies.kyverno.io/severity"])
	category := annotations["policies.kyverno.io/category"]
	description := annotations["policies.kyverno.io/description"]
	if description == "" {
		description = pol.Metadata.Name
	}

	baseAction := kyvernoValidationFailureActionToAction(pol.Spec.ValidationFailureAction)

	manifests := make([]aegisManifest, 0)
	comments := make([]string, 0)

	for _, rule := range pol.Spec.Rules {
		// Skip non-validate rule types
		if len(rule.Mutate) > 0 {
			id := fmt.Sprintf("kyverno-%s-%s", sanitizeID(pol.Metadata.Name), sanitizeID(rule.Name))
			m, comment := kyvernoImportTODO(id, "mutate rule — Nixis does not mutate requests",
				description, severity, category, filepath.Base(sourcePath))
			manifests = append(manifests, m)
			comments = append(comments, comment)
			continue
		}
		if len(rule.Generate) > 0 {
			id := fmt.Sprintf("kyverno-%s-%s", sanitizeID(pol.Metadata.Name), sanitizeID(rule.Name))
			m, comment := kyvernoImportTODO(id, "generate rule — Nixis does not generate resources",
				description, severity, category, filepath.Base(sourcePath))
			manifests = append(manifests, m)
			comments = append(comments, comment)
			continue
		}

		// Collect all matched resources across any/all
		allResources := append(rule.Match.Any, rule.Match.All...)
		if len(allResources) == 0 {
			id := fmt.Sprintf("kyverno-%s-%s", sanitizeID(pol.Metadata.Name), sanitizeID(rule.Name))
			m, comment := kyvernoImportTODO(id, "no match.any or match.all resources found",
				description, severity, category, filepath.Base(sourcePath))
			manifests = append(manifests, m)
			comments = append(comments, comment)
			continue
		}

		// Check if all deny conditions involve JMESPath — if so, still generate
		// a kubectl pattern match as the base but mark with IMPORT_TODO for conditions.
		allConditions := append(rule.Validate.Deny.Conditions.Any, rule.Validate.Deny.Conditions.All...)
		hasJMESPath := false
		for _, c := range allConditions {
			if kyvernoHasJMESPath(c.Key) {
				hasJMESPath = true
				break
			}
		}

		for _, matchRes := range allResources {
			for _, kind := range matchRes.Resources.Kinds {
				if kind == "" {
					continue
				}

				ops := matchRes.Resources.Operations
				kubectlPattern := kyvernoKindToKubectlPattern(kind, ops)
				cel := fmt.Sprintf(`tool == "Bash" && request.args.command.matches("(?i)%s")`, kubectlPattern)

				action := kyvernoSeverityToAction(annotations["policies.kyverno.io/severity"], baseAction)

				msg := rule.Validate.Message
				if msg == "" {
					msg = description
				}

				id := fmt.Sprintf("kyverno-%s-%s-%s",
					sanitizeID(pol.Metadata.Name),
					sanitizeID(rule.Name),
					sanitizeID(kind))

				annots := map[string]string{
					"nixis.io/imported-from": filepath.Base(sourcePath),
					"nixis.io/severity":      severity,
				}
				if category != "" {
					annots["kyverno.io/category"] = category
				}

				m := aegisManifest{
					APIVersion: "nixis.io/v1",
					Kind:       "PolicyTemplate",
					Metadata: aegisMetadata{
						Name:        id,
						Annotations: annots,
					},
					Spec: aegisPolicySpec{
						Description: description,
						MatchConstraints: aegisMatchConstraints{
							Tools: []string{"Bash"},
						},
						Validations: []aegisValidation{
							{
								Expression: cel,
								Message:    msg,
								Action:     action,
							},
						},
						DefaultAction: "ALLOW",
					},
				}

				comment := ""
				if hasJMESPath {
					comment = fmt.Sprintf("IMPORT_TODO: JMESPath conditions in %s/%s could not be translated — kubectl pattern match generated as base condition only", pol.Metadata.Name, rule.Name)
				}

				manifests = append(manifests, m)
				comments = append(comments, comment)
			}
		}
	}

	return manifests, comments, nil
}

// kyvernoImportTODO creates a placeholder manifest for rules that cannot be translated.
func kyvernoValidationFailureActionToAction(vfa string) string {
	switch strings.ToLower(vfa) {
	case "enforce":
		return "DENY"
	default:
		return "AUDIT"
	}
}

// kyvernoHasJMESPath returns true if the condition key contains a JMESPath template expression.
func kyvernoHasJMESPath(key string) bool {
	return strings.Contains(key, "{{") && strings.Contains(key, "}}")
}

// convertKyverno translates a Kyverno ClusterPolicy or Policy into Nixis manifests.

// Falco condition patterns for extractable cases.
var (
	falcoCmdlineContains   = regexp.MustCompile(`(?i)\bproc\.cmdline\s+contains\s+"([^"]+)"`)
	falcoCmdlineStartswith = regexp.MustCompile(`(?i)\bproc\.cmdline\s+startswith\s+"([^"]+)"`)
	falcoProcNameIn        = regexp.MustCompile(`(?i)\bproc\.name\s+in\s+\(([^)]+)\)`)
	falcoFdNameStartswith  = regexp.MustCompile(`(?i)\bfd\.name\s+startswith\s+"([^"]+)"`)
	falcoFdNameContains    = regexp.MustCompile(`(?i)\bfd\.name\s+contains\s+"([^"]+)"`)
	falcoEvtTypeExecve     = regexp.MustCompile(`(?i)\bevt\.type\s*=\s*execve\b`)
)

// ---- Falco translator ----

type falcoItem struct {
	Rule  string `yaml:"rule"`
	Macro string `yaml:"macro"`
	List  string `yaml:"list"`
}
type falcoList struct {
	List  string   `yaml:"list"`
	Items []string `yaml:"items"`
}

// falcoItem is used only for detecting which key each document item carries.
type falcoMacro struct {
	Macro     string `yaml:"macro"`
	Condition string `yaml:"condition"`
}
type falcoRule struct {
	Rule      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
	Enabled   *bool    `yaml:"enabled"`
}
type falcoFile struct {
	Rules  []falcoRule
	Macros []falcoMacro
	Lists  []falcoList
}

func parseFalcoFile(data []byte) (falcoFile, error) {
	// Parse as raw sequence so we can route each item by key.
	var raw []map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return falcoFile{}, fmt.Errorf("parse Falco YAML: %w", err)
	}

	var ff falcoFile
	for _, item := range raw {
		if ruleName, ok := item["rule"].(string); ok && ruleName != "" {
			r := falcoRule{Rule: ruleName}
			if v, ok := item["desc"].(string); ok {
				r.Desc = v
			}
			if v, ok := item["condition"].(string); ok {
				r.Condition = v
			}
			if v, ok := item["output"].(string); ok {
				r.Output = v
			}
			if v, ok := item["priority"].(string); ok {
				r.Priority = v
			}
			if tags, ok := item["tags"].([]interface{}); ok {
				for _, t := range tags {
					if ts, ok := t.(string); ok {
						r.Tags = append(r.Tags, ts)
					}
				}
			}
			if enabled, ok := item["enabled"].(bool); ok {
				r.Enabled = &enabled
			}
			ff.Rules = append(ff.Rules, r)
			continue
		}
		if macroName, ok := item["macro"].(string); ok && macroName != "" {
			m := falcoMacro{Macro: macroName}
			if v, ok := item["condition"].(string); ok {
				m.Condition = v
			}
			ff.Macros = append(ff.Macros, m)
			continue
		}
		if listName, ok := item["list"].(string); ok && listName != "" {
			l := falcoList{List: listName}
			if items, ok := item["items"].([]interface{}); ok {
				for _, it := range items {
					if s, ok := it.(string); ok {
						l.Items = append(l.Items, s)
					}
				}
			}
			ff.Lists = append(ff.Lists, l)
		}
	}
	return ff, nil
}

// falcoLookupTables builds macro and list lookup maps for condition resolution.
func falcoTranslateCondition(condition string, macros map[string]string, lists map[string][]string) (string, string) {
	condition = strings.TrimSpace(condition)

	// Resolve list references: proc.name in (shell_binaries) where shell_binaries is a list
	// Also handle inline lists: proc.name in (bash, sh, zsh)
	condition = falcoResolveListRefs(condition, lists)

	// Pattern: proc.cmdline contains "something" → request.args.command.contains("something")
	if m := falcoCmdlineContains.FindStringSubmatch(condition); m != nil {
		return fmt.Sprintf(`tool == "Bash" && request.args.command.contains(%q)`, m[1]), ""
	}

	// Pattern: proc.cmdline startswith "something"
	if m := falcoCmdlineStartswith.FindStringSubmatch(condition); m != nil {
		return fmt.Sprintf(`tool == "Bash" && request.args.command.startsWith(%q)`, m[1]), ""
	}

	// Pattern: proc.name in (nc, ncat, netcat) — resolved to alternation
	// Use \b in the raw string (single backslash). When %q formats this for output,
	// it becomes \\b in the YAML, which CEL parses as \b for RE2 word boundary.
	if m := falcoProcNameIn.FindStringSubmatch(condition); m != nil {
		items := splitFalcoList(m[1])
		if len(items) > 0 {
			pattern := `(?i)\b(` + strings.Join(items, "|") + `)\b`
			return fmt.Sprintf(`tool == "Bash" && request.args.command.matches(%q)`, pattern), ""
		}
	}

	// Pattern: fd.name startswith "/path" — file read/write path check
	if m := falcoFdNameStartswith.FindStringSubmatch(condition); m != nil {
		return fmt.Sprintf(`tool.matches("Read|Write|Edit") && request.args.path.startsWith(%q)`, m[1]), ""
	}

	// Pattern: fd.name contains "/path"
	if m := falcoFdNameContains.FindStringSubmatch(condition); m != nil {
		return fmt.Sprintf(`tool.matches("Read|Write|Edit") && request.args.path.contains(%q)`, m[1]), ""
	}

	// Pattern: evt.type = execve — all Bash tool calls
	if falcoEvtTypeExecve.MatchString(condition) {
		return `tool == "Bash"`, ""
	}

	// Condition references macros or kernel-only fields → IMPORT_TODO
	comment := fmt.Sprintf("IMPORT_TODO: Falco condition uses kernel or macro fields that cannot be automatically translated — manual review required. Original condition: %s", truncate(condition, 120))
	return "false", comment
}

// falcoResolveListRefs replaces list-name references with their inline items.
// e.g. "proc.name in (shell_binaries)" where shell_binaries = [bash, sh] →
//
//	"proc.name in (bash, sh)"
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Falco condition patterns for extractable cases.
func falcoPriorityToAction(priority string) string {
	switch strings.ToUpper(priority) {
	case "EMERGENCY", "ALERT", "CRITICAL", "ERROR":
		return "DENY"
	case "WARNING", "NOTICE":
		return "REQUIRE_APPROVAL"
	default:
		return "AUDIT"
	}
}

// falcoPriorityToSeverity maps Falco priority to Nixis severity annotation.
func falcoPriorityToSeverity(priority string) string {
	switch strings.ToUpper(priority) {
	case "EMERGENCY", "ALERT", "CRITICAL":
		return "critical"
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	default:
		return "low"
	}
}

// falcoTagsToTools infers Nixis tool constraints from Falco tags.
func falcoResolveListRefs(condition string, lists map[string][]string) string {
	for listName, items := range lists {
		if len(items) == 0 {
			continue
		}
		// Replace bare list name inside parentheses: "in (shell_binaries)" → "in (bash, sh)"
		condition = strings.ReplaceAll(condition, "("+listName+")", "("+strings.Join(items, ", ")+")")
		// Also handle "in (other, shell_binaries, more)" — replace as token
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(listName) + `\b`)
		condition = re.ReplaceAllString(condition, strings.Join(items, ", "))
	}
	return condition
}

// splitFalcoList splits a comma-separated list string into trimmed items.
func convertFalco(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	ff, err := parseFalcoFile(data)
	if err != nil {
		return nil, nil, err
	}

	macros, lists := falcoLookupTables(ff)

	manifests := make([]aegisManifest, 0, len(ff.Rules))
	comments := make([]string, 0, len(ff.Rules))

	for _, rule := range ff.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}

		cel, comment := falcoTranslateCondition(rule.Condition, macros, lists)
		action := falcoPriorityToAction(rule.Priority)
		severity := falcoPriorityToSeverity(rule.Priority)
		tools := falcoTagsToTools(rule.Tags)

		desc := rule.Desc
		if desc == "" {
			desc = rule.Rule
		}

		id := "falco-" + sanitizeID(rule.Rule)
		m := aegisManifest{
			APIVersion: "nixis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: id,
				Annotations: map[string]string{
					"nixis.io/imported-from": filepath.Base(sourcePath),
					"nixis.io/severity":      severity,
					"nixis.io/source-rule":   rule.Rule,
				},
			},
			Spec: aegisPolicySpec{
				Description: desc,
				MatchConstraints: aegisMatchConstraints{
					Tools: tools,
				},
				Validations: []aegisValidation{
					{
						Expression: cel,
						Message:    fmt.Sprintf("Falco rule violated: %s", rule.Rule),
						Action:     action,
					},
				},
				DefaultAction: "ALLOW",
			},
		}

		if len(rule.Tags) > 0 {
			m.Metadata.Annotations["nixis.io/falco-tags"] = strings.Join(rule.Tags, ",")
		}

		manifests = append(manifests, m)
		comments = append(comments, comment)
	}

	return manifests, comments, nil
}
func splitFalcoList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
func falcoLookupTables(ff falcoFile) (macros map[string]string, lists map[string][]string) {
	macros = make(map[string]string, len(ff.Macros))
	for _, m := range ff.Macros {
		macros[m.Macro] = m.Condition
	}
	lists = make(map[string][]string, len(ff.Lists))
	for _, l := range ff.Lists {
		lists[l.List] = l.Items
	}
	return macros, lists
}

// falcoPriorityToAction maps Falco priority levels to Nixis actions.
func falcoTagsToTools(tags []string) []string {
	for _, tag := range tags {
		switch {
		case strings.Contains(tag, "filesystem"):
			return []string{"Read", "Write", "Edit"}
		case strings.Contains(tag, "network"):
			return []string{"Bash"}
		case strings.Contains(tag, "process"):
			return []string{"Bash"}
		}
	}
	return []string{}
}

// falcoTranslateCondition attempts to convert a Falco condition string to CEL.
// Returns (cel, comment) — comment is non-empty when translation is partial or impossible.

// ---- Opa translator ----

type opaConstraint struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Match struct {
			Kinds []struct {
				APIGroups []string `yaml:"apiGroups"`
				Kinds     []string `yaml:"kinds"`
			} `yaml:"kinds"`
		} `yaml:"match"`
		Parameters map[string]interface{} `yaml:"parameters"`
	} `yaml:"spec"`
}

// constraintMapping maps OPA Gatekeeper constraint kinds to kubectl patterns and actions
type opaConstraintTemplate struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		CRD struct {
			Spec struct {
				Names struct {
					Kind string `yaml:"kind"`
				} `yaml:"names"`
			} `yaml:"spec"`
		} `yaml:"crd"`
		Targets []struct {
			Target string `yaml:"target"`
			Rego   string `yaml:"rego"`
		} `yaml:"targets"`
	} `yaml:"spec"`
}

// OPA Gatekeeper Constraint (instance of a ConstraintTemplate)
type constraintMapping struct {
	pattern string
	action  string
}

// constraintToKubectl maps known OPA Gatekeeper constraint kinds to Nixis patterns
var constraintToKubectl = map[string]constraintMapping{
	"K8sNoPrivilegedContainers":     {`kubectl.*--privileged`, "DENY"},
	"K8sBlockWildcardIngress":       {`kubectl.*ingress.*`, "REQUIRE_APPROVAL"},
	"K8sRequiredLabels":             {`kubectl.*(create|apply).*`, "AUDIT"},
	"K8sContainerLimits":            {`kubectl.*(create|apply).*`, "AUDIT"},
	"K8sDisallowedTags":             {`kubectl.*image.*:latest`, "DENY"},
	"K8sNoAnonymousSubjectBindings": {`kubectl.*clusterrolebinding.*`, "DENY"},
	"K8sBlockNodePort":              {`kubectl.*NodePort.*`, "DENY"},
	"K8sNoEnvVarSecrets":            {`kubectl.*secret.*env`, "DENY"},
	"K8sExternalIPs":                {`kubectl.*externalIPs.*`, "DENY"},
	"K8sHostFilesystem":             {`kubectl.*hostPath.*`, "DENY"},
	"K8sHostNetworkingPorts":        {`kubectl.*hostNetwork.*`, "DENY"},
	"K8sPSPAllowedUsers":            {`kubectl.*runAsUser.*0`, "DENY"},
	"K8sPSPCapabilities":            {`kubectl.*capabilities.*`, "REQUIRE_APPROVAL"},
	"K8sPSPForbiddenSysctls":        {`kubectl.*sysctl.*`, "DENY"},
	"K8sPSPHostNamespace":           {`kubectl.*hostPID.*|kubectl.*hostIPC.*`, "DENY"},
	"K8sPSPPrivilegedContainer":     {`kubectl.*privileged.*true`, "DENY"},
	"K8sPSPProcMount":               {`kubectl.*procMount.*`, "DENY"},
	"K8sPSPReadOnlyRootFilesystem":  {`kubectl.*(create|apply).*`, "AUDIT"},
	"K8sPSPSeccomp":                 {`kubectl.*seccomp.*`, "AUDIT"},
	"K8sReplicaLimits":              {`kubectl.*replicas.*`, "AUDIT"},
	"K8sRequiredAnnotations":        {`kubectl.*(create|apply).*`, "AUDIT"},
	"K8sRequiredProbes":             {`kubectl.*(create|apply).*`, "AUDIT"},
	"K8sRestrictRoleBindings":       {`kubectl.*rolebinding.*cluster-admin`, "DENY"},
	"K8sUniqueServiceSelector":      {`kubectl.*(create|apply).*service`, "AUDIT"},
}

// regoPatternMappings maps Rego input patterns to kubectl patterns
var regoPatternMappings = []struct {
	regoContains string
	kubectlPat   string
}{
	{"hostNetwork", `kubectl.*hostNetwork.*`},
	{"hostPID", `kubectl.*hostPID.*`},
	{"hostIPC", `kubectl.*hostIPC.*`},
	{"privileged", `kubectl.*privileged.*`},
	{"hostPath", `kubectl.*hostPath.*`},
	{"capabilities", `kubectl.*capabilities.*`},
	{"runAsUser", `kubectl.*runAsUser.*`},
	{"runAsNonRoot", `kubectl.*runAsNonRoot.*`},
	{"procMount", `kubectl.*procMount.*`},
	{"seccomp", `kubectl.*seccomp.*`},
	{"sysctl", `kubectl.*sysctl.*`},
	{"allowPrivilegeEscalation", `kubectl.*allowPrivilegeEscalation.*`},
	{"readOnlyRootFilesystem", `kubectl.*readOnlyRootFilesystem.*`},
}

// ---- output structs ----
func convertOPAConstraintInstance(c opaConstraint, sourcePath string) ([]aegisManifest, []string, error) {
	// Constraint instances reference a ConstraintTemplate by kind
	constraintKind := c.Kind
	name := c.Metadata.Name

	description := fmt.Sprintf("OPA Gatekeeper constraint %s (kind: %s)", name, constraintKind)

	// Determine pattern and action from lookup table
	pattern, action, comment := translateOPAConstraint(constraintKind, "")

	m := aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name: fmt.Sprintf("gatekeeper-%s", sanitizeID(name)),
			Annotations: map[string]string{
				"nixis.io/source":        "open-policy-agent/gatekeeper-library",
				"nixis.io/original-kind": constraintKind,
				"nixis.io/imported-from": filepath.Base(sourcePath),
				"nixis.io/severity":      "high",
			},
		},
		Spec: aegisPolicySpec{
			Description: description,
			MatchConstraints: aegisMatchConstraints{
				Tools: []string{"Bash"},
			},
			Validations: []aegisValidation{
				{
					Expression: fmt.Sprintf(`tool == "Bash" && request.args.command.matches(%q)`, pattern),
					Action:     action,
					Message:    description,
				},
			},
			DefaultAction: "ALLOW",
		},
	}

	headerComment := fmt.Sprintf("IMPORTED FROM: open-policy-agent/gatekeeper-library\nCONSTRAINT: %s", constraintKind)
	if comment != "" {
		headerComment += "\nMANUAL REVIEW: " + comment
	}

	return []aegisManifest{m}, []string{headerComment}, nil
}

// translateOPAConstraint determines the kubectl pattern and action for a constraint kind.
// It first checks the lookup table, then tries to infer from Rego if available.
func translateOPAConstraint(kind string, rego string) (pattern string, action string, comment string) {
	// Check the lookup table first
	if mapping, ok := constraintToKubectl[kind]; ok {
		return mapping.pattern, mapping.action, ""
	}

	// Try to infer pattern from Rego content
	if rego != "" {
		for _, pm := range regoPatternMappings {
			if strings.Contains(rego, pm.regoContains) {
				return pm.kubectlPat, "DENY", fmt.Sprintf("Pattern inferred from Rego containing '%s'", pm.regoContains)
			}
		}
	}

	// Unknown constraint - generate a catch-all with IMPORT_TODO
	return `kubectl.*`, "DENY", fmt.Sprintf("IMPORT_TODO: Unknown constraint kind '%s' - manual review required. Rego logic needs human translation.", kind)
}

// ---- rule translation helpers ----
func convertOPAConstraintTemplate(ct opaConstraintTemplate, sourcePath string) ([]aegisManifest, []string, error) {
	constraintKind := ct.Spec.CRD.Spec.Names.Kind
	if constraintKind == "" {
		constraintKind = ct.Metadata.Name
	}

	// Get description from annotations
	description := ct.Metadata.Annotations["description"]
	if description == "" {
		description = fmt.Sprintf("Imported from OPA Gatekeeper: %s", constraintKind)
	}

	// Get the Rego code for analysis
	var rego string
	for _, target := range ct.Spec.Targets {
		if target.Target == "admission.k8s.gatekeeper.sh" {
			rego = target.Rego
			break
		}
	}

	// Determine pattern and action from lookup table or Rego analysis
	pattern, action, comment := translateOPAConstraint(constraintKind, rego)

	// Truncate rego for the comment header (first 200 chars)
	regoPreview := rego
	if len(regoPreview) > 200 {
		regoPreview = regoPreview[:200] + "..."
	}
	regoPreview = strings.ReplaceAll(regoPreview, "\n", " ")

	m := aegisManifest{
		APIVersion: "nixis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name: fmt.Sprintf("gatekeeper-%s", sanitizeID(constraintKind)),
			Annotations: map[string]string{
				"nixis.io/source":        "open-policy-agent/gatekeeper-library",
				"nixis.io/original-kind": constraintKind,
				"nixis.io/imported-from": filepath.Base(sourcePath),
				"nixis.io/severity":      "high",
			},
		},
		Spec: aegisPolicySpec{
			Description: description,
			MatchConstraints: aegisMatchConstraints{
				Tools: []string{"Bash"},
			},
			Validations: []aegisValidation{
				{
					Expression: fmt.Sprintf(`tool == "Bash" && request.args.command.matches(%q)`, pattern),
					Action:     action,
					Message:    description,
				},
			},
			DefaultAction: "ALLOW",
		},
	}

	// Build header comment
	headerComment := fmt.Sprintf("IMPORTED FROM: open-policy-agent/gatekeeper-library\nCONSTRAINT: %s\nREGO LOGIC: %s",
		constraintKind, regoPreview)
	if comment != "" {
		headerComment += "\nMANUAL REVIEW: " + comment
	}

	return []aegisManifest{m}, []string{headerComment}, nil
}
func convertOPAGatekeeper(data []byte, sourcePath string) ([]aegisManifest, []string, error) {
	// Try parsing as ConstraintTemplate first
	var ct opaConstraintTemplate
	if err := yaml.Unmarshal(data, &ct); err == nil && ct.Kind == "ConstraintTemplate" {
		return convertOPAConstraintTemplate(ct, sourcePath)
	}

	// Try parsing as Constraint instance
	var c opaConstraint
	if err := yaml.Unmarshal(data, &c); err == nil && strings.HasPrefix(c.APIVersion, "constraints.gatekeeper.sh") {
		return convertOPAConstraintInstance(c, sourcePath)
	}

	return nil, nil, fmt.Errorf("unrecognized OPA Gatekeeper format in %s", filepath.Base(sourcePath))
}
