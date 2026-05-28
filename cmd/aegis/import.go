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

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var importOutDir string
var importDryRun bool

var importCmd = &cobra.Command{
	Use:   "import <source>",
	Short: "Import external policy formats to native Aegis YAML",
	Long: `Import policies from external formats and convert them to native Aegis YAML.

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
  aegis policy import policies.yaml                 # import to ./policies/imported/
  aegis policy import policies.yaml --out policies/ # import to custom directory
  aegis policy import policies.yaml --dry-run       # show what would be created
  aegis policy import https://github.com/owner/repo # fetch from GitHub`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	importCmd.Flags().StringVar(&importOutDir, "out", "./policies/imported", "Output directory for imported policies")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Print converted policies without writing files")
	policyCmd.AddCommand(importCmd)
}

type importFormat int

const (
	formatUnknown      importFormat = iota
	formatPolicyLayer               // layerName + policies[].rule
	formatGeneric                   // policies[].expression
	formatSettingsJSON              // {"permissions":{"deny":[...]}}
	formatAgentWall                 // version: "2" + tools[].action
	formatMCPVisor                  // deny_path / deny_command_pattern / etc.
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
	Name       string            `yaml:"name"`
	Action     string            `yaml:"action"`
	Risk       string            `yaml:"risk"`
	Parameters []agentWallParam  `yaml:"parameters"`
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d for %s", resp.StatusCode, zipURL)
	}

	body, err := io.ReadAll(resp.Body)
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
		rc.Close()
		if err != nil {
			continue
		}

		tmp, err := os.CreateTemp("", "aegis-import-*"+ext)
		if err != nil {
			continue
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			continue
		}
		tmp.Close()
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
	}

	if err := yaml.Unmarshal(data, &probe); err != nil {
		return formatUnknown
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

	manifests, comments, err := convertFile(data, source)
	if err != nil {
		return err
	}

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
		manifests, comments, err := convertFile(data, path)
		if err != nil || len(manifests) == 0 {
			continue
		}
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
	default:
		return nil, nil, fmt.Errorf("unknown policy format in %s: file must contain a recognized policy structure", filepath.Base(sourcePath))
	}
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
			APIVersion: "aegis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: p.ID,
				Annotations: map[string]string{
					"aegis.io/imported-from": filepath.Base(sourcePath),
					"aegis.io/severity":      severity,
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
			APIVersion: "aegis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: p.ID,
				Annotations: map[string]string{
					"aegis.io/imported-from": filepath.Base(sourcePath),
					"aegis.io/severity":      severity,
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
			APIVersion: "aegis.io/v1",
			Kind:       "PolicyTemplate",
			Metadata: aegisMetadata{
				Name: id,
				Annotations: map[string]string{
					"aegis.io/imported-from": filepath.Base(sourcePath),
					"aegis.io/severity":      "medium",
					"aegis.io/source-rule":   rule,
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
				APIVersion: "aegis.io/v1",
				Kind:       "PolicyTemplate",
				Metadata: aegisMetadata{
					Name: id,
					Annotations: map[string]string{
						"aegis.io/imported-from": filepath.Base(sourcePath),
						"aegis.io/severity":      severity,
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
						APIVersion: "aegis.io/v1",
						Kind:       "PolicyTemplate",
						Metadata: aegisMetadata{
							Name: id,
							Annotations: map[string]string{
								"aegis.io/imported-from": filepath.Base(sourcePath),
								"aegis.io/severity":      severity,
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
					APIVersion: "aegis.io/v1",
					Kind:       "PolicyTemplate",
					Metadata: aegisMetadata{
						Name: id,
						Annotations: map[string]string{
							"aegis.io/imported-from": filepath.Base(sourcePath),
							"aegis.io/severity":      severity,
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
		APIVersion: "aegis.io/v1",
		Kind:       "PolicyTemplate",
		Metadata: aegisMetadata{
			Name: id,
			Annotations: map[string]string{
				"aegis.io/imported-from": source,
				"aegis.io/severity":      severity,
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

// ---- output helpers ----

func printDryRun(cmd *cobra.Command, manifests []aegisManifest, comments []string) error {
	for i, m := range manifests {
		if i < len(comments) && comments[i] != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# %s\n", comments[i])
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "# imported from: %s via aegis policy import\n",
			m.Metadata.Annotations["aegis.io/imported-from"])

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
			content.WriteString("# ")
			content.WriteString(comments[i])
			content.WriteString("\n")
		}
		content.WriteString("# imported from: ")
		content.WriteString(filepath.Base(sourcePath))
		content.WriteString(" via aegis policy import\n")
		content.Write(data)

		if err := os.WriteFile(outPath, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outPath)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %d policies to %s\n", len(manifests), importOutDir)
	return nil
}
