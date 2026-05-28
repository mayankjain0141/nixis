package main

import (
	"fmt"
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

Examples:
  aegis policy import policies.yaml                 # import to ./policies/imported/
  aegis policy import policies.yaml --out policies/ # import to custom directory
  aegis policy import policies.yaml --dry-run       # show what would be created`,
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
	formatUnknown importFormat = iota
	formatPolicyLayer
	formatGeneric
)

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

func runImport(cmd *cobra.Command, args []string) error {
	sourcePath := args[0]

	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}

	format := detectFormat(data)
	if format == formatUnknown {
		return fmt.Errorf("unknown policy format: file must contain either layerName (PolicyLayer) or policies[].expression (generic)")
	}

	var manifests []aegisManifest
	var comments []string

	switch format {
	case formatPolicyLayer:
		manifests, comments, err = convertPolicyLayer(data, sourcePath)
	case formatGeneric:
		manifests, comments, err = convertGeneric(data, sourcePath)
	case formatUnknown:
		return fmt.Errorf("unknown policy format")
	}
	if err != nil {
		return err
	}

	if importDryRun {
		return printDryRun(cmd, manifests, comments)
	}

	return writeManifests(cmd, manifests, comments, sourcePath)
}

func detectFormat(data []byte) importFormat {
	var probe struct {
		LayerName string `yaml:"layerName"`
		Policies  []struct {
			Rule       string `yaml:"rule"`
			Expression string `yaml:"expression"`
		} `yaml:"policies"`
	}

	if err := yaml.Unmarshal(data, &probe); err != nil {
		return formatUnknown
	}

	if probe.LayerName != "" && len(probe.Policies) > 0 {
		for _, p := range probe.Policies {
			if p.Rule != "" {
				return formatPolicyLayer
			}
		}
	}

	if len(probe.Policies) > 0 {
		for _, p := range probe.Policies {
			if p.Expression != "" {
				return formatGeneric
			}
		}
	}

	return formatUnknown
}

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

func printDryRun(cmd *cobra.Command, manifests []aegisManifest, comments []string) error {
	for i, m := range manifests {
		if comments[i] != "" {
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
		if comments[i] != "" {
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
