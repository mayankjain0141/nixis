package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var fixImportsLLMModel string
var fixImportsLLMMaxRetries int
var fixImportsDryRun bool

var fixImportsCmd = &cobra.Command{
	Use:   "fix-imports <directory>",
	Short: "LLM in-place repair of IMPORT_TODO policies",
	Long: `Walk a directory of imported Aegis PolicyTemplate YAML files and attempt to
repair entries that contain expression: "false" and an IMPORT_TODO comment.

For each fixable file, the original condition is extracted and sent to the
Claude API to generate a CEL expression. On success the file is rewritten
in-place with the CEL expression, the IMPORT_TODO comment removed, and an
aegis.io/llm-confidence: medium annotation added.

Examples:
  aegis policy fix-imports policies/imported/falco/
  aegis policy fix-imports policies/imported/ --dry-run
  aegis policy fix-imports policies/imported/ --llm-model claude-opus-4-7`,
	Args: cobra.ExactArgs(1),
	RunE: runFixImports,
}

func init() {
	fixImportsCmd.Flags().StringVar(&fixImportsLLMModel, "llm-model", "claude-opus-4-7", "Claude model to use for translation")
	fixImportsCmd.Flags().IntVar(&fixImportsLLMMaxRetries, "llm-max-retries", 3, "Maximum CEL repair attempts per file")
	fixImportsCmd.Flags().BoolVar(&fixImportsDryRun, "dry-run", false, "Print what would change without writing files")
	policyCmd.AddCommand(fixImportsCmd)
}

func runFixImports(cmd *cobra.Command, args []string) error {
	dir := args[0]

	translator, err := NewLLMTranslator(fixImportsLLMModel, fixImportsLLMMaxRetries)
	if err != nil {
		return fmt.Errorf("fix-imports: create translator: %w", err)
	}

	var fixed, skipped, noMatch int

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".yaml" {
			return nil
		}

		result, writeErr := fixImportsFile(cmd.Context(), translator, path, fixImportsDryRun)
		switch result {
		case fixResultOK:
			fixed++
		case fixResultSkip:
			skipped++
			if writeErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[SKIP] %s — %v\n", filepath.Base(path), writeErr)
			}
		case fixResultNoMatch:
			noMatch++
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("fix-imports: walk %s: %w", dir, walkErr)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "fix-imports: fixed=%d skipped=%d no-match=%d\n", fixed, skipped, noMatch)
	return nil
}

type fixResult int

const (
	fixResultNoMatch fixResult = iota // file does not need fixing
	fixResultOK                       // successfully fixed (or dry-run preview)
	fixResultSkip                     // needs fixing but translation failed
)

// fixImportsFile processes a single YAML file.
// Returns (fixResultOK, nil) on success, (fixResultSkip, err) when translation failed,
// and (fixResultNoMatch, nil) when the file does not contain a fixable pattern.
func fixImportsFile(ctx context.Context, t *LLMTranslator, path string, dryRun bool) (fixResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fixResultSkip, fmt.Errorf("read: %w", err)
	}

	content := string(raw)

	// Quick pre-check: must have both markers to be worth parsing.
	if !strings.Contains(content, `expression: "false"`) || !strings.Contains(content, "# IMPORT_TODO:") {
		return fixResultNoMatch, nil
	}

	// Parse the YAML document as a generic node tree so we can rewrite in-place
	// while preserving the structure as closely as possible.
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fixResultSkip, fmt.Errorf("parse yaml: %w", err)
	}

	// Extract context for the LLM prompt.
	info := extractPolicyInfo(content, &doc)
	if info.importTODO == "" {
		return fixResultNoMatch, nil
	}

	sourceFormat := inferSourceFormat(path)
	snippet := buildFixSnippet(info)

	celExpr, attempts, translateErr := t.Translate(ctx, snippet, sourceFormat)
	if translateErr != nil {
		return fixResultSkip, fmt.Errorf("retries exhausted: %w", translateErr)
	}

	celPreview := celExpr
	if len(celPreview) > 80 {
		celPreview = celPreview[:80] + "..."
	}

	if dryRun {
		_, _ = fmt.Printf("[DRY-RUN] %s — %s\n", filepath.Base(path), celPreview)
		return fixResultOK, nil
	}

	rewritten, rewriteErr := rewriteFile(content, &doc, celExpr, attempts, sourceFormat)
	if rewriteErr != nil {
		return fixResultSkip, fmt.Errorf("rewrite: %w", rewriteErr)
	}

	if err := os.WriteFile(path, []byte(rewritten), 0644); err != nil {
		return fixResultSkip, fmt.Errorf("write: %w", err)
	}

	_, _ = fmt.Printf("[OK] %s — %s\n", filepath.Base(path), celPreview)
	return fixResultOK, nil
}

// policyInfo holds the context extracted from an IMPORT_TODO policy file.
type policyInfo struct {
	name       string
	importTODO string // the original condition text after "# IMPORT_TODO:"
	description string
	message     string
	sourceRule  string
}

// extractPolicyInfo pulls the fields needed to build the LLM prompt.
func extractPolicyInfo(content string, doc *yaml.Node) policyInfo {
	var info policyInfo

	// Extract IMPORT_TODO comment text from the raw content.
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# IMPORT_TODO:") {
			info.importTODO = strings.TrimSpace(strings.TrimPrefix(line, "# IMPORT_TODO:"))
			break
		}
	}

	// Walk the YAML node tree to pull metadata and spec fields.
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root := doc.Content[0]
		info.name = yamlMappingValue(root, "metadata", "name")
		info.description = yamlMappingValue(root, "spec", "description")
		info.sourceRule = yamlMappingAnnotation(root, "aegis.io/source-rule")
		// Pull message from spec.validations[0].message
		info.message = yamlFirstValidationMessage(root)
	}

	return info
}

// buildFixSnippet constructs the text sent to the LLM.
func buildFixSnippet(info policyInfo) string {
	var sb strings.Builder
	if info.name != "" {
		sb.WriteString("Policy: ")
		sb.WriteString(info.name)
		sb.WriteString("\n")
	}
	if info.description != "" {
		sb.WriteString("Description: ")
		sb.WriteString(info.description)
		sb.WriteString("\n")
	}
	if info.importTODO != "" {
		sb.WriteString("Original condition: ")
		sb.WriteString(info.importTODO)
		sb.WriteString("\n")
	}
	if info.message != "" {
		sb.WriteString("Message: ")
		sb.WriteString(info.message)
		sb.WriteString("\n")
	}
	if info.sourceRule != "" {
		sb.WriteString("Source rule: ")
		sb.WriteString(info.sourceRule)
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}

// inferSourceFormat returns the source format string based on the parent directory name.
func inferSourceFormat(path string) string {
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch dir {
	case "falco":
		return "falco"
	case "kyverno":
		return "kyverno"
	case "opa-gatekeeper":
		return "opa-gatekeeper"
	case "agentwall":
		return "agentwall"
	default:
		return dir
	}
}

// rewriteFile produces the updated file content:
// - removes all "# IMPORT_TODO:" comment lines from the top header
// - replaces expression: "false" with the CEL expression
// - adds aegis.io/llm-confidence: medium annotation
// - adds an IMPORT_REVIEW comment at the top
func rewriteFile(content string, doc *yaml.Node, celExpr string, attempts int, sourceFormat string) (string, error) {
	lines := strings.Split(content, "\n")

	// 1. Strip IMPORT_TODO comment lines (lines starting with "# IMPORT_TODO:").
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "# IMPORT_TODO:") {
			continue
		}
		filtered = append(filtered, line)
	}

	result := strings.Join(filtered, "\n")

	// 2. Replace expression: "false" with the CEL expression.
	// Only replace the first occurrence (the one in spec.validations).
	result = strings.Replace(result, `expression: "false"`, fmt.Sprintf("expression: %q", celExpr), 1)

	// 3. Add aegis.io/llm-confidence annotation.
	// Find the annotations block and append after the last annotation line before
	// the next non-annotation line. We do a targeted string insert for reliability.
	result = injectAnnotation(result, "aegis.io/llm-confidence: medium")

	// 4. Prepend an IMPORT_REVIEW comment at the top of the file (after any leading
	//    comment lines that are NOT IMPORT_TODO).
	reviewLine := fmt.Sprintf("# IMPORT_REVIEW: LLM-translated from %s — verify semantics (attempts: %d)", sourceFormat, attempts)
	result = reviewLine + "\n" + strings.TrimLeft(result, "\n")

	return result, nil
}

// injectAnnotation inserts a YAML annotation key into the annotations map.
// It finds the last "    aegis.io/" prefixed line (4-space indent) and appends
// the new annotation on the next line with matching indentation.
func injectAnnotation(content, annotation string) string {
	lines := strings.Split(content, "\n")

	// Check if the annotation is already present.
	key := strings.SplitN(annotation, ":", 2)[0]
	for _, l := range lines {
		if strings.Contains(l, key+":") {
			return content
		}
	}

	// Find insertion point: last line inside the annotations block.
	// Annotations lines look like: "        aegis.io/something: value" (8-space indent)
	lastAnnotIdx := -1
	for i, l := range lines {
		trimmed := strings.TrimLeft(l, " ")
		if strings.HasPrefix(trimmed, "aegis.io/") {
			lastAnnotIdx = i
		}
	}

	if lastAnnotIdx < 0 {
		return content
	}

	// Determine the indentation used by existing annotation lines.
	indent := strings.Repeat(" ", len(lines[lastAnnotIdx])-len(strings.TrimLeft(lines[lastAnnotIdx], " ")))
	newLine := indent + annotation

	// Insert after lastAnnotIdx.
	result := make([]string, 0, len(lines)+1)
	result = append(result, lines[:lastAnnotIdx+1]...)
	result = append(result, newLine)
	result = append(result, lines[lastAnnotIdx+1:]...)
	return strings.Join(result, "\n")
}

// ---- YAML node traversal helpers ----

// yamlMappingValue walks a YAML mapping node to retrieve a nested string value.
// Keys are specified as a path: e.g. "spec", "description" retrieves doc.spec.description.
func yamlMappingValue(node *yaml.Node, keys ...string) string {
	if node == nil {
		return ""
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return ""
		}
		return yamlMappingValue(node.Content[0], keys...)
	}
	if node.Kind != yaml.MappingNode {
		return ""
	}
	if len(keys) == 0 {
		return node.Value
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == keys[0] {
			if len(keys) == 1 {
				return node.Content[i+1].Value
			}
			return yamlMappingValue(node.Content[i+1], keys[1:]...)
		}
	}
	return ""
}

// yamlMappingAnnotation retrieves a specific annotation value from metadata.annotations.
func yamlMappingAnnotation(root *yaml.Node, annotKey string) string {
	if root == nil || root.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "metadata" {
			meta := root.Content[i+1]
			for j := 0; j+1 < len(meta.Content); j += 2 {
				if meta.Content[j].Value == "annotations" {
					annots := meta.Content[j+1]
					for k := 0; k+1 < len(annots.Content); k += 2 {
						if annots.Content[k].Value == annotKey {
							return annots.Content[k+1].Value
						}
					}
				}
			}
		}
	}
	return ""
}

// yamlFirstValidationMessage retrieves spec.validations[0].message from the root node.
func yamlFirstValidationMessage(root *yaml.Node) string {
	if root == nil || root.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "spec" {
			spec := root.Content[i+1]
			for j := 0; j+1 < len(spec.Content); j += 2 {
				if spec.Content[j].Value == "validations" {
					validations := spec.Content[j+1]
					if validations.Kind == yaml.SequenceNode && len(validations.Content) > 0 {
						first := validations.Content[0]
						for k := 0; k+1 < len(first.Content); k += 2 {
							if first.Content[k].Value == "message" {
								return first.Content[k+1].Value
							}
						}
					}
				}
			}
		}
	}
	return ""
}
