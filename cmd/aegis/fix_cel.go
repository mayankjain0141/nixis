package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	aegisCEL "github.com/mayjain/aegis/internal/cel"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var fixCelCmd = &cobra.Command{
	Use:   "fix-cel <directory>",
	Short: "Repair broken CEL escape sequences in imported policy YAML files",
	Long: `Walk a directory of Aegis PolicyTemplate YAML files, find validation
expressions that fail CEL compilation, apply escape normalization, and
write back fixed files.

For each file:
  - Expressions that already compile are skipped.
  - Broken expressions get fixCELEscaping applied (doubles invalid backslash sequences).
  - If the fix makes the expression compile, the file is rewritten in-place.
  - If the fix still fails, the expression is set to false (fail-secure) and a
    CEL_FIX_FAILED comment is added so operators can review manually.

Examples:
  aegis policy fix-cel policies/imported/
  aegis policy fix-cel policies/imported/kyverno/`,
	Args: cobra.ExactArgs(1),
	RunE: runFixCel,
}

func init() {
	policyCmd.AddCommand(fixCelCmd)
}

func runFixCel(cmd *cobra.Command, args []string) error {
	dir := args[0]

	celEnv, err := aegisCEL.NewCELEnvironment()
	if err != nil {
		return fmt.Errorf("fix-cel: create CEL environment: %w", err)
	}

	var fixed, skipped, alreadyOK, failSecure int

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		result, fixErr := fixCelFile(celEnv, path)
		switch result {
		case celFixOK:
			fixed++
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[FIXED] %s\n", filepath.Base(path))
		case celFixAlreadyOK:
			alreadyOK++
		case celFixFailed:
			failSecure++
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[FAIL]  %s — %v\n", filepath.Base(path), fixErr)
		case celFixSkip:
			skipped++
			if fixErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[SKIP]  %s — %v\n", filepath.Base(path), fixErr)
			}
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("fix-cel: walk %s: %w", dir, walkErr)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"fix-cel: fixed=%d already-ok=%d fail-secure=%d skipped=%d\n",
		fixed, alreadyOK, failSecure, skipped)
	return nil
}

type celFixResult int

const (
	celFixAlreadyOK celFixResult = iota // all expressions already compile
	celFixOK                            // at least one expression was repaired and written back
	celFixFailed                        // expression could not be repaired; set to false (fail-secure)
	celFixSkip                          // file could not be parsed or is not a PolicyTemplate
)

// fixCelFile inspects all validation expressions in path and repairs broken CEL escaping.
// Returns celFixAlreadyOK if nothing needed changing, celFixOK if repairs were written,
// celFixFailed if an expression could not be repaired (written as fail-secure false),
// or celFixSkip if the file could not be read/parsed.
func fixCelFile(env *aegisCEL.CELEnvironment, path string) (celFixResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return celFixSkip, fmt.Errorf("read: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return celFixSkip, fmt.Errorf("parse yaml: %w", err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return celFixSkip, nil
	}

	root := doc.Content[0]
	if !isAegisPolicyTemplate(root) {
		return celFixSkip, nil
	}

	exprNodes := collectExpressionNodes(root)
	if len(exprNodes) == 0 {
		return celFixAlreadyOK, nil
	}

	anyChanged := false
	anyFailed := false
	var firstFailErr error

	rawEnv := aegisCEL.RawEnv(env)

	for _, node := range exprNodes {
		expr := node.Value

		// Normalise the same way parse.go does before compilation.
		normalised := normaliseCELExprForFix(expr)

		_, issues := rawEnv.Parse(normalised)
		if issues == nil || issues.Err() == nil {
			// Already compiles — no change needed.
			continue
		}

		// Try auto-fix.
		fixed := fixCELEscaping(expr)
		normalisedFixed := normaliseCELExprForFix(fixed)
		_, fixIssues := rawEnv.Parse(normalisedFixed)
		if fixIssues == nil || fixIssues.Err() == nil {
			node.Value = fixed
			anyChanged = true
			continue
		}

		// Fix did not work — set to fail-secure false.
		node.Value = "false"
		node.Tag = "!!str"
		node.Style = yaml.TaggedStyle
		anyChanged = true
		anyFailed = true
		if firstFailErr == nil {
			firstFailErr = fixIssues.Err()
		}

		// Inject a CEL_FIX_FAILED comment on the node.
		node.LineComment = "# CEL_FIX_FAILED: original expression could not be repaired"
	}

	if !anyChanged {
		return celFixAlreadyOK, nil
	}

	// Re-marshal and write back.
	out, marshalErr := yaml.Marshal(&doc)
	if marshalErr != nil {
		return celFixSkip, fmt.Errorf("marshal: %w", marshalErr)
	}

	if err := os.WriteFile(path, out, 0644); err != nil {
		return celFixSkip, fmt.Errorf("write: %w", err)
	}

	if anyFailed {
		return celFixFailed, firstFailErr
	}
	return celFixOK, nil
}

// normaliseCELExprForFix applies the same normalisation as bundle/parse.go so we
// can test compilation against the actual CEL variable declarations.
func normaliseCELExprForFix(expr string) string {
	expr = strings.ReplaceAll(expr, "request.args.command", `args["command"]`)
	expr = strings.ReplaceAll(expr, "request.args.path", `args["path"]`)
	expr = strings.ReplaceAll(expr, "request.args.url", `args["url"]`)
	expr = strings.ReplaceAll(expr, "request.args.content", `args["content"]`)
	expr = strings.ReplaceAll(expr, "request.args.query", `args["query"]`)
	expr = strings.ReplaceAll(expr, "request.args", "args")
	expr = strings.ReplaceAll(expr, "request.session_id", "session_id")
	return expr
}

// isAegisPolicyTemplate returns true if root is a mapping with
// apiVersion: aegis.io/v1 and kind: PolicyTemplate.
func isAegisPolicyTemplate(root *yaml.Node) bool {
	if root.Kind != yaml.MappingNode {
		return false
	}
	var apiVersion, kind string
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "apiVersion":
			apiVersion = root.Content[i+1].Value
		case "kind":
			kind = root.Content[i+1].Value
		}
	}
	return apiVersion == "aegis.io/v1" && kind == "PolicyTemplate"
}

// collectExpressionNodes walks the YAML node tree and returns all scalar nodes
// that are values of an "expression" key inside spec.validations[].
func collectExpressionNodes(root *yaml.Node) []*yaml.Node {
	var nodes []*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "spec" {
			nodes = append(nodes, expressionNodesFromSpec(root.Content[i+1])...)
		}
	}
	return nodes
}

func expressionNodesFromSpec(spec *yaml.Node) []*yaml.Node {
	if spec.Kind != yaml.MappingNode {
		return nil
	}
	var nodes []*yaml.Node
	for i := 0; i+1 < len(spec.Content); i += 2 {
		if spec.Content[i].Value == "validations" {
			validations := spec.Content[i+1]
			if validations.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range validations.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				for j := 0; j+1 < len(item.Content); j += 2 {
					if item.Content[j].Value == "expression" {
						nodes = append(nodes, item.Content[j+1])
					}
				}
			}
		}
	}
	return nodes
}
