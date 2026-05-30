// SPDX-License-Identifier: MIT
package bundle

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	policy_types "github.com/mayjain/aegis/pkg/policy/types"
	"gopkg.in/yaml.v3"
)

// policyManifest mirrors the Kubernetes-style YAML format used in policies/builtin/.
type policyManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Description      string `yaml:"description"`
		Layer            string `yaml:"layer"` // ceiling | team | project | cel (default)
		MatchConstraints struct {
			Tools   []string `yaml:"tools"`
			Effects []string `yaml:"effects"`
		} `yaml:"matchConstraints"`
		Variables []struct {
			Name       string `yaml:"name"`
			Expression string `yaml:"expression"`
		} `yaml:"variables"`
		Validations []struct {
			Expression string `yaml:"expression"`
			Message    string `yaml:"message"`
			Action     string `yaml:"action"`
		} `yaml:"validations"`
		DefaultAction string                     `yaml:"defaultAction"`
		Params        map[string]paramDefinition `yaml:"params"`
	} `yaml:"spec"`
}

// paramDefinition holds the YAML schema for a single policy parameter.
type paramDefinition struct {
	Type    string `yaml:"type"`
	Default any    `yaml:"default"`
}

// ParsePolicyFile parses a single YAML policy file and returns a PolicyTemplate and PolicyBinding.
// The CEL expression is the first validation expression (for MVP-1 simplicity).
// Returns (nil, nil, nil) if the file is not a PolicyTemplate.
func ParsePolicyFile(path string) (*policy_types.PolicyTemplate, *policy_types.PolicyBinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var manifest policyManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, nil, err
	}

	if manifest.Kind != "PolicyTemplate" {
		return nil, nil, nil
	}

	if manifest.APIVersion != "aegis.io/v1" {
		return nil, nil, nil
	}

	expr, requireApproval := buildCombinedExpression(&manifest)
	if expr == "" {
		log.Printf("bundle: %s: PolicyTemplate %q has no evaluable validations — skipping", path, manifest.Metadata.Name)
		return nil, nil, nil
	}

	var message string
	for _, v := range manifest.Spec.Validations {
		if v.Message != "" {
			message = v.Message
			break
		}
	}

	params, err := resolveParams(manifest.Spec.Params, path)
	if err != nil {
		return nil, nil, err
	}

	template := &policy_types.PolicyTemplate{
		ID:          manifest.Metadata.Name,
		Name:        manifest.Metadata.Name,
		Description: strings.TrimRight(manifest.Spec.Description, "\n\r "),
		Expression:  expr,
		Params:      params,
		SourceFile:  path,
		SourceLine:  1,
	}

	layer := manifest.Spec.Layer
	if _, known := LayerPriority[layer]; !known || layer == "" {
		layer = LayerCEL
	}

	binding := &policy_types.PolicyBinding{
		TemplateID: manifest.Metadata.Name,
		Scope: policy_types.PolicyScope{
			Tools:   manifest.Spec.MatchConstraints.Tools,
			Effects: manifest.Spec.MatchConstraints.Effects,
		},
		Priority:        0,
		Layer:           layer,
		RequireApproval: requireApproval,
		Message:         message,
	}

	return template, binding, nil
}

// resolveParams converts the raw YAML params map into a resolved map[string]any
// with defaults applied and type validation performed.
//
// For array-typed params containing integers, each element is validated to be in
// the range 1024–65535. Well-known ports (< 1024) are rejected with an error.
func resolveParams(defs map[string]paramDefinition, sourceFile string) (map[string]any, error) {
	if len(defs) == 0 {
		return nil, nil
	}
	result := make(map[string]any, len(defs))
	for name, def := range defs {
		if def.Default == nil {
			result[name] = nil
			continue
		}
		switch def.Type {
		case "array":
			raw, ok := def.Default.([]any)
			if !ok {
				return nil, fmt.Errorf("bundle: %s: param %q type=array but default is not a sequence", sourceFile, name)
			}
			// For integer arrays, validate each element.
			resolved := make([]any, 0, len(raw))
			allInts := true
			for _, v := range raw {
				switch n := v.(type) {
				case int:
					if n < 1024 {
						return nil, fmt.Errorf("bundle: %s: param %q devPorts contains well-known port %d: use explicit policy for ports < 1024", sourceFile, name, n)
					}
					if n > 65535 {
						return nil, fmt.Errorf("bundle: %s: param %q devPorts contains out-of-range port %d (max 65535)", sourceFile, name, n)
					}
					resolved = append(resolved, int64(n))
				default:
					allInts = false
					resolved = append(resolved, v)
				}
			}
			_ = allInts
			result[name] = resolved
		default:
			result[name] = def.Default
		}
	}
	return result, nil
}

// buildCombinedExpression builds a single CEL expression from policy validations.
// Returns the expression string and a bool indicating whether this is a REQUIRE_APPROVAL policy.
// Variables defined in spec.variables are inlined by substitution before compilation.
//
// Key behaviors:
//   - Variables are inlined using multiple passes to handle nested references (e.g., isProtected → branchName).
//   - All DENY validations are combined with OR: !(expr1 || expr2 || ...).
//   - If no DENY validations exist, REQUIRE_APPROVAL validations are collected next.
//   - If neither exists, falls back to the first non-empty validation.
func buildCombinedExpression(m *policyManifest) (string, bool) {
	// Build variable substitution map: name → normalized expression.
	vars := make(map[string]string, len(m.Spec.Variables))
	for _, v := range m.Spec.Variables {
		vars[v.Name] = normalizeExpression(v.Expression)
	}

	// inline substitutes all variables, using multiple passes to handle nested references.
	// Go map iteration order is random, so if isProtected references branchName, a single pass
	// may substitute isProtected before branchName, leaving branchName un-substituted.
	// Multiple passes (up to len(vars)+1) guarantee all transitive references are resolved.
	inline := func(expr string) string {
		expr = normalizeExpression(expr)
		for i := 0; i < len(vars)+1; i++ {
			prev := expr
			for name, val := range vars {
				expr = replaceIdentifier(expr, name, "("+val+")")
			}
			if expr == prev {
				break // no more substitutions possible
			}
		}
		return expr
	}

	// Collect all DENY validations and combine with OR.
	var denyExprs []string
	for _, v := range m.Spec.Validations {
		if v.Action == "DENY" && v.Expression != "" {
			denyExprs = append(denyExprs, inline(v.Expression))
		}
	}

	if len(denyExprs) > 0 {
		// Combined expression: deny if ANY of the deny conditions is true.
		// The expression evaluates to true (allow) when none of the conditions match.
		// !(cond1 || cond2 || cond3) == allow when all conditions are false.
		return "!(" + strings.Join(denyExprs, " || ") + ")", false
	}

	// Collect REQUIRE_APPROVAL validations.
	var reqApprovalExprs []string
	for _, v := range m.Spec.Validations {
		if v.Action == "REQUIRE_APPROVAL" && v.Expression != "" {
			reqApprovalExprs = append(reqApprovalExprs, inline(v.Expression))
		}
	}

	if len(reqApprovalExprs) > 0 {
		return "!(" + strings.Join(reqApprovalExprs, " || ") + ")", true
	}

	// Fallback: use first non-empty validation expression regardless of action.
	// AUDIT stubs (expression: "false", action: AUDIT) must still be registered as
	// always-allow stubs so operators can see them in the active policy list.
	// The engine skips AUDIT evaluation at runtime; the loader must not drop them.
	for _, v := range m.Spec.Validations {
		if v.Expression != "" {
			return "!(" + inline(v.Expression) + ")", false
		}
	}
	return "", false
}

// replaceIdentifier replaces a CEL identifier (variable name) with a replacement value,
// but only when it appears as a standalone identifier — not as part of a larger identifier
// or function name.
//
// For example, replacing "targetPort" with "(bash.targetPort(...))" should not match
// the "targetPort" inside "bash.targetPort" because it's preceded by a dot.
func replaceIdentifier(expr, name, replacement string) string {
	var result strings.Builder
	result.Grow(len(expr) + len(replacement))

	i := 0
	for i < len(expr) {
		// Find next occurrence of name
		idx := strings.Index(expr[i:], name)
		if idx == -1 {
			result.WriteString(expr[i:])
			break
		}
		absIdx := i + idx

		// Check if this is a standalone identifier (not part of a larger word)
		// Preceding char must not be alphanumeric, underscore, or dot
		// Following char must not be alphanumeric or underscore
		validBefore := absIdx == 0 || !isIdentChar(expr[absIdx-1])
		validAfter := absIdx+len(name) >= len(expr) || !isIdentContinue(expr[absIdx+len(name)])

		result.WriteString(expr[i:absIdx])
		if validBefore && validAfter {
			result.WriteString(replacement)
		} else {
			result.WriteString(name)
		}
		i = absIdx + len(name)
	}

	return result.String()
}

// isIdentChar returns true if c can be part of or adjacent to a CEL identifier.
// Includes dot because function calls like "bash.targetPort" should not have
// "targetPort" substituted.
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '.'
}

// isIdentContinue returns true if c can continue a CEL identifier.
// Does not include dot — "targetPort." should allow substitution of "targetPort".
func isIdentContinue(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}

// normalizeExpression transforms policy YAML expression syntax to CEL activation syntax.
// The policy YAML uses `request.args.command` but CEL activation uses flat `args["command"]`.
func normalizeExpression(expr string) string {
	expr = strings.ReplaceAll(expr, "request.args.command", `args["command"]`)
	expr = strings.ReplaceAll(expr, "request.args", "args")
	return expr
}

// ParsePolicyDir parses all YAML files in a directory tree and returns templates and bindings.
// It recursively walks subdirectories to find all policy files. Files that fail to parse are
// skipped with a warning (logged to stderr) rather than failing the entire load.
func ParsePolicyDir(dir string) ([]policy_types.PolicyTemplate, []policy_types.PolicyBinding, error) {
	var templates []policy_types.PolicyTemplate
	var bindings []policy_types.PolicyBinding
	var skipped int

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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

		template, binding, parseErr := ParsePolicyFile(path)
		if parseErr != nil {
			log.Printf("bundle: skipping %s: %v", path, parseErr)
			skipped++
			return nil
		}

		if template != nil && binding != nil {
			templates = append(templates, *template)
			bindings = append(bindings, *binding)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if skipped > 0 {
		log.Printf("bundle: %d policy file(s) skipped due to parse errors (see above)", skipped)
	}

	return templates, bindings, nil
}
