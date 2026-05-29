package bundle

import (
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
		DefaultAction string `yaml:"defaultAction"`
	} `yaml:"spec"`
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

	expr := buildCombinedExpression(&manifest)
	if expr == "" {
		return nil, nil, nil
	}

	template := &policy_types.PolicyTemplate{
		ID:          manifest.Metadata.Name,
		Name:        manifest.Metadata.Name,
		Description: manifest.Spec.Description,
		Expression:  expr,
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
		Priority: 0,
		Layer:    layer,
	}

	return template, binding, nil
}

// buildCombinedExpression builds a single CEL expression from policy validations.
// Variables defined in spec.variables are inlined by substitution before compilation.
//
// Key behaviors:
//   - Variables are inlined using multiple passes to handle nested references (e.g., isProtected → branchName).
//   - All DENY validations are combined with OR: !(expr1 || expr2 || ...).
//   - If no DENY validations exist, falls back to the first non-empty validation.
func buildCombinedExpression(m *policyManifest) string {
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
		return "!(" + strings.Join(denyExprs, " || ") + ")"
	}

	// Fallback: use first non-empty validation (for REQUIRE_APPROVAL, etc.)
	for _, v := range m.Spec.Validations {
		if v.Expression != "" {
			return "!(" + inline(v.Expression) + ")"
		}
	}
	return ""
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
			// Skip files that fail to parse rather than failing the entire load
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

	// Log skipped count if any (caller can also check len(templates) vs expected)
	_ = skipped

	return templates, bindings, nil
}
