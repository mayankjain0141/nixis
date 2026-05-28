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
		MatchConstraints struct {
			Tools []string `yaml:"tools"`
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

	binding := &policy_types.PolicyBinding{
		TemplateID: manifest.Metadata.Name,
		Scope: policy_types.PolicyScope{
			Tools: manifest.Spec.MatchConstraints.Tools,
		},
		Priority: 0,
		Layer:    "cel",
	}

	return template, binding, nil
}

// buildCombinedExpression builds a single CEL expression from policy validations.
// For MVP-1, this uses the first validation expression that results in DENY.
// The expression is wrapped in negation so that when it evaluates true, it causes DENY.
func buildCombinedExpression(m *policyManifest) string {
	for _, v := range m.Spec.Validations {
		if v.Action == "DENY" && v.Expression != "" {
			expr := normalizeExpression(v.Expression)
			return "!(" + expr + ")"
		}
	}
	for _, v := range m.Spec.Validations {
		if v.Expression != "" {
			expr := normalizeExpression(v.Expression)
			return "!(" + expr + ")"
		}
	}
	return ""
}

// normalizeExpression transforms policy YAML expression syntax to CEL activation syntax.
// The policy YAML uses `request.args.command` but CEL activation uses flat `args["command"]`.
func normalizeExpression(expr string) string {
	expr = strings.ReplaceAll(expr, "request.args.command", `args["command"]`)
	expr = strings.ReplaceAll(expr, "request.args", "args")
	return expr
}

// ParsePolicyDir parses all YAML files in a directory and returns templates and bindings.
func ParsePolicyDir(dir string) ([]policy_types.PolicyTemplate, []policy_types.PolicyBinding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	var templates []policy_types.PolicyTemplate
	var bindings []policy_types.PolicyBinding

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)
		template, binding, err := ParsePolicyFile(path)
		if err != nil {
			return nil, nil, err
		}

		if template != nil && binding != nil {
			templates = append(templates, *template)
			bindings = append(bindings, *binding)
		}
	}

	return templates, bindings, nil
}
