// SPDX-License-Identifier: MIT
package types

// PolicyTemplate is a reusable policy pattern.
type PolicyTemplate struct {
	ID            string
	Name          string
	Description   string
	Expression    string         // CEL expression
	Params        map[string]any // resolved param values (defaults applied at parse time)
	SourceFile    string         // policy source file path for policySourceLocation in CheckResponse
	SourceLine    int            // policy source line number
	DefaultAction string         // "DENY" opts into fail-secure on CEL compile/runtime error
}

// PolicyBinding binds a template to a scope.
type PolicyBinding struct {
	TemplateID      string
	Scope           PolicyScope
	Priority        int
	Layer           string // "cel", "ifc", "adapter"
	RequireApproval bool   // true if the policy's primary action is REQUIRE_APPROVAL
	Message         string // human-readable message from YAML validations[].message
	DefaultAction   string // "DENY" opts into fail-secure on CEL runtime error
}

// PolicyScope defines which tools/sessions a binding applies to.
type PolicyScope struct {
	Tools    []string // empty = all tools
	Sessions []string // empty = all sessions
	Effects  []string // empty = all effects; if specified, binding only applies when tool has ALL listed effects
}

// PolicySet is the full set of active policies.
type PolicySet struct {
	Templates []PolicyTemplate
	Bindings  []PolicyBinding
	Version   uint64
}
