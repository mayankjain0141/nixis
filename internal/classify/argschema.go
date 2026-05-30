// SPDX-License-Identifier: MIT
package classify

import "fmt"

type ArgSchema struct {
	Required map[string]string // field → expected JSON type ("string", "int", "bool", "object", "array")
	Optional map[string]string
}

type ArgSchemaError struct {
	Field    string
	Expected string
	Got      string // "missing", "null", or actual JSON type name
}

func (e *ArgSchemaError) Error() string {
	return fmt.Sprintf("arg schema violation: field %q expected %s got %s", e.Field, e.Expected, e.Got)
}

type ArgSchemaResult struct {
	Err         error
	UnknownTool bool // true when no schema is registered for this tool
}

// Unknown tools pass with UnknownTool=true (fail-open for backward compat).
func CheckArgSchema(tool string, args map[string]any) ArgSchemaResult {
	schema, ok := toolSchemas[tool]
	if !ok {
		return ArgSchemaResult{UnknownTool: true}
	}
	if err := schema.validate(args); err != nil {
		return ArgSchemaResult{Err: err}
	}
	return ArgSchemaResult{}
}

func (s ArgSchema) validate(args map[string]any) error {
	for field, expectedType := range s.Required {
		v, ok := args[field]
		if !ok {
			return &ArgSchemaError{Field: field, Expected: expectedType, Got: "missing"}
		}
		if v == nil {
			return &ArgSchemaError{Field: field, Expected: expectedType, Got: "null"}
		}
		if got := jsonTypeName(v); got != expectedType {
			return &ArgSchemaError{Field: field, Expected: expectedType, Got: got}
		}
	}
	for field, expectedType := range s.Optional {
		v, ok := args[field]
		if !ok || v == nil {
			continue // missing or null optional is fine
		}
		if got := jsonTypeName(v); got != expectedType {
			return &ArgSchemaError{Field: field, Expected: expectedType, Got: got}
		}
	}
	return nil
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "int" // json.Unmarshal always produces float64 for JSON numbers
	case bool:
		return "bool"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "unknown"
	}
}

// Conservative Required set minimizes blast radius from future API evolution.
var toolSchemas = map[string]ArgSchema{
	"Bash": {
		Required: map[string]string{"command": "string"},
		Optional: map[string]string{
			"description":               "string",
			"timeout":                   "int",
			"dangerouslyDisableSandbox": "bool",
			"run_in_background":         "bool",
		},
	},
	"Read": {
		Required: map[string]string{"file_path": "string"},
		Optional: map[string]string{
			"offset": "int",
			"limit":  "int",
			"pages":  "string",
		},
	},
	"Write": {
		Required: map[string]string{
			"file_path": "string",
			"content":   "string",
		},
	},
	"Edit": {
		Optional: map[string]string{
			"file_path":   "string",
			"old_string":  "string",
			"new_string":  "string",
			"replace_all": "bool",
		},
	},
	"WebFetch": {
		Optional: map[string]string{
			"url":    "string",
			"prompt": "string",
		},
	},
	"WebSearch": {
		Optional: map[string]string{
			"query":           "string",
			"allowed_domains": "array",
			"blocked_domains": "array",
		},
	},
	"Agent": {
		Optional: map[string]string{
			"description":   "string",
			"prompt":        "string",
			"model":         "string",
			"team_name":     "string",
			"name":          "string",
			"subagent_type": "string",
		},
	},
	"SendMessage": {
		Optional: map[string]string{
			"to":      "string",
			"message": "string",
			"summary": "string",
		},
	},
	"NotebookEdit": {
		Optional: map[string]string{
			"notebook_path": "string",
			"new_source":    "string",
			"cell_id":       "string",
			"cell_type":     "string",
			"edit_mode":     "string",
		},
	},
}
