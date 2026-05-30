// SPDX-License-Identifier: MIT
package classify

import (
	"strings"
	"testing"
)

func TestCheckArgSchema_Bash_MissingCommand(t *testing.T) {
	result := CheckArgSchema("Bash", map[string]any{})
	if result.Err == nil {
		t.Fatal("expected error for missing command field, got nil")
	}
	e, ok := result.Err.(*ArgSchemaError)
	if !ok {
		t.Fatalf("expected *ArgSchemaError, got %T", result.Err)
	}
	if e.Field != "command" {
		t.Errorf("expected field %q, got %q", "command", e.Field)
	}
	if e.Got != "missing" {
		t.Errorf("expected Got=%q, got %q", "missing", e.Got)
	}
	if result.UnknownTool {
		t.Error("UnknownTool should be false for Bash")
	}
}

func TestCheckArgSchema_Bash_WrongType_Command(t *testing.T) {
	result := CheckArgSchema("Bash", map[string]any{"command": 42.0})
	if result.Err == nil {
		t.Fatal("expected error for wrong type on command field, got nil")
	}
	msg := result.Err.Error()
	if !strings.Contains(msg, "expected string got int") {
		t.Errorf("expected error to contain %q, got %q", "expected string got int", msg)
	}
}

func TestCheckArgSchema_Bash_ValidCommand(t *testing.T) {
	result := CheckArgSchema("Bash", map[string]any{"command": "ls -la"})
	if result.Err != nil {
		t.Fatalf("expected no error, got %v", result.Err)
	}
	if result.UnknownTool {
		t.Error("UnknownTool should be false for Bash")
	}
}

func TestCheckArgSchema_Read_ValidFilePath(t *testing.T) {
	result := CheckArgSchema("Read", map[string]any{"file_path": "/etc/passwd"})
	if result.Err != nil {
		t.Fatalf("expected no error, got %v", result.Err)
	}
	if result.UnknownTool {
		t.Error("UnknownTool should be false for Read")
	}
}

func TestCheckArgSchema_Write_MissingContent(t *testing.T) {
	result := CheckArgSchema("Write", map[string]any{"file_path": "/tmp/f"})
	if result.Err == nil {
		t.Fatal("expected error for missing content field, got nil")
	}
	e, ok := result.Err.(*ArgSchemaError)
	if !ok {
		t.Fatalf("expected *ArgSchemaError, got %T", result.Err)
	}
	if e.Field != "content" {
		t.Errorf("expected field %q, got %q", "content", e.Field)
	}
	if e.Got != "missing" {
		t.Errorf("expected Got=%q, got %q", "missing", e.Got)
	}
}

func TestCheckArgSchema_Edit_AllOptional_NoRequired(t *testing.T) {
	// Edit has no Required fields — empty args should pass.
	result := CheckArgSchema("Edit", map[string]any{})
	if result.Err != nil {
		t.Fatalf("expected no error for Edit with empty args, got %v", result.Err)
	}
	if result.UnknownTool {
		t.Error("UnknownTool should be false for Edit")
	}
}

func TestCheckArgSchema_UnknownTool_FailOpen(t *testing.T) {
	result := CheckArgSchema("MyCustomTool", map[string]any{})
	if result.Err != nil {
		t.Fatalf("expected no error for unknown tool (fail-open), got %v", result.Err)
	}
	if !result.UnknownTool {
		t.Error("UnknownTool should be true for unregistered tool")
	}
}

func TestCheckArgSchema_WebSearch_WrongTypeAllowedDomains(t *testing.T) {
	result := CheckArgSchema("WebSearch", map[string]any{
		"query":           "test",
		"allowed_domains": "not-an-array",
	})
	if result.Err == nil {
		t.Fatal("expected error for allowed_domains being string instead of array")
	}
	e, ok := result.Err.(*ArgSchemaError)
	if !ok {
		t.Fatalf("expected *ArgSchemaError, got %T", result.Err)
	}
	if e.Field != "allowed_domains" {
		t.Errorf("expected field %q, got %q", "allowed_domains", e.Field)
	}
	if e.Expected != "array" {
		t.Errorf("expected Expected=%q, got %q", "array", e.Expected)
	}
	if e.Got != "string" {
		t.Errorf("expected Got=%q, got %q", "string", e.Got)
	}
}
