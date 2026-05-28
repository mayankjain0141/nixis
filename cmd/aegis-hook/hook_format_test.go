package main

import (
	"encoding/json"
	"testing"
)

func TestHookInput_ClaudeCodeFormat(t *testing.T) {
	raw := `{
		"session_id": "sess-cc-001",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "git branch -D main"}
	}`

	var h HookInput
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := h.GetSessionID(); got != "sess-cc-001" {
		t.Errorf("GetSessionID() = %q, want %q", got, "sess-cc-001")
	}

	input := h.GetInput()
	if len(input) == 0 || string(input) == "null" {
		t.Fatal("GetInput() returned empty/null for Claude Code tool_input")
	}

	var m map[string]string
	if err := json.Unmarshal(input, &m); err != nil {
		t.Fatalf("tool_input is not valid JSON object: %v", err)
	}
	if m["command"] != "git branch -D main" {
		t.Errorf("command = %q, want %q", m["command"], "git branch -D main")
	}
}

func TestHookInput_CursorFormat(t *testing.T) {
	raw := `{
		"conversation_id": "conv-cursor-002",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"input": {"command": "ls -la"}
	}`

	var h HookInput
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := h.GetSessionID(); got != "conv-cursor-002" {
		t.Errorf("GetSessionID() = %q, want %q", got, "conv-cursor-002")
	}

	input := h.GetInput()
	if len(input) == 0 || string(input) == "null" {
		t.Fatal("GetInput() returned empty/null for Cursor input")
	}

	var m map[string]string
	if err := json.Unmarshal(input, &m); err != nil {
		t.Fatalf("input is not valid JSON object: %v", err)
	}
	if m["command"] != "ls -la" {
		t.Errorf("command = %q, want %q", m["command"], "ls -la")
	}
}

// TestHookInput_MixedFormat verifies that when both field names are present,
// Cursor's "input"/"conversation_id" win over Claude Code's "tool_input"/"session_id".
func TestHookInput_MixedFormat(t *testing.T) {
	raw := `{
		"conversation_id": "cursor-id",
		"session_id": "claude-id",
		"tool_name": "Write",
		"input": {"path": "/cursor/path"},
		"tool_input": {"path": "/claude/path"}
	}`

	var h HookInput
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := h.GetSessionID(); got != "cursor-id" {
		t.Errorf("GetSessionID() = %q, want %q (Cursor wins on conflict)", got, "cursor-id")
	}

	input := h.GetInput()
	var m map[string]string
	if err := json.Unmarshal(input, &m); err != nil {
		t.Fatalf("input parse: %v", err)
	}
	if m["path"] != "/cursor/path" {
		t.Errorf("path = %q, want %q (Cursor wins on conflict)", m["path"], "/cursor/path")
	}
}
