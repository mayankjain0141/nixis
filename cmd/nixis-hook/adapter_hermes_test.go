// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

func TestHermesAdapter_Detect_True(t *testing.T) {
	raw := json.RawMessage(`{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "ls"},
		"session_id": "sess-123",
		"cwd": "/home/user"
	}`)

	a := &HermesAdapter{}
	if !a.Detect(raw) {
		t.Error("Detect() = false, want true for payload with hook_event_name and cwd")
	}
}

func TestHermesAdapter_Detect_False_NoCwd(t *testing.T) {
	// Payload has hook_event_name but no cwd — this is Claude Code, not Hermes.
	raw := json.RawMessage(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "ls"},
		"session_id": "sess-cc-001"
	}`)

	a := &HermesAdapter{}
	if a.Detect(raw) {
		t.Error("Detect() = true, want false for payload with hook_event_name but no cwd")
	}
}

func TestHermesAdapter_Detect_False_NoHookEvent(t *testing.T) {
	// Payload has cwd but no hook_event_name — generic/unknown, not hermes.
	raw := json.RawMessage(`{
		"tool_name": "terminal",
		"cwd": "/home/user"
	}`)

	a := &HermesAdapter{}
	if a.Detect(raw) {
		t.Error("Detect() = true, want false for payload missing hook_event_name")
	}
}

func TestHermesAdapter_ParseInput(t *testing.T) {
	raw := json.RawMessage(`{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "rm -rf /"},
		"session_id": "sess-123",
		"task_id": "task-456",
		"tool_call_id": "call-789",
		"cwd": "/home/user"
	}`)

	a := &HermesAdapter{}
	req, err := a.ParseInput(raw)
	if err != nil {
		t.Fatalf("ParseInput() error = %v", err)
	}

	if req.Tool != "terminal" {
		t.Errorf("Tool = %q, want %q", req.Tool, "terminal")
	}
	if req.SessionID != "sess-123" {
		t.Errorf("SessionID = %q, want %q", req.SessionID, "sess-123")
	}

	// Args must be a JSON object containing "command".
	var args map[string]string
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.Fatalf("Args is not valid JSON object: %v", err)
	}
	if args["command"] != "rm -rf /" {
		t.Errorf("Args.command = %q, want %q", args["command"], "rm -rf /")
	}
}

func TestHermesAdapter_ParseInput_NullToolInput(t *testing.T) {
	// When tool_input is absent or null, Args should fall back to "{}".
	raw := json.RawMessage(`{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"session_id": "sess-999",
		"cwd": "/tmp"
	}`)

	a := &HermesAdapter{}
	req, err := a.ParseInput(raw)
	if err != nil {
		t.Fatalf("ParseInput() error = %v", err)
	}
	if string(req.Args) != "{}" {
		t.Errorf("Args = %s, want {}", req.Args)
	}
}

func TestHermesAdapter_FormatOutput_Allow(t *testing.T) {
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionAllow

	a := &HermesAdapter{}
	out, exitCode := a.FormatOutput(resp, nil)

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	// Allow response must be empty JSON object (possibly with trailing newline).
	trimmed := bytes.TrimSpace(out)
	if string(trimmed) != "{}" {
		t.Errorf("FormatOutput allow = %q, want {}", string(trimmed))
	}
}

func TestHermesAdapter_FormatOutput_Deny(t *testing.T) {
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionDeny
	resp.Decision.Reason = "Policy violation: destructive command"

	a := &HermesAdapter{}
	out, exitCode := a.FormatOutput(resp, nil)

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (hermes reads JSON, not exit code)", exitCode)
	}

	var m map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(out), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v (got: %s)", err, out)
	}
	if m["decision"] != "block" {
		t.Errorf("decision = %q, want %q", m["decision"], "block")
	}
	if m["reason"] != "Policy violation: destructive command" {
		t.Errorf("reason = %q, want %q", m["reason"], "Policy violation: destructive command")
	}
}

func TestHermesAdapter_FormatOutput_Audit(t *testing.T) {
	// ActionAudit (ActionLog) should not block — returns "{}".
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionAudit

	a := &HermesAdapter{}
	out, exitCode := a.FormatOutput(resp, nil)

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	trimmed := bytes.TrimSpace(out)
	if string(trimmed) != "{}" {
		t.Errorf("FormatOutput audit = %q, want {}", string(trimmed))
	}
}

func TestHermesAdapter_FormatFailOpen(t *testing.T) {
	a := &HermesAdapter{}
	out, exitCode := a.FormatFailOpen("daemon_unreachable", nil)

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	trimmed := bytes.TrimSpace(out)
	if string(trimmed) != "{}" {
		t.Errorf("FormatFailOpen = %q, want {}", string(trimmed))
	}
}

func TestHermesAdapter_InitRegistered(t *testing.T) {
	// Verify that the init() function registered HermesAdapter as the first entry
	// in the global adapters slice, before ClaudeCodeAdapter.
	if len(adapters) == 0 {
		t.Fatal("adapters slice is empty")
	}
	first, ok := adapters[0].(*HermesAdapter)
	if !ok || first == nil {
		t.Errorf("adapters[0] = %T, want *HermesAdapter", adapters[0])
	}
}
