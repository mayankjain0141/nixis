package main

import (
	"encoding/json"
	"testing"

	"github.com/mayjain/nixis/pkg/nixis"
	"os"
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

func TestTranslateToClaudeCode_Allow(t *testing.T) {
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionAllow

	out := translateToClaudeCode(resp, "PreToolUse")

	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want PreToolUse", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("PermissionDecision = %q, want allow", out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "" {
		t.Errorf("PermissionDecisionReason should be empty for allow, got %q", out.HookSpecificOutput.PermissionDecisionReason)
	}

	// Verify the JSON shape Claude Code expects.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hso, ok := raw["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("hookSpecificOutput key missing or wrong type")
	}
	if hso["permissionDecision"] != "allow" {
		t.Errorf("JSON permissionDecision = %v, want allow", hso["permissionDecision"])
	}
}

func TestTranslateToClaudeCode_Deny(t *testing.T) {
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionDeny
	resp.Decision.Reason = "policy P-001 prohibits rm -rf"

	out := translateToClaudeCode(resp, "PreToolUse")

	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("PermissionDecision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "policy P-001 prohibits rm -rf" {
		t.Errorf("PermissionDecisionReason = %q, want reason from response", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestTranslateToClaudeCode_RequireApproval(t *testing.T) {
	resp := nixis.CheckResponse{}
	resp.Decision.Action = nixis.ActionRequireApproval
	resp.Decision.Reason = "requires human approval"

	out := translateToClaudeCode(resp, "PreToolUse")

	if out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "requires human approval" {
		t.Errorf("PermissionDecisionReason = %q, want reason from response", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// TestBuildCheckRequest_SpawnTokenFromEnv verifies that buildCheckRequest reads
// NIXIS_SPAWN_TOKEN and NIXIS_PARENT_SESSION_ID from the environment and
// populates the corresponding CheckRequest fields. Both env vars are optional —
// empty string is the correct value for root (non-delegated) sessions.
func TestBuildCheckRequest_SpawnTokenFromEnv(t *testing.T) {
	h := HookInput{
		Tool:      "Bash",
		ToolInput: json.RawMessage(`{"command":"ls"}`),
		SessionID: "sess-child-001",
	}

	t.Run("token_and_parent_present", func(t *testing.T) {
		t.Setenv("NIXIS_SPAWN_TOKEN", "tok-abc123")
		t.Setenv("NIXIS_PARENT_SESSION_ID", "sess-parent-001")

		req := buildCheckRequest(h, 42)

		if req.SpawnToken != "tok-abc123" {
			t.Errorf("SpawnToken = %q, want %q", req.SpawnToken, "tok-abc123")
		}
		if req.ParentSessionID != "sess-parent-001" {
			t.Errorf("ParentSessionID = %q, want %q", req.ParentSessionID, "sess-parent-001")
		}
		if req.SessionID != "sess-child-001" {
			t.Errorf("SessionID = %q, want %q", req.SessionID, "sess-child-001")
		}
		if req.Tool != "Bash" {
			t.Errorf("Tool = %q, want Bash", req.Tool)
		}
		if req.Timestamp != 42 {
			t.Errorf("Timestamp = %d, want 42", req.Timestamp)
		}
	})

	t.Run("root_session_no_env_vars", func(t *testing.T) {
		os.Unsetenv("NIXIS_SPAWN_TOKEN")
		os.Unsetenv("NIXIS_PARENT_SESSION_ID")

		req := buildCheckRequest(h, 0)

		if req.SpawnToken != "" {
			t.Errorf("SpawnToken = %q for root session, want empty", req.SpawnToken)
		}
		if req.ParentSessionID != "" {
			t.Errorf("ParentSessionID = %q for root session, want empty", req.ParentSessionID)
		}
	})
}

// TestBuildCheckRequest_FieldTypes is a compile-time assertion that SpawnToken and
// ParentSessionID on CheckRequest are string fields, exercised here to catch any
// future type mismatch.
var _ = func() nixis.CheckRequest {
	return nixis.CheckRequest{SpawnToken: "", ParentSessionID: ""}
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
