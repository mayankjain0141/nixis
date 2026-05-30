// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mayjain/aegis/pkg/aegis"
)

// CursorAdapter handles the Cursor IDE hook protocol.
// Detection: presence of "conversation_id" OR absence of "hook_event_name".
type CursorAdapter struct{}

// cursorInput is the JSON shape sent by Cursor IDE hooks.
type cursorInput struct {
	ToolName       string          `json:"tool_name"`
	Input          json.RawMessage `json:"input"`
	ConversationID string          `json:"conversation_id"`
}

func (a *CursorAdapter) Name() string { return "cursor" }

func (a *CursorAdapter) Detect(raw json.RawMessage) bool {
	var probe struct {
		ConversationID string `json:"conversation_id"`
		HookEventName  string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	// Cursor sends conversation_id; Claude Code sends hook_event_name.
	// If hook_event_name is present, Claude Code adapter already matched (first in registry).
	// This adapter matches when conversation_id is present and hook_event_name is absent.
	return probe.ConversationID != "" && probe.HookEventName == ""
}

func (a *CursorAdapter) ParseInput(raw json.RawMessage) (aegis.CheckRequest, error) {
	var inp cursorInput
	if err := json.Unmarshal(raw, &inp); err != nil {
		return aegis.CheckRequest{}, fmt.Errorf("parse cursor input: %w", err)
	}
	return aegis.CheckRequest{
		Tool:            inp.ToolName,
		Args:            inp.Input,
		SessionID:       inp.ConversationID,
		SpawnToken:      os.Getenv("AEGIS_SPAWN_TOKEN"),
		ParentSessionID: os.Getenv("AEGIS_PARENT_SESSION_ID"),
		ProjectRoot:     os.Getenv("AEGIS_PROJECT_ROOT"),
	}, nil
}

func (a *CursorAdapter) FormatOutput(resp aegis.CheckResponse, _ json.RawMessage) ([]byte, int) {
	var out CursorHookOutput
	out.LatencyNs = resp.LatencyNs

	switch resp.Decision.Action {
	case aegis.ActionAllow:
		out.Decision.Action = "allow"
	case aegis.ActionDeny:
		out.Decision.Action = "deny"
		out.Decision.Reason = resp.Decision.Reason
		out.Decision.PolicyID = resp.Decision.PolicyID
	case aegis.ActionRequireApproval:
		out.Decision.Action = "require_approval"
		out.Decision.Reason = resp.Decision.Reason
		out.Decision.PolicyID = resp.Decision.PolicyID
	case aegis.ActionAudit:
		out.Decision.Action = "audit"
	default:
		out.Decision.Action = "deny"
		out.Decision.Reason = "unknown action"
	}

	exitCode := 0
	if resp.Decision.Action == aegis.ActionDeny || resp.Decision.Action == aegis.ActionRequireApproval {
		exitCode = 2
	}

	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"decision":{"action":"allow"}}` + "\n"), 0
	}
	return append(b, '\n'), exitCode
}

func (a *CursorAdapter) FormatFailOpen(reason string, _ json.RawMessage) ([]byte, int) {
	out := CursorHookOutput{}
	out.Decision.Action = "allow"
	out.Decision.Reason = fmt.Sprintf("fail-open: %s", reason)

	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"decision":{"action":"allow"}}` + "\n"), 0
	}
	return append(b, '\n'), 0
}
