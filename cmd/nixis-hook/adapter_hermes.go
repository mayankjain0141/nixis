// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// HermesAdapter handles the hermes-agent shell hook protocol.
// Detection: presence of both "hook_event_name" and "cwd" fields.
// Hermes always receives exit code 0; the decision is conveyed via the JSON body.
type HermesAdapter struct{}

// hermesInput is the JSON shape sent by hermes-agent shell hooks.
type hermesInput struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	SessionID     string          `json:"session_id"`
	TaskID        string          `json:"task_id"`
	ToolCallID    string          `json:"tool_call_id"`
	Cwd           string          `json:"cwd"`
}

// hermesBlockOutput is the body written when nixis blocks a tool call.
type hermesBlockOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func init() {
	// Prepend HermesAdapter so it is evaluated before ClaudeCodeAdapter.
	// Both formats carry "hook_event_name"; hermes is distinguished by also
	// carrying "cwd". First-match-wins requires hermes to come first.
	adapters = append([]IDEAdapter{&HermesAdapter{}}, adapters...)
}

func (a *HermesAdapter) Name() string { return "hermes" }

func (a *HermesAdapter) Detect(raw json.RawMessage) bool {
	var probe struct {
		HookEventName string `json:"hook_event_name"`
		Cwd           string `json:"cwd"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	// Hermes payloads carry both hook_event_name and cwd.
	// Claude Code payloads carry hook_event_name but not cwd.
	return probe.HookEventName != "" && probe.Cwd != ""
}

func (a *HermesAdapter) ParseInput(raw json.RawMessage) (nixis.CheckRequest, error) {
	var inp hermesInput
	if err := json.Unmarshal(raw, &inp); err != nil {
		return nixis.CheckRequest{}, fmt.Errorf("parse hermes input: %w", err)
	}
	args := inp.ToolInput
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	return nixis.CheckRequest{
		Tool:            inp.ToolName,
		Args:            args,
		SessionID:       inp.SessionID,
		SpawnToken:      os.Getenv("NIXIS_SPAWN_TOKEN"),
		ParentSessionID: os.Getenv("NIXIS_PARENT_SESSION_ID"),
		ProjectRoot:     os.Getenv("NIXIS_PROJECT_ROOT"),
	}, nil
}

func (a *HermesAdapter) FormatOutput(resp nixis.CheckResponse, _ json.RawMessage) ([]byte, int) {
	switch resp.Decision.Action {
	case nixis.ActionDeny:
		out := hermesBlockOutput{
			Decision: "block",
			Reason:   resp.Decision.Reason,
		}
		b, err := json.Marshal(out)
		if err != nil {
			return []byte(`{"decision":"block","reason":"policy violation"}` + "\n"), 0
		}
		return append(b, '\n'), 0
	default:
		// ActionAllow, ActionLog/ActionAudit, ActionRequireApproval — all allow; hermes
		// reads a non-empty "decision" field to block. Empty object = allow.
		return []byte("{}\n"), 0
	}
}

func (a *HermesAdapter) FormatFailOpen(_ string, _ json.RawMessage) ([]byte, int) {
	// Fail-open: daemon unreachable → do not block.
	return []byte("{}\n"), 0
}
