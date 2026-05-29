// SPDX-License-Identifier: MIT
// aegis-hook is the per-invocation hook binary for Claude Code and Cursor IDE.
//
// It is invoked for every tool call. It reads a HookInput JSON object from stdin,
// evaluates it against the aegis-daemon, and writes a hook output JSON object
// to stdout before exiting.
//
// Exit codes (Cursor):
//
//	0 — allow (or fail-open: daemon unreachable within deadline)
//	2 — deny / require_approval
//
// Exit codes (Claude Code):
//
//	0 — always; decision communicated via JSON permissionDecision field
//
// Build constraints:
//
//	CGO_ENABLED=0  (pure Go, no cgo)
//	-ldflags="-s -w"  (strip symbols to keep binary <3MB)
//
// Wire format: 4-byte big-endian uint32 length + JSON payload (shared with daemon).
// Total deadline budget: 200ms (startup 10 + stdin 20 + parse 5 + dial 30 + send 20 + recv 100 + write 15).
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mayjain/aegis/internal/otel"
	"github.com/mayjain/aegis/pkg/aegis"
)

// totalBudget is the wall-clock deadline for the entire hook invocation.
const totalBudget = 200 * time.Millisecond

// HookInput supports both Claude Code and Cursor IDE hook formats.
// Claude Code sends "tool_input" and "session_id"; Cursor sends "input" and "conversation_id".
type HookInput struct {
	Tool           string          `json:"tool_name"`
	Input          json.RawMessage `json:"input"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ConversationID string          `json:"conversation_id"`
	SessionID      string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
}

// GetInput returns the tool arguments regardless of which field name was used.
// Cursor sends "input"; Claude Code sends "tool_input". Cursor wins on conflict.
func (h *HookInput) GetInput() json.RawMessage {
	if len(h.Input) > 0 && string(h.Input) != "null" {
		return h.Input
	}
	return h.ToolInput
}

// GetSessionID returns the session identifier regardless of which field name was used.
// Cursor sends "conversation_id"; Claude Code sends "session_id". Cursor wins on conflict.
func (h *HookInput) GetSessionID() string {
	if h.ConversationID != "" {
		return h.ConversationID
	}
	return h.SessionID
}

// CursorHookOutput is the JSON structure the hook writes to stdout for Cursor IDE.
type CursorHookOutput struct {
	// Decision mirrors the daemon's CheckResponse.Decision for Cursor integration.
	Decision struct {
		Action   string `json:"action"`
		Reason   string `json:"reason,omitempty"`
		PolicyID string `json:"policy_id,omitempty"`
	} `json:"decision"`
	LatencyNs int64 `json:"latency_ns"`
}

// ClaudeCodeHookOutput is the JSON structure the hook writes to stdout for Claude Code.
// Claude Code reads this only on exit code 0; deny is communicated via permissionDecision.
type ClaudeCodeHookOutput struct {
	HookSpecificOutput ClaudeCodeHookSpecific `json:"hookSpecificOutput"`
}

// ClaudeCodeHookSpecific carries the decision fields inside hookSpecificOutput.
type ClaudeCodeHookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// FailOpenEntry is appended to AEGIS_FAILOPEN_LOG when the hook fails open.
type FailOpenEntry struct {
	Ts               time.Time `json:"ts"`
	SessionID        string    `json:"session_id"`
	Tool             string    `json:"tool"`
	ArgsHash         string    `json:"args_hash"`
	Reason           string    `json:"reason"`
	DeadlineExceeded bool      `json:"deadline_exceeded"`
}

func main() {
	// Initialize OTel before any other logic so metrics are routed to a real exporter.
	// OTel failure is non-fatal for the hook — fail-open behaviour must not be blocked
	// by telemetry infrastructure.
	otelCfg := otel.Config{
		Enabled:      os.Getenv("AEGIS_OTEL_ENDPOINT") != "",
		Endpoint:     os.Getenv("AEGIS_OTEL_ENDPOINT"),
		ServiceName:  "aegis-hook",
		BatchTimeout: 500 * time.Millisecond, // short-lived process: flush fast
	}
	otelShutdown, err := otel.Initialize(otelCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-hook: OTel init warning: %v\n", err)
		otelShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = otelShutdown(shutCtx) // ignore error — hook is exiting anyway
	}()

	// Deadline covers the entire execution.
	deadline := time.Now().Add(totalBudget)

	socketPath := socketPath()

	// Read stdin with a deadline.
	inputBytes, err := readStdin(deadline)
	if err != nil {
		allowWithWarning("stdin_read_error", "", nil, false, false)
		os.Exit(0)
	}

	var hookInput HookInput
	if err := json.Unmarshal(inputBytes, &hookInput); err != nil {
		allowWithWarning("stdin_parse_error", "", nil, false, false)
		os.Exit(0)
	}

	// Detect IDE: Claude Code sends hook_event_name; Cursor does not.
	isClaudeCode := hookInput.HookEventName != ""

	// Build CheckRequest.
	req := aegis.CheckRequest{
		Tool:      hookInput.Tool,
		Args:      hookInput.GetInput(),
		SessionID: hookInput.GetSessionID(),
		Timestamp: time.Now().UnixNano(),
	}

	// Connect to daemon socket.
	conn, err := dialSocket(socketPath, deadline)
	if err != nil {
		allowWithWarning("daemon_unreachable", hookInput.Tool, hookInput.GetInput(), time.Now().After(deadline), isClaudeCode)
		os.Exit(0)
	}
	defer func() { _ = conn.Close() }()

	// Serialize and send the CheckRequest.
	reqBytes, err := json.Marshal(req)
	if err != nil {
		allowWithWarning("marshal_error", hookInput.Tool, hookInput.GetInput(), false, isClaudeCode)
		os.Exit(0)
	}

	if err := writeFramed(conn, reqBytes, deadline); err != nil {
		allowWithWarning("send_error", hookInput.Tool, hookInput.GetInput(), time.Now().After(deadline), isClaudeCode)
		os.Exit(0)
	}

	// Receive CheckResponse.
	respBytes, err := readFramed(conn, deadline)
	if err != nil {
		allowWithWarning("recv_error", hookInput.Tool, hookInput.GetInput(), time.Now().After(deadline), isClaudeCode)
		os.Exit(0)
	}

	var resp aegis.CheckResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		allowWithWarning("response_parse_error", hookInput.Tool, hookInput.GetInput(), false, isClaudeCode)
		os.Exit(0)
	}

	if isClaudeCode {
		// Claude Code path: always exit 0; deny is communicated via permissionDecision.
		out := translateToClaudeCode(resp, hookInput.HookEventName)
		outBytes, err := json.Marshal(out)
		if err != nil {
			allowWithWarning("output_marshal_error", hookInput.Tool, hookInput.GetInput(), false, true)
			os.Exit(0)
		}
		_, _ = os.Stdout.Write(outBytes)
		_, _ = os.Stdout.Write([]byte("\n"))
		os.Exit(0)
	}

	// Cursor path: translate and write CursorHookOutput, exit 2 on deny/require_approval.
	out := translateResponse(resp)
	outBytes, err := json.Marshal(out)
	if err != nil {
		allowWithWarning("output_marshal_error", hookInput.Tool, hookInput.GetInput(), false, false)
		os.Exit(0)
	}

	_, _ = os.Stdout.Write(outBytes)
	_, _ = os.Stdout.Write([]byte("\n"))

	// Exit with code 2 on Deny or RequireApproval (DECISION-007).
	if resp.Decision.Action == aegis.ActionDeny || resp.Decision.Action == aegis.ActionRequireApproval {
		os.Exit(2)
	}
	os.Exit(0)
}

// socketPath returns the daemon Unix socket path.
// Priority: $AEGIS_SOCKET_PATH → $XDG_RUNTIME_DIR/aegis/aegis.sock → /tmp/aegis.sock
func socketPath() string {
	if v := os.Getenv("AEGIS_SOCKET_PATH"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return xdg + "/aegis/aegis.sock"
	}
	return "/tmp/aegis.sock"
}

// failOpenLogPath returns the fail-open log path.
func failOpenLogPath() string {
	if v := os.Getenv("AEGIS_FAILOPEN_LOG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/aegis-failopen.log"
	}
	return home + "/.aegis/failopen.log"
}

// allowWithWarning writes an allow response to stdout and appends a FailOpenEntry
// to AEGIS_FAILOPEN_LOG. This is the ONLY fail-open path in the system (A5, DECISION-007).
func allowWithWarning(reason, tool string, args json.RawMessage, deadlineExceeded bool, isClaudeCode bool) {
	// Write allow response to stdout first (before potentially slow log write).
	if isClaudeCode {
		out := ClaudeCodeHookOutput{
			HookSpecificOutput: ClaudeCodeHookSpecific{
				PermissionDecision:       "allow",
				PermissionDecisionReason: fmt.Sprintf("fail-open: %s", reason),
			},
		}
		if b, err := json.Marshal(out); err == nil {
			_, _ = os.Stdout.Write(b)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
	} else {
		out := CursorHookOutput{}
		out.Decision.Action = "allow"
		out.Decision.Reason = fmt.Sprintf("fail-open: %s", reason)
		if b, err := json.Marshal(out); err == nil {
			_, _ = os.Stdout.Write(b)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
	}

	otel.InstrumentFailOpen().Add(context.Background(), 1)

	// Append fail-open entry to log. Budget: ~50μs.
	entry := FailOpenEntry{
		Ts:               time.Now(),
		Tool:             tool,
		Reason:           reason,
		DeadlineExceeded: deadlineExceeded,
	}
	if len(args) > 0 {
		h := sha256.Sum256(args)
		entry.ArgsHash = "sha256:" + hex.EncodeToString(h[:])
	}

	// Log write failure must not prevent the fail-open allow (A5).
	_ = writeFailOpen(failOpenLogPath(), entry)
}

// readStdin reads all of stdin up to aegis.MaxMessageSize before the deadline.
func readStdin(deadline time.Time) ([]byte, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, fmt.Errorf("deadline exceeded before stdin read")
	}

	// Read at most MaxMessageSize bytes.
	limited := io.LimitReader(os.Stdin, int64(aegis.MaxMessageSize))
	var buf []byte
	reader := bufio.NewReader(limited)

	// Read until EOF (stdin is closed by Cursor after sending the JSON object).
	for {
		chunk := make([]byte, 4096)
		n, err := reader.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("deadline exceeded reading stdin")
		}
	}
	return buf, nil
}

// dialSocket connects to the daemon Unix socket before the deadline.
func dialSocket(path string, deadline time.Time) (net.Conn, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, fmt.Errorf("deadline exceeded before dial")
	}
	d := net.Dialer{Timeout: remaining}
	return d.Dial("unix", path)
}

// writeFramed writes a length-prefixed frame to conn.
// Wire format: [4-byte big-endian uint32 length][payload]
func writeFramed(conn net.Conn, payload []byte, deadline time.Time) error {
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readFramed reads a length-prefixed frame from conn.
// Wire format: [4-byte big-endian uint32 length][payload]
func readFramed(conn net.Conn, deadline time.Time) ([]byte, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if int(length) > aegis.MaxMessageSize {
		return nil, fmt.Errorf("response exceeds MaxMessageSize")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// translateToClaudeCode converts a CheckResponse into a ClaudeCodeHookOutput.
// Claude Code always receives exit 0; the decision is communicated via permissionDecision.
func translateToClaudeCode(resp aegis.CheckResponse, eventName string) ClaudeCodeHookOutput {
	specific := ClaudeCodeHookSpecific{
		HookEventName: eventName,
	}
	switch resp.Decision.Action {
	case aegis.ActionAllow:
		specific.PermissionDecision = "allow"
	case aegis.ActionDeny:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case aegis.ActionRequireApproval:
		specific.PermissionDecision = "ask"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case aegis.ActionAudit:
		specific.PermissionDecision = "allow"
	default:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = "unknown action"
	}
	return ClaudeCodeHookOutput{HookSpecificOutput: specific}
}

// translateResponse converts a CheckResponse into a CursorHookOutput.
func translateResponse(resp aegis.CheckResponse) CursorHookOutput {
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
	return out
}
