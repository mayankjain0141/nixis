// SPDX-License-Identifier: MIT
// nixis-hook is the per-invocation hook binary for Claude Code, Cursor IDE,
// and any IDE that exposes a tool-call hook.
//
// It is invoked for every tool call. It reads raw JSON from stdin, detects
// the IDE via an adapter registry, evaluates the request against nixis-daemon,
// and writes IDE-specific output to stdout.
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

	"github.com/mayankjain0141/nixis/internal/otel"
	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// totalBudget is the wall-clock deadline for the entire hook invocation.
const totalBudget = 200 * time.Millisecond

// HookInput is retained for backward-compatible test helpers that reference it.
// Adapters handle the actual parsing; this struct is not used in the main flow.
type HookInput struct {
	Tool           string          `json:"tool_name"`
	Input          json.RawMessage `json:"input"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ConversationID string          `json:"conversation_id"`
	SessionID      string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
}

// GetInput returns the tool arguments regardless of which field name was used.
func (h *HookInput) GetInput() json.RawMessage {
	if len(h.Input) > 0 && string(h.Input) != "null" {
		return h.Input
	}
	return h.ToolInput
}

// GetSessionID returns the session identifier regardless of which field name was used.
func (h *HookInput) GetSessionID() string {
	if h.ConversationID != "" {
		return h.ConversationID
	}
	return h.SessionID
}

// CursorHookOutput is the JSON structure for Cursor IDE.
type CursorHookOutput struct {
	Decision struct {
		Action   string `json:"action"`
		Reason   string `json:"reason,omitempty"`
		PolicyID string `json:"policy_id,omitempty"`
	} `json:"decision"`
	LatencyNs int64 `json:"latency_ns"`
}

// ClaudeCodeHookOutput is the JSON structure for Claude Code.
type ClaudeCodeHookOutput struct {
	HookSpecificOutput ClaudeCodeHookSpecific `json:"hookSpecificOutput"`
}

// ClaudeCodeHookSpecific carries the decision fields inside hookSpecificOutput.
type ClaudeCodeHookSpecific struct {
	HookEventName            string `json:"hookEventName,omitempty"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// FailOpenEntry is appended to NIXIS_FAILOPEN_LOG when the hook fails open.
type FailOpenEntry struct {
	Ts               time.Time `json:"ts"`
	SessionID        string    `json:"session_id"`
	Tool             string    `json:"tool"`
	ArgsHash         string    `json:"args_hash"`
	Reason           string    `json:"reason"`
	DeadlineExceeded bool      `json:"deadline_exceeded"`
}

func main() {
	otelCfg := otel.Config{
		Enabled:      os.Getenv("NIXIS_OTEL_ENDPOINT") != "",
		Endpoint:     os.Getenv("NIXIS_OTEL_ENDPOINT"),
		ServiceName:  "nixis-hook",
		BatchTimeout: 500 * time.Millisecond,
	}
	otelShutdown, err := otel.Initialize(otelCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nixis-hook: OTel init warning: %v\n", err)
		otelShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = otelShutdown(shutCtx)
	}()

	deadline := time.Now().Add(totalBudget)
	sock := socketPath()

	// Step 1: Read raw stdin.
	rawInput, err := readStdin(deadline)
	if err != nil {
		// No adapter yet — use generic fail-open format.
		stdout, _ := (&GenericAdapter{}).FormatFailOpen("stdin_read_error", nil)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("stdin_read_error", "", nil, false)
		os.Exit(0)
	}

	// Step 2: Detect adapter from raw input.
	adapter := detectAdapter(rawInput)

	// Step 3: Parse input into CheckRequest.
	req, err := adapter.ParseInput(rawInput)
	if err != nil {
		stdout, _ := adapter.FormatFailOpen("parse_error", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("parse_error", "", nil, false)
		os.Exit(0)
	}

	// Populate timing.
	req.Timestamp = time.Now().UnixNano()

	// Step 4: Connect to daemon socket.
	conn, err := dialSocket(sock, deadline)
	if err != nil {
		stdout, exitCode := adapter.FormatFailOpen("daemon_unreachable", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("daemon_unreachable", req.Tool, req.Args, time.Now().After(deadline))
		os.Exit(exitCode)
	}
	defer func() { _ = conn.Close() }()

	// Step 5: Serialize and send the CheckRequest.
	reqBytes, err := json.Marshal(req)
	if err != nil {
		stdout, exitCode := adapter.FormatFailOpen("marshal_error", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("marshal_error", req.Tool, req.Args, false)
		os.Exit(exitCode)
	}

	if err := writeFramed(conn, reqBytes, deadline); err != nil {
		stdout, exitCode := adapter.FormatFailOpen("send_error", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("send_error", req.Tool, req.Args, time.Now().After(deadline))
		os.Exit(exitCode)
	}

	// Step 6: Receive CheckResponse.
	respBytes, err := readFramed(conn, deadline)
	if err != nil {
		stdout, exitCode := adapter.FormatFailOpen("recv_error", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("recv_error", req.Tool, req.Args, time.Now().After(deadline))
		os.Exit(exitCode)
	}

	var resp nixis.CheckResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		stdout, exitCode := adapter.FormatFailOpen("response_parse_error", rawInput)
		_, _ = os.Stdout.Write(stdout)
		logFailOpen("response_parse_error", req.Tool, req.Args, false)
		os.Exit(exitCode)
	}

	// Step 7: Format IDE-specific output and exit.
	stdout, exitCode := adapter.FormatOutput(resp, rawInput)
	_, _ = os.Stdout.Write(stdout)
	os.Exit(exitCode)
}

// buildCheckRequest constructs a CheckRequest from parsed HookInput.
// Retained for test compatibility.
func buildCheckRequest(h HookInput, timestampNs int64) nixis.CheckRequest {
	return nixis.CheckRequest{
		Tool:            h.Tool,
		Args:            h.GetInput(),
		SessionID:       h.GetSessionID(),
		Timestamp:       timestampNs,
		SpawnToken:      os.Getenv("NIXIS_SPAWN_TOKEN"),
		ParentSessionID: os.Getenv("NIXIS_PARENT_SESSION_ID"),
		ProjectRoot:     os.Getenv("NIXIS_PROJECT_ROOT"),
	}
}

// translateToClaudeCode converts a CheckResponse into a ClaudeCodeHookOutput.
// Retained for test compatibility.
func translateToClaudeCode(resp nixis.CheckResponse, eventName string) ClaudeCodeHookOutput {
	specific := ClaudeCodeHookSpecific{
		HookEventName: eventName,
	}
	switch resp.Decision.Action {
	case nixis.ActionAllow:
		specific.PermissionDecision = "allow"
	case nixis.ActionDeny:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case nixis.ActionRequireApproval:
		specific.PermissionDecision = "ask"
		specific.PermissionDecisionReason = resp.Decision.Reason
	case nixis.ActionAudit:
		specific.PermissionDecision = "allow"
	default:
		specific.PermissionDecision = "deny"
		specific.PermissionDecisionReason = "unknown action"
	}
	return ClaudeCodeHookOutput{HookSpecificOutput: specific}
}

// logFailOpen records a fail-open event to the log file and increments the OTel counter.
func logFailOpen(reason, tool string, args json.RawMessage, deadlineExceeded bool) {
	otel.InstrumentFailOpen().Add(context.Background(), 1)

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
	_ = writeFailOpen(failOpenLogPath(), entry)
}

// socketPath returns the daemon Unix socket path.
func socketPath() string {
	if v := os.Getenv("NIXIS_SOCKET_PATH"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return xdg + "/nixis/nixis.sock"
	}
	return "/tmp/nixis.sock"
}

// failOpenLogPath returns the fail-open log path.
func failOpenLogPath() string {
	if v := os.Getenv("NIXIS_FAILOPEN_LOG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/nixis-failopen.log"
	}
	return home + "/.nixis/failopen.log"
}

// readStdin reads all of stdin up to nixis.MaxMessageSize before the deadline.
func readStdin(deadline time.Time) ([]byte, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, fmt.Errorf("deadline exceeded before stdin read")
	}

	limited := io.LimitReader(os.Stdin, int64(nixis.MaxMessageSize))
	var buf []byte
	reader := bufio.NewReader(limited)

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
func readFramed(conn net.Conn, deadline time.Time) ([]byte, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if int(length) > nixis.MaxMessageSize {
		return nil, fmt.Errorf("response exceeds MaxMessageSize")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
