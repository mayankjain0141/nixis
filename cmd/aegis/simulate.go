// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/spf13/cobra"
)

const simulateTimeout = 5 * time.Second

var (
	simulateArgs    string
	simulateSession string
	simulateSocket  string
)

var simulateCmd = &cobra.Command{
	Use:   "simulate <tool>",
	Short: "Simulate a tool call against the running daemon",
	Args:  cobra.ExactArgs(1),
	RunE:  runSimulate,
}

func init() {
	simulateCmd.Flags().StringVar(&simulateArgs, "args", "{}", "Tool arguments as JSON")
	simulateCmd.Flags().StringVar(&simulateSession, "session", "", "Session ID")
	simulateCmd.Flags().StringVar(&simulateSocket, "socket", "", "Daemon socket path (default: $AEGIS_SOCKET_PATH or /tmp/aegis.sock)")
}

func runSimulate(cmd *cobra.Command, args []string) error {
	tool := args[0]
	sockPath := simulateSocket
	if sockPath == "" {
		sockPath = daemonSocketPath()
	}

	rawArgs := json.RawMessage(simulateArgs)
	req := aegis.CheckRequest{
		Tool:      tool,
		Args:      rawArgs,
		SessionID: simulateSession,
		Timestamp: time.Now().UnixNano(),
	}

	deadline := time.Now().Add(simulateTimeout)
	conn, err := net.DialTimeout("unix", sockPath, time.Until(deadline))
	if err != nil {
		return fmt.Errorf("cannot connect to daemon at %s: %w", sockPath, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	if err := writeSimFramed(conn, reqBytes, deadline); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	respBytes, err := readSimFramed(conn, deadline)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var resp aegis.CheckResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	actionStr := actionString(resp.Decision.Action)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "action=%s policy=%s layer=%s latency=%dns\n",
		actionStr, resp.Decision.PolicyID, string(resp.EnforcingLayer), resp.LatencyNs)
	if resp.Decision.Reason != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "reason=%s\n", resp.Decision.Reason)
	}
	return nil
}

func actionString(a aegis.Action) string {
	switch a {
	case aegis.ActionAllow:
		return "allow"
	case aegis.ActionDeny:
		return "deny"
	case aegis.ActionRequireApproval:
		return "require_approval"
	case aegis.ActionAudit:
		return "audit"
	default:
		return "deny"
	}
}

func daemonSocketPath() string {
	if v := os.Getenv("AEGIS_SOCKET_PATH"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return xdg + "/aegis/aegis.sock"
	}
	return "/tmp/aegis.sock"
}

func writeSimFramed(conn net.Conn, payload []byte, deadline time.Time) error {
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

func readSimFramed(conn net.Conn, deadline time.Time) ([]byte, error) {
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
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
