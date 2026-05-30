// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/pkg/adapters"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <mcp-server-command> [args...]",
	Short: "Scan an MCP server and generate adapter YAML scaffold",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScan,
}

// mcpRequest is a minimal JSON-RPC 2.0 request.
type mcpRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// mcpResponse is a minimal JSON-RPC 2.0 response.
type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolsListResult is the result of a tools/list call.
type toolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func runScan(cmd *cobra.Command, args []string) error {
	serverCmd := args[0]
	serverArgs := args[1:]

	proc := exec.Command(serverCmd, serverArgs...)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	stderr, err := proc.StderrPipe()
	if err != nil {
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	if err := proc.Start(); err != nil {
		return fmt.Errorf("start MCP server %q: %w", serverCmd, err)
	}
	defer func() {
		_ = proc.Wait()
	}()
	defer func() {
		_ = stdin.Close()
	}()
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()

	enc := json.NewEncoder(stdin)
	dec := json.NewDecoder(bufio.NewReader(stdout))

	// 1. Send initialize
	initReq := mcpRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "aegis-scan",
				"version": "1.0",
			},
		},
	}
	if err := enc.Encode(initReq); err != nil {
		return fmt.Errorf("send initialize: %w", err)
	}

	var initResp mcpResponse
	if err := dec.Decode(&initResp); err != nil {
		return fmt.Errorf("read initialize response: %w", err)
	}
	if initResp.Error != nil {
		return fmt.Errorf("initialize error %d: %s", initResp.Error.Code, initResp.Error.Message)
	}

	// 2. Send tools/list
	listReq := mcpRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	if err := enc.Encode(listReq); err != nil {
		return fmt.Errorf("send tools/list: %w", err)
	}

	var listResp mcpResponse
	if err := dec.Decode(&listResp); err != nil {
		return fmt.Errorf("read tools/list response: %w", err)
	}
	if listResp.Error != nil {
		return fmt.Errorf("tools/list error %d: %s", listResp.Error.Code, listResp.Error.Message)
	}

	var toolsList toolsListResult
	if err := json.Unmarshal(listResp.Result, &toolsList); err != nil {
		return fmt.Errorf("parse tools/list result: %w", err)
	}

	catalog, err := adapters.Catalog()
	if err != nil {
		return fmt.Errorf("load adapter catalog: %w", err)
	}
	clf := classify.NewClassifier(catalog)

	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintln(out, "tools:"); err != nil {
		return err
	}
	for _, t := range toolsList.Tools {
		entry, _ := clf.Classify(t.Name)
		riskLevel := string(entry.RiskLevel)
		if riskLevel == "" {
			riskLevel = "medium"
		}
		desc := t.Description
		if idx := strings.IndexByte(desc, '\n'); idx >= 0 {
			desc = desc[:idx]
		}
		if _, err := fmt.Fprintf(out, "  - name: %s\n", t.Name); err != nil {
			return err
		}
		if desc != "" {
			if _, err := fmt.Fprintf(out, "    description: %s\n", desc); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(out, "    # aegis: classify as %s\n", riskLevel); err != nil {
			return err
		}
		effectsLine := buildEffectsLine(entry.Effects)
		if _, err := fmt.Fprintf(out, "    # aegis: effects: [%s]\n", effectsLine); err != nil {
			return err
		}
	}
	return nil
}

func buildEffectsLine(effects []string) string {
	if len(effects) == 0 {
		return "read"
	}
	return strings.Join(effects, ", ")
}
