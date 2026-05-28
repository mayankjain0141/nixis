// Package mcp implements an MCP proxy with Aegis governance.
//
// The proxy sits between an MCP client (e.g. Claude Code) and an upstream MCP
// server. Every tools/call request passes through the governance pipeline before
// it is forwarded. The proxy also tracks tool definition integrity across
// tools/list responses and scans upstream responses for secrets asynchronously.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
)

// JSONRPCRequest is a standard JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a standard JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolDefinition is a tool as listed by the MCP server.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolFingerprint tracks tool definition integrity.
type ToolFingerprint struct {
	Name       string
	Hash       [32]byte
	RecordedAt int64 // unix nanos
}

// Upstream is the connection to the real MCP server.
type Upstream interface {
	Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
	ListTools(ctx context.Context) ([]ToolDefinition, error)
	Close() error
}

// IntegrityTracker records and checks tool definition fingerprints for drift.
type IntegrityTracker struct {
	mu       sync.RWMutex
	baseline map[string]ToolFingerprint
}

// NewIntegrityTracker returns an initialised IntegrityTracker.
func NewIntegrityTracker() *IntegrityTracker {
	return &IntegrityTracker{
		baseline: make(map[string]ToolFingerprint),
	}
}

// Fingerprint returns the SHA-256 of the canonical tool definition JSON.
func (t *IntegrityTracker) Fingerprint(tool ToolDefinition) [32]byte {
	canonical, _ := json.Marshal(map[string]any{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": tool.InputSchema,
	})
	return sha256.Sum256(canonical)
}

// CheckDrift reports whether the tool's current definition differs from the
// recorded baseline. The first call for a given tool name sets the baseline and
// always returns hasDrift=false.
func (t *IntegrityTracker) CheckDrift(tool ToolDefinition) (hasDrift bool, baseline [32]byte) {
	hash := t.Fingerprint(tool)
	t.mu.Lock()
	defer t.mu.Unlock()
	existing, ok := t.baseline[tool.Name]
	if !ok {
		t.baseline[tool.Name] = ToolFingerprint{
			Name:       tool.Name,
			Hash:       hash,
			RecordedAt: time.Now().UnixNano(),
		}
		return false, hash
	}
	return existing.Hash != hash, existing.Hash
}
