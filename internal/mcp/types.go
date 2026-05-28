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
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	_ "modernc.org/sqlite" // register sqlite driver
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
// It optionally persists baselines to a SQLite tool_registrations table.
type IntegrityTracker struct {
	mu       sync.Mutex
	baseline map[string]ToolFingerprint
	drifted  map[string]bool
	db       *sql.DB // nil when not using persistence
}

// NewIntegrityTracker returns an in-memory IntegrityTracker with no persistence.
func NewIntegrityTracker() *IntegrityTracker {
	return &IntegrityTracker{
		baseline: make(map[string]ToolFingerprint),
		drifted:  make(map[string]bool),
	}
}

// NewIntegrityTrackerWithDB returns an IntegrityTracker backed by the given
// SQLite database. On startup it loads all existing baselines from the
// tool_registrations table so integrity is preserved across daemon restarts.
func NewIntegrityTrackerWithDB(db *sql.DB) (*IntegrityTracker, error) {
	if err := applyTrackerSchema(db); err != nil {
		return nil, err
	}
	t := &IntegrityTracker{
		baseline: make(map[string]ToolFingerprint),
		drifted:  make(map[string]bool),
		db:       db,
	}
	if err := t.loadFromDB(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

func applyTrackerSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS tool_registrations (
		name        TEXT    PRIMARY KEY,
		hash        BLOB    NOT NULL,
		recorded_at INTEGER NOT NULL
	)`)
	return err
}

func (t *IntegrityTracker) loadFromDB(ctx context.Context) error {
	rows, err := t.db.QueryContext(ctx, `SELECT name, hash, recorded_at FROM tool_registrations`)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		var fp ToolFingerprint
		var hashBytes []byte
		if err := rows.Scan(&fp.Name, &hashBytes, &fp.RecordedAt); err != nil {
			return err
		}
		if len(hashBytes) == 32 {
			copy(fp.Hash[:], hashBytes)
		}
		t.baseline[fp.Name] = fp
	}
	return rows.Err()
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
// always returns hasDrift=false. When a drift is detected the tool is added to
// the internal drifted set so subsequent tool calls are blocked until approved.
func (t *IntegrityTracker) CheckDrift(tool ToolDefinition) (hasDrift bool, baseline [32]byte) {
	hash := t.Fingerprint(tool)
	t.mu.Lock()
	defer t.mu.Unlock()
	existing, ok := t.baseline[tool.Name]
	if !ok {
		fp := ToolFingerprint{
			Name:       tool.Name,
			Hash:       hash,
			RecordedAt: time.Now().UnixNano(),
		}
		t.baseline[tool.Name] = fp
		if t.db != nil {
			t.persistBaseline(fp)
		}
		return false, hash
	}
	if existing.Hash != hash {
		t.drifted[tool.Name] = true
		return true, existing.Hash
	}
	return false, existing.Hash
}

// IsDrifted reports whether the named tool has a recorded drift against its baseline.
func (t *IntegrityTracker) IsDrifted(name string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.drifted[name]
}

func (t *IntegrityTracker) persistBaseline(fp ToolFingerprint) {
	_, _ = t.db.Exec(
		`INSERT OR IGNORE INTO tool_registrations (name, hash, recorded_at) VALUES (?, ?, ?)`,
		fp.Name, fp.Hash[:], fp.RecordedAt,
	)
}
