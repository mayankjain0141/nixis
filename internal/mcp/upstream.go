// SPDX-License-Identifier: MIT
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreaker implements a simple three-state (closed/open/half-open) circuit
// breaker for upstream calls. The zero value is not usable; use NewCircuitBreaker.
type CircuitBreaker struct {
	mu           sync.Mutex
	failures     int
	threshold    int
	openUntil    time.Time
	halfOpenWait time.Duration
}

// NewCircuitBreaker returns a CircuitBreaker with the given failure threshold and
// half-open wait duration. Typical values: threshold=5, halfOpenWait=30s.
func NewCircuitBreaker(threshold int, halfOpenWait time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:    threshold,
		halfOpenWait: halfOpenWait,
	}
}

// Allow returns true when the circuit is closed (or half-open for a probe).
// Returns false when the circuit is open and the wait has not elapsed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return !time.Now().Before(cb.openUntil)
}

// RecordFailure increments the failure counter. When the threshold is reached,
// the circuit opens for halfOpenWait.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		cb.openUntil = time.Now().Add(cb.halfOpenWait)
		cb.failures = 0
	}
}

// RecordSuccess resets the failure counter (transitions back to closed).
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

// errCircuitOpen is returned when the circuit breaker is open.
var errCircuitOpen = errors.New("mcp: circuit breaker open — upstream unavailable")

// StdioUpstream connects to an upstream MCP server via stdin/stdout using
// JSON-RPC 2.0. Each Call blocks until the matching response arrives.
type StdioUpstream struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	mu      sync.Mutex // serialises writes to stdin
	idCtr   atomic.Int64
	pending sync.Map // id(string) → chan json.RawMessage

	cb *CircuitBreaker
}

// NewStdioUpstream starts the given command and returns a StdioUpstream wired
// to its stdin/stdout. The caller is responsible for calling Close.
func NewStdioUpstream(command string, args ...string) (*StdioUpstream, error) {
	cmd := exec.Command(command, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp: start: %w", err)
	}

	u := &StdioUpstream{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdoutPipe),
		cb:     NewCircuitBreaker(5, 30*time.Second),
	}
	go u.readLoop()
	return u, nil
}

func (u *StdioUpstream) readLoop() {
	dec := json.NewDecoder(u.stdout)
	for {
		var resp JSONRPCResponse
		if err := dec.Decode(&resp); err != nil {
			return
		}
		if resp.ID == nil {
			continue
		}
		key := string(resp.ID)
		if ch, ok := u.pending.Load(key); ok {
			result := resp.Result
			if resp.Error != nil {
				result = nil
			}
			ch.(chan json.RawMessage) <- result
		}
	}
}

// Call sends a JSON-RPC request and waits for the matching response.
// Returns errCircuitOpen immediately when the circuit breaker is open.
func (u *StdioUpstream) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if !u.cb.Allow() {
		return nil, errCircuitOpen
	}

	id := u.idCtr.Add(1)
	idJSON, _ := json.Marshal(id)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      idJSON,
		Method:  method,
		Params:  params,
	}

	ch := make(chan json.RawMessage, 1)
	u.pending.Store(string(idJSON), ch)
	defer u.pending.Delete(string(idJSON))

	encoded, err := json.Marshal(req)
	if err != nil {
		u.cb.RecordFailure()
		return nil, fmt.Errorf("mcp: marshal: %w", err)
	}
	encoded = append(encoded, '\n')

	u.mu.Lock()
	_, err = u.stdin.Write(encoded)
	u.mu.Unlock()
	if err != nil {
		u.cb.RecordFailure()
		return nil, fmt.Errorf("mcp: write: %w", err)
	}

	select {
	case <-ctx.Done():
		u.cb.RecordFailure()
		return nil, ctx.Err()
	case result := <-ch:
		u.cb.RecordSuccess()
		return result, nil
	}
}

// ListTools calls tools/list on the upstream and decodes the tool array.
func (u *StdioUpstream) ListTools(ctx context.Context) ([]ToolDefinition, error) {
	result, err := u.Call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Tools []ToolDefinition `json:"tools"`
	}
	if err := json.Unmarshal(result, &wrapper); err != nil {
		return nil, fmt.Errorf("mcp: decode tools/list: %w", err)
	}
	return wrapper.Tools, nil
}

// Close terminates the upstream process and its I/O.
func (u *StdioUpstream) Close() error {
	err := u.stdin.Close()
	if killErr := u.cmd.Process.Kill(); killErr != nil && err == nil {
		err = killErr
	}
	return err
}
