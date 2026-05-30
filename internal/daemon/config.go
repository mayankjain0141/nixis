// SPDX-License-Identifier: MIT
// Package daemon implements the Nixis governance daemon: Unix socket listener,
// length-prefixed JSON framing, policy evaluation dispatch, and graceful shutdown.
//
// Critical invariants enforced here:
//   - No atomic.Pointer.Store() in this package — PolicyEngine owns reload.
//   - Every error path returns Decision{Action: ActionDeny} (fail-secure, A5).
//   - MaxMessageSize (2MB) enforced at framing layer before any allocation.
//   - Per-connection 50ms evaluation deadline.
//   - Graceful shutdown: drain in-flight → close listener → flush audit.
package daemon

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// maxConcurrentConnections bounds the accept loop semaphore.
	maxConcurrentConnections = 128
	socketPermissions        = 0600
	socketDirPermissions     = 0700
	evaluationDeadline       = 50 * time.Millisecond
)

// Config carries daemon startup parameters.
type Config struct {
	SocketPath  string
	PolicyDir   string
	AuditDBPath string
	// FailOpenLog defaults to ~/.nixis/failopen.log (or $NIXIS_FAILOPEN_LOG).
	FailOpenLog string
	// HealthzAddr is the address for the /healthz HTTP endpoint. Defaults to "127.0.0.1:9091".
	HealthzAddr string
}

// defaultSocketPath returns the canonical Unix socket path.
// Priority: $NIXIS_SOCKET_PATH → $XDG_RUNTIME_DIR/nixis/nixis.sock → /tmp/nixis.sock
func defaultSocketPath() string {
	if v := os.Getenv("NIXIS_SOCKET_PATH"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "nixis", "nixis.sock")
	}
	return "/tmp/nixis.sock"
}

// defaultFailOpenLog returns the default fail-open log path.
func defaultFailOpenLog() string {
	if v := os.Getenv("NIXIS_FAILOPEN_LOG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/nixis-failopen.log"
	}
	return filepath.Join(home, ".nixis", "failopen.log")
}

// applyDefaults fills in zero-value Config fields.
func (c *Config) applyDefaults() {
	if c.SocketPath == "" {
		c.SocketPath = defaultSocketPath()
	}
	if c.FailOpenLog == "" {
		c.FailOpenLog = defaultFailOpenLog()
	}
	if c.HealthzAddr == "" {
		c.HealthzAddr = "127.0.0.1:9091"
	}
}
