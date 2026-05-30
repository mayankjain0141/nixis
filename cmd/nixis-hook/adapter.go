// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"

	"github.com/mayjain/nixis/pkg/nixis"
)

// IDEAdapter translates between a specific IDE's hook format and Nixis's
// internal CheckRequest/CheckResponse protocol.
type IDEAdapter interface {
	// Name returns the adapter identifier for logging.
	Name() string
	// Detect returns true if this adapter should handle the given raw input.
	Detect(raw json.RawMessage) bool
	// ParseInput converts IDE-specific JSON into a CheckRequest.
	ParseInput(raw json.RawMessage) (nixis.CheckRequest, error)
	// FormatOutput converts a CheckResponse into IDE-specific stdout bytes and exit code.
	FormatOutput(resp nixis.CheckResponse, rawInput json.RawMessage) (stdout []byte, exitCode int)
	// FormatFailOpen produces fail-open output when the daemon is unreachable.
	FormatFailOpen(reason string, rawInput json.RawMessage) (stdout []byte, exitCode int)
}

// adapters is the ordered registry. First match wins.
var adapters = []IDEAdapter{
	&ClaudeCodeAdapter{},
	&CursorAdapter{},
	&GenericAdapter{},
}

// detectAdapter finds the matching adapter for the raw input.
func detectAdapter(raw json.RawMessage) IDEAdapter {
	for _, a := range adapters {
		if a.Detect(raw) {
			return a
		}
	}
	return &GenericAdapter{}
}
