// SPDX-License-Identifier: MIT
package nixis

import "encoding/json"

// ExtractScanTarget pulls the content to scan from tool arguments.
// Only the user-controlled content field is extracted to avoid false positives
// from file paths, metadata, and other non-content fields.
// On JSON parse failure, returns the raw args (fail-secure: scan everything).
// Returns nil when no content needs scanning (e.g. Read — path is not content).
func ExtractScanTarget(tool string, args []byte) []byte {
	switch tool {
	case "SendMessage":
		var msg struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(args, &msg); err != nil {
			return args
		}
		return []byte(msg.Message)
	case "Write":
		var w struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(args, &w); err != nil {
			return args
		}
		return []byte(w.Content)
	case "Edit":
		var e struct {
			NewString string `json:"new_string"`
		}
		if err := json.Unmarshal(args, &e); err != nil {
			return args
		}
		return []byte(e.NewString)
	case "Read":
		return nil // file path is not content — no scan needed
	default:
		return args
	}
}
