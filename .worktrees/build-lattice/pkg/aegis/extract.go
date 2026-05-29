package aegis

import "encoding/json"

// ExtractScanTarget pulls the content to scan from tool arguments.
// For SendMessage, extracts the "message" field to avoid scanning metadata
// (the "to" and "summary" fields do not carry user-controlled secret content).
// For all other tools, returns the full args as content.
// On JSON parse failure, returns the raw args (fail-secure: scan everything).
func ExtractScanTarget(tool string, args []byte) []byte {
	if tool != "SendMessage" {
		return args
	}
	var msg struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(args, &msg); err != nil {
		return args
	}
	return []byte(msg.Message)
}
