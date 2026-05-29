// SPDX-License-Identifier: MIT
package adapters

import (
	_ "embed"
	"encoding/json"
)

//go:embed catalog.json
var catalogData []byte

// AdapterDef is one entry in the tool verdict catalog.
type AdapterDef struct {
	Tool         string   `json:"tool"`          // exact tool name (e.g. "Bash", "Read", "Write")
	Family       string   `json:"family"`        // adapter family (e.g. "bash", "filesystem", "claude-code-coordination")
	Operation    string   `json:"operation"`     // "read", "write", "exec", "publish", "create", "update", "delete"
	Effects      []string `json:"effects"`       // effect strings (see ENGINEERING_STANDARDS.md)
	ResourceType string   `json:"resource_type"` // "file", "process", "network", "agent_coordination", etc.
	RiskLevel    string   `json:"risk_level"`    // "none", "low", "medium", "high", "critical"
}

// Catalog returns the full parsed adapter catalog.
// Called once at startup by internal/classify/ to build the VerdictMap.
// Returns an error only if the embedded JSON is malformed (build-time bug).
func Catalog() ([]AdapterDef, error) {
	var defs []AdapterDef
	if err := json.Unmarshal(catalogData, &defs); err != nil {
		return nil, err
	}
	return defs, nil
}
