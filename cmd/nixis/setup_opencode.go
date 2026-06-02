// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const openCodeInstructionsTemplate = `# Nixis Governance Policy

Nixis is enforcing governance policies on tool calls in this session.
Policy directory: ~/.nixis/policies/

When a tool call is blocked, respect the decision and do not attempt to circumvent it.
`

// detectOpenCode returns the opencode config path to patch, "" if not applicable.
// For global setup we target ~/.config/opencode/opencode.json.
func detectOpenCode(homeDir string) string {
	return filepath.Join(homeDir, ".config", "opencode", "opencode.json")
}

// patchOpenCodeConfig adds nixis instructions to opencode config. Idempotent.
func patchOpenCodeConfig(w io.Writer, homeDir, nixisDir string) error {
	cfgPath := detectOpenCode(homeDir)
	fmt.Fprintf(w, "  OpenCode config: %s\n", cfgPath)

	instructionsPath := filepath.Join(nixisDir, "opencode-instructions.md")

	// Write (or overwrite) the instructions file.
	if !setupDryRun {
		if err := os.MkdirAll(nixisDir, 0o755); err != nil {
			return fmt.Errorf("create nixis dir: %w", err)
		}
		if err := os.WriteFile(instructionsPath, []byte(openCodeInstructionsTemplate), 0o644); err != nil {
			return fmt.Errorf("write opencode instructions: %w", err)
		}
	}

	// instructionsRef is what we store in the JSON (home-dir-relative tilde path).
	instructionsRef := "~/.nixis/opencode-instructions.md"

	// Read existing config or start fresh.
	var config map[string]any
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read opencode config: %w", err)
		}
		// File doesn't exist — start with a minimal config.
		config = map[string]any{
			"$schema": "https://opencode.ai/config.json",
		}
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil && !setupDryRun {
			return fmt.Errorf("create opencode config dir: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse opencode config: %w", err)
		}
	}

	// Check / update the instructions array.
	existing, _ := config["instructions"].([]any)
	for _, v := range existing {
		if s, ok := v.(string); ok && s == instructionsRef {
			fmt.Fprintln(w, "  nixis instructions already registered in opencode config")
			return nil
		}
	}
	config["instructions"] = append(existing, instructionsRef)

	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal opencode config: %w", err)
	}

	if setupDryRun {
		fmt.Fprintln(w, "  (dry-run) Would patch opencode config")
		return nil
	}

	if err := os.WriteFile(cfgPath, append(newData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write opencode config: %w", err)
	}
	fmt.Fprintln(w, "  opencode config patched")
	return nil
}

// unpatchOpenCodeConfig removes nixis instructions from opencode config.
func unpatchOpenCodeConfig(w io.Writer, homeDir string) error {
	cfgPath := detectOpenCode(homeDir)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read opencode config: %w", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse opencode config: %w", err)
	}

	const instructionsRef = "~/.nixis/opencode-instructions.md"

	existing, _ := config["instructions"].([]any)
	filtered := existing[:0]
	removed := false
	for _, v := range existing {
		if s, ok := v.(string); ok && s == instructionsRef {
			removed = true
			continue
		}
		filtered = append(filtered, v)
	}

	if !removed {
		fmt.Fprintln(w, "  nixis instructions not found in opencode config, skipping")
		return nil
	}

	if len(filtered) == 0 {
		delete(config, "instructions")
	} else {
		config["instructions"] = filtered
	}

	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal opencode config: %w", err)
	}

	if setupDryRun {
		fmt.Fprintln(w, "  (dry-run) Would unpatch opencode config")
		return nil
	}

	if err := os.WriteFile(cfgPath, append(newData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write opencode config: %w", err)
	}
	fmt.Fprintln(w, "  nixis instructions removed from opencode config")
	return nil
}
