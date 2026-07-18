// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	hermesBeginMarker = "    # nixis-begin"
	hermesEndMarker   = "    # nixis-end"
)

// detectHermes returns the hermes config path if hermes is installed, "" otherwise.
func detectHermes(homeDir string) string {
	path := filepath.Join(homeDir, ".hermes", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// patchHermesConfig adds nixis-hook to hermes shell hooks. Idempotent.
func patchHermesConfig(w io.Writer, homeDir, hookPath string) error {
	cfgPath := filepath.Join(homeDir, ".hermes", "config.yaml")
	fmt.Fprintf(w, "  Hermes config: %s\n", cfgPath)

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(w, "  hermes config not found, skipping")
			return nil
		}
		return fmt.Errorf("read hermes config: %w", err)
	}

	content := string(data)

	// Idempotent: already registered.
	if strings.Contains(content, "nixis-hook") {
		fmt.Fprintln(w, "  nixis-hook already registered in hermes config")
		return nil
	}

	// The block we insert, indented to match YAML structure under pre_tool_call.
	hookBlock := fmt.Sprintf("%s\n    - command: %s\n      timeout: 5\n%s",
		hermesBeginMarker, hookPath, hermesEndMarker)

	var newContent string
	switch {
	case strings.Contains(content, "pre_tool_call:"):
		// Append our entry after the pre_tool_call: key line.
		newContent = insertAfterLine(content, "pre_tool_call:", "\n"+hookBlock)
	case strings.Contains(content, "hooks:"):
		// Add pre_tool_call section under hooks:.
		preToolCallSection := fmt.Sprintf("\n  pre_tool_call:\n%s", hookBlock)
		newContent = insertAfterLine(content, "hooks:", preToolCallSection)
	default:
		// Append entire hooks block at end of file.
		newContent = strings.TrimRight(content, "\n") +
			fmt.Sprintf("\n\nhooks:\n  pre_tool_call:\n%s\n", hookBlock)
	}

	if setupDryRun {
		fmt.Fprintln(w, "  (dry-run) Would patch hermes config")
		return nil
	}

	if err := os.WriteFile(cfgPath, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("write hermes config: %w", err)
	}
	fmt.Fprintln(w, "  hermes config patched")
	return nil
}

// unpatchHermesConfig removes nixis-hook from hermes shell hooks.
func unpatchHermesConfig(w io.Writer, homeDir string) error {
	cfgPath := filepath.Join(homeDir, ".hermes", "config.yaml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read hermes config: %w", err)
	}

	content := string(data)
	if !strings.Contains(content, hermesBeginMarker) {
		fmt.Fprintln(w, "  No nixis-begin marker found in hermes config, skipping")
		return nil
	}

	// Remove the lines between nixis-begin and nixis-end inclusive.
	newContent := removeMarkedBlock(content, hermesBeginMarker, hermesEndMarker)

	if setupDryRun {
		fmt.Fprintln(w, "  (dry-run) Would unpatch hermes config")
		return nil
	}

	if err := os.WriteFile(cfgPath, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("write hermes config: %w", err)
	}
	fmt.Fprintln(w, "  nixis-hook removed from hermes config")
	return nil
}

// insertAfterLine finds the first line in content that starts with (or equals) marker
// and appends addition immediately after it (before the next newline if any).
func insertAfterLine(content, marker, addition string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == strings.TrimSpace(marker) {
			// Rebuild: everything up to and including this line, then addition, then rest.
			before := strings.Join(lines[:i+1], "\n")
			after := strings.Join(lines[i+1:], "\n")
			return before + addition + "\n" + after
		}
	}
	// marker not found — append at end.
	return strings.TrimRight(content, "\n") + addition + "\n"
}

// removeMarkedBlock removes all lines from the begin marker to the end marker, inclusive.
func removeMarkedBlock(content, beginMarker, endMarker string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		if strings.TrimSpace(line) == strings.TrimSpace(beginMarker) {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.TrimSpace(line) == strings.TrimSpace(endMarker) {
				inBlock = false
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
