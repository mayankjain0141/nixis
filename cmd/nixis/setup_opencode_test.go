// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectOpenCode(t *testing.T) {
	homeDir := "/home/testuser"
	got := detectOpenCode(homeDir)
	want := filepath.Join(homeDir, ".config", "opencode", "opencode.json")
	if got != want {
		t.Fatalf("detectOpenCode = %q, want %q", got, want)
	}
}

func TestPatchOpenCodeConfig_CreatesNewConfig(t *testing.T) {
	dir := t.TempDir()
	nixisDir := filepath.Join(dir, ".nixis")

	var w bytes.Buffer
	if err := patchOpenCodeConfig(&w, dir, nixisDir); err != nil {
		t.Fatalf("patchOpenCodeConfig: %v", err)
	}

	cfgPath := detectOpenCode(dir)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not created: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("config not valid JSON: %v", err)
	}

	instructions, _ := config["instructions"].([]any)
	if len(instructions) == 0 {
		t.Fatal("instructions array is empty")
	}
	found := false
	for _, v := range instructions {
		if s, ok := v.(string); ok && s == "~/.nixis/opencode-instructions.md" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nixis instructions ref not in config: %v", instructions)
	}
}

func TestPatchOpenCodeConfig_AppendsToExistingConfig(t *testing.T) {
	dir := t.TempDir()
	nixisDir := filepath.Join(dir, ".nixis")
	cfgPath := detectOpenCode(dir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"$schema": "https://opencode.ai/config.json", "instructions": ["~/.other/instructions.md"]}` + "\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := patchOpenCodeConfig(&w, dir, nixisDir); err != nil {
		t.Fatalf("patchOpenCodeConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON after patch: %v", err)
	}
	instructions, _ := config["instructions"].([]any)
	if len(instructions) < 2 {
		t.Fatalf("expected at least 2 instructions, got %d: %v", len(instructions), instructions)
	}
	// Original must be preserved.
	foundOther := false
	foundNixis := false
	for _, v := range instructions {
		if s, ok := v.(string); ok {
			if s == "~/.other/instructions.md" {
				foundOther = true
			}
			if s == "~/.nixis/opencode-instructions.md" {
				foundNixis = true
			}
		}
	}
	if !foundOther {
		t.Fatal("existing instructions entry was removed")
	}
	if !foundNixis {
		t.Fatal("nixis instructions entry not added")
	}
}

func TestPatchOpenCodeConfig_Idempotent(t *testing.T) {
	dir := t.TempDir()
	nixisDir := filepath.Join(dir, ".nixis")
	cfgPath := detectOpenCode(dir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"instructions": ["~/.nixis/opencode-instructions.md"]}` + "\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := patchOpenCodeConfig(&w, dir, nixisDir); err != nil {
		t.Fatalf("patchOpenCodeConfig: %v", err)
	}

	data, _ := os.ReadFile(cfgPath)
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	instructions, _ := config["instructions"].([]any)
	count := 0
	for _, v := range instructions {
		if s, ok := v.(string); ok && s == "~/.nixis/opencode-instructions.md" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 nixis instructions entry, got %d", count)
	}
	if !strings.Contains(w.String(), "already registered") {
		t.Fatalf("expected 'already registered' message, got: %s", w.String())
	}
}

func TestPatchOpenCodeConfig_WritesInstructionsFile(t *testing.T) {
	dir := t.TempDir()
	nixisDir := filepath.Join(dir, ".nixis")

	var w bytes.Buffer
	if err := patchOpenCodeConfig(&w, dir, nixisDir); err != nil {
		t.Fatalf("patchOpenCodeConfig: %v", err)
	}

	instrPath := filepath.Join(nixisDir, "opencode-instructions.md")
	data, err := os.ReadFile(instrPath)
	if err != nil {
		t.Fatalf("instructions file not created: %v", err)
	}
	if !strings.Contains(string(data), "Nixis Governance Policy") {
		t.Fatalf("instructions file missing expected content: %s", data)
	}
}

func TestUnpatchOpenCodeConfig_RemovesEntry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := detectOpenCode(dir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"instructions": ["~/.nixis/opencode-instructions.md", "~/.other/instr.md"]}` + "\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := unpatchOpenCodeConfig(&w, dir); err != nil {
		t.Fatalf("unpatchOpenCodeConfig: %v", err)
	}

	data, _ := os.ReadFile(cfgPath)
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	instructions, _ := config["instructions"].([]any)
	for _, v := range instructions {
		if s, ok := v.(string); ok && s == "~/.nixis/opencode-instructions.md" {
			t.Fatal("nixis instructions entry not removed")
		}
	}
	// Other entry must remain.
	found := false
	for _, v := range instructions {
		if s, ok := v.(string); ok && s == "~/.other/instr.md" {
			found = true
		}
	}
	if !found {
		t.Fatal("other instructions entry was removed")
	}
}

func TestUnpatchOpenCodeConfig_EmptyInstructions_DeletesKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := detectOpenCode(dir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"$schema": "https://opencode.ai/config.json", "instructions": ["~/.nixis/opencode-instructions.md"]}` + "\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := unpatchOpenCodeConfig(&w, dir); err != nil {
		t.Fatalf("unpatchOpenCodeConfig: %v", err)
	}

	data, _ := os.ReadFile(cfgPath)
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := config["instructions"]; ok {
		t.Fatal("instructions key should be deleted when array becomes empty")
	}
}

func TestUnpatchOpenCodeConfig_NotExist_Noop(t *testing.T) {
	dir := t.TempDir()
	var w bytes.Buffer
	if err := unpatchOpenCodeConfig(&w, dir); err != nil {
		t.Fatalf("unpatchOpenCodeConfig on missing file: %v", err)
	}
}

func TestUnpatchOpenCodeConfig_NotRegistered_Noop(t *testing.T) {
	dir := t.TempDir()
	cfgPath := detectOpenCode(dir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"instructions": ["~/.other/instr.md"]}` + "\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := unpatchOpenCodeConfig(&w, dir); err != nil {
		t.Fatalf("unpatchOpenCodeConfig: %v", err)
	}
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "~/.other/instr.md") {
		t.Fatal("other entry was removed")
	}
	if !strings.Contains(w.String(), "not found") {
		t.Fatalf("expected 'not found' message, got: %s", w.String())
	}
}
