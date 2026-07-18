// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectHermes_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	got := detectHermes(dir)
	if got != "" {
		t.Fatalf("detectHermes on empty dir = %q, want empty", got)
	}
}

func TestDetectHermes_Installed(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("model:\n  default: claude\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectHermes(dir)
	if got != cfgPath {
		t.Fatalf("detectHermes = %q, want %q", got, cfgPath)
	}
}

func TestPatchHermesConfig_NoHooksSection(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	initial := "model:\n  default: claude\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	hookPath := "/home/user/.nixis/nixis-hook"
	var w bytes.Buffer
	if err := patchHermesConfig(&w, dir, hookPath); err != nil {
		t.Fatalf("patchHermesConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "nixis-hook") {
		t.Fatalf("nixis-hook not found in patched config:\n%s", content)
	}
	if !strings.Contains(content, "hooks:") {
		t.Fatalf("hooks: section not present:\n%s", content)
	}
	if !strings.Contains(content, "pre_tool_call:") {
		t.Fatalf("pre_tool_call: not present:\n%s", content)
	}
	if !strings.Contains(content, hermesBeginMarker) {
		t.Fatalf("nixis-begin marker not present:\n%s", content)
	}
}

func TestPatchHermesConfig_WithHooksButNoPreToolCall(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	initial := "hooks:\n  post_tool_call: []\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	hookPath := "/home/user/.nixis/nixis-hook"
	var w bytes.Buffer
	if err := patchHermesConfig(&w, dir, hookPath); err != nil {
		t.Fatalf("patchHermesConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "pre_tool_call:") {
		t.Fatalf("pre_tool_call: not inserted:\n%s", content)
	}
	if !strings.Contains(content, "nixis-hook") {
		t.Fatalf("nixis-hook not present:\n%s", content)
	}
}

func TestPatchHermesConfig_WithPreToolCall(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	initial := "hooks:\n  pre_tool_call:\n    - command: /other/tool\n      timeout: 30\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	hookPath := "/home/user/.nixis/nixis-hook"
	var w bytes.Buffer
	if err := patchHermesConfig(&w, dir, hookPath); err != nil {
		t.Fatalf("patchHermesConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "/other/tool") {
		t.Fatalf("existing hook removed:\n%s", content)
	}
	if !strings.Contains(content, "nixis-hook") {
		t.Fatalf("nixis-hook not added:\n%s", content)
	}
}

func TestPatchHermesConfig_Idempotent(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	// File already has nixis-hook.
	initial := "hooks:\n  pre_tool_call:\n    - command: /home/user/.nixis/nixis-hook\n      timeout: 5\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	hookPath := "/home/user/.nixis/nixis-hook"
	var w bytes.Buffer
	if err := patchHermesConfig(&w, dir, hookPath); err != nil {
		t.Fatalf("patchHermesConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Content must be identical — no duplicate entries.
	if string(data) != initial {
		t.Fatalf("idempotent run changed file:\ngot:\n%s\nwant:\n%s", data, initial)
	}
	if strings.Contains(w.String(), "patched") {
		t.Fatalf("expected 'already registered' message, got: %s", w.String())
	}
}

func TestPatchHermesConfig_NotExist_Skip(t *testing.T) {
	dir := t.TempDir()
	var w bytes.Buffer
	// No .hermes directory or config.yaml.
	if err := patchHermesConfig(&w, dir, "/path/nixis-hook"); err != nil {
		t.Fatalf("patchHermesConfig on missing config: %v", err)
	}
	if !strings.Contains(w.String(), "not found") {
		t.Fatalf("expected 'not found' message, got: %s", w.String())
	}
}

func TestUnpatchHermesConfig_RemovesBlock(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	initial := "hooks:\n  pre_tool_call:\n    # nixis-begin\n    - command: /home/user/.nixis/nixis-hook\n      timeout: 5\n    # nixis-end\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := unpatchHermesConfig(&w, dir); err != nil {
		t.Fatalf("unpatchHermesConfig: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "nixis-hook") {
		t.Fatalf("nixis-hook still present after unpatching:\n%s", content)
	}
	if strings.Contains(content, hermesBeginMarker) {
		t.Fatalf("nixis-begin marker still present:\n%s", content)
	}
}

func TestUnpatchHermesConfig_NoMarker_Noop(t *testing.T) {
	dir := t.TempDir()
	hermesDir := filepath.Join(dir, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(hermesDir, "config.yaml")
	initial := "hooks:\n  pre_tool_call: []\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	if err := unpatchHermesConfig(&w, dir); err != nil {
		t.Fatalf("unpatchHermesConfig: %v", err)
	}
	// File should be unchanged.
	data, _ := os.ReadFile(cfgPath)
	if string(data) != initial {
		t.Fatalf("file changed unexpectedly:\n%s", data)
	}
}

func TestUnpatchHermesConfig_NotExist_Noop(t *testing.T) {
	dir := t.TempDir()
	var w bytes.Buffer
	if err := unpatchHermesConfig(&w, dir); err != nil {
		t.Fatalf("unpatchHermesConfig on missing file: %v", err)
	}
}

func TestInsertAfterLine(t *testing.T) {
	content := "hooks:\n  post_tool_call: []\n"
	result := insertAfterLine(content, "hooks:", "\n  pre_tool_call:\n    - command: /hook\n")
	if !strings.Contains(result, "pre_tool_call:") {
		t.Fatalf("pre_tool_call not inserted: %q", result)
	}
	if !strings.HasPrefix(result, "hooks:") {
		t.Fatalf("hooks: should be first line: %q", result)
	}
}

func TestRemoveMarkedBlock(t *testing.T) {
	content := "before\n    # nixis-begin\n    - command: hook\n    # nixis-end\nafter\n"
	result := removeMarkedBlock(content, "    # nixis-begin", "    # nixis-end")
	if strings.Contains(result, "nixis-begin") {
		t.Fatalf("begin marker still present: %q", result)
	}
	if strings.Contains(result, "nixis-end") {
		t.Fatalf("end marker still present: %q", result)
	}
	if strings.Contains(result, "command: hook") {
		t.Fatalf("hook command still present: %q", result)
	}
	if !strings.Contains(result, "before") || !strings.Contains(result, "after") {
		t.Fatalf("surrounding content removed: %q", result)
	}
}
