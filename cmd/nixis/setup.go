// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	setupYes       bool
	setupUninstall bool
	setupDryRun    bool
	setupPolicyDir string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install and configure Nixis on this machine",
	Long: `Interactive setup wizard that deploys binaries, installs policies,
configures the daemon service, and patches Claude Code settings.json.`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().BoolVarP(&setupYes, "yes", "y", false, "Skip all confirmation prompts")
	setupCmd.Flags().BoolVar(&setupUninstall, "uninstall", false, "Remove Nixis installation")
	setupCmd.Flags().BoolVar(&setupDryRun, "dry-run", false, "Show what would be done without making changes")
	setupCmd.Flags().StringVar(&setupPolicyDir, "policy-dir", "", "Source policy directory (default: ./policies)")
}

func runSetup(cmd *cobra.Command, _ []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	aegisDir := filepath.Join(homeDir, ".nixis")

	if setupUninstall {
		return runUninstall(cmd, homeDir, aegisDir)
	}
	return runInstall(cmd, homeDir, aegisDir)
}

func runInstall(cmd *cobra.Command, homeDir, aegisDir string) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "Nixis Setup")
	fmt.Fprintln(w, "===========")
	fmt.Fprintln(w)

	// Step 1: Detect binaries
	fmt.Fprintln(w, "[1/8] Detecting binaries...")
	binaries := []string{"nixis", "nixis-hook", "nixis-daemon"}
	binSources := make(map[string]string, len(binaries))
	for _, name := range binaries {
		path := findBinary(name)
		if path == "" {
			return fmt.Errorf("binary %q not found in PATH or current directory; run 'go build ./cmd/%s/' first", name, name)
		}
		binSources[name] = path
		fmt.Fprintf(w, "  Found: %s → %s\n", name, path)
	}

	// Step 2: Deploy binaries to ~/.nixis/
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2/8] Deploying binaries to", aegisDir)
	if err := os.MkdirAll(aegisDir, 0o755); err != nil && !setupDryRun {
		return fmt.Errorf("create %s: %w", aegisDir, err)
	}
	for _, name := range binaries {
		dest := filepath.Join(aegisDir, name)
		fmt.Fprintf(w, "  %s → %s\n", binSources[name], dest)
		if !setupDryRun {
			if err := copyFile(binSources[name], dest, 0o755); err != nil {
				return fmt.Errorf("deploy %s: %w", name, err)
			}
		}
	}

	// Step 3: Create policy directories
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3/8] Creating policy directories...")
	builtinDir := filepath.Join(aegisDir, "policies", "builtin")
	customDir := filepath.Join(aegisDir, "policies", "custom")
	for _, dir := range []string{builtinDir, customDir} {
		fmt.Fprintf(w, "  mkdir -p %s\n", dir)
		if !setupDryRun {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}
		}
	}

	// Step 4: Copy builtin policies
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[4/8] Installing builtin policies...")
	policySource := setupPolicyDir
	if policySource == "" {
		policySource = "./policies"
	}
	if err := copyPolicies(w, policySource, builtinDir); err != nil {
		return fmt.Errorf("install policies: %w", err)
	}

	// Step 5: Install daemon service
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[5/8] Installing daemon service...")
	policyDir := filepath.Join(aegisDir, "policies")
	if !setupDryRun {
		if err := installDaemonService(homeDir, policyDir, setupYes); err != nil {
			return fmt.Errorf("install daemon service: %w", err)
		}
		fmt.Fprintln(w, "  Daemon service installed")
	} else {
		fmt.Fprintln(w, "  (dry-run) Would install daemon service")
	}

	// Step 6: Patch settings.json
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[6/8] Patching Claude Code settings.json...")
	hookPath := filepath.Join(aegisDir, "nixis-hook")
	if err := patchSettingsJSON(w, homeDir, hookPath); err != nil {
		return fmt.Errorf("patch settings.json: %w", err)
	}

	// Step 7: Smoke test
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[7/8] Running smoke test...")
	if !setupDryRun {
		if err := runSmokeTest(w, aegisDir); err != nil {
			fmt.Fprintf(w, "  ⚠ Smoke test warning: %v\n", err)
		} else {
			fmt.Fprintln(w, "  ✓ Smoke test passed")
		}
	} else {
		fmt.Fprintln(w, "  (dry-run) Would run smoke test")
	}

	// Step 8: Clean up stale artifacts
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[8/8] Cleaning up stale artifacts...")
	staleFiles := []string{
		filepath.Join(aegisDir, "nixis-hook-wrapper.sh"),
		filepath.Join(aegisDir, "audit.log"),
	}
	for _, f := range staleFiles {
		if _, err := os.Stat(f); err == nil {
			fmt.Fprintf(w, "  Removing: %s\n", f)
			if !setupDryRun {
				_ = os.Remove(f)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "✓ Nixis setup complete!")
	fmt.Fprintf(w, "  Run 'nixis doctor' to verify installation health.\n")
	return nil
}

func runUninstall(cmd *cobra.Command, homeDir, aegisDir string) error {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Nixis Uninstall")
	fmt.Fprintln(w, "===============")
	fmt.Fprintln(w)

	// Step 1: Stop daemon service
	fmt.Fprintln(w, "[1/4] Stopping daemon service...")
	if !setupDryRun {
		if err := uninstallDaemonService(); err != nil {
			fmt.Fprintf(w, "  Warning: %v\n", err)
		} else {
			fmt.Fprintln(w, "  Service stopped and removed")
		}
	}

	// Step 2: Remove hook from settings.json
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2/4] Removing hook from settings.json...")
	if err := unpatchSettingsJSON(w, homeDir); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	}

	// Step 3: Remove ~/.nixis directory
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3/4] Removing", aegisDir)
	if !setupDryRun {
		if !setupYes {
			if !confirm(fmt.Sprintf("Remove %s and all contents?", aegisDir)) {
				fmt.Fprintln(w, "  Skipped (user declined)")
				return nil
			}
		}
		if err := os.RemoveAll(aegisDir); err != nil {
			return fmt.Errorf("remove %s: %w", aegisDir, err)
		}
		fmt.Fprintln(w, "  Removed")
	}

	// Step 4: Done
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[4/4] Done")
	fmt.Fprintln(w, "✓ Nixis uninstalled")
	return nil
}

func findBinary(name string) string {
	// Check current directory build output first
	candidates := []string{
		"./" + name,
		"./cmd/" + name + "/" + name,
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	// Check PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode)
}

func copyPolicies(w io.Writer, srcDir, destDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			subSrc := filepath.Join(srcDir, entry.Name())
			subDest := filepath.Join(destDir, entry.Name())
			if !setupDryRun {
				if err := os.MkdirAll(subDest, 0o755); err != nil {
					return err
				}
			}
			subEntries, err := os.ReadDir(subSrc)
			if err != nil {
				return err
			}
			for _, se := range subEntries {
				if se.IsDir() || !isYAML(se.Name()) {
					continue
				}
				src := filepath.Join(subSrc, se.Name())
				dst := filepath.Join(subDest, se.Name())
				if !setupDryRun {
					if err := copyFile(src, dst, 0o644); err != nil {
						return err
					}
				}
				count++
			}
			continue
		}
		if !isYAML(entry.Name()) {
			continue
		}
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(destDir, entry.Name())
		if !setupDryRun {
			if err := copyFile(src, dst, 0o644); err != nil {
				return err
			}
		}
		count++
	}
	fmt.Fprintf(w, "  Installed %d policy files\n", count)
	return nil
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func settingsJSONPath(homeDir string) string {
	return filepath.Join(homeDir, ".claude", "settings.json")
}

func patchSettingsJSON(w io.Writer, homeDir, hookPath string) error {
	path := settingsJSONPath(homeDir)
	fmt.Fprintf(w, "  Settings file: %s\n", path)

	var settings map[string]interface{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			settings = make(map[string]interface{})
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !setupDryRun {
				return fmt.Errorf("create settings directory: %w", err)
			}
		} else {
			return fmt.Errorf("read settings.json: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse settings.json: %w", err)
		}
	}

	hookEntry := map[string]interface{}{
		"type":    "command",
		"command": hookPath,
		"timeout": 10,
	}

	hookConfig := map[string]interface{}{
		"matcher": "",
		"hooks":   []interface{}{hookEntry},
	}

	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
	}
	hooks["PreToolUse"] = []interface{}{hookConfig}
	settings["hooks"] = hooks

	newData, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings.json: %w", err)
	}

	fmt.Fprintf(w, "  Hook command: %s\n", hookPath)

	if setupDryRun {
		fmt.Fprintln(w, "  (dry-run) Would write settings.json")
		return nil
	}

	if !setupYes {
		fmt.Fprintf(w, "\n  Will write to: %s\n", path)
		if !confirm("Apply settings.json patch?") {
			fmt.Fprintln(w, "  Skipped (user declined)")
			return nil
		}
	}

	if err := os.WriteFile(path, append(newData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write settings.json: %w", err)
	}
	fmt.Fprintln(w, "  ✓ settings.json patched")
	return nil
}

func unpatchSettingsJSON(w io.Writer, homeDir string) error {
	path := settingsJSONPath(homeDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings.json: %w", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse settings.json: %w", err)
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		fmt.Fprintln(w, "  No hooks section found")
		return nil
	}
	delete(hooks, "PreToolUse")
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	newData, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings.json: %w", err)
	}

	if !setupDryRun {
		if err := os.WriteFile(path, append(newData, '\n'), 0o644); err != nil {
			return fmt.Errorf("write settings.json: %w", err)
		}
	}
	fmt.Fprintln(w, "  ✓ Hook removed from settings.json")
	return nil
}

func runSmokeTest(w io.Writer, aegisDir string) error {
	hookBin := filepath.Join(aegisDir, "nixis-hook")
	cmd := exec.Command(hookBin, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook --version failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	fmt.Fprintf(w, "  Hook version: %s\n", strings.TrimSpace(string(output)))
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("  %s [Y/n] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}
