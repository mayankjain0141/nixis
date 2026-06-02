// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	setupYes          bool
	setupUninstall    bool
	setupDryRun       bool
	setupPolicyDir    string
	setupSkipBinaries bool
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
	setupCmd.Flags().BoolVar(&setupSkipBinaries, "skip-binaries", false, "Skip binary deployment (use when binaries are already in place)")
}

func runSetup(cmd *cobra.Command, _ []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	nixisDir := filepath.Join(homeDir, ".nixis")

	if setupUninstall {
		return runUninstall(cmd, homeDir, nixisDir)
	}
	return runInstall(cmd, homeDir, nixisDir)
}

func runInstall(cmd *cobra.Command, homeDir, nixisDir string) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "Nixis Setup")
	fmt.Fprintln(w, "===========")
	fmt.Fprintln(w)

	// Step 1: Detect binaries
	fmt.Fprintln(w, "[1/8] Detecting binaries...")
	binaries := []string{"nixis", "nixis-hook", "nixis-daemon"}
	binSources := make(map[string]string, len(binaries))
	if !setupSkipBinaries {
		for _, name := range binaries {
			path := findBinary(name)
			if path == "" {
				return fmt.Errorf("binary %q not found in PATH or current directory; run 'go build ./cmd/%s/' first", name, name)
			}
			binSources[name] = path
			fmt.Fprintf(w, "  Found: %s → %s\n", name, path)
		}
	} else {
		fmt.Fprintln(w, "  Skipped (--skip-binaries)")
	}

	// Step 2: Deploy binaries to ~/.nixis/
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2/8] Deploying binaries to", nixisDir)
	if !setupSkipBinaries {
		if err := os.MkdirAll(nixisDir, 0o755); err != nil && !setupDryRun {
			return fmt.Errorf("create %s: %w", nixisDir, err)
		}
		for _, name := range binaries {
			dest := filepath.Join(nixisDir, name)
			fmt.Fprintf(w, "  %s → %s\n", binSources[name], dest)
			if !setupDryRun {
				if err := copyFile(binSources[name], dest, 0o755); err != nil {
					return fmt.Errorf("deploy %s: %w", name, err)
				}
			}
		}
	} else {
		fmt.Fprintln(w, "  Skipped (--skip-binaries)")
	}

	// Step 3: Create policy directories
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3/8] Creating policy directories...")
	policyDestDir := filepath.Join(nixisDir, "policies")
	customDir := filepath.Join(policyDestDir, "custom")
	for _, dir := range []string{policyDestDir, customDir} {
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
	if err := copyPolicies(w, policySource, policyDestDir); err != nil {
		return fmt.Errorf("install policies: %w", err)
	}

	// Step 5: Install daemon service
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[5/8] Installing daemon service...")
	policyDir := filepath.Join(nixisDir, "policies")
	if !setupDryRun {
		if err := installDaemonService(homeDir, policyDir, setupYes); err != nil {
			return fmt.Errorf("install daemon service: %w", err)
		}
		fmt.Fprintln(w, "  Daemon service installed")
	} else {
		fmt.Fprintln(w, "  (dry-run) Would install daemon service")
	}

	// Step 5b: Restart daemon
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[5b/8] Managing daemon lifecycle...")
	if !setupDryRun {
		running, pid, _ := daemonServiceStatusWithTimeout(3 * time.Second)
		if running {
			fmt.Fprintf(w, "  Restarting daemon (PID %d)...\n", pid)
			if err := stopDaemonWithTimeout(5 * time.Second); err != nil {
				fmt.Fprintf(w, "  Warning: graceful stop failed (%v), force-killing...\n", err)
				if p := findDaemonPID(); p > 0 {
					_ = syscall.Kill(p, syscall.SIGKILL)
					time.Sleep(500 * time.Millisecond)
				}
			}
			if err := startDaemon(); err != nil {
				fmt.Fprintf(w, "  Warning: restart failed: %v\n", err)
			} else {
				fmt.Fprintln(w, "  Daemon restarted")
				waitForDaemon(w)
			}
		} else {
			if err := startDaemon(); err != nil {
				fmt.Fprintf(w, "  Warning: could not start daemon: %v\n", err)
			} else {
				fmt.Fprintln(w, "  Daemon started")
				waitForDaemon(w)
			}
		}
	} else {
		fmt.Fprintln(w, "  (dry-run) Would restart daemon")
	}

	// Step 6: Patch settings.json
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[6/8] Patching Claude Code settings.json...")
	hookPath := filepath.Join(nixisDir, "nixis-hook")
	if err := patchSettingsJSON(w, homeDir, hookPath); err != nil {
		return fmt.Errorf("patch settings.json: %w", err)
	}

	// Step 7: Smoke test
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[7/8] Running smoke test...")
	if !setupDryRun {
		if err := runSmokeTest(w, nixisDir); err != nil {
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
		filepath.Join(nixisDir, "nixis-hook-wrapper.sh"),
		filepath.Join(nixisDir, "audit.log"),
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

func runUninstall(cmd *cobra.Command, homeDir, nixisDir string) error {
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
	fmt.Fprintln(w, "[3/4] Removing", nixisDir)
	if !setupDryRun {
		if !setupYes {
			if !confirm(fmt.Sprintf("Remove %s and all contents?", nixisDir)) {
				fmt.Fprintln(w, "  Skipped (user declined)")
				return nil
			}
		}
		if err := os.RemoveAll(nixisDir); err != nil {
			return fmt.Errorf("remove %s: %w", nixisDir, err)
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
	candidates := []string{
		filepath.Join("bin", name),
		"./" + name,
		filepath.Join("cmd", name, name),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	// Fallback: already-installed copy
	homeDir, _ := os.UserHomeDir()
	installed := filepath.Join(homeDir, ".nixis", name)
	if info, err := os.Stat(installed); err == nil && !info.IsDir() {
		fmt.Fprintf(os.Stderr, "  WARNING: No fresh build found for %s, using installed copy at %s\n", name, installed)
		fmt.Fprintf(os.Stderr, "           Did you forget 'make build'?\n")
		return installed
	}
	// Check PATH last
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func copyFile(src, dst string, mode fs.FileMode) error {
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if absSrc == absDst {
		return nil
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if dstInfo, err := os.Stat(dst); err == nil {
		if os.SameFile(srcInfo, dstInfo) {
			return nil
		}
	}

	tmpDst := dst + ".tmp"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpDst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}
	if err := os.Rename(tmpDst, dst); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}
	return os.Chmod(dst, mode)
}

func copyPolicies(w io.Writer, srcDir, destDir string) error {
	// Confirm srcDir exists before walking.
	if _, err := os.Stat(srcDir); err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}

	count := 0
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(destDir, rel)

		if d.IsDir() {
			if setupDryRun {
				return nil
			}
			return os.MkdirAll(dst, 0o755)
		}
		if !isYAML(d.Name()) {
			return nil
		}
		if !setupDryRun {
			if err := copyFile(path, dst, 0o644); err != nil {
				return err
			}
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  Installed %d policy files\n", count)
	return nil
}

// waitForDaemon polls until the daemon healthz endpoint responds or 10s elapses.
// Called immediately after startDaemon() because launchctl/systemctl returns
// before the process has bound its socket and HTTP server.
func waitForDaemon(w io.Writer) {
	fmt.Fprintf(w, "  Waiting for daemon to be ready")
	client := &http.Client{Timeout: 1 * time.Second}
	socketPath := daemonSocketPath()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Check healthz HTTP endpoint
		if resp, err := client.Get("http://127.0.0.1:9091/healthz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Also wait for socket
				if _, serr := os.Stat(socketPath); serr == nil {
					fmt.Fprintln(w, " ready.")
					return
				}
			}
		}
		fmt.Fprintf(w, ".")
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintln(w, " timed out (run 'nixis doctor' to check status).")
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

	_, _ = fmt.Fprintf(w, "  Hook command: %s\n", hookPath)

	if setupDryRun {
		_, _ = fmt.Fprintln(w, "  (dry-run) Would write settings.json")
		return nil
	}

	if !setupYes {
		_, _ = fmt.Fprintf(w, "\n  Will write to: %s\n", path)
		if !confirm("Apply settings.json patch?") {
			_, _ = fmt.Fprintln(w, "  Skipped (user declined)")
			return nil
		}
	}

	if err := os.WriteFile(path, append(newData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write settings.json: %w", err)
	}
	_, _ = fmt.Fprintln(w, "  ✓ settings.json patched")
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
		_, _ = fmt.Fprintln(w, "  No hooks section found")
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
	_, _ = fmt.Fprintln(w, "  ✓ Hook removed from settings.json")
	return nil
}

func runSmokeTest(w io.Writer, nixisDir string) error {
	hookBin := filepath.Join(nixisDir, "nixis-hook")
	cmd := exec.Command(hookBin, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook --version failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	_, _ = fmt.Fprintf(w, "  Hook version: %s\n", strings.TrimSpace(string(output)))
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("  %s [Y/n] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}
