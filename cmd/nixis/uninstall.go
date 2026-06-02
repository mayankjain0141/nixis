// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	uninstallYes   bool
	uninstallForce bool
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove Nixis from this machine",
	Long: `Removes all Nixis components: stops daemon, removes service,
unhooks from Claude Code/Cursor, deletes policies, removes PATH entry,
and cleans up ~/.nixis/.

This is the inverse of 'nixis setup'. Run it manually — AI agents
cannot execute this command (Nixis blocks self-removal by policy).

If this command hangs, use --force to bypass service management:
  nixis uninstall --force --yes

Manual recovery (if even --force hangs):
  pgrep -f nixis | xargs kill -9 2>/dev/null
  rm -f ~/Library/LaunchAgents/com.nixis.daemon.plist
  rm -rf ~/.nixis && rm -f /tmp/nixis.sock`,
	RunE: runUninstallCmd,
}

func init() {
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip confirmation prompt")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "Skip service management (use when launchctl/systemctl is stuck)")
}

func runUninstallCmd(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	nixisDir := filepath.Join(homeDir, ".nixis")

	fmt.Fprintln(w, "Nixis Uninstall")
	fmt.Fprintln(w, "===============")
	fmt.Fprintln(w)

	// Show what will be removed
	fmt.Fprintln(w, "This will remove:")
	fmt.Fprintf(w, "  • Daemon service and process\n")
	fmt.Fprintf(w, "  • Hook from ~/.claude/settings.json\n")
	fmt.Fprintf(w, "  • PATH entries from shell configs\n")
	fmt.Fprintf(w, "  • Socket at /tmp/nixis.sock\n")
	fmt.Fprintf(w, "  • Directory %s\n", nixisDir)
	fmt.Fprintln(w)

	if !uninstallYes {
		if !confirm("Proceed with uninstall?") {
			fmt.Fprintln(w, "Aborted.")
			return nil
		}
		fmt.Fprintln(w)
	}

	// Step 1: Stop daemon
	fmt.Fprintln(w, "[1/6] Stopping daemon...")
	if uninstallForce {
		if p := findDaemonPID(); p > 0 {
			fmt.Fprintf(w, "  Force-killing daemon (PID %d)...\n", p)
			_ = syscall.Kill(p, syscall.SIGKILL)
			time.Sleep(500 * time.Millisecond)
		} else {
			fmt.Fprintln(w, "  No daemon process found")
		}
	} else {
		if err := stopDaemonWithTimeout(5 * time.Second); err != nil {
			fmt.Fprintf(w, "  Warning: graceful stop failed (%v), force-killing...\n", err)
			if p := findDaemonPID(); p > 0 {
				_ = syscall.Kill(p, syscall.SIGKILL)
				time.Sleep(500 * time.Millisecond)
			}
		} else {
			fmt.Fprintln(w, "  Daemon stopped")
		}
	}

	// Step 2: Remove service definition
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2/6] Removing service definition...")
	if err := uninstallDaemonService(); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	} else {
		fmt.Fprintln(w, "  Service removed")
	}

	// Step 3: Remove hook from settings.json
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3/6] Removing hook from settings.json...")
	if err := unpatchSettingsJSON(w, homeDir); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	}

	// Step 4: Clean shell configs
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[4/6] Removing PATH entries from shell configs...")
	cleanShellConfigs(w, homeDir)

	// Step 5: Remove socket
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[5/6] Removing socket...")
	sockPath := "/tmp/nixis.sock"
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(w, "  Warning: could not remove %s: %v\n", sockPath, err)
	} else {
		fmt.Fprintf(w, "  Removed %s\n", sockPath)
	}

	// Step 6: Remove ~/.nixis/
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[6/6] Removing", nixisDir+"...")
	if err := os.RemoveAll(nixisDir); err != nil {
		fmt.Fprintf(w, "  Warning: %v\n", err)
	} else {
		fmt.Fprintln(w, "  Removed")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "✓ Nixis uninstalled successfully.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To reinstall:")
	fmt.Fprintln(w, "  git clone https://github.com/mayjain/nixis && cd nixis")
	fmt.Fprintln(w, "  make build && ./nixis setup")
	return nil
}

func cleanShellConfigs(w io.Writer, homeDir string) {
	configs := []string{
		filepath.Join(homeDir, ".zshrc"),
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".profile"),
		filepath.Join(homeDir, ".config", "fish", "config.fish"),
	}
	for _, cfg := range configs {
		if removed := removeNixisLines(cfg); removed {
			fmt.Fprintf(w, "  Cleaned %s\n", cfg)
		}
	}
}

func removeNixisLines(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	modified := false
	skipNext := false

	for i, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, "# Nixis") {
			// Also remove the blank line that install.sh writes immediately
			// before the marker (\n# Nixis\n...). If the previous collected
			// line is blank, trim it.
			if len(result) > 0 && result[len(result)-1] == "" {
				result = result[:len(result)-1]
			}
			skipNext = true // skip the path/export line that follows
			modified = true
			_ = i // suppress unused warning
			continue
		}
		result = append(result, line)
	}

	if modified {
		_ = os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o644)
	}
	return modified
}
