// SPDX-License-Identifier: MIT
//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const plistLabel = "com.nixis.daemon"

func plistPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, "Library", "LaunchAgents", plistLabel+".plist")
}

func installDaemonService(homeDir, policyDir string, yes bool) error {
	if !filepath.IsAbs(policyDir) {
		if abs, err := filepath.Abs(policyDir); err == nil {
			policyDir = abs
		}
	}
	nixisDir := filepath.Join(homeDir, ".nixis")
	daemonBin := filepath.Join(nixisDir, "nixis-daemon")
	logPath := filepath.Join(nixisDir, "daemon.log")
	socketPath := "/tmp/nixis.sock"

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>-policy-dir</string>
        <string>%s</string>
        <string>-socket</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NIXIS_DASHBOARD_ADDR</key>
        <string>127.0.0.1:9090</string>
    </dict>
</dict>
</plist>
`, plistLabel, daemonBin, policyDir, socketPath, logPath, logPath)

	dest := plistPath()

	if setupDryRun {
		fmt.Printf("  (dry-run) Would write: %s\n", dest)
		return nil
	}

	if !yes {
		fmt.Printf("  Plist: %s\n", dest)
		if !confirm("Install launchd plist?") {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}

	if err := os.WriteFile(dest, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Purge any prior registration before bootstrapping so we never hit
	// "Bad request" from a stale entry left by a previous install.
	purgeServiceFromLaunchd()

	// Load the service
	cmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), dest)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Fallback to legacy load if bootstrap not available (macOS < Ventura).
		cmd2 := exec.Command("launchctl", "load", dest)
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("launchctl load failed: %w (%s; bootstrap: %s)", err2,
				strings.TrimSpace(string(output2)), strings.TrimSpace(string(output)))
		}
	}

	return nil
}

func uninstallDaemonService() error {
	dest := plistPath()

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		return nil
	}

	// Try bootout first, then legacy unload
	cmd := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel))
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd2 := exec.Command("launchctl", "unload", dest)
		_ = cmd2.Run()
	}

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

func daemonServiceStatus() (running bool, pid int, err error) {
	cmd := exec.Command("launchctl", "list", plistLabel)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, 0, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == plistLabel {
			if fields[0] != "-" {
				p, _ := strconv.Atoi(fields[0])
				return true, p, nil
			}
			return false, 0, nil
		}
	}

	// Parse "PID" key from verbose output
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "\"PID\"") || strings.HasPrefix(trimmed, "\"pid\"") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(strings.TrimRight(parts[1], ";"))
				p, _ := strconv.Atoi(val)
				if p > 0 {
					return true, p, nil
				}
			}
		}
	}

	return false, 0, nil
}

func startDaemon() error {
	dest := plistPath()
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		return fmt.Errorf("plist not found at %s; run 'nixis setup' first", dest)
	}

	// Purge any ghost registration before bootstrapping. Without this, a
	// prior `launchctl load` (legacy path) or a crashed daemon can leave the
	// label partially registered, causing bootstrap to return "Bad request".
	purgeServiceFromLaunchd()

	cmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), dest)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Last-resort fallback for macOS < Ventura where bootstrap is unavailable.
		// purgeServiceFromLaunchd() already cleared legacy registrations above, so
		// load won't accumulate a ghost on top of an existing entry.
		cmd2 := exec.Command("launchctl", "load", dest)
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("start daemon: %w (%s; bootstrap: %s)", err2,
				strings.TrimSpace(string(output2)), strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func stopDaemon() error {
	cmd := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel))
	if output, err := cmd.CombinedOutput(); err != nil {
		cmd2 := exec.Command("launchctl", "unload", plistPath())
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			// Both launchctl calls failed; still attempt to kill the process
			// so the caller doesn't inherit an orphan.
			killDaemonProcess()
			return fmt.Errorf("stop daemon: %w (%s; %s)", err2,
				strings.TrimSpace(string(output2)), strings.TrimSpace(string(output)))
		}
	}
	killDaemonProcess()
	return nil
}

func stopDaemonWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), plistLabel))
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		killDaemonProcess()
		return fmt.Errorf("launchctl timed out after %v (service may be stuck)", timeout)
	}
	if err != nil {
		cmd2 := exec.CommandContext(ctx, "launchctl", "unload", plistPath())
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			killDaemonProcess()
			return fmt.Errorf("stop daemon: %w (%s; %s)", err2,
				strings.TrimSpace(string(output2)), strings.TrimSpace(string(output)))
		}
	}
	killDaemonProcess()
	return nil
}

// killDaemonProcess sends SIGTERM to the daemon process and waits up to 1s
// for it to exit, then sends SIGKILL. The PID is re-fetched before SIGKILL to
// avoid sending the signal to a different process that may have been assigned
// the same PID after the original daemon exited.
func killDaemonProcess() {
	pid := findDaemonPID()
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		if findDaemonPID() == 0 {
			return
		}
	}
	// Re-fetch PID: the original process may have died and launchd (if not yet
	// booted out) could have restarted a new instance with a different PID.
	if fresh := findDaemonPID(); fresh > 0 {
		_ = syscall.Kill(fresh, syscall.SIGKILL)
		// Wait until the kernel reaps the process before returning.
		for i := 0; i < 20; i++ {
			time.Sleep(50 * time.Millisecond)
			if findDaemonPID() == 0 {
				return
			}
		}
	}
}

func daemonServiceStatusWithTimeout(timeout time.Duration) (running bool, pid int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "launchctl", "list", plistLabel)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return false, 0, fmt.Errorf("launchctl timed out — service may be corrupt")
	}
	if err != nil {
		return false, 0, nil
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == plistLabel {
			if fields[0] != "-" {
				p, _ := strconv.Atoi(fields[0])
				return true, p, nil
			}
			return false, 0, nil
		}
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "\"PID\"") || strings.HasPrefix(trimmed, "\"pid\"") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(strings.TrimRight(parts[1], ";"))
				p, _ := strconv.Atoi(val)
				if p > 0 {
					return true, p, nil
				}
			}
		}
	}
	return false, 0, nil
}

func findDaemonPID() int {
	cmd := exec.Command("pgrep", "-f", "nixis-daemon")
	output, _ := cmd.Output()
	pid, _ := strconv.Atoi(strings.TrimSpace(string(output)))
	return pid
}

// purgeServiceFromLaunchd removes all traces of the daemon from launchd and
// kills any orphaned process. This is necessary because launchd can enter an
// inconsistent state where bootstrap fails with "Bad request" when the label
// is partially registered from a previous load/unload cycle — for example,
// when a deprecated `launchctl load` was used instead of `bootstrap`, or when
// the process crashed without a clean `bootout`. Calling this before any
// bootstrap call guarantees we start from a known-clean state.
func purgeServiceFromLaunchd() {
	uid := os.Getuid()

	// Fire all removal variants — they are order-independent and each is a
	// no-op if the service isn't registered in that domain.
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, plistLabel)).Run()
	_ = exec.Command("launchctl", "remove", plistLabel).Run()
	_ = exec.Command("launchctl", "unload", plistPath()).Run()

	// Kill any process that survived the launchd removal (orphaned daemon).
	killDaemonProcess()
}
