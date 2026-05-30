// SPDX-License-Identifier: MIT
//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const plistLabel = "com.nixis.daemon"

func plistPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, "Library", "LaunchAgents", plistLabel+".plist")
}

func installDaemonService(homeDir, policyDir string, yes bool) error {
	aegisDir := filepath.Join(homeDir, ".nixis")
	daemonBin := filepath.Join(aegisDir, "nixis-daemon")
	logPath := filepath.Join(aegisDir, "daemon.log")
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

	// Load the service
	cmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), dest)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Fallback to legacy load if bootstrap not available
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
	cmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), dest)
	if output, err := cmd.CombinedOutput(); err != nil {
		cmd2 := exec.Command("launchctl", "load", dest)
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("start daemon: %w (%s; %s)", err2,
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
			return fmt.Errorf("stop daemon: %w (%s; %s)", err2,
				strings.TrimSpace(string(output2)), strings.TrimSpace(string(output)))
		}
	}
	return nil
}
