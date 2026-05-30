// SPDX-License-Identifier: MIT
//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const systemdServiceName = "aegis-daemon.service"

func systemdUnitPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "systemd", "user", systemdServiceName)
}

func installDaemonService(homeDir, policyDir string, yes bool) error {
	aegisDir := filepath.Join(homeDir, ".aegis")
	daemonBin := filepath.Join(aegisDir, "aegis-daemon")
	socketPath := "/tmp/aegis.sock"

	unit := fmt.Sprintf(`[Unit]
Description=Aegis Governance Daemon
After=default.target

[Service]
ExecStart=%s -policy-dir %s -socket %s
Restart=always
Environment=AEGIS_DASHBOARD_ADDR=127.0.0.1:9090

[Install]
WantedBy=default.target
`, daemonBin, policyDir, socketPath)

	dest := systemdUnitPath()

	if setupDryRun {
		fmt.Printf("  (dry-run) Would write: %s\n", dest)
		return nil
	}

	if !yes {
		fmt.Printf("  Unit file: %s\n", dest)
		if !confirm("Install systemd user unit?") {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create systemd user directory: %w", err)
	}

	if err := os.WriteFile(dest, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload systemd and enable the service
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "--user", "enable", "--now", systemdServiceName).Run(); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}

	return nil
}

func uninstallDaemonService() error {
	dest := systemdUnitPath()
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		return nil
	}

	_ = exec.Command("systemctl", "--user", "stop", systemdServiceName).Run()
	_ = exec.Command("systemctl", "--user", "disable", systemdServiceName).Run()

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

func daemonServiceStatus() (running bool, pid int, err error) {
	cmd := exec.Command("systemctl", "--user", "show", systemdServiceName,
		"--property=ActiveState,MainPID")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, 0, nil
	}

	var active string
	var mainPID int
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "ActiveState=") {
			active = strings.TrimPrefix(line, "ActiveState=")
		}
		if strings.HasPrefix(line, "MainPID=") {
			val := strings.TrimPrefix(line, "MainPID=")
			mainPID, _ = strconv.Atoi(strings.TrimSpace(val))
		}
	}

	isRunning := active == "active"
	return isRunning, mainPID, nil
}

func startDaemon() error {
	if _, err := os.Stat(systemdUnitPath()); os.IsNotExist(err) {
		return fmt.Errorf("unit file not found at %s; run 'aegis setup' first", systemdUnitPath())
	}
	cmd := exec.Command("systemctl", "--user", "start", systemdServiceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start daemon: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stopDaemon() error {
	cmd := exec.Command("systemctl", "--user", "stop", systemdServiceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stop daemon: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
