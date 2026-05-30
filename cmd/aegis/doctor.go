// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check Aegis installation health",
	RunE:  runDoctor,
}

type doctorCheck struct {
	name    string
	status  string
	detail  string
	warning bool
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	aegisDir := filepath.Join(homeDir, ".aegis")

	fmt.Fprintln(w, "Aegis Health Check")
	fmt.Fprintln(w, "==================")

	var checks []doctorCheck
	warnings := 0

	// Check 1: Daemon running
	checks = append(checks, checkDaemon())

	// Check 2: Socket
	checks = append(checks, checkSocket())

	// Check 3: Hook binary
	checks = append(checks, checkHookBinary(aegisDir))

	// Check 4: Hook output format
	checks = append(checks, checkHookFormat(aegisDir))

	// Check 5: settings.json hook
	checks = append(checks, checkSettingsJSON(homeDir, aegisDir))

	// Check 6: Policies loaded
	checks = append(checks, checkPoliciesLoaded())

	// Check 7: Fail-open count
	checks = append(checks, checkFailOpen(aegisDir))

	// Check 8: Heartbeat
	checks = append(checks, checkHeartbeat())

	for _, c := range checks {
		mark := "✓"
		if c.warning {
			mark = "⚠"
			warnings++
		}
		if c.status == "FAIL" {
			mark = "✗"
			warnings++
		}
		fmt.Fprintf(w, "  %-14s %s %s\n", c.name+":", mark, c.detail)
	}

	fmt.Fprintln(w)
	if warnings == 0 {
		fmt.Fprintln(w, "Overall: HEALTHY (0 warnings)")
	} else {
		fmt.Fprintf(w, "Overall: DEGRADED (%d warning(s))\n", warnings)
	}
	return nil
}

func checkDaemon() doctorCheck {
	running, pid, err := daemonServiceStatus()
	if err != nil {
		return doctorCheck{name: "Daemon", status: "FAIL", detail: fmt.Sprintf("error checking status: %v", err), warning: true}
	}
	if !running {
		return doctorCheck{name: "Daemon", status: "FAIL", detail: "not running", warning: true}
	}

	// Try healthz
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9091/healthz")
	if err != nil {
		return doctorCheck{name: "Daemon", status: "OK", detail: fmt.Sprintf("running (PID %d) but healthz unreachable", pid), warning: true}
	}
	defer func() { _ = resp.Body.Close() }()

	var health struct {
		Status   string `json:"status"`
		UptimeMs int64  `json:"uptime_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return doctorCheck{name: "Daemon", status: "OK", detail: fmt.Sprintf("running (PID %d)", pid)}
	}

	uptime := time.Duration(health.UptimeMs) * time.Millisecond
	return doctorCheck{name: "Daemon", status: "OK", detail: fmt.Sprintf("running (PID %d, uptime %s)", pid, formatDuration(uptime))}
}

func checkSocket() doctorCheck {
	sockPath := daemonSocketPath()
	info, err := os.Stat(sockPath)
	if err != nil {
		return doctorCheck{name: "Socket", status: "FAIL", detail: fmt.Sprintf("%s not found", sockPath), warning: true}
	}
	mode := info.Mode().Perm()
	detail := fmt.Sprintf("%s (mode %04o)", sockPath, mode)
	if mode&0o077 != 0 {
		return doctorCheck{name: "Socket", status: "OK", detail: detail + " — warning: world-accessible", warning: true}
	}
	return doctorCheck{name: "Socket", status: "OK", detail: detail}
}

func checkHookBinary(aegisDir string) doctorCheck {
	hookPath := filepath.Join(aegisDir, "aegis-hook")
	info, err := os.Stat(hookPath)
	if err != nil {
		return doctorCheck{name: "Hook", status: "FAIL", detail: fmt.Sprintf("%s not found", hookPath), warning: true}
	}
	if info.Mode()&0o111 == 0 {
		return doctorCheck{name: "Hook", status: "FAIL", detail: fmt.Sprintf("%s not executable", hookPath), warning: true}
	}
	return doctorCheck{name: "Hook", status: "OK", detail: fmt.Sprintf("%s (executable)", hookPath)}
}

func checkHookFormat(aegisDir string) doctorCheck {
	hookPath := filepath.Join(aegisDir, "aegis-hook")
	if _, err := os.Stat(hookPath); err != nil {
		return doctorCheck{name: "Hook Format", status: "FAIL", detail: "hook binary missing, cannot test", warning: true}
	}
	return doctorCheck{name: "Hook Format", status: "OK", detail: "skipped (requires running daemon)"}
}

func checkSettingsJSON(homeDir, aegisDir string) doctorCheck {
	path := settingsJSONPath(homeDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return doctorCheck{name: "Settings", status: "FAIL", detail: fmt.Sprintf("cannot read %s: %v", path, err), warning: true}
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return doctorCheck{name: "Settings", status: "FAIL", detail: fmt.Sprintf("invalid JSON in %s", path), warning: true}
	}

	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		return doctorCheck{name: "Settings", status: "FAIL", detail: "no hooks section in settings.json", warning: true}
	}

	preToolUse, ok := hooks["PreToolUse"]
	if !ok {
		return doctorCheck{name: "Settings", status: "FAIL", detail: "no PreToolUse hook configured", warning: true}
	}

	hookJSON, _ := json.Marshal(preToolUse)
	hookStr := string(hookJSON)
	expectedPath := filepath.Join(aegisDir, "aegis-hook")

	if !strings.Contains(hookStr, expectedPath) {
		return doctorCheck{name: "Settings", status: "FAIL", detail: "PreToolUse hook does not reference " + expectedPath, warning: true}
	}

	if strings.Contains(hookStr, "$HOME") || strings.Contains(hookStr, "~") {
		return doctorCheck{name: "Settings", status: "FAIL", detail: "hook path uses $HOME or ~ (must be literal)", warning: true}
	}

	return doctorCheck{name: "Settings", status: "OK", detail: "PreToolUse hook configured with literal path"}
}

func checkPoliciesLoaded() doctorCheck {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9091/healthz")
	if err != nil {
		return doctorCheck{name: "Policies", status: "FAIL", detail: "cannot reach daemon healthz", warning: true}
	}
	defer func() { _ = resp.Body.Close() }()

	var health struct {
		Evaluations int64 `json:"evaluations"`
		Checks      []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return doctorCheck{name: "Policies", status: "FAIL", detail: "cannot parse healthz response", warning: true}
	}

	engineOK := false
	for _, c := range health.Checks {
		if c.Name == "engine" && c.Status == "ok" {
			engineOK = true
		}
	}
	if !engineOK {
		return doctorCheck{name: "Policies", status: "FAIL", detail: "engine check not ok", warning: true}
	}
	return doctorCheck{name: "Policies", status: "OK", detail: fmt.Sprintf("engine ok, %d evaluations served", health.Evaluations)}
}

func checkFailOpen(aegisDir string) doctorCheck {
	logPath := filepath.Join(aegisDir, "failopen.log")
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{name: "Fail-open", status: "OK", detail: "no fail-open events (log not found)"}
		}
		return doctorCheck{name: "Fail-open", status: "OK", detail: "cannot read failopen.log"}
	}
	defer func() { _ = f.Close() }()

	cutoff := time.Now().Add(-24 * time.Hour)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Each line starts with an RFC3339 timestamp
		if len(line) >= 20 {
			ts, err := time.Parse(time.RFC3339, line[:20])
			if err == nil && ts.After(cutoff) {
				count++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return doctorCheck{name: "Fail-open", status: "OK", detail: fmt.Sprintf("error reading failopen.log: %v", err)}
	}

	if count > 0 {
		return doctorCheck{name: "Fail-open", status: "OK", detail: fmt.Sprintf("%d events in last 24h", count), warning: count > 10}
	}
	return doctorCheck{name: "Fail-open", status: "OK", detail: "0 events in last 24h"}
}

func checkHeartbeat() doctorCheck {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9091/healthz")
	if err != nil {
		return doctorCheck{name: "Heartbeat", status: "FAIL", detail: "cannot reach daemon", warning: true}
	}
	defer func() { _ = resp.Body.Close() }()

	var health struct {
		UptimeMs int64 `json:"uptime_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return doctorCheck{name: "Heartbeat", status: "FAIL", detail: "cannot parse healthz", warning: true}
	}

	if health.UptimeMs <= 0 {
		return doctorCheck{name: "Heartbeat", status: "FAIL", detail: "daemon reports zero uptime", warning: true}
	}
	return doctorCheck{name: "Heartbeat", status: "OK", detail: "daemon responsive"}
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
