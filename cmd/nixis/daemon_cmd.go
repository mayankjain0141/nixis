// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the Aegis daemon lifecycle",
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	RunE:  runDaemonStatus,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon",
	RunE:  runDaemonStart,
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the daemon",
	RunE:  runDaemonStop,
}

var daemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the daemon",
	RunE:  runDaemonRestart,
}

var daemonLogsN int

var daemonLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Tail daemon log file",
	RunE:  runDaemonLogs,
}

func init() {
	daemonLogsCmd.Flags().IntVarP(&daemonLogsN, "lines", "n", 50, "Number of lines to show")
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonRestartCmd)
	daemonCmd.AddCommand(daemonLogsCmd)
}

func runDaemonStatus(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	running, pid, err := daemonServiceStatus()
	if err != nil {
		return fmt.Errorf("check status: %w", err)
	}

	if !running {
		fmt.Fprintln(w, "Daemon: stopped")
		return nil
	}

	fmt.Fprintf(w, "Daemon: running (PID %d)\n", pid)

	// Fetch healthz for extended info
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9091/healthz")
	if err != nil {
		fmt.Fprintf(w, "  Healthz: unreachable (%v)\n", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var health struct {
		Status      string `json:"status"`
		Mode        string `json:"mode"`
		UptimeMs    int64  `json:"uptime_ms"`
		Evaluations int64  `json:"evaluations"`
		Version     string `json:"version"`
		Checks      []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		fmt.Fprintf(w, "  Healthz: cannot parse response\n")
		return nil
	}

	uptime := time.Duration(health.UptimeMs) * time.Millisecond
	fmt.Fprintf(w, "  Status:      %s\n", health.Status)
	fmt.Fprintf(w, "  Mode:        %s\n", health.Mode)
	fmt.Fprintf(w, "  Uptime:      %s\n", formatDuration(uptime))
	fmt.Fprintf(w, "  Evaluations: %d\n", health.Evaluations)
	fmt.Fprintf(w, "  Version:     %s\n", health.Version)
	fmt.Fprintf(w, "  Socket:      %s\n", daemonSocketPath())

	if len(health.Checks) > 0 {
		fmt.Fprintln(w, "  Components:")
		for _, c := range health.Checks {
			mark := "✓"
			if c.Status != "ok" {
				mark = "✗"
			}
			fmt.Fprintf(w, "    %s %s\n", mark, c.Name)
		}
	}
	return nil
}

func runDaemonStart(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	running, _, _ := daemonServiceStatus()
	if running {
		fmt.Fprintln(w, "Daemon is already running")
		return nil
	}

	fmt.Fprintln(w, "Starting daemon...")
	if err := startDaemon(); err != nil {
		return err
	}

	// Wait for healthy
	if err := waitForHealthy(5 * time.Second); err != nil {
		fmt.Fprintf(w, "  Started but not yet healthy: %v\n", err)
		return nil
	}
	fmt.Fprintln(w, "  ✓ Daemon started and healthy")
	return nil
}

func runDaemonStop(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	running, _, _ := daemonServiceStatus()
	if !running {
		fmt.Fprintln(w, "Daemon is not running")
		return nil
	}

	fmt.Fprintln(w, "Stopping daemon...")
	if err := stopDaemon(); err != nil {
		return err
	}
	fmt.Fprintln(w, "  ✓ Daemon stopped")
	return nil
}

func runDaemonRestart(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "Restarting daemon...")

	running, _, _ := daemonServiceStatus()
	if running {
		if err := stopDaemon(); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		// Brief pause to allow socket cleanup
		time.Sleep(500 * time.Millisecond)
	}

	if err := startDaemon(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	if err := waitForHealthy(5 * time.Second); err != nil {
		fmt.Fprintf(w, "  Started but not yet healthy: %v\n", err)
		return nil
	}
	fmt.Fprintln(w, "  ✓ Daemon restarted and healthy")
	return nil
}

func runDaemonLogs(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	logPath := filepath.Join(homeDir, ".aegis", "daemon.log")

	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer func() { _ = f.Close() }()

	// Read last N lines by seeking from end
	lines, err := tailFile(f, daemonLogsN)
	if err != nil {
		return fmt.Errorf("read log: %w", err)
	}

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return nil
}

func waitForHealthy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://127.0.0.1:9091/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for healthz")
}

func tailFile(f *os.File, n int) ([]string, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, nil
	}

	// Read up to 64KB from the end
	bufSize := int64(64 * 1024)
	if bufSize > size {
		bufSize = size
	}

	buf := make([]byte, bufSize)
	offset := size - bufSize
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}

	content := string(buf)
	allLines := splitLines(content)

	if len(allLines) <= n {
		return allLines, nil
	}
	return allLines[len(allLines)-n:], nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
