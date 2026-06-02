// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Signal the daemon to reload policies from disk",
	Long:  `Triggers an immediate policy reload on the running daemon via its HTTP API.`,
	RunE:  runReload,
}

func runReload(cmd *cobra.Command, _ []string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post("http://127.0.0.1:9091/reload", "", nil)
	if err != nil {
		return fmt.Errorf("daemon unreachable (is it running?): %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reload failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Policies reloaded.")
	return nil
}
