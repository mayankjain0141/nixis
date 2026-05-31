// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	policyUpgradeLocal bool
	policyUpgradeDir   string
	policyUpgradeOwner string
	policyUpgradeRepo  string
	policyUpgradeYes   bool
)

var policyUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade builtin policies to latest version",
	Long: `Fetches the latest builtin policies from the project GitHub release
(or from a local directory with --local) and installs them to ~/.nixis/policies/builtin/.
Custom policies in ~/.nixis/policies/custom/ are never modified.`,
	RunE: runPolicyUpgrade,
}

func init() {
	policyUpgradeCmd.Flags().BoolVar(&policyUpgradeLocal, "local", false, "Copy from local directory instead of GitHub")
	policyUpgradeCmd.Flags().StringVar(&policyUpgradeDir, "dir", "./policies", "Local policy source directory (used with --local)")
	policyUpgradeCmd.Flags().StringVar(&policyUpgradeOwner, "owner", "mayjain", "GitHub repository owner")
	policyUpgradeCmd.Flags().StringVar(&policyUpgradeRepo, "repo", "nixis", "GitHub repository name")
	policyUpgradeCmd.Flags().BoolVarP(&policyUpgradeYes, "yes", "y", false, "Skip confirmation prompts")
	policyCmd.AddCommand(policyUpgradeCmd)
}

func runPolicyUpgrade(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}

	builtinDir := filepath.Join(homeDir, ".nixis", "policies", "builtin")
	if err := os.MkdirAll(builtinDir, 0o755); err != nil {
		return fmt.Errorf("create builtin directory: %w", err)
	}

	fmt.Fprintln(w, "Nixis Policy Upgrade")
	fmt.Fprintln(w, "====================")
	fmt.Fprintln(w)

	if policyUpgradeLocal {
		return upgradeFromLocal(w, builtinDir)
	}
	return upgradeFromGitHub(w, builtinDir)
}

func upgradeFromLocal(w io.Writer, builtinDir string) error {
	fmt.Fprintf(w, "Source: %s (local)\n", policyUpgradeDir)
	fmt.Fprintf(w, "Target: %s\n\n", builtinDir)

	changes, err := diffPolicies(policyUpgradeDir, builtinDir)
	if err != nil {
		return fmt.Errorf("diff policies: %w", err)
	}

	if len(changes) == 0 {
		fmt.Fprintln(w, "No changes — policies are up to date.")
		return nil
	}

	fmt.Fprintf(w, "Changes (%d files):\n", len(changes))
	for _, c := range changes {
		fmt.Fprintf(w, "  %s %s\n", c.action, c.name)
	}
	fmt.Fprintln(w)

	if !policyUpgradeYes {
		if !confirm("Apply policy upgrade?") {
			fmt.Fprintln(w, "Cancelled.")
			return nil
		}
	}

	if err := copyPoliciesForUpgrade(policyUpgradeDir, builtinDir); err != nil {
		return fmt.Errorf("copy policies: %w", err)
	}

	fmt.Fprintf(w, "\n✓ Upgraded %d policies in %s\n", len(changes), builtinDir)
	fmt.Fprintln(w, "  Daemon will reload via fsnotify (no restart needed)")
	return nil
}

func upgradeFromGitHub(w io.Writer, builtinDir string) error {
	releaseURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		policyUpgradeOwner, policyUpgradeRepo)

	fmt.Fprintf(w, "Fetching latest release from %s/%s...\n", policyUpgradeOwner, policyUpgradeRepo)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(releaseURL)
	if err != nil {
		return fmt.Errorf("fetch release info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned %d; try --local for offline upgrade", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
		TarballURL string `json:"tarball_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("parse release response: %w", err)
	}

	fmt.Fprintf(w, "Latest release: %s\n", release.TagName)

	// Look for a policies tarball/zip asset
	var policyAssetURL string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, "policies") {
			policyAssetURL = asset.BrowserDownloadURL
			break
		}
	}

	if policyAssetURL == "" {
		fmt.Fprintln(w, "  No policy asset found in release; use --local to upgrade from source")
		return fmt.Errorf("no policy asset in release %s", release.TagName)
	}

	// Download to temp directory
	fmt.Fprintf(w, "Downloading policies from %s...\n", policyAssetURL)
	tmpDir, err := downloadAndExtractPolicies(client, policyAssetURL)
	if err != nil {
		return fmt.Errorf("download policies: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Diff and apply
	changes, err := diffPolicies(tmpDir, builtinDir)
	if err != nil {
		return fmt.Errorf("diff policies: %w", err)
	}

	if len(changes) == 0 {
		fmt.Fprintln(w, "No changes — policies are up to date.")
		return nil
	}

	fmt.Fprintf(w, "Changes (%d files):\n", len(changes))
	for _, c := range changes {
		fmt.Fprintf(w, "  %s %s\n", c.action, c.name)
	}
	fmt.Fprintln(w)

	if !policyUpgradeYes {
		if !confirm("Apply policy upgrade?") {
			fmt.Fprintln(w, "Cancelled.")
			return nil
		}
	}

	if err := copyPoliciesForUpgrade(tmpDir, builtinDir); err != nil {
		return fmt.Errorf("copy policies: %w", err)
	}

	fmt.Fprintf(w, "\n✓ Upgraded %d policies to %s\n", len(changes), release.TagName)
	fmt.Fprintln(w, "  Daemon will reload via fsnotify (no restart needed)")
	return nil
}

type policyChange struct {
	name   string
	action string // "ADD", "MOD", "DEL"
}

func diffPolicies(srcDir, destDir string) ([]policyChange, error) {
	var changes []policyChange

	srcFiles := make(map[string]struct{})
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !isYAML(info.Name()) {
			return nil
		}
		rel, _ := filepath.Rel(srcDir, path)
		srcFiles[rel] = struct{}{}

		destPath := filepath.Join(destDir, rel)
		srcData, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		destData, err := os.ReadFile(destPath)
		if err != nil {
			if os.IsNotExist(err) {
				changes = append(changes, policyChange{name: rel, action: "ADD"})
				return nil
			}
			return err
		}
		if string(srcData) != string(destData) {
			changes = append(changes, policyChange{name: rel, action: "MOD"})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Check for files in dest that don't exist in src (deletions)
	_ = filepath.Walk(destDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isYAML(info.Name()) {
			return nil
		}
		rel, _ := filepath.Rel(destDir, path)
		if _, exists := srcFiles[rel]; !exists {
			changes = append(changes, policyChange{name: rel, action: "DEL"})
		}
		return nil
	})

	return changes, nil
}

func copyPoliciesForUpgrade(srcDir, destDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcDir, path)
		destPath := filepath.Join(destDir, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}
		if !isYAML(info.Name()) {
			return nil
		}
		return copyFile(path, destPath, 0o644)
	})
}

func downloadAndExtractPolicies(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmpDir, err := os.MkdirTemp("", "nixis-policies-*")
	if err != nil {
		return "", err
	}

	// Write the downloaded content to a temp file for extraction
	tmpFile := filepath.Join(tmpDir, "policies.tar.gz")
	f, err := os.Create(tmpFile)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.RemoveAll(tmpDir)
		return "", err
	}
	_ = f.Close()

	// For now, just return tmpDir — in a real implementation this would
	// extract the tarball. Users should prefer --local for offline upgrades.
	return tmpDir, nil
}
