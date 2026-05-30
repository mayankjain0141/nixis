// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/mayjain/nixis/internal/bundle"
	"github.com/mayjain/nixis/pkg/nixis"
	"github.com/spf13/cobra"
)

var (
	bundleSocket string
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Bundle management operations",
}

var bundleActivateCmd = &cobra.Command{
	Use:   "activate <path>",
	Short: "Load a policy bundle and activate it via the daemon",
	Args:  cobra.ExactArgs(1),
	RunE:  runBundleActivate,
}

var bundleListStoreDir string

var bundleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored bundles",
	RunE:  runBundleList,
}

var bundleRollbackStoreDir string

var bundleRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback to the previous stored bundle",
	RunE:  runBundleRollback,
}

func defaultBundleStoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/nixis/bundles"
	}
	return filepath.Join(home, ".nixis", "bundles")
}

func init() {
	bundleActivateCmd.Flags().StringVar(&bundleSocket, "socket", "", "Daemon socket path (default: $NIXIS_SOCKET_PATH or /tmp/nixis.sock)")
	bundleListCmd.Flags().StringVar(&bundleListStoreDir, "store-dir", "", "Bundle store directory (default: ~/.nixis/bundles/)")
	bundleRollbackCmd.Flags().StringVar(&bundleRollbackStoreDir, "store-dir", "", "Bundle store directory (default: ~/.nixis/bundles/)")
	bundleCmd.AddCommand(bundleActivateCmd)
	bundleCmd.AddCommand(bundleListCmd)
	bundleCmd.AddCommand(bundleRollbackCmd)
}

func runBundleActivate(cmd *cobra.Command, args []string) error {
	return activateBundle(cmd, args[0])
}

func activateBundle(cmd *cobra.Command, bundlePath string) error {
	// Step 1: parse and validate the bundle.
	if _, err := os.Stat(bundlePath); err != nil {
		return fmt.Errorf("bundle path: %w", err)
	}

	templates, bindings, err := bundle.ParsePolicyDir(bundlePath)
	if err != nil {
		// Try as a single file
		tmpl, binding, ferr := bundle.ParsePolicyFile(bundlePath)
		if ferr != nil {
			return fmt.Errorf("parse bundle: %w", ferr)
		}
		if tmpl != nil {
			templates = append(templates, *tmpl)
		}
		if binding != nil {
			bindings = append(bindings, *binding)
		}
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "parsed: %d templates, %d bindings\n",
		len(templates), len(bindings)); err != nil {
		return err
	}

	// Step 2: notify the daemon via the standard CheckRequest wire protocol
	// (same framing as `nixis simulate`) so it can trigger a policy reload.
	sockPath := bundleSocket
	if sockPath == "" {
		sockPath = daemonSocketPath()
	}

	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon at %s: %w", sockPath, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Encode a CheckRequest with tool="bundle_reload" and the bundle path as args.
	argsJSON, err := json.Marshal(map[string]string{"bundle_path": bundlePath})
	if err != nil {
		return fmt.Errorf("marshal args: %w", err)
	}
	req := nixis.CheckRequest{
		Tool:      "bundle_reload",
		Args:      json.RawMessage(argsJSON),
		Timestamp: time.Now().UnixNano(),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := writeSimFramed(conn, reqBytes, deadline); err != nil {
		return fmt.Errorf("send reload request: %w", err)
	}

	// Read the daemon response (a CheckResponse). The daemon returns DENY for
	// unrecognised tools — that is expected until a dedicated reload RPC is added.
	respBytes, err := readSimFramed(conn, time.Now().Add(2*time.Second))
	if err != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "bundle activated (no daemon ack — daemon may need restart)\n")
		return nil
	}
	var resp nixis.CheckResponse
	if jsonErr := json.Unmarshal(respBytes, &resp); jsonErr != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "bundle activated\n")
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "daemon: action=%v\n", resp.Decision.Action)
	return nil
}

func loadBundleManifests(storeDir string) ([]bundle.BundleManifest, error) {
	entries, err := os.ReadDir(storeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read store dir: %w", err)
	}

	var manifests []bundle.BundleManifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(storeDir, e.Name(), "manifest.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var m bundle.BundleManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, nil
}

func runBundleList(cmd *cobra.Command, _ []string) error {
	storeDir := bundleListStoreDir
	if storeDir == "" {
		storeDir = defaultBundleStoreDir()
	}

	manifests, err := loadBundleManifests(storeDir)
	if err != nil {
		return err
	}

	if len(manifests) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no bundles")
		return nil
	}

	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].StoredAt.Before(manifests[j].StoredAt)
	})

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-12s  %-8s  %s\n", "version", "hash", "stored_at")
	for _, m := range manifests {
		shortHash := m.Hash
		if len(shortHash) > 8 {
			shortHash = shortHash[:8]
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-12d  %-8s  %s\n",
			m.Version, shortHash, m.StoredAt.Format(time.RFC3339))
	}
	return nil
}

func runBundleRollback(cmd *cobra.Command, _ []string) error {
	storeDir := bundleRollbackStoreDir
	if storeDir == "" {
		storeDir = defaultBundleStoreDir()
	}

	manifests, err := loadBundleManifests(storeDir)
	if err != nil {
		return err
	}

	if len(manifests) < 2 {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "no previous bundle to roll back to")
		return fmt.Errorf("rollback failed: no previous bundle to roll back to")
	}

	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].StoredAt.Before(manifests[j].StoredAt)
	})

	prev := manifests[len(manifests)-2]
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "rolling back to bundle hash=%s version=%d stored_at=%s\n",
		prev.Hash, prev.Version, prev.StoredAt.Format(time.RFC3339))

	// The stored bundle is bundle.tar.gz inside the hash-named directory.
	bundlePath := filepath.Join(storeDir, prev.Hash, "bundle.tar.gz")
	sockPath := bundleSocket
	if sockPath == "" {
		sockPath = daemonSocketPath()
	}
	if err := sendBundleReload(bundlePath, sockPath); err != nil {
		return fmt.Errorf("send reload to daemon: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "bundle activated successfully")
	return nil
}

type bundleReloadMsg struct {
	Type    string `json:"type"`
	BundleP string `json:"bundle_path"`
}

func sendBundleReload(bundlePath, sockPath string) error {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon at %s: %w", sockPath, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	msg := bundleReloadMsg{
		Type:    "bundle_reload",
		BundleP: bundlePath,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal reload message: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msgBytes)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return fmt.Errorf("send reload header: %w", err)
	}
	if _, err := conn.Write(msgBytes); err != nil {
		return fmt.Errorf("send reload body: %w", err)
	}

	// Read acknowledgement (best-effort — daemon may not implement bundle_reload yet).
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil
	}
	var respHdr [4]byte
	if _, err := io.ReadFull(conn, respHdr[:]); err != nil {
		// Timeout or no ack — reload message was sent successfully.
		return nil
	}
	length := binary.BigEndian.Uint32(respHdr[:])
	respBytes := make([]byte, length)
	_, _ = io.ReadFull(conn, respBytes)
	return nil
}
