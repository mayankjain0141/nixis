package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BundleManifest is persisted alongside each stored bundle.
type BundleManifest struct {
	Hash        string    `json:"hash"`
	Version     uint64    `json:"version"`
	PolicyCount int       `json:"policy_count"`
	StoredAt    time.Time `json:"stored_at"`
}

// bundleStore is a content-addressable on-disk store keyed by SHA-256 hex.
// Layout:
//
//	<storageDir>/
//	  <sha256hex>/
//	    bundle.tar.gz
//	    bundle.sig
//	    manifest.json
type bundleStore struct {
	dir  string
	keep int
}

func newBundleStore(dir string, keep int) (*bundleStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("bundle store: mkdir %s: %w", dir, err)
	}
	if keep <= 0 {
		keep = 3
	}
	return &bundleStore{dir: dir, keep: keep}, nil
}

// save writes bundle content, signature, and manifest to disk.
// Returns the directory path for this bundle entry.
func (s *bundleStore) save(hashHex string, content, sig []byte, manifest BundleManifest) (string, error) {
	entryDir := filepath.Join(s.dir, hashHex)
	if err := os.MkdirAll(entryDir, 0700); err != nil {
		return "", fmt.Errorf("bundle store: mkdir entry: %w", err)
	}

	if err := os.WriteFile(filepath.Join(entryDir, "bundle.tar.gz"), content, 0600); err != nil {
		return "", fmt.Errorf("bundle store: write bundle.tar.gz: %w", err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, "bundle.sig"), sig, 0600); err != nil {
		return "", fmt.Errorf("bundle store: write bundle.sig: %w", err)
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("bundle store: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, "manifest.json"), manifestJSON, 0600); err != nil {
		return "", fmt.Errorf("bundle store: write manifest.json: %w", err)
	}

	return entryDir, nil
}

// gc removes oldest bundles beyond the keep count.
// It reads stored_at from each manifest.json to determine order.
func (s *bundleStore) gc() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("bundle store gc: readdir: %w", err)
	}

	type entry struct {
		name     string
		storedAt time.Time
	}
	var candidates []entry

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(s.dir, e.Name(), "manifest.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var m BundleManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		candidates = append(candidates, entry{name: e.Name(), storedAt: m.StoredAt})
	}

	if len(candidates) <= s.keep {
		return nil
	}

	// sort oldest first
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].storedAt.Before(candidates[j].storedAt)
	})

	toDelete := candidates[:len(candidates)-s.keep]
	for _, c := range toDelete {
		if err := os.RemoveAll(filepath.Join(s.dir, c.name)); err != nil {
			return fmt.Errorf("bundle store gc: remove %s: %w", c.name, err)
		}
	}
	return nil
}

// count returns the number of stored bundle entries.
func (s *bundleStore) count() int {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}
