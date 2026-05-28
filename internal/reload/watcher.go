package reload

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounceDuration = 100 * time.Millisecond

// PolicyReloader is the interface for the policy engine's Reload method.
// Defined here to avoid importing internal/policy (circular dep).
type PolicyReloader interface {
	Reload() error
}

// ReloadWatcher watches a directory and triggers policy reloads on file changes.
type ReloadWatcher struct {
	policyDir string
	engine    PolicyReloader
}

// New creates a new ReloadWatcher.
func New(policyDir string, engine PolicyReloader) (*ReloadWatcher, error) {
	return &ReloadWatcher{
		policyDir: policyDir,
		engine:    engine,
	}, nil
}

// Start begins watching and blocks until ctx is cancelled.
// Must be called AFTER initial policy load.
func (r *ReloadWatcher) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(r.policyDir); err != nil {
		if cerr := watcher.Close(); cerr != nil {
			slog.Error("fsnotify watcher close error", "err", cerr)
		}
		return err
	}
	defer func() {
		if cerr := watcher.Close(); cerr != nil {
			slog.Error("fsnotify watcher close error", "err", cerr)
		}
	}()

	var debounceTimer *time.Timer
	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !isYAMLFile(event.Name) {
				continue
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove) == 0 {
				continue
			}
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debounceDuration, func() {
				if err := r.engine.Reload(); err != nil {
					slog.Error("policy reload failed; retaining last-known-good snapshot", "err", err)
				} else {
					slog.Info("policy reload succeeded")
				}
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.Error("fsnotify watcher error", "err", err)
		}
	}
}

func isYAMLFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yaml" || ext == ".yml"
}
