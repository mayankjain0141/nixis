// SPDX-License-Identifier: MIT
package reload

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mayjain/aegis/internal/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

const debounceDuration = 100 * time.Millisecond

// Package-level reload counters. Prometheus integration comes in a later phase.
var (
	reloadSuccessTotal atomic.Int64
	reloadErrorTotal   atomic.Int64
)

func ReloadSuccessTotal() int64 { return reloadSuccessTotal.Load() }

func ReloadErrorTotal() int64 { return reloadErrorTotal.Load() }

// PolicyReloader is the interface for the policy engine's Reload method.
// Defined here to avoid importing internal/policy (circular dep).
type PolicyReloader interface {
	Reload() error
}

type ReloadWatcher struct {
	policyDir string
	engine    PolicyReloader
}

func NewReloadWatcher(policyDir string, engine PolicyReloader) (*ReloadWatcher, error) {
	return &ReloadWatcher{
		policyDir: policyDir,
		engine:    engine,
	}, nil
}

func New(policyDir string, engine PolicyReloader) (*ReloadWatcher, error) {
	return NewReloadWatcher(policyDir, engine)
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
					reloadErrorTotal.Add(1)
					otel.InstrumentPolicyReload().Add(context.Background(), 1,
						otelmetric.WithAttributes(attribute.String("status", "error")))
					slog.Error("policy reload failed; retaining last-known-good snapshot", "err", err)
				} else {
					reloadSuccessTotal.Add(1)
					otel.InstrumentPolicyReload().Add(context.Background(), 1,
						otelmetric.WithAttributes(attribute.String("status", "success")))
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
