package reload_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/reload"
)

type mockReloader struct {
	mu      sync.Mutex
	count   int
	failErr error
}

func (m *mockReloader) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count++
	return m.failErr
}

func (m *mockReloader) reloadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}

// startWatcher spins up a watcher in a goroutine and returns cancel + done channel.
func startWatcher(t *testing.T, dir string, engine reload.PolicyReloader) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	w, err := reload.New(dir, engine)
	if err != nil {
		t.Fatalf("reload.New: %v", err)
	}
	go func() {
		done <- w.Start(ctx)
	}()
	return cancel, done
}

func TestReload_Debounce(t *testing.T) {
	dir := t.TempDir()
	mock := &mockReloader{}

	cancel, done := startWatcher(t, dir, mock)
	// Allow watcher to initialise
	time.Sleep(20 * time.Millisecond)

	// Write 10 YAML files within 50ms
	for i := range 10 {
		name := filepath.Join(dir, "policy"+string(rune('a'+i))+".yaml")
		if err := os.WriteFile(name, []byte("key: value"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	// Wait long enough for debounce to fire (100ms) plus margin
	time.Sleep(300 * time.Millisecond)

	cancel()
	<-done

	count := mock.reloadCount()
	if count != 1 {
		t.Errorf("expected exactly 1 reload; got %d", count)
	}
}

func TestReload_FailureKeepsOldSnapshot(t *testing.T) {
	dir := t.TempDir()
	mock := &mockReloader{failErr: errReloadFailed}

	cancel, done := startWatcher(t, dir, mock)
	time.Sleep(20 * time.Millisecond)

	// First file change → reload returns error
	if err := os.WriteFile(filepath.Join(dir, "pol.yaml"), []byte("x: 1"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	if mock.reloadCount() != 1 {
		t.Errorf("expected 1 reload attempt on error; got %d", mock.reloadCount())
	}

	// Clear error; second file change → reload should succeed
	mock.mu.Lock()
	mock.failErr = nil
	mock.mu.Unlock()

	if err := os.WriteFile(filepath.Join(dir, "pol2.yaml"), []byte("x: 2"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	if mock.reloadCount() != 2 {
		t.Errorf("expected 2 reload attempts total; got %d", mock.reloadCount())
	}

	cancel()
	<-done
}

func TestReload_ConcurrentEvalCorrectness(t *testing.T) {
	dir := t.TempDir()
	mock := &mockReloader{}

	cancel, done := startWatcher(t, dir, mock)
	time.Sleep(20 * time.Millisecond)

	// Spawn concurrent goroutines calling reloadCount while the watcher fires reloads.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mock.reloadCount()
		}()
	}

	// Trigger a reload at the same time
	if err := os.WriteFile(filepath.Join(dir, "concurrent.yaml"), []byte("c: 1"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	wg.Wait()

	cancel()
	<-done
	// go test -race will catch any races
}

func TestReload_ContextCancel_Exits(t *testing.T) {
	dir := t.TempDir()
	mock := &mockReloader{}

	cancel, done := startWatcher(t, dir, mock)
	time.Sleep(20 * time.Millisecond)

	cancel()
	err := <-done
	if err != context.Canceled {
		t.Errorf("expected context.Canceled; got %v", err)
	}
}

func TestReload_NonYAMLIgnored(t *testing.T) {
	dir := t.TempDir()
	mock := &mockReloader{}

	cancel, done := startWatcher(t, dir, mock)
	time.Sleep(20 * time.Millisecond)

	// Write a .go file — must not trigger reload
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	cancel()
	<-done

	if count := mock.reloadCount(); count != 0 {
		t.Errorf("expected 0 reloads for non-YAML file; got %d", count)
	}
}
