// SPDX-License-Identifier: MIT
package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAcquirePIDLock_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")

	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock() unexpected error: %v", err)
	}
	defer func() { _ = lock.Unlock() }()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	got, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pid from file: %v", err)
	}
	if got != os.Getpid() {
		t.Errorf("pid file contains %d, want %d", got, os.Getpid())
	}
}

func TestAcquirePIDLock_SecondInstanceBlocked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")

	lock1, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer func() { _ = lock1.Unlock() }()

	_, err = AcquirePIDLock(path)
	if err == nil {
		t.Fatal("second AcquirePIDLock() should have failed")
	}
	if !strings.Contains(err.Error(), "another instance is already running") {
		t.Errorf("error message = %q, want containing 'another instance is already running'", err.Error())
	}
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("error message = %q, want containing PID %d", err.Error(), os.Getpid())
	}
}

func TestAcquirePIDLock_RelockAfterUnlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")

	lock1, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	lock2, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("second lock after unlock: %v", err)
	}
	defer func() { _ = lock2.Unlock() }()
}

func TestAcquirePIDLock_CreatesDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested", "path")
	path := filepath.Join(nested, "daemon.pid")

	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("AcquirePIDLock() with nested dir: %v", err)
	}
	defer func() { _ = lock.Unlock() }()

	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("stat nested dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected nested path to be a directory")
	}
}

func TestPIDLock_UnlockIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")

	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := lock.Unlock(); err != nil {
		t.Fatalf("first unlock: %v", err)
	}
	if err := lock.Unlock(); err != nil {
		t.Fatalf("second unlock should be no-op, got: %v", err)
	}
}

func TestPIDLock_UnlockRemovesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.pid")

	lock, err := AcquirePIDLock(path)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := lock.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("pid file should be removed after unlock")
	}
}
