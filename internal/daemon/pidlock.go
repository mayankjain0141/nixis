// SPDX-License-Identifier: MIT
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// PIDLock provides mutual exclusion for the daemon process using flock(2).
// Only one daemon instance can hold the lock at a time; subsequent attempts
// receive a descriptive error indicating the owning PID.
type PIDLock struct {
	file *os.File
	path string
}

// AcquirePIDLock attempts to obtain an exclusive, non-blocking file lock at path.
// On success the current PID is written to the file and the lock is held until
// Unlock() is called or the process exits. The parent directory is created if needed.
func AcquirePIDLock(path string) (*PIDLock, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create pid lock directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open pid file: %w", err)
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		existingPID := readPIDFromFile(f)
		_ = f.Close()
		if existingPID > 0 {
			return nil, fmt.Errorf("another instance is already running (PID %d)", existingPID)
		}
		return nil, fmt.Errorf("another instance is already running (PID unknown)")
	}

	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("truncate pid file: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek pid file: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pid: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync pid file: %w", err)
	}

	return &PIDLock{file: f, path: path}, nil
}

// Unlock releases the file lock and removes the PID file.
func (l *PIDLock) Unlock() error {
	if l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	_ = os.Remove(l.path)
	l.file = nil
	if err != nil {
		return fmt.Errorf("unlock pid file: %w", err)
	}
	return closeErr
}

// readPIDFromFile attempts to read a PID from the beginning of the file.
func readPIDFromFile(f *os.File) int {
	if _, err := f.Seek(0, 0); err != nil {
		return 0
	}
	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		return 0
	}
	return pid
}
