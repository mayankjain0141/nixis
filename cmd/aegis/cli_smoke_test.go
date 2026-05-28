package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCLI_Smoke_AllCommandsExitCleanly runs each CLI command with --help
// to verify they're registered and have valid flag definitions.
func TestCLI_Smoke_AllCommandsExitCleanly(t *testing.T) {
	binary := buildAegisBinary(t)

	cmds := []struct {
		name string
		args []string
	}{
		{"validate", []string{"validate", "--help"}},
		{"simulate", []string{"simulate", "--help"}},
		{"audit verify", []string{"audit", "verify", "--help"}},
		{"audit export", []string{"audit", "export", "--help"}},
		{"audit tail", []string{"audit", "tail", "--help"}},
		{"scan", []string{"scan", "--help"}},
		{"bundle activate", []string{"bundle", "activate", "--help"}},
		{"bundle list", []string{"bundle", "list", "--help"}},
		{"bundle rollback", []string{"bundle", "rollback", "--help"}},
		{"delegation issue", []string{"delegation", "issue", "--help"}},
		{"delegation verify", []string{"delegation", "verify", "--help"}},
		{"delegation list", []string{"delegation", "list", "--help"}},
		{"delegation revoke", []string{"delegation", "revoke", "--help"}},
		{"policy cost", []string{"policy", "cost", "--help"}},
		{"policy lint", []string{"policy", "lint", "--help"}},
	}

	for _, tc := range cmds {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("command %q --help exited non-zero: %v\noutput:\n%s", tc.name, err, out)
			}
		})
	}
}

// buildAegisBinary compiles the aegis CLI binary into a temp dir and returns its path.
// The test is skipped if go build fails (e.g., missing dependencies in CI).
func buildAegisBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	binaryName := "aegis"
	if runtime.GOOS == "windows" {
		binaryName = "aegis.exe"
	}
	binaryPath := filepath.Join(dir, binaryName)

	// Resolve the module root from the package source file location.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	pkgDir := filepath.Dir(thisFile)

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = pkgDir

	// Propagate environment so go toolchain resolves modules correctly.
	cmd.Env = os.Environ()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\noutput:\n%s", err, out)
	}
	return binaryPath
}
