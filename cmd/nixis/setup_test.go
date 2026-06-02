// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFile_SameFile_NoError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	if err := os.WriteFile(path, []byte("content"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Copying a file onto itself must be a no-op, not an error.
	if err := copyFile(path, path, 0o755); err != nil {
		t.Fatalf("copyFile same src/dst: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Fatalf("file content changed: %q", got)
	}
}

func TestCopyFile_UnlinksExistingDst(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("dst content = %q, want %q", got, "new")
	}
}

func TestCopyFile_CreatesNewDst(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o644); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("dst content = %q, want %q", got, "hello")
	}
}

func TestCopyFile_AtomicRename_NoTmpLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	// .tmp file should not exist after successful copy
	tmpFile := dst + ".tmp"
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Fatalf("tmp file %s should not exist after successful copy", tmpFile)
	}
}

func TestCopyFile_PreservesMode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("exec"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	// Check executable bit is set
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("dst mode %v does not have executable bit set", info.Mode().Perm())
	}
}

func TestCopyFile_SameInode_Symlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(src, []byte("content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	// Copying real → link (same inode) should be a no-op
	if err := copyFile(src, link, 0o755); err != nil {
		t.Fatalf("copyFile symlink same file: %v", err)
	}
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Fatalf("content changed: %q", got)
	}
}

func TestFindBinary_BinDir(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks for macOS where /var → /private/var
	dir, _ = filepath.EvalSymlinks(dir)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(binDir, "test-tool")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := findBinary("test-tool")
	if got == "" {
		t.Fatal("findBinary returned empty, expected bin/test-tool")
	}
	expected := filepath.Join(dir, "bin", "test-tool")
	if got != expected {
		t.Fatalf("findBinary = %q, want %q", got, expected)
	}
}

func TestFindBinary_CurrentDir(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	toolPath := filepath.Join(dir, "my-binary")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := findBinary("my-binary")
	if got == "" {
		t.Fatal("findBinary returned empty, expected ./my-binary")
	}
	expected := filepath.Join(dir, "my-binary")
	if got != expected {
		t.Fatalf("findBinary = %q, want %q", got, expected)
	}
}

func TestFindBinary_NotFound(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	got := findBinary("nonexistent-tool-xyz-12345")
	if got != "" {
		t.Fatalf("findBinary for nonexistent tool returned %q, want empty", got)
	}
}

// TestRemoveNixisLines exercises the shell-config cleanup logic used by
// 'nixis uninstall'. Each sub-test mirrors a real scenario.
func TestRemoveNixisLines(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "shellrc")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(content); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		return f.Name()
	}
	read := func(t *testing.T, path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("removes_marker_export_and_preceding_blank_line", func(t *testing.T) {
		// Exactly what install.sh appends: \n# Nixis\nexport PATH=...\n
		input := "export FOO=bar\n\n# Nixis\nexport PATH=\"/home/user/.nixis:$PATH\"\n"
		want := "export FOO=bar\n"
		path := write(t, input)
		if !removeNixisLines(path) {
			t.Fatal("removeNixisLines reported no modification")
		}
		if got := read(t, path); got != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("removes_fish_add_path_and_preceding_blank_line", func(t *testing.T) {
		input := "set -x FOO bar\n\n# Nixis\nfish_add_path /home/user/.nixis\n"
		want := "set -x FOO bar\n"
		path := write(t, input)
		if !removeNixisLines(path) {
			t.Fatal("removeNixisLines reported no modification")
		}
		if got := read(t, path); got != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("no_preceding_blank_line_still_removes_block", func(t *testing.T) {
		// Block at start of file with no preceding blank line.
		input := "# Nixis\nexport PATH=\"/home/user/.nixis:$PATH\"\nexport BAR=baz\n"
		want := "export BAR=baz\n"
		path := write(t, input)
		if !removeNixisLines(path) {
			t.Fatal("removeNixisLines reported no modification")
		}
		if got := read(t, path); got != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("no_nixis_block_is_noop", func(t *testing.T) {
		input := "export FOO=bar\nexport BAZ=qux\n"
		path := write(t, input)
		if removeNixisLines(path) {
			t.Fatal("removeNixisLines reported modification on file with no Nixis block")
		}
		if got := read(t, path); got != input {
			t.Fatalf("file was modified: got %q, want %q", got, input)
		}
	})

	t.Run("preserves_rest_of_file_intact", func(t *testing.T) {
		input := "# other config\nexport EDITOR=vim\n\n# Nixis\nexport PATH=\"/home/user/.nixis:$PATH\"\n\n# more config\nexport TERM=xterm\n"
		want := "# other config\nexport EDITOR=vim\n\n# more config\nexport TERM=xterm\n"
		path := write(t, input)
		if !removeNixisLines(path) {
			t.Fatal("removeNixisLines reported no modification")
		}
		if got := read(t, path); got != want {
			t.Fatalf("got:\n%q\nwant:\n%q", got, want)
		}
	})
}
